#include <io.h>
#include <Ws2tcpip.h>
#include "httpServThread.h"
#include "common.h"
#include "others.h"

extern GLogger glogger;

HttpServThread::HttpServThread(PHTTPSERV_THREAD_PARA para)
	:GThread(para)
{
	m_glogger.setHeader(TEXT("Serv"));
	m_para = para;    
	m_clients.clear();
	InitSocket();
	InitResources();
}


HttpServThread::~HttpServThread()
{
}

typedef struct _sock_thread_para
{
    SOCKET sock;
    DWORD remoteIP;
    PHTTPSERV_THREAD_PARA para;
    vector<RESOURCE> *resources;
    char* prevHtml;
	char* currentHtml;
}SOCK_THREAD_PARA,*PSOCK_THREAD_PARA;

const char* m_htmlHead = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n";
const char* m_svgHead = "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n";
const char* m_jpgHead = "HTTP/1.1 200 OK\r\nContent-Type: image/jpg; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n";
const char* m_swfHead = "HTTP/1.1 200 OK\r\nContent-Type: application/x-shockwave-flash; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n";
const char* m_jsHead = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n";
const char* m_cssHead = "HTTP/1.1 200 OK\r\nContent-Type: text/css; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n";
const char* m_errorpage = "<html><head><title>mixFuzz error</title></head><body><H1>mixFuzz error</H1></body></html>";

DWORD WINAPI SocketThread(PVOID para)
{
    char* m_receiveMessage = new char[1024];
    char* m_requestUrl = new char[1024];
    char* m_sendBuff = new char[MAX_SENDBUFF_SIZE + 1];
    size_t headLen, dataLen = 0;
    const char* sendHead = m_htmlHead;
    const char* sendData = NULL;
    PSOCK_THREAD_PARA pPara = (PSOCK_THREAD_PARA)para;

    // 接收请求数据
    int ret = recv(pPara->sock, m_receiveMessage, 1023, 0);
    if (ret == 0 || ret == SOCKET_ERROR)
    {
        goto _safe_exit;
    }
	ret = (ret < 1024) ? ret : 1023;
	m_receiveMessage[ret] = 0;

    // 获取Get的URL
    char* url_start = strstr(m_receiveMessage, " ");
    if (url_start == NULL)
    {
        goto _safe_exit;
    }
    char* url_end = strstr(url_start + 1, " ");
    if (url_end == NULL)
    {
        goto _safe_exit;
    }
    memcpy(m_requestUrl, url_start + 1, url_end - url_start - 1);
    m_requestUrl[url_end - url_start - 1] = 0;

    // 根据URL,设置数据头    
    if (strstr(m_requestUrl, ".svg") != NULL)
        sendHead = m_svgHead;
    else if (strstr(m_requestUrl, ".jpg") != NULL)
        sendHead = m_jpgHead;
    else if (strstr(m_requestUrl, ".swf") != NULL)
        sendHead = m_swfHead;
    else if (strstr(m_requestUrl, ".html") != NULL)
        sendHead = m_htmlHead;
    else if (strstr(m_requestUrl, ".js") != NULL)
        sendHead = m_jsHead;
    else if (strstr(m_requestUrl, ".css") != NULL)
        sendHead = m_cssHead;
    headLen = strlen(sendHead);

    // 设置发送数据
    if (strstr(m_requestUrl, "prev.html") != NULL)
    {
        if (pPara->prevHtml != NULL && strlen(pPara->prevHtml) > 0)
        {
            sendData = pPara->prevHtml;
            dataLen = strlen(sendData);       
        }
        else
        {
            sendData = m_errorpage;
            dataLen = strlen(sendData);
        }
    }
	else if (strstr(m_requestUrl, "current.html") != NULL)
	{
		if (pPara->para->mode == TEXT("server"))
		{
			tstring remoteIP = inet_ltot(pPara->remoteIP);
			glogger.setDefaultColor(gcommon::PRINT_COLOR::BRIGHT_RED);
			glogger.insertCurrentTime(TEXT("   [yyyy-MM-dd HH:mm:ss] "));
			glogger.screen(TEXT("[") + remoteIP + TEXT("] find crash, wait for poc ...\n"));
			glogger.setDefaultColor();
		}

		if (pPara->currentHtml != NULL && strlen(pPara->currentHtml) > 0)
		{
			sendData = pPara->currentHtml;
			dataLen = strlen(sendData);
		}
		else
		{
			sendData = m_errorpage;
			dataLen = strlen(sendData);
		}
	}
    else if (strlen(m_requestUrl) != 1)// "/"
    {
        
        for each (RESOURCE var in *pPara->resources)
        {
            if (var.name == m_requestUrl + 1)
            {
                sendData = var.data;
                dataLen = var.size;
                break;
            }
        }

        if (sendData == NULL)
        {            
            sendHead = m_htmlHead;
            sendData = m_errorpage;
        }
    }
    else //样本
    {
        sendData = pPara->para->htmlBuff;        
    }

    if (headLen + dataLen > MAX_SENDBUFF_SIZE)
    {
        sendHead = m_htmlHead;
        sendData = m_errorpage;
    }

    // 其他资源请求，直接发送
    if (sendData != pPara->para->htmlBuff)
    {
		dataLen = strlen(sendData);
        memcpy(m_sendBuff, sendHead, headLen);
        memcpy(m_sendBuff + headLen, sendData, dataLen);
        m_sendBuff[headLen + dataLen] = 0;
        send(pPara->sock, m_sendBuff, (int)(headLen + dataLen), 0);
        goto _safe_exit;
    }

    // fuzz请求，需申请互斥量    
    memcpy(m_sendBuff, sendHead, headLen);
    if (WAIT_OBJECT_0 != WaitForSingleObject(pPara->para->semHtmlbuff_c, INFINITE))
    {
        goto _safe_exit;
    }
	dataLen = strlen(sendData);
    memcpy(m_sendBuff + headLen, sendData, dataLen);
    m_sendBuff[headLen + dataLen] = 0;
    ReleaseSemaphore(pPara->para->semHtmlbuff_p, 1, NULL);// 释放互斥量       
    send(pPara->sock, m_sendBuff, (int)(headLen + dataLen), 0);

    // 保存html
	if (pPara->prevHtml && pPara->currentHtml)
	{
		int currentSize = strlen(pPara->currentHtml);
		if (currentSize > 0)
		{
			memcpy(pPara->prevHtml, pPara->currentHtml, currentSize);
			pPara->prevHtml[currentSize] = 0;
		}
	}
	if (pPara->currentHtml)
	{
		memcpy(pPara->currentHtml, m_sendBuff + headLen, dataLen);
		pPara->currentHtml[dataLen] = 0;
	}

    _safe_exit:
    closesocket(pPara->sock);
    delete[] m_receiveMessage;
    delete[] m_requestUrl;
    delete[] m_sendBuff;
    delete para;
    return 0;
}

void HttpServThread::ThreadMain()
{
	// 判断client是否存活
	for (auto client = m_clients.begin(); client != m_clients.end(); client++)
	{
		if (time(NULL) - (*client).second.activeTime > 600 &&
			(*client).second.isDead == false) // 超过600s则认为client已经失效
		{
			tstring remoteIP = inet_ltot((*client).first);
			glogger.setDefaultColor(gcommon::PRINT_COLOR::DARK_YELLOW);
			glogger.insertCurrentTime(TEXT("   [yyyy-MM-dd HH:mm:ss] "));
			glogger.screen(TEXT("client seems dead: ") + remoteIP + TEXT("\n"));
			glogger.logfile(TEXT("client seems dead: ") + remoteIP + TEXT("\n"));
			glogger.setDefaultColor();

			(*client).second.isDead = true;
		}		
	}

    // 等待客户端建立连接
    SOCKADDR_IN inAddr;
    inAddr.sin_family = AF_INET;
    int inAddrSize = sizeof(SOCKADDR_IN);
	SOCKET sServer = accept(m_sock, (SOCKADDR *)&inAddr, &inAddrSize);
	if (sServer == INVALID_SOCKET)
	{
		m_glogger.error(TEXT("accept failed with error: %d"), WSAGetLastError());
		m_state = THREAD_STATE::STOPPED;
		return;
	}

    // 打印客户端信息
    char* prevHtml = NULL;
	char* currentHtml = NULL;
    if (m_clients.find(inAddr.sin_addr.S_un.S_addr) == m_clients.end())
    {
        m_glogger.info(TEXT("new client: %s"), gcommon::inet_ltot(inAddr.sin_addr.S_un.S_addr));
        prevHtml = new char[MAX_SENDBUFF_SIZE];
        prevHtml[0] = 0;
		currentHtml = new char[MAX_SENDBUFF_SIZE];
		currentHtml[0] = 0;
		m_clients.insert_or_assign(inAddr.sin_addr.S_un.S_addr,
			CLIENT{ (uint64_t)currentHtml , (uint64_t)prevHtml, time(NULL), false });
    }
	else
	{
		if(m_clients.at(inAddr.sin_addr.S_un.S_addr).isDead == true)
			m_glogger.info(TEXT("client alive: %s"), gcommon::inet_ltot(inAddr.sin_addr.S_un.S_addr));
		prevHtml = (char*)m_clients.at(inAddr.sin_addr.S_un.S_addr).prevHtml;
		currentHtml = (char*)m_clients.at(inAddr.sin_addr.S_un.S_addr).currentHtml;		
		m_clients.insert_or_assign(inAddr.sin_addr.S_un.S_addr, 
			CLIENT{ (uint64_t)currentHtml , (uint64_t)prevHtml, time(NULL), false });
	}

    // 启动处理线程
    PSOCK_THREAD_PARA pPara = new SOCK_THREAD_PARA();
    pPara->sock = sServer;
    pPara->remoteIP = inAddr.sin_addr.S_un.S_addr;
    pPara->para = m_para;
    pPara->resources = &m_resources;
	pPara->prevHtml = prevHtml;
	pPara->currentHtml = currentHtml;
    DWORD id;
    HANDLE h = CreateThread(NULL, 0, SocketThread, (PVOID)(pPara), 0, &id);
    if(h) CloseHandle(h);		
}

bool HttpServThread::InitSocket()
{
	// Initialize Winsock
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR)
	{
		m_glogger.error(TEXT("WSAStartup failed with error: %d"), WSAGetLastError());
		return false;
	}

	// socket
	m_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_sock == INVALID_SOCKET)
	{
		m_glogger.error(TEXT("socket failed with error: %d"), WSAGetLastError());
		WSACleanup();
		return 0;
	}

	//构建本地地址信息  
	struct sockaddr_in saServer;
	saServer.sin_family = AF_INET; 
	saServer.sin_port = gcommon::g_htons(m_para->port);
	saServer.sin_addr.S_un.S_addr = INADDR_ANY; 											   
	iResult = bind(m_sock, (struct sockaddr *)&saServer, sizeof(saServer));
	if (iResult != NO_ERROR)
	{
		m_glogger.error(TEXT("bind failed with error: %d"), WSAGetLastError());		
		closesocket(m_sock); //关闭套接字  
		WSACleanup();
		return false;
	}

	//侦听连接请求  
	iResult = listen(m_sock, 5);
	if (iResult != NO_ERROR)
	{
		m_glogger.error(TEXT("listen failed with error: %d"), WSAGetLastError());
		closesocket(m_sock); //关闭套接字  
		WSACleanup();
		return false;
	}

	return true;
}

void HttpServThread::InitResources()
{
	_finddata_t FileInfo;
	string strfind = m_resourceDir + "\\*.*";
	intptr_t hh = _findfirst(strfind.c_str(), &FileInfo);
	if (hh == -1L)
		return;

	do 
	{
		//判断是否目录
		if (FileInfo.attrib & _A_SUBDIR)
			continue;
		else
		{
			string filepath = m_resourceDir;
			filepath.append("\\");
			filepath.append(FileInfo.name);
			FILE* ff;
			if (fopen_s(&ff, filepath.c_str(), "rb") != 0)
				continue;
			if (ff == NULL)
				continue;
			
			char* data = new char[FileInfo.size + 1];
			size_t nread = fread_s(data, FileInfo.size + 1, 1, FileInfo.size, ff);
			fclose(ff);
			if (nread == 0)
			{
				delete[] data;
				continue;
			}
			data[FileInfo.size] = 0;
			m_resources.push_back(RESOURCE{ string(FileInfo.name), FileInfo.size, data });
			
		}
	} while (_findnext(hh, &FileInfo) == 0);

	_findclose(hh);
}
