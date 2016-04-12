#include <io.h>
#include <Ws2tcpip.h>
#include "httpServThread.h"
#include "common.h"

#pragma comment(lib,"Ws2_32.lib")


HttpServThread::HttpServThread(PHTTPSERV_THREAD_PARA para)
	:GThread(para)
{
	m_para = para;    
    m_prevHtmls.clear();
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
    int ret = recv(pPara->sock, m_receiveMessage, 1024, 0);
    if (ret == 0)
    {
        goto _safe_exit;
    }
    else if (ret == SOCKET_ERROR)
    {
        goto _safe_exit;
    }
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
            dataLen = strlen(m_errorpage);
        }
    }
    else
    {
        sendData = pPara->para->htmlBuff;
        dataLen = strlen(sendData);
    }

    if (headLen + dataLen > MAX_SENDBUFF_SIZE)
    {
        sendHead = m_htmlHead;
        sendData = m_errorpage;
        dataLen = strlen(m_errorpage);
    }

    // 其他资源请求，直接发送
    if (sendData != pPara->para->htmlBuff)
    {
        memcpy(m_sendBuff, sendHead, headLen);
        memcpy(m_sendBuff + headLen, sendData, dataLen);
        m_sendBuff[headLen + dataLen] = 0;
        send(pPara->sock, m_sendBuff, headLen + dataLen, 0);
        goto _safe_exit;
    }

    // fuzz请求，需申请互斥量    
    memcpy(m_sendBuff, sendHead, headLen);
    if (WAIT_OBJECT_0 != WaitForSingleObject(pPara->para->semHtmlbuff_c, INFINITE))
    {
        goto _safe_exit;
    }
    memcpy(m_sendBuff + headLen, sendData, dataLen);
    m_sendBuff[headLen + dataLen] = 0;
    // 保存html
    memcpy(pPara->prevHtml, sendData, dataLen);
    pPara->prevHtml[dataLen] = 0;
    ReleaseSemaphore(pPara->para->semHtmlbuff_p, 1, NULL);// 释放互斥量 
    
    send(pPara->sock, m_sendBuff, headLen + dataLen, 0);        

    _safe_exit:
    closesocket(pPara->sock);
    delete m_receiveMessage;
    delete m_requestUrl;
    delete m_sendBuff;
    delete para;
    return 0;
}

void HttpServThread::ThreadMain()
{
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
    if (m_prevHtmls.find(inAddr.sin_addr.S_un.S_addr) == m_prevHtmls.end())
    {
        m_glogger.info(TEXT("new client: %s"), gcommon::inet_ltot(inAddr.sin_addr.S_un.S_addr));
        prevHtml = new char[MAX_SENDBUFF_SIZE];
        prevHtml[0] = 0;
        m_prevHtmls.insert_or_assign(inAddr.sin_addr.S_un.S_addr, (uint64_t)prevHtml);
    }
    else
        prevHtml = (char*)m_prevHtmls.at(inAddr.sin_addr.S_un.S_addr);

    // 启动处理线程
    PSOCK_THREAD_PARA pPara = new SOCK_THREAD_PARA();
    pPara->sock = sServer;
    pPara->remoteIP = inAddr.sin_addr.S_un.S_addr;
    pPara->para = m_para;
    pPara->resources = &m_resources;
    pPara->prevHtml = prevHtml;
    DWORD id;
    HANDLE h = CreateThread(NULL, 0, SocketThread, (PVOID)(pPara), 0, &id);
    CloseHandle(h);	
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
	saServer.sin_port = gcommon::htons(m_para->port);  
	saServer.sin_addr.S_un.S_addr = htonl(INADDR_ANY); 											   
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
			{
				continue;
			}
			
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
