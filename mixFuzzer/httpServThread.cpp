#include <io.h>
#include "httpServThread.h"

#pragma comment(lib,"Ws2_32.lib")


HttpServThread::HttpServThread(PHTTPSERV_THREAD_PARA para)
	:GThread(para)
{
	m_para = para;
	m_receiveMessage = new char[1024];
	m_requestUrl = new char[1024];
	m_sendBuff = new char[MAX_SENDBUFF_SIZE+1];

	InitSocket();
	InitResources();
}


HttpServThread::~HttpServThread()
{
	delete[] m_receiveMessage;
	delete[] m_requestUrl;
	delete[] m_sendBuff;
}

void HttpServThread::ThreadMain()
{

	SOCKET sServer = accept(m_sock, NULL, NULL);
	if (sServer == INVALID_SOCKET)
	{
		m_glogger.error(TEXT("accept failed with error: %d"), WSAGetLastError());
		m_state = THREAD_STATE::STOPPED;
		return;
	}
	
	int ret = recv(sServer, m_receiveMessage, 1024, 0); // 接受GET请求
	if (ret == SOCKET_ERROR)
	{
		m_glogger.warning(TEXT("recv failed with error: %d"), WSAGetLastError());
		closesocket(sServer);
		return;
	} 

	// 获取Get的URL
	char* url_start = strstr(m_receiveMessage, "GET");
	char* url_end = strstr(m_receiveMessage, "HTTP");
	if (url_start != NULL && url_end != NULL && 
		url_end > url_start)
	{
		memcpy(m_requestUrl, url_start + 4, url_end - url_start - 5);
		m_requestUrl[url_end - url_start - 5] = 0;
	}
	else
	{
		m_glogger.warning(TEXT("request not supported"));
		closesocket(sServer);
		return;
	}

	// 根据URL,设置数据头
	size_t headLen, dataLen = 0;
	const char* sendHead = m_htmlHead;	
	const char* sendData = NULL;
	if (strstr(m_requestUrl,".svg") != NULL)
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

	if (strlen(m_requestUrl) != 1)
	{
		for each (RESOURCE var in m_resources)
		{
			if (var.name == m_requestUrl + 1)
			{
				sendData = var.data;
				dataLen = var.size;
			}
		}

		if (sendData == NULL)
		{
			m_glogger.warning(TEXT("resource not find"));
			closesocket(sServer);
			return;
		}
	}
	else
	{
		sendData = m_para->htmlBuff;
	}
	
	if (WAIT_OBJECT_0 != WaitForSingleObject(m_para->semHtmlbuff_c, INFINITE))
	{
		closesocket(sServer);
		return;
	}

	if (sendData == m_para->htmlBuff)
		dataLen = strlen(sendData);
	if ( headLen + dataLen > MAX_SENDBUFF_SIZE)
	{
		m_glogger.warning(TEXT("send buffer overflow"));
		closesocket(sServer);
		return;
	}
	memcpy(m_sendBuff, sendHead, headLen);
	memcpy(m_sendBuff + headLen, sendData, dataLen);
	send(sServer, m_sendBuff, headLen + dataLen, 0);
	closesocket(sServer);
	ReleaseSemaphore(m_para->semHtmlbuff_p, 1, NULL);
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
	saServer.sin_port = htons(m_para->port);  
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
