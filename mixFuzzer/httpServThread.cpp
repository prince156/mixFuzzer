#include "httpServThread.h"

#pragma comment(lib,"Ws2_32.lib")


HttpServThread::HttpServThread(PHTTPSERV_THREAD_PARA para)
	:GThread(para)
{
	m_para = para;
	InitSocket();
}


HttpServThread::~HttpServThread()
{
}

void HttpServThread::ThreadMain()
{
	SOCKET sServer = accept(m_sock, NULL, NULL);
	if (sServer == INVALID_SOCKET)
	{
		m_glogger.error(TEXT("accept failed with error: %d"), WSAGetLastError());
		return;
	}
	char receiveMessage[1024];
	int ret = recv(sServer, receiveMessage, 1024, 0); // 接受GET请求
	if (ret == SOCKET_ERROR)
	{
		m_glogger.error(TEXT("recv failed with error: %d"), WSAGetLastError());
		closesocket(sServer);
		return;
	} 

	if (WAIT_OBJECT_0 != WaitForSingleObject(m_para->semHtmlbuff_c, INFINITE))
		return;	 
	send(sServer, m_para->htmlBuff, strlen(m_para->htmlBuff), 0);
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
