#include "fileRecvThread.h"
#include "common.h"

extern GLogger2 glogger;

typedef struct _sock_thread_para
{
	SOCKET sock;
	DWORD remoteIP;
	PFILERECV_THREAD_PARA para;
}SOCK_THREAD_PARA, *PSOCK_THREAD_PARA;

DWORD WINAPI SocketThread_FileRecv(PVOID para);

FileRecvThread::FileRecvThread(PFILERECV_THREAD_PARA para)
	:GThread(para)
{
	m_para = para;
	InitSocket();
}


FileRecvThread::~FileRecvThread()
{
}

void FileRecvThread::ThreadMain()
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

	// 启动处理线程
	PSOCK_THREAD_PARA pPara = new SOCK_THREAD_PARA();
	pPara->sock = sServer;
	pPara->remoteIP = inAddr.sin_addr.S_un.S_addr;
	pPara->para = m_para;
	DWORD id;
	HANDLE h = CreateThread(NULL, 0, SocketThread_FileRecv, (PVOID)(pPara), 0, &id);
	CloseHandle(h); // 关闭句柄，释放句柄资源，不影响线程运行
}

DWORD WINAPI SocketThread_FileRecv(PVOID para)
{
	PSOCK_THREAD_PARA pPara = (PSOCK_THREAD_PARA)para;
	char* recvBuff = new char[1024];
	tstring filename = TEXT("unknown");
	tstring dirname = TEXT("unknown");
	tstring dirpath;
	char* filedata;
	int datalen = 0;
	bool first = true;
	FILE* ff = NULL;

	while(1)
	{
		memset(recvBuff, 0, 1024);
		int recv_size = recv(pPara->sock, recvBuff, 1024, 0);
		if (recv_size == 0 || recv_size == SOCKET_ERROR)
			break;

		if (first) // 应该包含文件名等信息
		{
			first = false;
			PFILEPACK fp = (PFILEPACK)recvBuff;
			if (fp->dirLen + sizeof(FILEPACK) > recv_size)
			{
				glogger.error(TEXT("error file packet"));
				break;
			}

			filename = to_tstring(fp->time);
			if (fp->type == 'H')
				filename += TEXT(".html");
			else if (fp->type == 'L')
				filename += TEXT(".log");
			else
				filename += TEXT(".txt");

			dirname = gcommon::StringToTString(string(fp->data, fp->dirLen));
			filedata = fp->data + fp->dirLen;
			datalen = recv_size - sizeof(FILEPACK) - fp->dirLen;
		}
		else
		{
			filedata = recvBuff;
			datalen = recv_size;
		}

		// 打开文件
		if (ff == NULL)
		{
			dirpath = pPara->para->outPath + inet_ltot(pPara->remoteIP) + TEXT("\\");
			CreateDirectory(dirpath.c_str(), NULL); 
			dirpath += dirname + TEXT("\\");
			CreateDirectory(dirpath.c_str(), NULL);
			_tfopen_s(&ff, (dirpath+filename).c_str(),TEXT("a"));
			if (ff == NULL)
			{
				glogger.error(TEXT("can not create file: %s"), filename.c_str());
				break;
			}
		}

		// 写文件
		fwrite(filedata, 1, datalen, ff);
	}

	if (ff)fclose(ff);
	closesocket(pPara->sock);
	delete recvBuff;
	return 0;
}

bool FileRecvThread::InitSocket()
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

	// 设置接收缓冲区
	int nBuf = RECV_BUFF_SIZE;
	int nBufLen = sizeof(nBuf);
	int nRe = setsockopt(m_sock, SOL_SOCKET, SO_RCVBUF, (char*)&nBuf, nBufLen);
	if (SOCKET_ERROR == nRe)
	{
		m_glogger.error(TEXT("setsockopt error!"));
		WSACleanup();
		return 0;
	}
	//检查缓冲区是否设置成功
	nRe = getsockopt(m_sock, SOL_SOCKET, SO_RCVBUF, (char*)&nBuf, &nBufLen);
	if (RECV_BUFF_SIZE != nBuf)
	{
		m_glogger.error(TEXT("setsockopt error!"));
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
