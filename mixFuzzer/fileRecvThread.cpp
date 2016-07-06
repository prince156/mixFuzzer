#include "fileRecvThread.h"
#include "common.h"

extern GLogger glogger;

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
	m_glogger.setHeader(TEXT("Recv"));
	m_para = para;
	InitSocket();
}


FileRecvThread::~FileRecvThread()
{
}

void FileRecvThread::ThreadMain()
{
	// �ȴ��ͻ��˽�������
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

	// ���������߳�
	PSOCK_THREAD_PARA pPara = new SOCK_THREAD_PARA();
	pPara->sock = sServer;
	pPara->remoteIP = inAddr.sin_addr.S_un.S_addr;
	pPara->para = m_para;
	DWORD id;
	HANDLE h = CreateThread(NULL, 0, SocketThread_FileRecv, (PVOID)(pPara), 0, &id);
	if(h) CloseHandle(h); // �رվ�����ͷž����Դ����Ӱ���߳�����
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
	byte type = '0';
	FILE* ff = NULL;

	while(1)
	{
		memset(recvBuff, 0, 1024);
		int recv_size = recv(pPara->sock, recvBuff, 1024, 0);
		if (recv_size == 0 || recv_size == SOCKET_ERROR)
			break;

		if (first) // Ӧ�ð����ļ�������Ϣ
		{
			first = false;
			PFILEPACK fp = (PFILEPACK)recvBuff;
			if (fp->dirLen + sizeof(FILEPACK) > (uint32_t)recv_size)
			{
				glogger.error(TEXT("error file packet"));
				break;
			}

			type = fp->type;
			filename = to_tstring(fp->time);
			if (fp->type == 'H')
				filename += TEXT(".html");
			else if (fp->type == 'P')
				filename += TEXT("_prev.html");
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

		// ���ļ�
		if (ff == NULL)
		{
			dirpath = pPara->para->outPath + inet_ltot(pPara->remoteIP) + TEXT("\\");
			CreateDirectory(dirpath.c_str(), NULL); 
			dirpath += dirname + TEXT("\\");
			CreateDirectory(dirpath.c_str(), NULL);
			ff = tfopen((dirpath+filename).c_str(),TEXT("a"));
			if (ff == NULL)
			{
				glogger.error(TEXT("can not create file: %s"), filename.c_str());
				dirpath = pPara->para->outPath + inet_ltot(pPara->remoteIP) +
					TEXT("\\unknown\\");
				ff = tfopen((dirpath + filename).c_str(), TEXT("a"));
				if(ff == NULL)
					break;
			}
		}

		// д�ļ�
		fwrite(filedata, 1, datalen, ff);
	}

	if (ff)fclose(ff);
	closesocket(pPara->sock);
	delete[] recvBuff;

	// ��ʾ��Ϣ
	if (type == 'H')
	{
		tstring remoteIP = inet_ltot(pPara->remoteIP);
		glogger.screen(TEXT("   [") + remoteIP + TEXT("] ") + dirname + TEXT("\n"));
		glogger.logfile(TEXT("   [") + remoteIP + TEXT("] ") + dirname + TEXT("\n"));
	}
	
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

	// ���ý��ջ�����
	int nBuf = RECV_BUFF_SIZE;
	int nBufLen = sizeof(nBuf);
	int nRe = setsockopt(m_sock, SOL_SOCKET, SO_RCVBUF, (char*)&nBuf, nBufLen);
	if (SOCKET_ERROR == nRe)
	{
		m_glogger.error(TEXT("setsockopt error!"));
		WSACleanup();
		return 0;
	}
	//��黺�����Ƿ����óɹ�
	nRe = getsockopt(m_sock, SOL_SOCKET, SO_RCVBUF, (char*)&nBuf, &nBufLen);
	if (RECV_BUFF_SIZE != nBuf)
	{
		m_glogger.error(TEXT("setsockopt error!"));
		WSACleanup();
		return 0;
	}

	//�������ص�ַ��Ϣ  
	struct sockaddr_in saServer;
	saServer.sin_family = AF_INET;
	saServer.sin_port = gcommon::htons(m_para->port);
	saServer.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	iResult = bind(m_sock, (struct sockaddr *)&saServer, sizeof(saServer));
	if (iResult != NO_ERROR)
	{
		m_glogger.error(TEXT("bind failed with error: %d"), WSAGetLastError());
		closesocket(m_sock); //�ر��׽���  
		WSACleanup();
		return false;
	}

	//������������  
	iResult = listen(m_sock, 5);
	if (iResult != NO_ERROR)
	{
		m_glogger.error(TEXT("listen failed with error: %d"), WSAGetLastError());
		closesocket(m_sock); //�ر��׽���  
		WSACleanup();
		return false;
	}

	return true;
}
