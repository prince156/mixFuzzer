#pragma once
#include "gthread.h"

using namespace gcommon;
using namespace std;


#pragma pack(push,1)
typedef struct _file_pack
{
	time_t time;
	size_t dirLen;
	byte type;
	char data[0];
}FILEPACK, *PFILEPACK;
#pragma pack(pop)

typedef struct _filerecvpara :_thread_para
{
	uint16_t port = 12220;
	tstring outPath = TEXT(".\\crash\\");
}FILERECV_THREAD_PARA, *PFILERECV_THREAD_PARA;

class FileRecvThread : public GThread
{
public:
	FileRecvThread(PFILERECV_THREAD_PARA para);
	~FileRecvThread();

private:
	static const uint32_t RECV_BUFF_SIZE = 0x10000;
	PFILERECV_THREAD_PARA m_para;
	SOCKET m_sock;

private:
	void ThreadMain();
	bool InitSocket();
};

