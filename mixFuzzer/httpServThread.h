#pragma once
#include "gthread.h"

using namespace gcommon;

typedef struct _httpservpara:_thread_para
{
	HANDLE semHtmlbuff_p;
	HANDLE semHtmlbuff_c;
	char* htmlBuff;
	uint16_t port;
}HTTPSERV_THREAD_PARA,*PHTTPSERV_THREAD_PARA;

class HttpServThread: public GThread
{
public:
	HttpServThread(PHTTPSERV_THREAD_PARA para);
	~HttpServThread();

private:
	PHTTPSERV_THREAD_PARA m_para;
	SOCKET m_sock;

private:
	void ThreadMain();

	bool InitSocket();
};

