#pragma once
#include <map>
#include "gthread.h"

using namespace std;
using namespace gcommon;

const static size_t MAX_SENDBUFF_SIZE = 1024 * 200;


typedef struct _httpservpara:_thread_para
{
	HANDLE semHtmlbuff_p = NULL;
	HANDLE semHtmlbuff_c = NULL;
	char* htmlBuff = NULL;
	uint16_t port = 12228;
    tstring outPath = TEXT(".\\crash\\");
	tstring mode;
}HTTPSERV_THREAD_PARA,*PHTTPSERV_THREAD_PARA;

typedef struct _resource
{
	string name;
	_fsize_t size;
	char* data;
}RESOURCE;

class HttpServThread: public GThread
{
public:
	HttpServThread(PHTTPSERV_THREAD_PARA para);
	~HttpServThread();

private:	
	const string m_resourceDir = "resources";
	PHTTPSERV_THREAD_PARA m_para;
	SOCKET m_sock;	
	vector<RESOURCE> m_resources;
    map<DWORD, uint64_t> m_prevHtmls;
	map<DWORD, time_t> m_clientsActive;

private:
	void ThreadMain();

	bool InitSocket();
	void InitResources();
};

