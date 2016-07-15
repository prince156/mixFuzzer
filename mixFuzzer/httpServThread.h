#pragma once
#include <map>
#include "gthread.h"

using namespace std;
using namespace gcommon;

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

typedef struct _client
{
	uint64_t currentHtml;
	uint64_t prevHtml;
	time_t activeTime;
	bool isDead;
}CLIENT,*PCLIENT;

class HttpServThread: public GThread
{
public:
	HttpServThread(PHTTPSERV_THREAD_PARA para);
	~HttpServThread();

private:	
	const string m_resourceDir = "template\\resources";
	PHTTPSERV_THREAD_PARA m_para;
	SOCKET m_sock;	
	vector<RESOURCE> m_resources;
	map<DWORD, CLIENT> m_clients;

private:
	void ThreadMain();

	bool InitSocket();
	void InitResources();
};

