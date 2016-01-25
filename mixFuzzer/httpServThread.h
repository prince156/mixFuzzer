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
	const size_t MAX_SENDBUFF_SIZE = 1024 * 200;
	const string m_resourceDir = "resources";
	const char* m_htmlHead = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n";
	const char* m_svgHead = "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n";
	const char* m_jpgHead = "HTTP/1.1 200 OK\r\nContent-Type: image/jpg; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n";
	const char* m_swfHead = "HTTP/1.1 200 OK\r\nContent-Type: application/x-shockwave-flash; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n";
	const char* m_jsHead = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n";
	const char* m_cssHead = "HTTP/1.1 200 OK\r\nContent-Type: text/css; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n";


	PHTTPSERV_THREAD_PARA m_para;
	SOCKET m_sock;

	char* m_receiveMessage;
	char* m_requestUrl;
	char* m_sendBuff;
	vector<RESOURCE> m_resources;

private:
	void ThreadMain();

	bool InitSocket();
	void InitResources();
};

