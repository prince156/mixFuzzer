#pragma once
#include "gthread.h"

using namespace gcommon;

typedef struct _htmlgen_para:_thread_para
{	
	HANDLE semHtmlbuff_p;
	HANDLE semHtmlbuff_c;
	char* htmlBuff;
	int buffSize;
	char* htmlTempl;
	int port;
}HTMLGEN_THREA_PARA,*PHTMLGEN_THREAD_PARA;

class HtmlGenThread : public GThread
{
public:
	HtmlGenThread(PHTMLGEN_THREAD_PARA para);
	~HtmlGenThread();

private:
	PHTMLGEN_THREAD_PARA m_para;
	char* m_htmlTempl;

	vector<vector<string>> ufile;

private:
	void ThreadMain();

	void Init();
	string GetRandomLine(string file);
};

