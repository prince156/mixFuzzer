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
	char* m_prevHtml;
	int m_headLen;

	vector<vector<string>> m_ufile;
	vector<string> m_events;
	vector<string> m_tags;

public:
	char* GetPrevHtml();

private:
	void ThreadMain();

	void Init();
	int ReadDic(const char* dicfile, vector<string>& list);
	void GenerateTempl(char* src, char* dst);
	string GetRandomLine_u(int id);
};

