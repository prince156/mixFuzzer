#pragma once
#include <map>
#include "gthread.h"

using namespace gcommon;
using namespace std;

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
	char* m_prevprevHtml;
	int m_headLen;

	vector<vector<string>> m_ufile;
	vector<string> m_events;
	vector<string> m_evfunctions;
	vector<string> m_tags;
	vector<string> m_values;
	vector<string> m_attributes;
	map<string, vector<string>> m_tag_attributes;
	map<string, vector<string>> m_attr_values;
	
public:
	char* GetPrevHtml();

private:
	void ThreadMain();

	void Init();
	int ReadDic(const char* dicfile, vector<string>& list);
	void GenerateTempl(char* src, char* dst);
	string GetRandomLine_u(int id);
	string GetRandomTag(int id);
};

