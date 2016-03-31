#pragma once
#include <map>
#include "gthread.h"

using namespace gcommon;
using namespace std;

typedef struct _htmlgen_para:_thread_para
{	
	HANDLE semHtmlbuff_p;
	HANDLE semHtmlbuff_c;
	char* htmlBuff = NULL;
	int buffSize = 0;
	vector<char*> htmlTempls;
	string serverip = "127.0.0.1";
	int port = 12228;
}HTMLGEN_THREA_PARA,*PHTMLGEN_THREAD_PARA;

typedef struct _attr
{
	string name;
	vector<string> values;
}ATTRIBUTE;

class HtmlGenThread : public GThread
{
public:
	HtmlGenThread(PHTMLGEN_THREAD_PARA para);
	~HtmlGenThread();

private:
	PHTMLGEN_THREAD_PARA m_para;
	char* m_htmlTempl;
	char* m_prevHtml;
	char* m_pprevHtml;
	char* m_ppprevHtml;

	vector<vector<string>> m_ufile;
	vector<string> m_events;
	vector<string> m_evfunctions;
	vector<string> m_tags;

	map<string, vector<ATTRIBUTE>> m_tag_attributes;
	map<string, vector<string>> m_type_values;
	
public:
	char* GetNextHtml();
	char* GetPrevHtml();
	char* GetPPrevHtml();

private:
	void ThreadMain();

	void Init();
	void LoadTagAttrubites(string path, string name);
	void LoadTypeValues(string path, string name);
	int ReadDic(const char* dicfile, vector<string>& list);
	void GenerateTempl(char* src, char* dst);
	string GetRandomLine_u(int id);
	string GetRandomAttrExp(string tag, bool quot=true);
	string GetRandomTag(int id);
};

