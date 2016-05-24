#pragma once
#include <map>
#include "gthread.h"

using namespace gcommon;
using namespace std;

typedef struct _tmplnode
{
    uint32_t offset;
    char *data;
    uint32_t type;
    struct _tmplnode *next;
}TMPL_NODE, *PTMPL_NODE;

typedef struct _htmlgen_para:_thread_para
{	
	HANDLE semHtmlbuff_p;
	HANDLE semHtmlbuff_c;
	char* htmlBuff = NULL;
	int buffSize = 0;
	vector<PTMPL_NODE> htmlTemplNodes;
    vector<char*> htmlTempls;
	string serverip = "127.0.0.1";
	int port = 12228;
}HTMLGEN_THREA_PARA,*PHTMLGEN_THREAD_PARA;

typedef struct _attr
{
	string name;
	string ret;
	string type;
	vector<string> values;
}PROPERTY;

class HtmlGenThread : public GThread
{
public:
	HtmlGenThread(PHTMLGEN_THREAD_PARA para);
	~HtmlGenThread();

private:
	PHTMLGEN_THREAD_PARA m_para;
	char* m_htmlTempl;

	vector<vector<string>> m_ufile;
	vector<string> m_evts;
	vector<string> m_evtfuncs;
	vector<string> m_tags;	// html tags
    vector<string> m_commands;
	vector<string> m_funcNames;
	vector<string> m_ids;

	map<string, string> m_tag_dom;
	map<string, vector<PROPERTY>> m_tag_props;	
    map<string, vector<PROPERTY>> m_dom_props;
	map<string, vector<string>> m_type_values;	// 以%开头的为type

private:
	void ThreadMain();

	void Init();

	int ReadDic(const char* dicfile, vector<string>& list);
	int ReadDic2(const char* dicfile, map<string,string>& tags);
	void InitTagProperties(const string &path, 
		const string &name, 
		map<string, vector<PROPERTY>>& tag_funcs);
	void InitTypeValues(const string &path, const string &name, map<string, vector<string>>& tag_values);
	void HandleInheritation();

    void GenerateTempl(const char* src, char* dst);
    void GenerateFromVector(vector<string> &strs, char* dst, int dstsize, int& dstlen);
	
    string GenTagAttrExp(const string &tag);

	string GenHtmlLine(int id);
    string GenJsFunction(const string &name);
    string GenJsLine();
	string GenJsLine_Property(const vector<PROPERTY>& props, int deep);
	string GenJsLine_ExecCommand(const vector<PROPERTY>& props, int deep);

	string GetRandomValue(const vector<string>& values);
	string GetRandomObject(const string& className);
	string GetRandomFuncArgs(const PROPERTY& prop);
};

