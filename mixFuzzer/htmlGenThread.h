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
	uint32_t buffSize = 0;
	vector<PTMPL_NODE> htmlTemplNodes;
    vector<char*> htmlTempls;
	string serverip = "127.0.0.1";
	int port = 12228;
	tstring mode;
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
	static const uint32_t RANDOM_MAX = 0x00ffffff;
	PHTMLGEN_THREAD_PARA m_para;
	char* m_htmlTempl;

	map<string, vector<string>> m_dicfiles; // u0.txt u1.txt ...
	vector<string> m_evts;  // e.g. click
	vector<string> m_evtfuncs; // e.g. onclick
	vector<string> m_htmltags;	// html tags
	vector<string> m_htmldoms;
	vector<string> m_svgtags;	// svg tags
	vector<string> m_svgdoms;	
    vector<string> m_commands;
	vector<string> m_funcNames; // e.g. fuzz0  fuzz1 ...
	vector<string> m_ids; // e.g. id_0  id_1 ...
	vector<string> m_objects;
	vector<string> m_jslines;

	map<string, string> m_htmltag_dom;// <tagname, DOMInterface>
	map<string, string> m_svgtag_dom;// <tagname, DOMInterface>
	map<string, vector<PROPERTY>> m_tag_props;	
	map<string, vector<PROPERTY>> m_svgtag_props;
    map<string, vector<PROPERTY>> m_dom_props;
	map<string, vector<PROPERTY>> m_svg_props;
	map<string, vector<string>> m_type_values;
	map<string, map<string, vector<PROPERTY>>> m_retobj_props;
	uint32_t htmlLines;

private:
	void ThreadMain();

	void Init();

	int ReadDic(const char* dicfile, vector<string>& list);
	int ReadDic2(const char* dicfile, map<string,string>& tags);
	int LoadDicFiles(const string& path, map<string, vector<string>>& files);
	void InitTagProperties(const string &path, const string &name, map<string, vector<PROPERTY>>& tag_funcs);
	void InitTypeValues(const string &path, const string &name, map<string, vector<string>>& tag_values);
	void InitRetobjDic();
	void HandleInheritation();
	void GenInheritation(map<string, vector<PROPERTY>> &obj_props, const string& obj); //ตÝน้
	void GenInheritation(map<string, vector<string>> &type_values, const string& type);//ตÝน้

    void GenerateTempl(const char* src, char* dst);
    void GenerateFromVector(vector<string> &strs, char* dst, uint32_t dstsize, uint32_t& dstlen);   

	// DOM	
	string GenHtmlLine(int id);
    string GenJsFunction(const string &name);
    string GenJsLine(const string &templ);
	string GenJsLine_Property(const map<string, vector<PROPERTY>>& obj_props, const string& obj, int deep, const string dft = "id"); //ตÝน้
	string GenJsLine_ExecCommand(const map<string, vector<PROPERTY>>& obj_props, const string& obj, int deep, const string dft = "id");//ตÝน้

	// SVG
	string SVG_GenHtmlLine(int id);
	string SVG_GenJsFunction(const string &name);
	string SVG_GenJsLine();

	string GenFromDicType(const string& type);
	string GenTagAttrExp(map<string, vector<PROPERTY>>& tag_props,const string &tag);
	string GetRandomItem(const vector<string>& items, const string dft="");
	string GetRandomValue(const vector<string>& values, const string dft = "null");
	string GetRandomObject(const string& objType, const string dft = "id_0");
	string GetRandomFuncArgs(const PROPERTY& prop, const string dft = "");

	string TrueOrFalse();
};

