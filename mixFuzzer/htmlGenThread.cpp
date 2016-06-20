#include <io.h>

#include "htmlGenThread.h"
#include "common.h"
#include "fuzzstr.h"

using namespace gcommon;


HtmlGenThread::HtmlGenThread(PHTMLGEN_THREAD_PARA para)
	:GThread(para)
{
	m_glogger.setHeader(TEXT("Fuzz"));
	m_para = para;
	m_htmlTempl = new char[m_para->buffSize + 1];
	m_htmlTempl[0] = 0;
	if (m_para->mode != TEXT("client"))
		Init();
}


HtmlGenThread::~HtmlGenThread()
{
}

void HtmlGenThread::ThreadMain()
{
	htmlLines = 0;
	m_ids = m_type_values["id"];
	m_funcNames = { "fuzz0", "fuzz1", "fuzz2" };
	m_htmlTempl[0] = 0;
	int tr = random(0, (uint32_t)m_para->htmlTempls.size());
	GenerateTempl(m_para->htmlTempls[tr], m_htmlTempl);
	GenerateTempl(m_htmlTempl, m_htmlTempl);
	if (m_htmlTempl[0] == 0)
	{
		m_glogger.error(TEXT("can not fuzz html file"));
		m_state = THREAD_STATE::STOPPED;
		return;
	}

	if (WAIT_OBJECT_0 != WaitForSingleObject(m_para->semHtmlbuff_p, INFINITE))
		return;
	memcpy_s(m_para->htmlBuff, m_para->buffSize, m_htmlTempl, strlen(m_htmlTempl) + 1);
	ReleaseSemaphore(m_para->semHtmlbuff_c, 1, NULL);
}

void HtmlGenThread::Init()
{
	m_glogger.info(TEXT("load dictionaries ..."));

	LoadDicFiles("template\\??.txt", m_dicfiles);
	ReadDic("dic\\eventNames.txt", m_evts);
	if (m_evts.empty())
		m_glogger.warning(TEXT("load dictionary [eventNames] error"));
	ReadDic("dic\\eventFunctions.txt", m_evtfuncs);
	if (m_evtfuncs.empty())
		m_glogger.warning(TEXT("load dictionary [eventFunctions] error"));
	ReadDic2("dic\\tags.txt", m_htmltag_dom);
	if (m_htmltag_dom.empty())
		m_glogger.warning(TEXT("load dictionary [tags] error"));
	ReadDic2("dic\\tags_svg.txt", m_svgtag_dom);
	if (m_svgtag_dom.empty())
		m_glogger.warning(TEXT("load dictionary [tags_svg] error"));
	ReadDic("dic\\commands.txt", m_commands);
	if (m_commands.empty())
		m_glogger.warning(TEXT("load dictionary [commands] error"));

	for each (auto tag_dom in m_htmltag_dom)
	{
		m_htmltags.push_back(tag_dom.first);
		m_htmldoms.push_back(tag_dom.second);
	}
	for each (auto tag_dom in m_svgtag_dom)
	{
		m_svgtags.push_back(tag_dom.first);
		m_svgdoms.push_back(tag_dom.second);
	}

	// dic for SVG
	InitTagProperties("dic\\attributes_domsvg\\", "attributes-*.txt", m_svg_props);
	if (m_svg_props.empty())
		m_glogger.warning(TEXT("load dictionary [attributes_domsvg] error"));
	InitTagProperties("dic\\attributes_javascript\\", "attributes-*.txt", m_svg_props);
	InitTagProperties("dic\\attributes_dom2core\\", "attributes-*.txt", m_svg_props);
	InitTagProperties("dic\\attributes_htmlsvg\\", "attributes-*.txt", m_svgtag_props);
	if (m_svgtag_props.empty())
		m_glogger.warning(TEXT("load dictionary [attributes_htmlsvg] error"));

	// dic for DOM
	InitTagProperties("dic\\attributes_dom2html5\\", "attributes-*.txt", m_dom_props);
	if (m_dom_props.empty())
		m_glogger.warning(TEXT("load dictionary [attributes_dom2html5] error"));
	InitTagProperties("dic\\attributes_javascript\\", "attributes-*.txt", m_dom_props);
	InitTagProperties("dic\\attributes_dom2core\\", "attributes-*.txt", m_dom_props);

	// dic for HTML
	InitTagProperties("dic\\attributes_html\\", "attributes-*.txt", m_tag_props);
	if (m_tag_props.empty())
		m_glogger.warning(TEXT("load dictionary [attributes_html] error"));

	// dic for values
	InitTypeValues("dic\\values\\", "values-*.txt", m_type_values);
	if (m_tag_props.empty())
		m_glogger.warning(TEXT("load dictionary [values] error"));

	//InitRetobjDic();
	HandleInheritation(); // 处里继承


						  // rand seed
	char* chr = new char[1];
	srand((int)chr);
	delete[] chr;
}

void HtmlGenThread::InitTagProperties(
	const string &path,
	const string &name,
	map<string, vector<PROPERTY>>& tag_props)
{
	if (name.empty() || path.empty())
		return;

	_finddata_t FileInfo;
	intptr_t hh = _findfirst((path + name).c_str(), &FileInfo);
	if (hh == -1L)
		return;

	do
	{
		//判断是否目录
		if (FileInfo.attrib & _A_SUBDIR)
			continue;
		else
		{
			vector<string> props_lines;
			vector<PROPERTY> props;
			string filepath = path;
			filepath.append(FileInfo.name);
			ReadDic(filepath.c_str(), props_lines);
			if (props_lines.empty())
				continue;

			for each (string line in props_lines)
			{
				// 去除所有空格
				RemoveAllChar(line, ' ');

				// 去除空行
				if (line.empty())
					continue;

				// 去除注释
				if (line.front() == '#')
					continue;

				// 保存继承关系
				if (line.front() == '$')
				{
					vector<string> parents = SplitString(line, ',');
					for each (string parent in parents)
					{
						if (parent.front() == '$')
							props.push_back(PROPERTY{ parent, "", "", vector<string>() });
					}
					continue;
				}

				// 正常属性值
				string name = line.substr(0, line.find_first_of(':'));
				string value_line;
				if (line.find_first_of(':') != string::npos)
					value_line = line.substr(line.find_first_of(':') + 1, string::npos);
				else
					value_line.clear();
				vector<string> values = SplitString(value_line, ',');
				if (values.size() > 0)
				{
					string type, ret;
					type = values[0];
					if (values[0] == "function" && values.size() > 1)	// function 
					{
						ret = values[1];
					}
					else
					{
						ret = "";
						if (values.size() > 1)
						{
							ret = type;
						}
					}

					if (values.size() > 1 && values[0] == "function")
					{
						values.erase(values.begin()); // remove type
						values.erase(values.begin()); // remove ret
					}
					else
						values.erase(values.begin()); // remove type
					props.push_back(PROPERTY{ name, ret, type, values });
				}
			}

			string tag = filepath.substr(filepath.find_first_of('-') + 1, string::npos);
			tag = tag.substr(0, tag.find_last_of('.'));
			tag_props.insert(make_pair(tag, props));
		}
	} while (_findnext(hh, &FileInfo) == 0);

	_findclose(hh);
}

void HtmlGenThread::InitTypeValues(
	const string &path,
	const string &name,
	map<string, vector<string>>& tag_values)
{
	if (name.empty() || path.empty())
		return;

	_finddata_t FileInfo;
	intptr_t hh = _findfirst((path + name).c_str(), &FileInfo);
	if (hh == -1L)
		return;

	do
	{
		//判断是否目录
		if (FileInfo.attrib & _A_SUBDIR)
			continue;
		else
		{
			vector<string> values;
			string filepath = path;
			filepath.append(FileInfo.name);
			ReadDic(filepath.c_str(), values);
			if (values.empty())
				continue;

			// 处理继承关系
			for (auto i = values.begin(); i < values.end(); i++)
			{
				if ((*i).front() == '$')
				{
					vector<string> parents = SplitString(*i, ',');
					if (parents.size() == 1)
						continue;

					values.erase(i);
					for each (string parent in parents)
					{
						if (parent.front() == '$')
						{
							values.insert(values.begin(), parent);
							i = values.begin();
						}
					}
				}
				else
					break;

			}

			string type = filepath.substr(filepath.find_first_of('-') + 1, string::npos);
			type = type.substr(0, type.find_last_of('.'));
			tag_values.insert(make_pair(type, values));
		}
	} while (_findnext(hh, &FileInfo) == 0);

	_findclose(hh);
}

// 太慢了！！
void HtmlGenThread::InitRetobjDic()
{
	// DOM
	for each (auto props in m_dom_props)
	{
		string retobj = "$" + props.first;
		for each (auto props in m_dom_props)
		{
			for each (auto prop in props.second)
			{
				if (prop.ret == retobj)
				{
					m_retobj_props[retobj.substr(1)][props.first].push_back(prop);
				}
			}
		}
	}

	// SVG
	for each (auto props in m_svg_props)
	{
		string retobj = "$" + props.first;
		for each (auto props in m_svg_props)
		{
			for each (auto prop in props.second)
			{
				if (prop.ret == retobj)
				{

					m_retobj_props[retobj.substr(1)][props.first].push_back(prop);
				}
			}
		}
	}
}

void HtmlGenThread::HandleInheritation()
{
	// 处理未赋值tag
	for each (string tag in m_htmltags)
	{
		if (m_tag_props.find(tag) == m_tag_props.end())
		{
			m_tag_props.insert(make_pair(tag, vector<PROPERTY>{ {"$common"} }));
		}
	}



	// 处理m_dom_props的继承数据
	for each (auto item in m_dom_props)
	{
		GenInheritation(m_dom_props, item.first);
	}

	// 处理m_tag_props的继承数据
	for each (auto item in m_tag_props)
	{
		GenInheritation(m_tag_props, item.first);
	}

	// 处理m_svg_props的继承数据
	for each (auto item in m_svg_props)
	{
		GenInheritation(m_svg_props, item.first);
	}

	// 处理m_type_values的继承数据
	for each (auto item in m_type_values)
	{
		GenInheritation(m_type_values, item.first);
	}


}

void HtmlGenThread::GenInheritation(map<string, vector<PROPERTY>> &obj_props, const string& obj)
{
	vector<PROPERTY>& props = obj_props[obj];
	if (props.empty())
		return;

	for (auto p = props.begin(); p<props.end(); )
	{
		if ((*p).name.front() == '$')
		{
			string parentobj = (*p).name.substr(1);
			props.erase(p);
			GenInheritation(obj_props, parentobj); // name需去除$			
			for each (auto pitem in obj_props[parentobj])
			{
				props.push_back(pitem);
			}
			p = props.begin();
		}
		else
			p++;
	}
}

void HtmlGenThread::GenInheritation(map<string, vector<string>> &type_values, const string& type)
{
	vector<string>& values = type_values[type];
	if (values.empty())
		return;

	for (auto p = values.begin(); p<values.end(); )
	{
		if ((*p).front() == '$')
		{
			string parent = (*p).substr(1);
			values.erase(p);
			GenInheritation(type_values, parent);
			for each (auto pitem in type_values[parent])
			{
				values.push_back(pitem);
			}
			p = values.begin();
		}
		else
			p++;
	}
}


int HtmlGenThread::ReadDic(const char * dicfile, vector<string>& list)
{
	list.clear();
	FILE* file;
	errno_t err = fopen_s(&file, dicfile, "r");
	if (err != 0 || file == NULL)
		return 0;

	if (m_para->buffSize <= 0)
		return 0;

	char* ufiledata = new char[m_para->buffSize];
	size_t nread = fread_s(ufiledata, m_para->buffSize, 1, m_para->buffSize - 1, file);
	if (nread == 0)
	{
		fclose(file);
		delete[] ufiledata;
		return 0;
	}

	nread = (nread < m_para->buffSize) ? nread : m_para->buffSize - 1;
	ufiledata[nread] = 0;

	size_t start = 0;
	size_t len = strlen(ufiledata);
	len = (len <= m_para->buffSize) ? len : m_para->buffSize;
	for (size_t j = start; j < len; j++)
	{
		if (ufiledata[j] == '\n')
		{
			ufiledata[j] = '\0';
			if (strlen(ufiledata + start) > 0)
				list.push_back(string(ufiledata + start));
			start = j + 1;
		}
	}
	if (start < len)
	{
		if (strlen(ufiledata + start) > 0)
			list.push_back(string(ufiledata + start));
	}
	fclose(file);
	delete[] ufiledata;
	return (int)list.size();
}

int HtmlGenThread::ReadDic2(const char * dicfile, map<string, string>& tags)
{
	vector<string> lines;
	ReadDic(dicfile, lines);
	if (!lines.empty())
	{
		for each (string line in lines)
		{
			vector<string> tag_dom = SplitString(line, ':');
			DeleteEmptyItems(tag_dom);
			if (tag_dom.size() == 2)
			{
				tags.insert(make_pair(tag_dom[0], tag_dom[1].substr(1)));// 须去除$
			}
		}
	}
	return 0;
}

int HtmlGenThread::LoadDicFiles(const string & path, map<string, vector<string>>& files)
{
	files.clear();

	_finddata_t FileInfo;
	intptr_t hh = _findfirst(path.c_str(), &FileInfo);
	if (hh == -1L)
		return 0;

	do
	{
		//判断是否有子目录
		if (FileInfo.attrib & _A_SUBDIR)
			continue;
		else
		{
			if (strlen(FileInfo.name) == 6)
			{
				string filepath;
				if (path.rfind('\\') > 0)
					filepath = path.substr(0, path.rfind('\\') + 1);
				else
					filepath = ".\\";
				filepath.append(FileInfo.name);

				vector<string> lines;
				string name = string(FileInfo.name, 2);
				ReadDic(filepath.c_str(), lines);
				if (!lines.empty())
					files.insert(make_pair(name, lines));
			}

		}
	} while (_findnext(hh, &FileInfo) == 0);

	_findclose(hh);
	return files.size();
}

void HtmlGenThread::GenerateTempl(const char * src, char * dst)
{
	if (src == NULL || dst == NULL)
		return;

	uint32_t rd = 0;
	uint32_t dstlen = 0;
	uint32_t srclen = (uint32_t)strlen(src);
	uint32_t dstsize = m_para->buffSize;
	if (srclen > dstsize)
		return;
	char* tmp = new char[srclen + 1];
	memcpy_s(tmp, srclen + 1, src, srclen);
	tmp[srclen] = 0;

	for (size_t i = 0; i < srclen; i++)
	{
		// [xx] for DOM
		if (tmp[i] == '[')
		{
			if (memcmp(tmp + i, "[dt]", 4) == 0)
			{
				GenerateFromVector(g_doctypeName, dst, dstsize, dstlen);
			}
			else if (memcmp(tmp + i, "[cd]", 4) == 0)
			{
				GenerateFromVector(m_commands, dst, dstsize, dstlen);
			}
			else if (memcmp(tmp + i, "[vl]", 4) == 0)
			{
				GenerateFromVector(m_type_values["str"], dst, dstsize, dstlen);
			}
			else if (memcmp(tmp + i, "[nr]", 4) == 0)
			{
				rd = random(0, 0x00ffffff);
				memcpy_s(dst + dstlen, dstsize - dstlen, to_string(rd).c_str(), to_string(rd).size());
				dstlen += (uint32_t)to_string(rd).size();
			}
			else if (memcmp(tmp + i, "[el]", 4) == 0)
			{
				GenerateFromVector(m_htmltags, dst, dstsize, dstlen);
			}
			else if (memcmp(tmp + i, "[ev]", 4) == 0)
			{
				GenerateFromVector(m_evts, dst, dstsize, dstlen);
			}
			else if (memcmp(tmp + i, "[ef]", 4) == 0)
			{
				GenerateFromVector(m_evtfuncs, dst, dstsize, dstlen);
			}
			else if (memcmp(tmp + i, "[at]", 4) == 0)
			{
				if (!m_tag_props.empty() && !m_htmltags.empty())
				{
					string tag;
					int count = 0;
					do
					{
						if (count++ >= 10)
							break;
						rd = random(0, (uint32_t)m_htmltags.size());
						tag = m_htmltags[rd];
					} while (m_tag_props[tag].empty());

					if (!m_tag_props[tag].empty())
					{
						rd = random(0, (uint32_t)m_tag_props[tag].size());
						memcpy_s(dst + dstlen, dstsize - dstlen,
							m_tag_props[tag][rd].name.c_str(),
							m_tag_props[tag][rd].name.size());
						dstlen += (uint32_t)m_tag_props[tag][rd].name.size();
					}
				}
			}
			else if (memcmp(tmp + i, "[ae]", 4) == 0)
			{
				string tag;
				const char* t_start = tmp + i;
				while (*(--t_start) != '<' && *t_start != '\n' && t_start > tmp);
				if (t_start[0] == '<')
				{
					const char* t_end = t_start;
					while (*(++t_end) != ' ' && t_end < tmp + i);
					if (t_end < tmp + i)
					{
						tag.assign(++t_start, t_end - t_start);
						string attexp = GenTagAttrExp(m_tag_props, tag);
						if (!attexp.empty())
						{
							memcpy_s(dst + dstlen, dstsize - dstlen, attexp.c_str(), attexp.size());
							dstlen += (uint32_t)attexp.size();
						}
					}
				}
			}
			else if (memcmp(tmp + i, "[sf]", 4) == 0)
			{
				char *safeurl = "window.location.href = document.URL;";
				memcpy_s(dst + dstlen, dstsize - dstlen, safeurl, strlen(safeurl));
				dstlen += (uint32_t)strlen(safeurl);
			}
			else if (memcmp(tmp + i, "[cc]", 4) == 0)
			{
				GenerateFromVector(g_compatibleName, dst, dstsize, dstlen);
			}
			else if (memcmp(tmp + i, "[n", 2) == 0 && tmp[i + 3] == ']')
			{
				if (tmp[i + 2] >= '0' && tmp[i + 2] <= '9')
				{
					int id = tmp[i + 2];
					dst[dstlen++] = (char)random('0', id);
					dst[dstlen] = 0;
				}
			}
			else if (memcmp(tmp + i, "[e", 2) == 0 && tmp[i + 3] == ']')
			{
				if (tmp[i + 2] >= '0' && tmp[i + 2] <= '9')
				{
					for (byte j = '0'; j < tmp[i + 2]; j++)
					{
						string line = GenHtmlLine(htmlLines++);
						if (!line.empty())
						{
							memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
							dstlen += (uint32_t)line.length();
						}
					}
				}
			}
			else if (memcmp(tmp + i, "[ff]", 4) == 0) // 自动生成一个function
			{
				string funcName = "fuzz" + to_string(m_funcNames.size());
				string line = GenJsFunction(funcName);
				if (!line.empty())
				{
					m_funcNames.push_back(funcName);
					memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
					dstlen += (uint32_t)line.length();
				}
			}
			else if (memcmp(tmp + i, "[ln]", 4) == 0) // 自动生成一行
			{
				string line = GenJsLine();
				if (!line.empty())
				{
					memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
					dstlen += (uint32_t)line.length();
				}
			}
			else if (tmp[i + 3] == ']')
			{
				string dicname = string(tmp + i + 1, 2);
				GenerateFromVector(m_dicfiles[dicname], dst, dstsize, dstlen);
			}
			else
			{
				dst[dstlen++] = tmp[i];
				continue;
			}
			i += 3;
		}
		// {xx} for SVG
		else if (tmp[i] == '{')
		{
			if (memcmp(tmp + i, "{e", 2) == 0 && tmp[i + 3] == '}')
			{
				if (tmp[i + 2] >= '0' && tmp[i + 2] <= '9')
				{
					for (byte j = '0'; j < tmp[i + 2]; j++)
					{
						string line = SVG_GenHtmlLine(htmlLines++);
						if (!line.empty())
						{
							memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
							dstlen += (uint32_t)line.length();
						}
					}
				}
			}
			else if (memcmp(tmp + i, "{ff}", 4) == 0) // 自动生成一个function
			{
				string funcName = "fuzz" + to_string(m_funcNames.size());
				string line = SVG_GenJsFunction(funcName);
				if (!line.empty())
				{
					m_funcNames.push_back(funcName);
					memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
					dstlen += (uint32_t)line.length();
				}
			}
			else if (memcmp(tmp + i, "{ln}", 4) == 0) // 自动生成一行
			{
				string line = SVG_GenJsLine();
				if (!line.empty())
				{
					memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
					dstlen += (uint32_t)line.length();
				}
			}
			else
			{
				dst[dstlen++] = tmp[i];
				continue;
			}
			i += 3;
		}
		else // if(tmp[i] == '[')
			dst[dstlen++] = tmp[i];
	}
	dst[dstlen] = 0;
	delete[] tmp;
}

void HtmlGenThread::GenerateFromVector(vector<string>& strs, char * dst, uint32_t dstsize, uint32_t & dstlen)
{
	if (!strs.empty())
	{
		uint32_t rd = random(0, (uint32_t)strs.size());
		memcpy_s(dst + dstlen, dstsize - dstlen, strs[rd].c_str(), strs[rd].size());
		dstlen += (uint32_t)strs[rd].size();
	}
}

string HtmlGenThread::GenTagAttrExp(map<string, vector<PROPERTY>>& tag_props, const string &tag)
{
	if (tag_props[tag].size() == 0)
		return string();
	uint32_t rd = random(0, (uint32_t)tag_props[tag].size());
	PROPERTY attr = tag_props[tag][rd];
	if (attr.values.empty())
		return attr.name + "=\'\'";

	uint32_t vr = random(0, (uint32_t)attr.values.size());
	string valueortype = attr.values[vr];
	if (valueortype.front() == '%')
	{
		string type = valueortype.substr(1, string::npos);
		if (m_type_values[type].empty())
			return attr.name + "=\'\'";

		uint32_t tr = random(0, (uint32_t)m_type_values[type].size());
		valueortype = m_type_values[type][tr];
	}

	return attr.name + "=" + valueortype;
}

string HtmlGenThread::GenHtmlLine(int id)
{
	if (m_htmltags.empty())
		return string();
	string tag = GetRandomItem(m_htmltags, "div");
	string event_exp = GetRandomItem(m_evtfuncs, "onchange") + "='" +
		GetRandomItem(m_funcNames, "fuzz0") + "();'";

	string attr_exp1 = GenTagAttrExp(m_tag_props, tag);
	string attr_exp2 = GenTagAttrExp(m_tag_props, tag);
	string attr_exp3 = GenTagAttrExp(m_tag_props, tag);

	char* templ = "<%s id='id_%d' %s %s %s %s>fuzz0();</%s>\n\0";
	char result[1024];
	sprintf_s(result, templ, tag.c_str(), id,
		event_exp.c_str(),
		attr_exp1.c_str(),
		attr_exp2.c_str(),
		attr_exp3.c_str(),
		tag.c_str());
	return string(result);
}

string HtmlGenThread::GenJsFunction(const string &name)
{
	string funcstr = "function " + name + "(){try{\n";
	uint32_t count = random(10, 30);
	for (uint32_t i = 0; i < count; i++)
	{
		funcstr += "    ";
		funcstr += GenJsLine();
		funcstr += "\n";
	}
	funcstr += "}catch(e){}}\n";
	return funcstr;
}

string HtmlGenThread::GenJsLine()
{
	string prop_right;
	string tmp, tmp2, tmp3;
	uint32_t sw = random(0, 15);
	switch (sw)
	{
	case 0: // window对象属性赋值
		return "try{var tmp = window." +
			GenJsLine_Property(m_dom_props, "Window", random(0, 5)) +
			"}catch(e){}";
	case 1:
		return "try{var tmp = " + GetRandomItem(m_ids, "id_0") + "." +
			GenJsLine_Property(m_dom_props, GetRandomItem(m_htmldoms, "HTMLElement"), random(0, 5)) +
			"}catch(e){}";
	case 2:
		return "try{var tmp = document." +
			GenJsLine_Property(m_dom_props, "Document", random(0, 5))
			+ "}catch(e){}";
	case 3:
		tmp = GetRandomItem(m_htmltags, "body");
		return "try{var els=document.getElementsByTagName(\"" +
			tmp + "\"); " +
			"if(els.length>0)var tmp = els[" + to_string(random(0, 10)) + "%els.length]." +
			GenJsLine_Property(m_dom_props, m_htmltag_dom[tmp], random(0, 5)) +
			"}catch(e){}";
	case 4:
		return "try{var tmp = window." +
			GenJsLine_ExecCommand(m_dom_props, "Window", random(0, 3)) +
			"}catch(e){}";
	case 5:
		return "try{var tmp = " + GetRandomItem(m_ids, "id_0") + "." +
			GenJsLine_ExecCommand(m_dom_props, GetRandomItem(m_htmldoms, "HTMLElement"), random(0, 3)) +
			"}catch(e){}";
	case 6:
		return "try{var tmp = document." +
			GenJsLine_ExecCommand(m_dom_props, "Document", random(0, 3)) +
			"}catch(e){}";
	case 7:
		tmp = GetRandomItem(m_htmltags, "body");
		return "try{var els=document.getElementsByTagName(\"" +
			tmp + "\"); " +
			"if(els.length>0)var tmp = els[" + to_string(random(0, 10)) + "%els.length]." +
			GenJsLine_ExecCommand(m_dom_props, m_htmltag_dom[tmp], random(0, 3)) +
			"}catch(e){}";
	case 8:
		return "try{var ee = document.createElement(\'" +
			GetRandomItem(m_htmltags, "body") + "\');" +
			"ee.id = \"id_" + to_string(m_ids.size() - 1) + "\";" +
			GetRandomItem(m_ids, "id_0") + ".appendChild(ee);" +
			"}catch(e){}";
	case 9:
		tmp = GetRandomItem(m_ids, "id_0");
		return "try{var ee = document.createElement(\'" +
			GetRandomItem(m_htmltags) + "\');" +
			tmp + ".replaceChild(" + tmp + ".firstChild,ee);" + "}catch(e){}";
	case 10:
		tmp = GetRandomItem(m_htmltags, "body");
		return "try{var ee = " + GetRandomObject(m_htmltag_dom[tmp]) + ";" +
			"ee.__proto__ = " + GetRandomObject(m_htmltag_dom[tmp]) + ";" +
			"var tmp = ee." + GenJsLine_Property(m_dom_props, GetRandomItem(m_htmldoms, "HTMLElement"), random(0, 3)) +
			";" + "}catch(e){}";
	case 11:
		return "try{" + GetRandomObject("HTMLElement") + ".attachEvent(\"" +
			GetRandomItem(m_evtfuncs, "onchange") + "\"," +
			GetRandomItem(m_funcNames, "fuzz0") +
			");}catch(e){}";
	case 12:
		return "try{" + GetRandomObject("HTMLElement") + ".addEventListener(\"" +
			GetRandomItem(m_evts, "change") + "\"," +
			GetRandomItem(m_funcNames, "fuzz0") + "," + TrueOrFalse() +
			");}catch(e){}";
	case 13: // 通过tag创建element
		m_ids.push_back("id_" + to_string(m_ids.size()));
		return "try{var ee = document.createElement(\'" + GetRandomItem(m_htmltags, "div") + "\');" +
			"ee.id = \"id_" + to_string(m_ids.size() - 1) + "\";" +
			"document.body.appendChild(ee);" + "}catch(e){}";
	case 14:
		tmp = GetRandomItem(m_htmltags, "body");
		return "try{var ee = " + GetRandomObject(m_htmltag_dom[tmp]) + ";" +
			"ee.constructor = " + GetRandomObject(m_htmltag_dom[tmp]) + ";" +
			"var tmp = ee." + GenJsLine_Property(m_dom_props, GetRandomItem(m_htmldoms, "HTMLElement"), random(0, 3)) +
			";" + "}catch(e){}";
	default:
		break;
	}
	return string();
}

string HtmlGenThread::GenJsLine_Property(const map<string, vector<PROPERTY>>& obj_props,
	const string &obj, int deep, const string dft)
{
	if (obj_props.empty() || obj_props.find(obj) == obj_props.end())
		return dft;

	const vector<PROPERTY>& props = obj_props.at(obj);
	if (props.empty())
		return dft;

	uint32_t rd = random(0, (uint32_t)props.size());
	if (deep == 0)
	{
		if (props[rd].ret.empty())
		{
			return props[rd].name + ";";
		}
		if (props[rd].type == "function")
		{
			return props[rd].name + "(" + GetRandomFuncArgs(props[rd]) + ");";
		}
		else
		{
			return props[rd].name + "=" + GetRandomValue(props[rd].values) + ";";
		}
	}
	else
	{
		if (props[rd].ret.empty())
		{
			return props[rd].name + ";";
		}
		else if (props[rd].type == "function")
		{
			if (props[rd].ret.front() == '$')
			{
				string right = GenJsLine_Property(
					obj_props, props[rd].ret.substr(1, string::npos), --deep, dft); // 递归
				if (!right.empty())
					return props[rd].name + "(" + GetRandomFuncArgs(props[rd]) + ")." + right;
			}
			return props[rd].name + "(" + GetRandomFuncArgs(props[rd]) + ");";
		}
		else if (props[rd].ret.front() == '$')
		{
			string right = GenJsLine_Property(
				obj_props, props[rd].ret.substr(1, string::npos), --deep, dft); // 递归	
			if (!right.empty())
				return props[rd].name + "." + right;
			return props[rd].name + ";";
		}
		else
		{
			return props[rd].name + "=" + GetRandomValue(props[rd].values) + ";";
		}

	}
	return props[rd].name + ";";
}

string HtmlGenThread::GenJsLine_ExecCommand(const map<string, vector<PROPERTY>>& obj_props,
	const string& obj, int deep, const string dft)
{
	if (obj_props.empty() || obj_props.find(obj) == obj_props.end())
	{
		return dft;
	}

	const vector<PROPERTY>& props = obj_props.at(obj);
	if (props.empty())
		return dft;

	uint32_t rd = random(0, (uint32_t)props.size());
	if (deep == 0)
	{
		uint32_t cd = random(0, (uint32_t)m_commands.size());
		if (props[rd].ret.empty())
		{
			return props[rd].name + ";";
		}
		else if (props[rd].type == "function")
		{
			if (props[rd].ret.front() == '$')
			{
				return props[rd].name + "(" + GetRandomFuncArgs(props[rd]) + ")" +
					".execCommand(" + m_commands[cd] + ");";
			}
			else
			{
				return props[rd].name + "(" + GetRandomFuncArgs(props[rd]) + ");";
			}
		}
		else if (props[rd].ret.front() == '$')
		{
			return props[rd].name + ".execCommand(" + m_commands[cd] + ");";
		}
	}
	else
	{
		if (props[rd].ret.empty())
		{
			return props[rd].name + ";";
		}
		else if (props[rd].type == "function")
		{
			if (props[rd].ret.front() == '$')
			{
				string right = GenJsLine_ExecCommand(
					obj_props, props[rd].ret.substr(1, string::npos), --deep, dft); // 递归
				if (!right.empty())
					return props[rd].name + "(" + GetRandomFuncArgs(props[rd]) + ")." + right;
			}
			return props[rd].name + "(" + GetRandomFuncArgs(props[rd]) + ");";
		}
		else if (props[rd].ret.front() == '$')
		{
			string right = GenJsLine_ExecCommand(
				obj_props, props[rd].ret.substr(1, string::npos), --deep, dft); // 递归
			if (!right.empty())
				return props[rd].name + "." + right;
			return props[rd].name + ";";
		}
	}
	return props[rd].name + ";";
}

string HtmlGenThread::SVG_GenHtmlLine(int id)
{
	if (m_svgtags.empty())
		return string();
	string tag = GetRandomItem(m_svgtags, "rect");
	string event_exp = GetRandomItem(m_evtfuncs, "onchange") + "='" +
		GetRandomItem(m_funcNames, "fuzz0") + "();'";

	string color = GetRandomItem(m_type_values["color"], "rgb(0,0,255)");
	string attr_exp1 = GenTagAttrExp(m_svgtag_props, tag);
	string attr_exp2 = GenTagAttrExp(m_svgtag_props, tag);
	string attr_exp3 = "style = \"fill:" + color.substr(1, color.size() - 2) +
		";stroke-width:" + to_string(random(1, 20)) +
		";stroke:" + color.substr(1, color.size() - 2) + "\"";

	char* templ = "<%s id='id_%d' %s %s %s %s>fuzz0();</%s>\n\0";
	char result[1024];
	sprintf_s(result, templ, tag.c_str(), id,
		event_exp.c_str(),
		attr_exp1.c_str(),
		attr_exp2.c_str(),
		attr_exp3.c_str(),
		tag.c_str());
	return string(result);
}

string HtmlGenThread::SVG_GenJsFunction(const string & name)
{
	string funcstr = "function " + name + "(){try{\n";
	uint32_t count = random(10, 30);
	for (uint32_t i = 0; i < count; i++)
	{
		funcstr += "    ";
		funcstr += SVG_GenJsLine();
		funcstr += "\n";
	}
	funcstr += "}catch(e){}}\n";
	return funcstr;
}

string HtmlGenThread::SVG_GenJsLine()
{
	string prop_right;
	string tmp, tmp2, tmp3;
	uint32_t sw = random(0, 14);
	switch (sw)
	{
	case 0: // window对象属性赋值
	case 1:
	case 2:
		return "try{var tmp = " + GetRandomItem(m_ids, "id_0") + "." +
			GenJsLine_Property(m_svg_props, GetRandomItem(m_svgdoms, "SVGSVGElement"), random(0, 5)) +
			"}catch(e){}";
	case 3:
		tmp = GetRandomItem(m_svgtags, "svg");
		return "try{var els=document.getElementsByTagName(\"" +
			tmp + "\"); " +
			"if(els.length>0)var tmp = els[" + to_string(random(0, 10)) + "%els.length]." +
			GenJsLine_Property(m_svg_props, m_svgtag_dom[tmp], random(0, 5)) +
			"}catch(e){}";
	case 4:
	case 5:
	case 6:
		return "try{var tmp = " + GetRandomItem(m_ids, "id_0") + "." +
			GenJsLine_ExecCommand(m_svg_props, GetRandomItem(m_svgdoms, "SVGSVGElement"), random(0, 3)) +
			"}catch(e){}";
	case 7:
		tmp = GetRandomItem(m_svgtags, "svg");
		return "try{var els=document.getElementsByTagName(\"" +
			tmp + "\"); " +
			"if(els.length>0)var tmp = els[" + to_string(random(0, 10)) + "%els.length]." +
			GenJsLine_ExecCommand(m_svg_props, m_svgtag_dom[tmp], random(0, 3)) +
			"}catch(e){}";
	case 8:
		return "try{var ee = document.createElement(\'" +
			GetRandomItem(m_svgtags, "svg") + "\');" +
			"ee.id = \"id_" + to_string(m_ids.size() - 1) + "\";" +
			GetRandomItem(m_ids, "id_0") + ".appendChild(ee);" +
			"}catch(e){}";
	case 9:
		tmp = GetRandomItem(m_ids, "id_0");
		return "try{var ee = document.createElement(\'" +
			GetRandomItem(m_svgtags, "svg") + "\');" +
			tmp + ".replaceChild(" + tmp + ".firstChild,ee);" + "}catch(e){}";
	case 10:
		tmp = GetRandomItem(m_svgtags, "svg");
		return "try{var ee = " + GetRandomObject(m_svgtag_dom[tmp]) + ";" +
			"ee.__proto__ = " + GetRandomObject(m_svgtag_dom[tmp]) + ";" +
			"var tmp = ee." + GenJsLine_Property(m_svg_props, GetRandomItem(m_svgdoms, "SVGSVGElement"), random(0, 3)) +
			";" + "}catch(e){}";
	case 11:
		return "try{" + GetRandomObject("HTMLElement") + ".attachEvent(\"" +
			GetRandomItem(m_evtfuncs, "onchange") + "\"," +
			GetRandomItem(m_funcNames, "fuzz0") +
			");}catch(e){}";
	case 12:
		return "try{" + GetRandomObject("HTMLElement") + ".addEventListener(\"" +
			GetRandomItem(m_evts, "change") + "\"," +
			GetRandomItem(m_funcNames, "fuzz0") + "," + TrueOrFalse() +
			");}catch(e){}";
	case 13: // 通过tag创建element
		m_ids.push_back("id_" + to_string(m_ids.size()));
		return "try{var ee = document.createElement(\'" + GetRandomItem(m_svgtags, "rect") + "\');" +
			"ee.id = \"id_" + to_string(m_ids.size() - 1) + "\";" +
			"svg_0.appendChild(ee);" + "}catch(e){}";
	default:
		break;
	}
	return string();
}

string HtmlGenThread::GetRandomItem(const vector<string>& items, const string dft)
{
	if (items.size() > 0)
	{
		uint32_t rd = random(0, items.size());
		if (!items[rd].empty())
			return items[rd];
	}
	return dft;
}

string HtmlGenThread::GetRandomValue(const vector<string>& values, const string dft)
{
	if (values.size() == 0)
		return dft;

	string valueortype = GetRandomItem(values, dft);
	if (valueortype.empty())
		return dft;
	else if (valueortype.front() == '%')
	{
		string type = valueortype.substr(1);
		return GetRandomItem(m_type_values[type], dft);
	}
	else if (valueortype.front() == '$')
	{
		return GetRandomObject(valueortype, dft);
	}

	return valueortype;
}

string HtmlGenThread::GetRandomObject(const string & objType, const string dft)
{
	uint32_t rd = random(0, 25);
	string tmp;
	switch (rd)
	{
	case 0:
		return GetRandomItem(m_ids, dft);
	case 1:
		return "document.createElement(\"" + GetRandomItem(m_htmltags) + "\")";
	case 2:
		return "document.createComment(" + GetRandomItem(m_type_values["str"]) + ")";
	case 3:
		return GetRandomItem(m_ids, "id_0") + ".firstChild";
	case 4:
		return GetRandomItem(m_ids, "id_0") + ".cloneNode(true)";
	case 5:
		return GetRandomItem(m_ids, "id_0") + ".attributes";
	case 6:
		return GetRandomItem(m_ids, "id_0") + ".parentNode";
	case 7:
		return "document.createTextNode(" + GetRandomItem(m_type_values["str"], "mixfuzz") + ")";
	case 8:
		return "document.createDocumentFragment()";
	case 9:
		return "document.documentElement";
	case 10:
		return "document.createCDATASection(" + GetRandomItem(m_type_values["str"], "mixfuzz") + ")";
	case 11:
		return "document.createProcessingInstruction(" + GetRandomItem(m_type_values["str"], "mixfuzz") + ")";
	case 12:
		return "document.createAttribute(" + GetRandomItem(m_type_values["str"], "mixfuzz") + ")";
	case 13:
		return "document.createEntityReference(" + GetRandomItem(m_type_values["str"], "mixfuzz") + ")";
	case 14:
		return "document.getElementsByTagName(\"" + GetRandomItem(m_htmltags, "body") + "\")";
	case 15:
		return "document.getElementsByTagName(\"" + GetRandomItem(m_htmltags, "body") + "\")[0]";
	case 16:
		return "document.getElementById(\"" + GetRandomItem(m_ids, "id_0") + "\")";
	case 17:
		return "document.createElementNS(\"" + GetRandomItem(m_htmltags, "body") + "\")";
	case 18:
		return "document.createAttributeNS(" + GetRandomItem(m_type_values["str"], "mixfuzz") + ")";
	case 19:
		return "document";
	case 20:
		return "window";
	case 21:
		return "document.body";
	case 22:
		return "document.all[" + to_string(random(0, 30)) + "]";
	case 23:
		return "new Array(10)";
	default:
		return GetRandomItem(m_ids, dft);
	}
}

/********************************************************************
* [函数名]: GetRandomFuncArgs
* [描述]:
* [输入]
*   prop：proterty结构体（函数信息）
* [输出]
*   out：获取的参数（无需释放）
* [返回值]
*   string: 参数
* [修改记录]
*   2016-06-09,littledj:
*********************************************************************/
string HtmlGenThread::GetRandomFuncArgs(const PROPERTY & prop, const string dft)
{
	if (prop.values.size() == 0)
		return dft;

	string args;
	for each (string arg in prop.values)
	{
		if (arg.front() == '$')
		{
			string type = arg.substr(1, string::npos);
			if (type == "EventListener")
			{
				args += GetRandomItem(m_funcNames, "fuzz0");
				args += ",";
			}
			else
			{
				args += GetRandomObject(type);
				args += ",";
			}
		}
		else if (arg.front() == '%')
		{
			string type = arg.substr(1, string::npos);
			if (!m_type_values[type].empty())
			{
				int tr = random(0, (uint32_t)m_type_values[type].size());
				args += m_type_values[type][tr];
				args += ",";
			}
		}
		else
		{
			args += arg;
			args += ",";
		}

	}

	if (!args.empty())
		args.erase(args.end() - 1);
	if (args.empty())
		return dft;
	return args;
}

string HtmlGenThread::TrueOrFalse()
{
	int rd = rand();
	if (rd % 2 == 0)
		return "true";
	else
		return "false";
}
