#include <io.h>

#include "htmlGenThread.h"
#include "common.h"
#include "fuzzstr.h"

using namespace gcommon;


HtmlGenThread::HtmlGenThread(PHTMLGEN_THREAD_PARA para)
    :GThread(para)
{
    m_para = para;
    m_htmlTempl = new char[m_para->buffSize + 1];
    m_htmlTempl[0] = 0;
    m_ufile.resize(10);
    Init();
}


HtmlGenThread::~HtmlGenThread()
{
}

void HtmlGenThread::ThreadMain()
{
	m_ids = { "id_0","id_1", "id_2", "id_3", "id_4", "id_5", "id_6", "id_7", "id_8" };
	m_funcNames = { "fuzz0", "fuzz1", "fuzz2" };
    m_htmlTempl[0] = 0;
    int tr = random(0, m_para->htmlTempls.size());
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
    char* file_f = "template\\u%d.txt";
    char filename[MAX_PATH];
    for (size_t i = 0; i < 10; i++)
    {
        sprintf_s(filename, file_f, i);
        ReadDic(filename, m_ufile[i]);
    }
    ReadDic("dic\\eventNames.txt", m_evts);
    ReadDic("dic\\eventFunctions.txt", m_evtfuncs);
    ReadDic2("dic\\tags.txt", m_tag_dom);
    ReadDic("dic\\commands.txt", m_commands);

	for each (auto tag_dom in m_tag_dom)
	{
		m_tags.push_back(tag_dom.first);
	}

	InitTagProperties("dic\\attributes_html\\", "attributes-*.txt", m_tag_props);
	InitTagProperties("dic\\attributes_dom2core\\", "attributes-*.txt", m_dom_props);
	InitTagProperties("dic\\attributes_dom2html5\\", "attributes-*.txt", m_dom_props);
    InitTypeValues("dic\\values\\", "values-*.txt", m_type_values);
	HandleInheritation(); // 处里继承

    // rand seed
    char* chr = new char[1];
    srand((int)chr);
    delete chr;

    file_f = NULL;
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

void HtmlGenThread::HandleInheritation()
{
	// 处理未赋值tag
	for each (string tag in m_tags)
	{
		if (m_tag_props.find(tag) == m_tag_props.end())
		{
			m_tag_props.insert(make_pair(tag, vector<PROPERTY>{ {"$common"} }));
		}
	}

	// 处理m_dom_props的继承数据
	for each (auto item in m_dom_props)
	{
		for (auto i = m_dom_props[item.first].begin(); i < m_dom_props[item.first].end();)
		{
			if ((*i).name.front() == '$')
			{
				string parent = string((*i).name.c_str() + 1);
				m_dom_props[item.first].erase(i);
				if (!m_dom_props[parent].empty())
				{
					for each (auto pitem in m_dom_props[parent])
					{
						m_dom_props[item.first].push_back(pitem);
					}
				}
				i = m_dom_props[item.first].begin();
			}
			else
				i++;
		}
	}

	// 处理m_dom_props的继承数据
	for each (auto item in m_dom_props)
	{
		for (auto i = m_dom_props[item.first].begin(); i < m_dom_props[item.first].end();)
		{
			if ((*i).name.front() == '$')
			{
				string parent = string((*i).name.c_str() + 1);
				m_dom_props[item.first].erase(i);
				if (!m_dom_props[parent].empty())
				{
					for each (auto pitem in m_dom_props[parent])
					{
						m_dom_props[item.first].push_back(pitem);
					}
				}
				i = m_dom_props[item.first].begin();
			}
			else
				i++;
		}
	}

	// 处理m_tag_props的继承数据
	for each (auto item in m_tag_props)
	{
		for (auto i = m_tag_props[item.first].begin(); i < m_tag_props[item.first].end();)
		{
			if ((*i).name.front() == '$')
			{
				string parent = string((*i).name.c_str() + 1);
				m_tag_props[item.first].erase(i);
				if (!m_tag_props[parent].empty())
				{
					for each (auto pitem in m_tag_props[parent])
					{
						m_tag_props[item.first].push_back(pitem);
					}
				}
				i = m_tag_props[item.first].begin();
			}
			else
				i++;
		}
	}

	// 处理m_dtag_funcs的继承数据
	//for each (auto item in m_dtag_funcs)
	//{
	//	for (auto i = m_dtag_funcs[item.first].begin(); i < m_dtag_funcs[item.first].end();)
	//	{
	//		if ((*i).name.front() == '$')
	//		{
	//			string parent = string((*i).name.c_str() + 1);
	//			m_dtag_funcs[item.first].erase(i);
	//			if (!m_dtag_funcs[parent].empty())
	//			{
	//				for each (auto pitem in m_dtag_funcs[parent])
	//				{
	//					m_dtag_funcs[item.first].push_back(pitem);
	//				}
	//			}
	//			i = m_dtag_funcs[item.first].begin();
	//		}
	//		else
	//			i++;
	//	}
	//}

	// 处理m_type_values的继承数据
	for each (auto item in m_type_values)
	{
		for (auto i = m_type_values[item.first].begin(); i < m_type_values[item.first].end();)
		{
			if ((*i).front() == '$')
			{
				string parent = string((*i).c_str() + 1);
				m_type_values[item.first].erase(i);
				if (!m_type_values[parent].empty())
				{
					for each (auto pitem in m_type_values[parent])
					{
						m_type_values[item.first].push_back(pitem);
					}
				}
				i = m_type_values[item.first].begin();
			}
			else
				break;
		}
	}
}


int HtmlGenThread::ReadDic(const char * dicfile, vector<string>& list)
{
    list.clear();
    FILE* file;
    errno_t err = fopen_s(&file, dicfile, "r");
    if (err != 0)
    {
        return 0;
    }

    char* ufiledata = new char[m_para->buffSize];
    size_t nread = fread_s(ufiledata, m_para->buffSize, 1, m_para->buffSize - 1, file);
    if (nread == 0)
    {
        fclose(file);
        delete[] ufiledata;
        return 0;
    }
    ufiledata[nread] = 0;

    size_t start = 0;
    size_t len = strlen(ufiledata);
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
    return list.size();
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
			if (tag_dom.size() == 2)
			{
				tags.insert(make_pair(tag_dom[0], tag_dom[1]));
			}
		}		
	}
	return 0;
}

void HtmlGenThread::GenerateTempl(const char * src, char * dst)
{
    if (src == NULL || dst == NULL)
        return;

    int rd = 0;
    int dstlen = 0;
    int srclen = strlen(src);
    int dstsize = m_para->buffSize;
    if (srclen > dstsize)
        return;
    char* tmp = new char[srclen + 1];
    memcpy_s(tmp, srclen + 1, src, srclen);
    tmp[srclen] = 0;

    for (size_t i = 0; i < srclen; i++)
    {
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
                dstlen += to_string(rd).size();
            }
            else if (memcmp(tmp + i, "[el]", 4) == 0)
            {
                GenerateFromVector(m_tags, dst, dstsize, dstlen);
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
                if (!m_tag_props.empty() && !m_tags.empty())
                {
                    string tag;
                    int count = 0;
                    do
                    {
                        if (count++ >= 10)
                            break;
                        rd = random(0, m_tags.size());
                        tag = m_tags[rd];
                    } while (m_tag_props[tag].empty());

                    if (!m_tag_props[tag].empty())
                    {
                        rd = random(0, m_tag_props[tag].size());
                        memcpy_s(dst + dstlen, dstsize - dstlen,
							m_tag_props[tag][rd].name.c_str(),
							m_tag_props[tag][rd].name.size());
                        dstlen += m_tag_props[tag][rd].name.size();
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
                        string attexp = GenTagAttrExp(tag);
                        if (!attexp.empty())
                        {
                            memcpy_s(dst + dstlen, dstsize - dstlen, attexp.c_str(), attexp.size());
                            dstlen += attexp.size();
                        }
                    }
                }
            }
            else if (memcmp(tmp + i, "[sf]", 4) == 0)
            {
                //char* safeurl_f = "window.location.href = 'http://%s:%d';";
                //char safeurl[100];
                //sprintf_s(safeurl, safeurl_f, m_para->serverip.c_str(), m_para->port);
                //memcpy_s(dst + dstlen, dstsize - dstlen, safeurl, strlen(safeurl));
				char *safeurl = "window.location.href = document.URL;";
				memcpy_s(dst + dstlen, dstsize - dstlen, safeurl, strlen(safeurl));
                dstlen += strlen(safeurl);
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
            else if (memcmp(tmp + i, "[u", 2) == 0 && tmp[i + 3] == ']')
            {
                if (tmp[i + 2] >= '0' && tmp[i + 2] <= '9')
                {
                    GenerateFromVector(m_ufile[tmp[i + 2] - '0'], dst, dstsize, dstlen);
                }
            }
            else if (memcmp(tmp + i, "[e", 2) == 0 && tmp[i + 3] == ']')
            {
                if (tmp[i + 2] >= '0' && tmp[i + 2] <= '9')
                {
                    for (size_t j = '0'; j < tmp[i + 2]; j++)
                    {
                        string line = GenHtmlLine(j - '0');
						if (!line.empty())
						{
							memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
							dstlen += line.length();
						}
                    }
                }
            }
			else if (memcmp(tmp + i, "[ff]", 4) == 0) // 自动生成一个function
			{
				string funcName = "AutoFunc_" + to_string(m_funcNames.size());
				string line = GenJsFunction(funcName);
				if (!line.empty())
				{
					m_funcNames.push_back(funcName);
					memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
					dstlen += line.length();
				}
			}
			else if (memcmp(tmp + i, "[ln]", 4) == 0) // 自动生成一行
			{
				string line = GenJsLine();
				if (!line.empty())
				{
					memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
					dstlen += line.length();
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
    delete tmp;
}

void HtmlGenThread::GenerateFromVector(vector<string>& strs, char * dst, int dstsize, int & dstlen)
{
    if (!strs.empty())
    {
        int rd = random(0, strs.size());
        memcpy_s(dst + dstlen, dstsize - dstlen, strs[rd].c_str(), strs[rd].size());
        dstlen += strs[rd].size();
    }
}

string HtmlGenThread::GenTagAttrExp(const string &tag)
{    
	if (m_tag_props[tag].empty())
		return string();
	int rd = random(0, m_tag_props[tag].size());
	PROPERTY attr = m_tag_props[tag][rd];
    if (attr.values.empty())
        return attr.name + "=\'\'";

    int vr = random(0, attr.values.size());
    string valueortype = attr.values[vr];
    if (valueortype.front() == '%')
    {
        string type = valueortype.substr(1, string::npos);
        if (m_type_values[type].empty())
			return attr.name + "=\'\'";

        int tr = random(0, m_type_values[type].size());
        valueortype = m_type_values[type][tr];
    }

    return attr.name + "=" + valueortype;
}

string HtmlGenThread::GenHtmlLine(int id)
{
    if (m_tags.empty())
        return string();
    int rd = random(0, m_tags.size());
    string tag = m_tags[rd];

    string event_exp = "";
    if (!m_evtfuncs.empty())
    {
        int fr = random(0, m_funcNames.size());
        rd = random(0, m_evtfuncs.size());
        event_exp = m_evtfuncs[rd] + "='" + m_funcNames[fr] + "();'";
    }

    string attr_exp1 = GenTagAttrExp(tag);
    string attr_exp2 = GenTagAttrExp(tag);
    string attr_exp3 = GenTagAttrExp(tag);

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
    string funcstr = "function " + name + "()\n{\n";
    int count = random(20, 30);
    for (int i = 0; i < count; i++)
    {
        funcstr += "    ";
        funcstr += GenJsLine();
        funcstr += "\n";
    }
    funcstr += "}\n";
    return funcstr;
}

string HtmlGenThread::GenJsLine()
{
	string line = "try{";
	string prop_right;
	string tmp;
    int rd,rd2,rd3;
    int sw = random(0, 13);
    switch (sw)
    {
    case 0: // window对象属性赋值
		rd = random(0, 5);
		prop_right = GenJsLine_Property(m_dom_props["Window"], rd);
		if(!prop_right.empty())
			return "try{window." + prop_right + "}catch(e){}";
		break;
    case 1: // 对象属性赋值		
    case 2: // 对象属性赋值
    case 3: // 对象属性赋值
		rd = random(0, 5);
		if (m_type_values["id"].size() > 0)
		{
			prop_right = GenJsLine_Property(m_dom_props["HTMLElement"], rd);
			if (!prop_right.empty())
			{
				rd2 = random(0, m_type_values["id"].size());
				return "try{" +
					m_type_values["id"][rd2].substr(1, m_type_values["id"][rd2].size() - 2) + "." +
					prop_right + "}catch(e){}";
			}
		}
		break;
    case 4: // 对象属性赋值
	case 5:
		rd = random(0, 5);
		prop_right = GenJsLine_Property(m_dom_props["Document"], rd);
		if (!prop_right.empty())
			return "try{document." + prop_right + "}catch(e){}";
		break;
	case 6:
		rd = random(0, 5);
		if (m_tags.size() > 0)
		{
			rd2 = random(0, m_tags.size());
			prop_right = GenJsLine_Property(m_dom_props[m_tags[rd2]], rd);
			if (!prop_right.empty())
			{				
				return "try{var els=document.getElementsByTagName(\"" + m_tags[rd2] + "\"); " +
					"if(els.length>0)els[" + to_string(random(0, 10)) + "%els.length]." + 
					prop_right + "}catch(e){}";
			}
		}	
		break;
	case 7: // 
		rd = random(0, 3);
		prop_right = GenJsLine_ExecCommand(m_dom_props["Window"], rd);
		if (!prop_right.empty())
		{
			return "try{window." + prop_right + "}catch(e){}";
		}
		break;
	case 8: // 
		rd = random(0, 3);
		if (m_type_values["id"].size() > 0)
		{			
			prop_right = GenJsLine_ExecCommand(m_dom_props["HTMLElement"], rd);
			if (!prop_right.empty())
			{
				rd2 = random(0, m_type_values["id"].size());
				return "try{" +
					m_type_values["id"][rd2].substr(1, m_type_values["id"][rd2].size() - 2) + "." +
					prop_right + "}catch(e){}";
			}
		}
		break;
	case 9:
		rd = random(0, 3);
		prop_right = GenJsLine_ExecCommand(m_dom_props["Document"], rd);
		if(!prop_right.empty())
			return "try{document." + prop_right + "}catch(e){}";
		break;
	case 10:
		rd = random(0, 3);
		if (m_tags.size() > 0)
		{			
			rd2 = random(0, m_tags.size());
			prop_right = GenJsLine_ExecCommand(m_dom_props[m_tags[rd2]], rd);
			if (!prop_right.empty())
			{				
				return "try{var els=document.getElementsByTagName(\"" + m_tags[rd2] + "\"); " +
					"if(els.length>0)els[" + to_string(random(0, 10)) + "%els.length]." + 
					prop_right + "}catch(e){}";
			}
		}
		break;
	case 11:
		rd = random(0, m_tags.size());
		return "try{var ee = document.createElement(\'" + m_tags[rd] + "\');" +
			"id_" + to_string(random(0, 10)) + ".appendChild(ee);" +
			"}catch(e){}";
		break;
	case 12:
		rd = random(0, m_tags.size());
		rd2 = random(0, m_ids.size());
		return "try{var ee = document.createElement(\'" + m_tags[rd] + "\');" +
			m_ids[rd2] + ".replaceChild("+ m_ids[rd2] +".firstChild,ee);" +
			"}catch(e){}";
		break;
    default:
        break;
    }
    return string();
}

string HtmlGenThread::GenJsLine_Property(const vector<PROPERTY>& props, int deep)
{
	if (props.size() == 0)
	{
		return "";
	}
	 
	int rd = random(0, props.size());
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
				string right = GenJsLine_Property(m_dom_props[props[rd].ret.substr(1, string::npos)], --deep); // 递归
				if (!right.empty())
					return props[rd].name + "(" + GetRandomFuncArgs(props[rd]) + ")." + right;
			}
			return props[rd].name + "(" + GetRandomFuncArgs(props[rd]) + ");";			
		}
		else if(props[rd].ret.front() == '$')
		{
			string right = GenJsLine_Property(m_dom_props[props[rd].ret.substr(1, string::npos)], --deep); // 递归	
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

string HtmlGenThread::GenJsLine_ExecCommand(const vector<PROPERTY>& props, int deep)
{
	if (props.size() == 0)
	{
		return "";
	}

	int rd = random(0, props.size());
	if (deep == 0)
	{
		int cd = random(0, m_commands.size());
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
		else if(props[rd].ret.front() == '$')
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
				string right = GenJsLine_ExecCommand(m_dom_props[props[rd].ret.substr(1, string::npos)], --deep); // 递归
				if (!right.empty())
					return props[rd].name + "(" + GetRandomFuncArgs(props[rd]) + ")." + right;
			}
			return props[rd].name + "(" + GetRandomFuncArgs(props[rd]) + ");";
		}
		else if(props[rd].ret.front() == '$')
		{
			string right = GenJsLine_ExecCommand(m_dom_props[props[rd].ret.substr(1, string::npos)], --deep); // 递归
			if (!right.empty())
				return props[rd].name + "." + right;
			return props[rd].name + ";";
		}
	}
	return props[rd].name + ";";
}

string HtmlGenThread::GetRandomValue(const vector<string>& values)
{
	if(values.size() == 0)
		return "\'\'";

	int vr = random(0, values.size());
	string valueortype = values[vr];
	if (valueortype.empty())
	{
		return "\'\'";
	}
	else if (valueortype.front() == '%')
	{
		string type = valueortype.substr(1, string::npos);
		if (m_type_values[type].empty())
			valueortype = "\'\'";

		int tr = random(0, m_type_values[type].size());
		return m_type_values[type][tr];
	}
	else if (valueortype.front() == '$')
	{
		return GetRandomObject(valueortype);
	}

	return valueortype;
}

string HtmlGenThread::GetRandomObject(const string & className)
{
	int rd = random(0,2);
	int r1, r2;
	switch (rd)
	{
	case 0:
		r1 = random(0, m_ids.size());
		return m_ids[r1];
	case 1:
		r1 = random(0, m_tags.size());
		return "document.createElement(\"" + m_tags[r1] + "\")";
	default:
		r1 = random(0, m_ids.size());
		return m_ids[r1];
	}
}

string HtmlGenThread::GetRandomFuncArgs(const PROPERTY & prop)
{
	if (prop.values.size() == 0)
	{
		return string();
	}
	string args;
	for each (string arg in prop.values)
	{
		if (arg.front() == '$')
		{
			args += GetRandomObject(arg.substr(1, string::npos));
			args += ",";
		}
		else if (arg.front() == '%')
		{
			string type = arg.substr(1, string::npos);
			if (!m_type_values[type].empty())
			{
				int tr = random(0, m_type_values[type].size());
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
	{
		args.erase(args.end() - 1);
	}
	return args;
}
