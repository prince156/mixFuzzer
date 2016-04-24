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
    ReadDic("dic\\htmlTags.txt", m_tags);
	ReadDic("dic\\domTags.txt", m_dtags);
    ReadDic("dic\\commands.txt", m_commands);

	InitTagProperties("dic\\attributes_html\\", "attributes-*.txt", m_tag_props);
	InitTagProperties("dic\\attributes_dom\\", "attributes-*.txt", m_dtag_props);
	InitTagFunctions("dic\\functions\\", "functions-*.txt", m_dtag_funcs);
    InitTypeValues("dic\\values\\", "values-*.txt", m_type_values);
	HandleInheritation();

    // rand seed
    char* chr = new char[1];
    srand((int)chr);
    delete chr;

    file_f = NULL;
}

void HtmlGenThread::InitTagFunctions(
	const string & path, 
	const string & name, 
	map<string, vector<FUNCTION>>& tag_funcs)
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
			vector<string> func_lines;
			vector<FUNCTION> funcs;
			string filepath = path;
			filepath.append(FileInfo.name);
			ReadDic(filepath.c_str(), func_lines);
			if (func_lines.empty())
				continue;

			for each (string line in func_lines)
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
							funcs.push_back(FUNCTION{ parent, "", vector<string>() });
					}					
					continue;
				}

				// 正常函数信息
				string name = line.substr(0, line.find_first_of(':'));
				string value_line;
				if (line.find_first_of(':') != string::npos)
					value_line = line.substr(line.find_first_of(':') + 1, string::npos);
				else
					value_line.clear();
				vector<string> values = SplitString(value_line, ',');
				if (values.size() > 0)
				{
					string ret = values[0];
					values.erase(values.begin());
					funcs.push_back(FUNCTION{ name, ret, values });
				}				
			}

			string tag = filepath.substr(filepath.find_first_of('-') + 1, string::npos);
			tag = tag.substr(0, tag.find_last_of('.'));
			tag_funcs.insert(make_pair(tag, funcs));
		}
	} while (_findnext(hh, &FileInfo) == 0);

	_findclose(hh);
}

void HtmlGenThread::InitTagProperties(
	const string &path, 
	const string &name, 
	map<string, vector<ATTRIBUTE>>& tag_props)
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
            vector<string> attribute_lines;
            vector<ATTRIBUTE> attributes;
            string filepath = path;
            filepath.append(FileInfo.name);
            ReadDic(filepath.c_str(), attribute_lines);
            if (attribute_lines.empty())
                continue;

            for each (string line in attribute_lines)
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
							attributes.push_back(ATTRIBUTE{ parent, vector<string>() });
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
                attributes.push_back(ATTRIBUTE{ name, values });
            }

            string tag = filepath.substr(filepath.find_first_of('-') + 1, string::npos);
            tag = tag.substr(0, tag.find_last_of('.'));
			tag_props.insert(make_pair(tag, attributes));
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
	// 处理m_dtag_props的继承数据
	for each (auto item in m_dtag_props)
	{
		for (auto i = m_dtag_props[item.first].begin(); i < m_dtag_props[item.first].end();)
		{
			if ((*i).name.front() == '$')
			{
				string parent = string((*i).name.c_str() + 1);
				m_dtag_props[item.first].erase(i);
				if (!m_dtag_props[parent].empty())
				{
					for each (auto pitem in m_dtag_props[parent])
					{
						m_dtag_props[item.first].push_back(pitem);
					}
				}
				i = m_dtag_props[item.first].begin();
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
	for each (auto item in m_dtag_funcs)
	{
		for (auto i = m_dtag_funcs[item.first].begin(); i < m_dtag_funcs[item.first].end();)
		{
			if ((*i).name.front() == '$')
			{
				string parent = string((*i).name.c_str() + 1);
				m_dtag_funcs[item.first].erase(i);
				if (!m_dtag_funcs[parent].empty())
				{
					for each (auto pitem in m_dtag_funcs[parent])
					{
						m_dtag_funcs[item.first].push_back(pitem);
					}
				}
				i = m_dtag_funcs[item.first].begin();
			}
			else
				i++;
		}
	}

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

	// 处理未赋值tag
	for each (string tag in m_tags)
	{
		if (m_tag_props.find(tag) == m_tag_props.end())
		{
			m_tag_props.insert(make_pair(tag, m_tag_props["common"]));
		}
	}
	for each (string tag in m_dtags)
	{
		if (m_dtag_props.find(tag) == m_dtag_props.end())
		{
			m_dtag_props.insert(make_pair(tag, m_dtag_props["element"]));
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
                GenerateFromVector(doctypeName, dst, dstsize, dstlen);
                i += 3;
                continue;
            }
            else if (memcmp(tmp + i, "[cd]", 4) == 0)
            {
                GenerateFromVector(m_commands, dst, dstsize, dstlen);
                i += 3;
                continue;
            }
            else if (memcmp(tmp + i, "[vl]", 4) == 0)
            {
                GenerateFromVector(m_type_values["str"], dst, dstsize, dstlen);
                i += 3;
                continue;
            }
            else if (memcmp(tmp + i, "[nr]", 4) == 0)
            {
                rd = random(0, 0x00ffffff);
                memcpy_s(dst + dstlen, dstsize - dstlen, to_string(rd).c_str(), to_string(rd).size());
                dstlen += to_string(rd).size();
                i += 3;
                continue;
            }
            else if (memcmp(tmp + i, "[el]", 4) == 0)
            {
                GenerateFromVector(m_tags, dst, dstsize, dstlen);
                i += 3;
                continue;
            }
            else if (memcmp(tmp + i, "[ev]", 4) == 0)
            {
                GenerateFromVector(m_evts, dst, dstsize, dstlen);
                i += 3;
                continue;
            }
            else if (memcmp(tmp + i, "[ef]", 4) == 0)
            {
                GenerateFromVector(m_evtfuncs, dst, dstsize, dstlen);
                i += 3;
                continue;
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
                i += 3;
                continue;
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
                i += 3;
                continue;
            }
            else if (memcmp(tmp + i, "[sf]", 4) == 0)
            {
                char* safeurl_f = "window.location.href = 'http://%s:%d';";
                char safeurl[100];
                sprintf_s(safeurl, safeurl_f, m_para->serverip.c_str(), m_para->port);
                memcpy_s(dst + dstlen, dstsize - dstlen, safeurl, strlen(safeurl));
                dstlen += strlen(safeurl);
                i += 3;
                continue;
            }
            else if (memcmp(tmp + i, "[cc]", 4) == 0) // 未完成
            {
                GenerateFromVector(compatibleName, dst, dstsize, dstlen);
                i += 3;
                continue;
            }
            else if (memcmp(tmp + i, "[n", 2) == 0 && tmp[i + 3] == ']')
            {
                if (tmp[i + 2] >= '0' && tmp[i + 2] <= '9')
                {
                    int id = tmp[i + 2];
                    dst[dstlen++] = (char)random('0', id);
                    dst[dstlen] = 0;
                }
                i += 3;
                continue;
            }
            else if (memcmp(tmp + i, "[u", 2) == 0 && tmp[i + 3] == ']')
            {
                if (tmp[i + 2] >= '0' && tmp[i + 2] <= '9')
                {
                    GenerateFromVector(m_ufile[tmp[i + 2] - '0'], dst, dstsize, dstlen);
                }
                i += 3;
                continue;
            }
            else if (memcmp(tmp + i, "[e", 2) == 0 && tmp[i + 3] == ']')
            {
                if (tmp[i + 2] >= '0' && tmp[i + 2] <= '9')
                {
                    for (size_t j = '0'; j < tmp[i + 2]; j++)
                    {
                        string line = GenHtmlLine(j - '0');
                        memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
                        dstlen += line.length();
                    }
                }
                i += 3;
                continue;
            }

        }

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
	ATTRIBUTE attr = m_tag_props[tag][rd];
    if (attr.values.empty())
        return attr.name + "=\'\'";

    int vr = random(0, attr.values.size());
    string valueortype = attr.values[vr];
    if (valueortype.front() == '$')
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
        char fr = random(0, 3) + '0';
        rd = random(0, m_evtfuncs.size());
        event_exp.assign(m_evtfuncs[rd]);
        event_exp.append("='fuzz");
        event_exp.append(&fr, 1);
        event_exp.append("();'");
    }

    string attr_exp1 = GenTagAttrExp(tag);
    string attr_exp2 = GenTagAttrExp(tag);
    string attr_exp3 = GenTagAttrExp(tag);

    char* templ = "<%s id='id_%d' %s %s %s %s>fuzz</%s>\n\0";
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
    int count = random(0, 30);
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
    int rd;
    int sw = random(0, 10);
    switch (sw)
    {
    case 0: // 属性赋值
        break;
    case 1: // 函数调用
        break;
    case 2: // execCommand
        break;
    case 3: // event操作
        break;
    case 4: // 创建元素
        break;
    default:
        break;
    }

    int id = random(0, 9);
    return string();
}
