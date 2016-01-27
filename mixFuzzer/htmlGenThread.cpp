#include <io.h>

#include "htmlGenThread.h"
#include "common.h"

using namespace gcommon;


HtmlGenThread::HtmlGenThread(PHTMLGEN_THREAD_PARA para)
	:GThread(para)
{
	m_para = para;
	m_htmlTempl = new char[m_para->buffSize + 1];
	m_prevHtml = new char[m_para->buffSize + 1];
	m_prevprevHtml = new char[m_para->buffSize + 1];
	m_prevHtml[0] = 0;
	m_prevprevHtml[0] = 0;
	m_htmlTempl[0] = 0;
	m_ufile.resize(10);
	Init();
}


HtmlGenThread::~HtmlGenThread()
{
}

char * HtmlGenThread::GetPrevHtml()
{
	return m_prevprevHtml;
}

void HtmlGenThread::ThreadMain()
{
	if (m_para->htmlTempls.empty())
	{
		m_state == THREAD_STATE::STOPPED;
		return;
	}

	static int count = 0;
	strcpy(m_prevprevHtml, m_prevHtml);
	strcpy(m_prevHtml, m_htmlTempl);

	m_htmlTempl[0] = 0;
	int tr = random(0, m_para->htmlTempls.size());
	GenerateTempl(m_para->htmlTempls[tr], m_htmlTempl);
	GenerateTempl(m_htmlTempl, m_htmlTempl);
	if (m_htmlTempl[0] == 0)
	{
		m_glogger.error(TEXT("can not fuzz html file"));
		m_state == THREAD_STATE::STOPPED;
		return;
	}

	if (WAIT_OBJECT_0 != WaitForSingleObject(m_para->semHtmlbuff_p, INFINITE))
		return;
	memcpy_s(m_para->htmlBuff, m_para->buffSize, m_htmlTempl, strlen(m_htmlTempl) + 1);
	ReleaseSemaphore(m_para->semHtmlbuff_c, 1, NULL);
}

void HtmlGenThread::Init()
{
	char* file_f = "u%d.txt";
	char filename[MAX_PATH];
	for (size_t i = 0; i < 10; i++)
	{
		sprintf_s(filename, file_f, i);
		ReadDic(filename, m_ufile[i]);
	}
	ReadDic("dic\\events.txt", m_events);
	ReadDic("dic\\event-functions.txt", m_evfunctions);
	ReadDic("dic\\tags.txt", m_tags);
	if (m_events.empty())
		m_events.push_back("onresize");
	if (m_tags.empty())
		m_tags.push_back("table");
	
	LoadTagAttrubites("dic\\attributes-*.txt");
	LoadTypeValues("dic\\values-*.txt");	

	file_f = NULL;
}

void HtmlGenThread::LoadTagAttrubites(char * name)
{
	if (name == NULL)
		return;

	_finddata_t FileInfo;
	intptr_t hh = _findfirst(name, &FileInfo);
	if (hh == -1L)
		return;

	do
	{
		//ÅÐ¶ÏÊÇ·ñÄ¿Â¼
		if (FileInfo.attrib & _A_SUBDIR)
			continue;
		else
		{						
			vector<string> attribute_lines;
			vector<ATTRIBUTE> attributes;
			string filepath = "dic\\";
			filepath.append(FileInfo.name);
			ReadDic(filepath.c_str(), attribute_lines);
			if (attribute_lines.empty())
				continue;

			for each (string line in attribute_lines)
			{
				string name = line.substr(0, line.find_first_of(':'));
				string value_line;
				if (line.find_first_of(':') != string::npos)
					value_line = line.substr(line.find_first_of(':') + 1, string::npos);
				else
					value_line = "$default";
				vector<string> values = SplitString(value_line, ',');
				attributes.push_back(ATTRIBUTE{ name, values });
			}

			string tag = filepath.substr(filepath.find_first_of('-') + 1, string::npos);
			tag = tag.substr(0, tag.find_last_of('.'));
			m_tag_attributes.insert(make_pair(tag, attributes));
		}
	} while (_findnext(hh, &FileInfo) == 0);

	_findclose(hh);
}

void HtmlGenThread::LoadTypeValues(char * name)
{
	if (name == NULL)
		return;

	_finddata_t FileInfo;
	intptr_t hh = _findfirst(name, &FileInfo);
	if (hh == -1L)
		return;

	do
	{
		//ÅÐ¶ÏÊÇ·ñÄ¿Â¼
		if (FileInfo.attrib & _A_SUBDIR)
			continue;
		else
		{
			vector<string> values;
			string filepath = "dic\\";
			filepath.append(FileInfo.name);
			ReadDic(filepath.c_str(), values);
			if (values.empty())
				continue;

			string type = filepath.substr(filepath.find_first_of('-') + 1, string::npos);
			type = type.substr(0, type.find_last_of('.'));
			m_type_values.insert(make_pair(type, values));
		}
	} while (_findnext(hh, &FileInfo) == 0);

	_findclose(hh);
}


int HtmlGenThread::ReadDic(const char * dicfile, vector<string>& list)
{
	list.clear();
	FILE* file;	
	errno_t err = fopen_s(&file, dicfile, "r");
	if (err != 0)
		return 0;

	char* ufiledata = new char[m_para->buffSize];
	size_t nread = fread_s(ufiledata, m_para->buffSize, 1, m_para->buffSize - 1, file);
	if (nread == 0)
	{
		fclose(file);
		delete[] ufiledata;
		return  0;
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

void HtmlGenThread::GenerateTempl(char * src, char * dst)
{
	if (src == NULL || dst == NULL)
		return;

	int srclen = strlen(src);
	int dstsize = m_para->buffSize;
	if (srclen > dstsize)
		return;

	char* tmp = new char[srclen + 1];
	strcpy_s(tmp, srclen + 1, src);

	memset(dst, 0, dstsize);
	size_t dstlen = 0;
	for (size_t i = 0; i < srclen; i++)
	{
		if (tmp[i] == '[' && i + 3 < srclen)
		{
			if (memcmp(tmp + i, "[vl]", 4) == 0)
			{
				if (!m_type_values["default"].empty())
				{
					int vr = random(0, m_type_values["default"].size());
					memcpy_s(dst + dstlen, dstsize - dstlen, 
						m_type_values["default"][vr].c_str(), 
						m_type_values["default"][vr].size());
					dstlen += m_type_values["default"][vr].size();					
				}
				i += 3;
				continue;
			}
			else if (memcmp(tmp + i, "[nr]", 4) == 0)
			{
				int nr = random(0, 1000);
				char ch[10];
				itoa(nr, ch, 10);
				memcpy_s(dst + dstlen, dstsize - dstlen, ch, strlen(ch));
				dstlen += strlen(ch);
				i += 3;
				continue;
			}
			else if (memcmp(tmp + i, "[el]", 4) == 0)
			{
				if (!m_tags.empty())
				{
					int er = random(0, m_tags.size());
					memcpy_s(dst + dstlen, dstsize - dstlen, m_tags[er].c_str(), m_tags[er].size());
					dstlen += m_tags[er].size();
				}
				i += 3;
				continue;
			}
			else if (memcmp(tmp + i, "[ev]", 4) == 0)
			{
				if (!m_events.empty())
				{
					int er = random(0, m_events.size());
					memcpy_s(dst + dstlen, dstsize - dstlen, m_events[er].c_str(), m_events[er].size());
					dstlen += m_events[er].size();
				}
				i += 3;
				continue;
			}
			else if (memcmp(tmp + i, "[ef]", 4) == 0)
			{
				if (!m_evfunctions.empty())
				{
					int er = random(0, m_evfunctions.size());
					memcpy_s(dst + dstlen, dstsize - dstlen, m_evfunctions[er].c_str(), m_evfunctions[er].size());
					dstlen += m_evfunctions[er].size();
				}
				i += 3;
				continue;
			}
			else if (memcmp(tmp + i, "[at]", 4) == 0)
			{
				string tag;
				char* t_start = tmp+i;
				while (*(--t_start) != '<' && t_start > tmp);
				if (t_start[0] == '<')
				{
					char* t_end = t_start;
					while (*(++t_end) != ' ' && t_end < tmp+i);
					if (t_end < tmp + i)
					{
						tag.assign(++t_start, t_end - t_start);
						string attexp = GetRandomAttrExp(tag);
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
			else if (memcmp(tmp + i, "[cc]", 4) == 0)
			{
				memcpy_s(dst + dstlen, dstsize - dstlen, "\"IE=IE7\"", 8);
				dstlen += 8;
				i += 3;
				continue;
			}
			else if (memcmp(tmp + i, "[n", 2) == 0 && tmp[i + 3] == ']')
			{
				if (tmp[i + 2] >= '0' && tmp[i + 2] <= '9')
				{
					int r = random(0, tmp[i + 2] - '0' + 1);
					dst[dstlen++] = '0' + r;
					dst[dstlen] = 0;
				}
				i += 3;
				continue;
			}
			else if (memcmp(tmp + i, "[u", 2) == 0 && tmp[i + 3] == ']')
			{
				if (tmp[i + 2] >= '0' && tmp[i + 2] <= '9')
				{
					string line = GetRandomLine_u(tmp[i + 2] - '0');
					memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
					dstlen += line.length();
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
						string line = GetRandomTag(j-'0');
						memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
						dstlen += line.length();						
					}
				}
				i += 3;
				continue;
			}
			
		}

		dst[dstlen++] = tmp[i];
		dst[dstlen] = 0;
	}

	delete[] tmp;
}

string HtmlGenThread::GetRandomLine_u(int id)
{
	if (m_ufile[id].empty())
		return string();
	int r = random(0, m_ufile[id].size());
	return m_ufile[id][r];
}

string HtmlGenThread::GetRandomAttrExp(string tag)
{
	if (m_tag_attributes[tag].empty())
		return string();

	int r = random(0, m_tag_attributes[tag].size());
	ATTRIBUTE attr = m_tag_attributes[tag][r];
	if (attr.values.empty())
		return string();

	int vr = random(0, attr.values.size());
	string valueortype = attr.values[vr];
	if (valueortype.front() == '$')
	{
		string type = valueortype.substr(1, string::npos);
		if (m_type_values[type].empty())
			return string();

		int tr = random(0, m_type_values[type].size());
		valueortype = m_type_values[type][tr];
	}

	return attr.name + "=\"" + valueortype + "\"";
}

string HtmlGenThread::GetRandomTag(int id)
{
	if(m_tags.empty())
		return string();
	int tr = random(0, m_tags.size());
	string tag = m_tags[tr];

	string event_exp = "";
	if (!m_events.empty())
	{
		char fr = random(0, 3)+'0';
		int er = random(0, m_events.size());
		event_exp.assign(m_events[er]);
		event_exp.append("='fuzz");
		event_exp.append(&fr,1);
		event_exp.append("();'");
	}
	
	string attr_exp1 = GetRandomAttrExp(tag);	
	string attr_exp2 = GetRandomAttrExp(tag);
	string attr_exp3 = GetRandomAttrExp(tag);
	
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
