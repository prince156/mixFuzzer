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
	strcpy_s(m_htmlTempl, m_para->buffSize,
		"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: keep-alive\r\nServer: mixfuzzer\r\n\r\n");
	m_headLen = strlen(m_htmlTempl);
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
	static int count = 0;
	strcpy(m_prevprevHtml, m_prevHtml);
	strcpy(m_prevHtml, m_htmlTempl + m_headLen);
	GenerateTempl(m_para->htmlTempl, m_htmlTempl+ m_headLen);
	GenerateTempl(m_htmlTempl+ m_headLen, m_htmlTempl+ m_headLen);

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
	ReadDic("dic\\values.txt", m_values);
	if (m_events.empty())
		m_events.push_back("onresize");
	if (m_tags.empty())
		m_tags.push_back("table");
	if (m_values.empty())
		m_values.push_back("0");
	
	file_f = "dic\\attributes-%s.txt";
	for each (string tag in m_tags)
	{
		vector<string> attributes;
		sprintf_s(filename, file_f, tag.c_str());
		ReadDic(filename, attributes);
		if (attributes.empty())
			continue;
		m_tag_attributes.insert(make_pair(tag, attributes));
		for each (string attr in attributes)
		{
			m_attr_values.insert(make_pair(attr, vector<string>()));
			m_attributes.push_back(attr);
		}		
	}

	file_f = "dic\\values-%s.txt";
	for each (pair<string, vector<string>> attr_values in m_attr_values)
	{
		vector<string> values;
		sprintf_s(filename, file_f, attr_values.first.c_str());
		ReadDic(filename, values);
		if (values.empty())
			continue;
		else
			m_attr_values.insert_or_assign(attr_values.first, values);
	}

	file_f = NULL;
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
	int dstsize = m_para->buffSize - m_headLen;
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
				if (!m_values.empty())
				{
					int vr = random(0, m_values.size());
					memcpy_s(dst + dstlen, dstsize - dstlen, m_values[vr].c_str(), m_values[vr].size());
					dstlen += m_values[vr].size();
					i += 3;
					continue;
				}
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
					i += 3;
					continue;
				}
			}
			else if (memcmp(tmp + i, "[ev]", 4) == 0)
			{
				if (!m_events.empty())
				{
					int er = random(0, m_events.size());
					memcpy_s(dst + dstlen, dstsize - dstlen, m_events[er].c_str(), m_events[er].size());
					dstlen += m_events[er].size();
					i += 3;
					continue;
				}
			}
			else if (memcmp(tmp + i, "[ef]", 4) == 0)
			{
				if (!m_evfunctions.empty())
				{
					int er = random(0, m_evfunctions.size());
					memcpy_s(dst + dstlen, dstsize - dstlen, m_evfunctions[er].c_str(), m_evfunctions[er].size());
					dstlen += m_evfunctions[er].size();
					i += 3;
					continue;
				}
			}
			else if (memcmp(tmp + i, "[at]", 4) == 0)
			{
				if (!m_attributes.empty())
				{
					int er = random(0, m_attributes.size());
					memcpy_s(dst + dstlen, dstsize - dstlen, m_attributes[er].c_str(), m_attributes[er].size());
					dstlen += m_attributes[er].size();
					i += 3;
					continue;
				}
			}
			else if (memcmp(tmp + i, "[sf]", 4) == 0)
			{
				char* safeurl_f = "window.location.href = 'http://localhost:%d';";
				char safeurl[100];
				sprintf_s(safeurl, safeurl_f, m_para->port);
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
					i += 3;
					continue;
				}
			}
			else if (memcmp(tmp + i, "[u", 2) == 0 && tmp[i + 3] == ']')
			{
				if (tmp[i + 2] >= '0' && tmp[i + 2] <= '9')
				{
					string line = GetRandomLine_u(tmp[i + 2] - '0');
					memcpy_s(dst + dstlen, dstsize - dstlen, line.c_str(), line.size());
					dstlen += line.length();
					i += 3;
					continue;
				}
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
					i += 3;
					continue;
				}
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
	
	string attr_exp = "";
	if (m_tag_attributes.find(tag) != m_tag_attributes.end())
	{
		if (!m_tag_attributes[tag].empty())
		{
			int pr = random(0, m_tag_attributes[tag].size());
			string attr = m_tag_attributes[tag][pr];
			attr_exp.assign(attr);
			attr_exp.append("='");
			if (m_attr_values.find(attr) != m_attr_values.end())
			{
				if (!m_attr_values[attr].empty())
				{
					int vr = random(0, m_attr_values[attr].size());
					attr_exp.append(m_attr_values[attr][vr]);
				}
				else
				{
					int vr = random(0, m_values.size());
					attr_exp.append(m_values[vr]);
				}
			}
			else
			{
				int vr = random(0, m_values.size());
				attr_exp.append(m_values[vr]);
			}
			attr_exp.append("'");
		}		
	}

	
	
	char* templ = "<%s id='id_%d' %s %s>fuzz</%s>\n\0";
	char result[1024];
	sprintf_s(result, templ, tag.c_str(), id,
		event_exp.c_str(), 
		attr_exp.c_str(),
		tag.c_str());
	return string(result);
}
