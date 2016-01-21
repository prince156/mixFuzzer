#include "htmlGenThread.h"
#include "common.h"

using namespace gcommon;


HtmlGenThread::HtmlGenThread(PHTMLGEN_THREAD_PARA para)
	:GThread(para)
{
	m_para = para;
	m_htmlTempl = new char[m_para->buffSize + 1];
	m_prevHtml = new char[m_para->buffSize + 1];
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
	return m_prevHtml;
}

void HtmlGenThread::ThreadMain()
{
	static int count = 0;
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
	char* ufiledata = new char[m_para->buffSize];
	string ufilestr;
	FILE* file;
	char* file_f = "u%d.txt";
	char filename[10];
	for (size_t i = 0; i < 10; i++)
	{
		sprintf_s(filename, file_f, i);		
		errno_t err = fopen_s(&file, filename, "r");
		if (err != 0)
		{
			continue;
		}
		
		size_t nread = fread_s(ufiledata, m_para->buffSize, 1, m_para->buffSize - 1, file);
		if (nread == 0)
		{
			fclose(file);
			continue;
		}		
		ufiledata[nread] = 0;
		
		size_t start = 0;
		size_t len = strlen(ufiledata);
		for (size_t j = start; j < len; j++)
		{
			if (ufiledata[j] == '\n')
			{
				ufiledata[j] = '\0';
				if(strlen(ufiledata + start) > 0)
					m_ufile[i].push_back(string(ufiledata + start));
				start = j + 1;
			}
		}
		if (start < len)
		{
			if (strlen(ufiledata + start) > 0)
				m_ufile[i].push_back(string(ufiledata + start));
		}
		fclose(file);
	}
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
			if (memcmp(tmp + i, "[n", 2) == 0 && tmp[i + 3] == ']')
			{
				if (tmp[i + 2] >= '0' && tmp[i + 2] <= '9')
				{
					int r = random(0, tmp[i + 2] - '0');
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
		}

		dst[dstlen++] = tmp[i];
		dst[dstlen] = 0;
	}

	delete[] tmp;
}

string HtmlGenThread::GetRandomLine_u(int id)
{
	if (m_ufile[id].empty())
	{
		return string();
	}
	int r = random(0, m_ufile[id].size());
	return m_ufile[id][r];
}
