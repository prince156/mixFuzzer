#include "htmlGenThread.h"



HtmlGenThread::HtmlGenThread(PHTMLGEN_THREAD_PARA para)
	:GThread(para)
{
	m_para = para;
	m_htmlTempl = new char[m_para->buffSize];
}


HtmlGenThread::~HtmlGenThread()
{
}

void HtmlGenThread::ThreadMain()
{
	static int count = 0;
	

	char* html = "\
HTTP/1.1 200 OK\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Connection: keep-alive\r\n\
Server: mixfuzzer\r\n\r\n\
<html>\r\n\
<script>\r\n\
setTimeout(\"window.location.href='http://localhost:12228'\",10);\r\n\
</script>\r\n\
<body>Test Test %d</body>\r\n\
</html>\r\n";
	char outbuff[1024];
	sprintf_s(outbuff, html, count++);

	size_t templlen = strlen(m_para->htmlTempl);
	size_t newtempllen = 0;
	for (size_t i = 0; i < templlen; i++)
	{
		if (m_para->htmlTempl[i] == '[' && i+3 < templlen)
		{
			if (memcmp(m_para->htmlTempl+i,"[u",2) == 0 && m_para->htmlTempl[i+3] == ']')
			{
				if (m_para->htmlTempl[i + 2] >= '0' && m_para->htmlTempl[i + 2] <= '9')
				{
					string filename;
					filename.assign(m_para->htmlTempl + i + 1, m_para->htmlTempl + i + 2);
					filename.append(".txt");
					string line = GetRandomLine(filename);
					strcat(m_htmlTempl, line.c_str());
					newtempllen += line.length();
					i += 4;
					continue;
				}
			}
			else if (memcmp(m_para->htmlTempl + i, "[sf]", 4) == 0)
			{
				char* safeurl_f = "window.location.href = 'http://localhost:%d'";
				char safeurl[100];
				sprintf_s(safeurl, safeurl_f, m_para->port);
				strcat(m_htmlTempl, safeurl);
				newtempllen += strlen(safeurl);
				i += 4;
				continue;
			}
			else if (memcmp(m_para->htmlTempl + i, "[cc]", 4) == 0)
			{
				strcat(m_htmlTempl, "\"IE=IE7\"");
				newtempllen += 8;
				i += 4;
				continue;
			}
		}

		m_htmlTempl[newtempllen++] = m_para->htmlTempl[i];
	}

	if (WAIT_OBJECT_0 != WaitForSingleObject(m_para->semHtmlbuff_p, INFINITE))
		return;
	memcpy_s(m_para->htmlBuff, m_para->buffSize, outbuff, strlen(outbuff) + 1);
	ReleaseSemaphore(m_para->semHtmlbuff_c, 1, NULL);
}

void HtmlGenThread::Init()
{	
	char* ufiledata = new char[m_para->buffSize];
	string ufilestr;
	char* file_f = "u%d.txt";
	char file[10];
	for (size_t i = 0; i < 10; i++)
	{
		sprintf_s(file, file_f, i);

		// 读取模板文件
		FILE* ftempl;
		errno_t err = fopen_s(&ftempl, file, "r");
		if (err != 0)
		{
			continue;
		}
		
		size_t nread = fread_s(ufiledata, m_para->buffSize, 1, m_para->buffSize - 1, ftempl);
		if (nread == 0)
		{
			continue;
		}
		
		ufiledata[nread] = 0;
		ufilestr.assign(ufiledata);
		
	}

	delete[] ufiledata;
}

string HtmlGenThread::GetRandomLine(string file)
{
	
	
}
