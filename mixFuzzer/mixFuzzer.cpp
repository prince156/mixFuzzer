// mixFuzzer.cpp : 定义控制台应用程序的入口点。
//
#include <Windows.h>
#include <cstdio>
#include <conio.h>
#include "tstream.h"

#include "common.h"
#include "httpServThread.h"
#include "htmlGenThread.h"

using namespace std;
using namespace gcommon;

GLogger2 glogger;

tstring GetCurrentDirPath();

int _tmain(int argc, TCHAR** argv)
{
	const uint16_t LISTEN_PORT = 12228;
	const uint32_t BUFF_SIZE = 1024 * 100;

	char* htmlBuff = new char[BUFF_SIZE];
	char* htmlTempl = new char[BUFF_SIZE];

	PRINT_TARGET print_target = PRINT_TARGET::BOTH;
	int debug_level = 0;
	tstring log_file = TEXT("mixfuzz.log");

	// 初始化glogger	
	glogger.setDebugLevel(debug_level);
	glogger.setHeader(TEXT("main"));
	glogger.enableColor();
	glogger.setLogFile(log_file);
	glogger.setTarget(print_target);

	// 获取当前文件夹路径		
	tstring currentDir = GetCurrentDirPath();
	if (currentDir.empty())
	{
		glogger.warning(TEXT("can not get current dir, use default dir"));
		currentDir = TEXT(".\\");
	}
	SetCurrentDirectory(currentDir.c_str());

	// 读取模板文件
	FILE* ftempl;
	errno_t err = fopen_s(&ftempl, "template.html", "r");
	if (err != 0)
	{
		glogger.error(TEXT("failed to open template.html"));
		exit(_getch());
	}
	size_t nread = fread_s(htmlTempl, BUFF_SIZE, 1, BUFF_SIZE - 1, ftempl);
	if (nread == 0)
	{
		glogger.error(TEXT("failed to read template.html"));
		exit(_getch());
	}
	htmlTempl[nread] = 0;

	// semaphore
	HANDLE semaphorep = CreateSemaphore(NULL, 1, 1, TEXT("mixfuzzer_sem_htmlbuff_p"));
	HANDLE semaphorec = CreateSemaphore(NULL, 0, 1, TEXT("mixfuzzer_sem_htmlbuff_c"));

	// 启动http服务线程
	HTTPSERV_THREAD_PARA httpServPara;
	httpServPara.htmlBuff = htmlBuff;
	httpServPara.semHtmlbuff_c = semaphorec;
	httpServPara.semHtmlbuff_p = semaphorep;
	httpServPara.port = LISTEN_PORT;
	HttpServThread httpServThread(&httpServPara);
	if (!httpServThread.Run())
	{
		glogger.error(TEXT("failed to create [HttpServ] thread"));
		exit(_getch());
	}

	// 启动html生成线程
	HTMLGEN_THREA_PARA htmlGenPara;
	htmlGenPara.buffSize = BUFF_SIZE;
	htmlGenPara.htmlBuff = htmlBuff;
	htmlGenPara.htmlTempl = htmlTempl;
	htmlGenPara.semHtmlbuff_c = semaphorec;
	htmlGenPara.semHtmlbuff_p = semaphorep;
	htmlGenPara.port = LISTEN_PORT;
	HtmlGenThread htmlGenThread(&htmlGenPara);
	if (!htmlGenThread.Run())
	{
		glogger.error(TEXT("failed to create [HtmlGen] thread"));
		exit(_getch());
	}

	// 启动浏览器
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = TRUE; //TRUE表示显示创建的进程的窗口
	TCHAR cmdline[1024];
	_stprintf_s(cmdline, TEXT("explorer Microsoft-Edge:http://localhost:%d"),LISTEN_PORT);
	BOOL bRet = CreateProcess(NULL, cmdline,
		NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (!bRet)
	{
		_tprintf(TEXT("error: %d"),GetLastError());
		exit(_getch());
	}   

	exit(_getch());
}

tstring GetCurrentDirPath()
{
	tstring strCurrentDir;
	TCHAR* pCurrentDir = new TCHAR[MAX_PATH + 1];
	memset(pCurrentDir, 0, MAX_PATH + 1);
	DWORD nRet = GetModuleFileName(NULL, pCurrentDir, MAX_PATH);
	if (nRet == 0)
	{
		delete[] pCurrentDir;
		return TEXT(".\\");
	}

	(_tcsrchr(pCurrentDir, '\\'))[1] = 0;
	strCurrentDir = pCurrentDir;
	delete[] pCurrentDir;

	return strCurrentDir;
}