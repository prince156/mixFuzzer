// mixFuzzer.cpp : 定义控制台应用程序的入口点。
//
#include <Windows.h>
#include <cstdio>
#include <conio.h>
#include <Shobjidl.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <io.h>
#include "tstream.h"

#include "common.h"
#include "httpServThread.h"
#include "htmlGenThread.h"

#define SOFT_NAME TEXT("mixFuzzer")
#define SOFT_VER TEXT("v0.5")
#define SOFT_LOGO TEXT(\
	"================================================================================\n"\
	"|                         Wellcome to " SOFT_NAME " " SOFT_VER "                          |\n"\
	"================================================================================\n\n")

using namespace std;
using namespace gcommon;

GLogger2 glogger;
tstring GetCurrentDirPath();
int GetDebugInfo(HANDLE hPipe, char* buff, int size, int timeout = 2000);
tstring GetCrashPos(HANDLE hinPipeW, HANDLE houtPipeR);
bool CheckCCInt3(char* buff);
bool CheckC3Ret(char* buff);
vector<DWORD> GetAllProcessId(LPCTSTR pszProcessName);
bool TerminateAllProcess(LPCTSTR pszProcessName);
uint32_t GetFilecountInDir(tstring dir, tstring fileext);
void LoudTemplate(vector<char*> & templs, int maxBuffSize);

int _tmain(int argc, TCHAR** argv)
{
	//const TCHAR* sAUMID = TEXT("Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge");
	const TCHAR* sMicrosoftEdgeExecutable = TEXT("MicrosoftEdge.exe");
	const TCHAR* sBrowserBrokerExecutable = TEXT("browser_broker.exe");
	const TCHAR* sRuntimeBrokerExecutable = TEXT("RuntimeBroker.exe");
	const TCHAR* sMicrosoftEdgeCPExecutable = TEXT("MicrosoftEdgeCP.exe");

	const uint16_t LISTEN_PORT = 12228;
	const uint32_t BUFF_SIZE = 1024 * 100;
	const uint32_t FUZZ_TIMEOUT = 5000;
	const uint32_t READ_DBGINFO_TIMEOUT = 1000;
	const uint32_t MAX_POC_COUNT = 5;

	char* htmlBuff = new char[BUFF_SIZE+1]; // http packet buff
	vector<char*> htmlTempls; // html template buff

	tstring configFile = TEXT("config.ini");
	tstring symPath = TEXT("srv*");
	tstring outPath = TEXT("crash");
	tstring htmlPath;
	tstring logPath;
	tstring appPath = TEXT(".");

	PRINT_TARGET print_target = PRINT_TARGET::BOTH;
	int debug_level = 0;
	tstring log_file = TEXT("mixfuzz.log");
	tstring mode = TEXT("autofuzz");
	tstring webserver = TEXT("127.0.0.1");
	tstring fuzztarget = TEXT("edge");
	TCHAR* appName = TEXT("MicrosoftEdgeCP.exe");

	// 初始化glogger	
	glogger.setDebugLevel(debug_level);
	glogger.setHeader(TEXT("main"));
	glogger.enableColor();
	glogger.setLogFile(log_file);
	glogger.setTarget(print_target);

	// 初始化console显示
	tstring title = SOFT_NAME;
	title.append(TEXT(" "));
	title.append(SOFT_VER);
	SetConsoleTitle(title.c_str());
	glogger.screen(SOFT_LOGO);

	// 创建debug Pipe
	HANDLE inputPipeR, inputPipeW;
	HANDLE outputPipeR, outputPipeW;
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
	if (!CreatePipe(&inputPipeR, &inputPipeW, &saAttr, 0))
	{
		glogger.error(TEXT("failed to create pipe"));
		exit(_getch());
	}
	if (!CreatePipe(&outputPipeR, &outputPipeW, &saAttr, 0))
	{
		glogger.error(TEXT("failed to create pipe"));
		exit(_getch());
	}

	// 获取当前文件夹路径		
	tstring currentDir = GetCurrentDirPath();
	if (currentDir.empty())
	{
		glogger.warning(TEXT("can not get current dir, use default dir"));
		currentDir = TEXT(".\\");
	}
	SetCurrentDirectory(currentDir.c_str());

	// 读取config文件
	debug_level = _ttoi(GetConfigPara(currentDir+configFile, TEXT("DEBUG_LEVEL"), TEXT("0")).c_str());
	fuzztarget = GetConfigPara(currentDir + configFile, TEXT("FUZZ_APP"), fuzztarget);
	appPath = GetConfigPara(currentDir + configFile, TEXT("APP_PATH"), appPath);
	symPath = GetConfigPara(currentDir+configFile, TEXT("SYMBOL_PATH"), symPath);
	outPath = GetConfigPara(currentDir+configFile, TEXT("OUT_PATH"), outPath);
	mode = GetConfigPara(currentDir + configFile, TEXT("MODE"), mode);
	webserver = GetConfigPara(currentDir + configFile, TEXT("WEB_SERVER_IP"), webserver);
	glogger.info(TEXT("symbol path: ") + symPath);
	glogger.info(TEXT(" ouput path: ") + outPath);
	if (outPath.back() != '\\')
		outPath.append(TEXT("\\"));
	if (appPath.back() != '\\')
		appPath.append(TEXT("\\"));

	// 创建crash目录
	CreateDirectory(outPath.c_str(), NULL);	

	// 读取模板文件
	LoudTemplate(htmlTempls, BUFF_SIZE);
	if (htmlTempls.size() == 0)
	{
		glogger.error(TEXT("no template available"));
		exit(_getch());
	}

	// semaphore
	HANDLE semaphorep = CreateSemaphore(NULL, 1, 1, TEXT("mixfuzzer_sem_htmlbuff_p"));
	HANDLE semaphorec = CreateSemaphore(NULL, 0, 1, TEXT("mixfuzzer_sem_htmlbuff_c"));

	// 启动http服务线程
	HTTPSERV_THREAD_PARA httpServPara;
	httpServPara.htmlBuff = htmlBuff;
	httpServPara.semHtmlbuff_c = semaphorec;
	httpServPara.semHtmlbuff_p = semaphorep;
	httpServPara.port = LISTEN_PORT;
	httpServPara.debugLevel = debug_level;
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
	htmlGenPara.htmlTempls = htmlTempls;
	htmlGenPara.semHtmlbuff_c = semaphorec;
	htmlGenPara.semHtmlbuff_p = semaphorep;
	htmlGenPara.serverip = WStringToString(webserver);
	htmlGenPara.port = LISTEN_PORT;
	htmlGenPara.debugLevel = debug_level;
	HtmlGenThread htmlGenThread(&htmlGenPara);
	if (!htmlGenThread.Run())
	{
		glogger.error(TEXT("failed to create [HtmlGen] thread"));
		exit(_getch());
	}

	if (mode == TEXT("webserver"))
	{
		glogger.info(TEXT("webserver mode, listening at port: %d"), LISTEN_PORT);
		while (true)
		{
			Sleep(100);
		}
	}

	// 打开page heap, 关闭内存保护, ...
	if (fuzztarget == TEXT("edge"))
	{
		_tsystem(TEXT("gflags /p /enable MicroSoftEdgeCP.exe /full >nul"));
		appName = TEXT("MicrosoftEdgeCP.exe");
		appPath = TEXT("explorer Microsoft-Edge:");
	}
	else if (fuzztarget == TEXT("chrome"))
	{
		//_tsystem(TEXT("gflags /p /enable chrome.exe /full >nul"));
		appName = TEXT("chrome.exe");
		appPath.append(appName);
		appPath = TEXT("\"") + appPath + TEXT("\"");
	}
	else if (fuzztarget == TEXT("firefox"))
	{
		_tsystem(TEXT("gflags /p /enable firefox.exe /full >nul"));
		appName = TEXT("firefox.exe");
		appPath.append(appName);
		appPath = TEXT("\"") + appPath + TEXT("\"");
	}
	else if (fuzztarget == TEXT("ie"))
	{
		_tsystem(TEXT("gflags /p /enable iexplore.exe /full >nul"));
		appName = TEXT("iexplore.exe");
		appPath.append(appName);
		appPath = TEXT("\"") + appPath + TEXT("\"");
	}
	else if (fuzztarget == TEXT("opera"))
	{
		//_tsystem(TEXT("gflags /p /enable opera.exe /full >nul"));
		appName = TEXT("opera.exe");
		appPath.append(TEXT("launcher.exe"));
		appPath = TEXT("\"") + appPath + TEXT("\"");
	}
	

	// fuzz循环
	DWORD nwrite,nread;
	uint32_t buffsize = 1024;
	char* rbuff = new char[buffsize+1];
	char* pbuff = new char[2*buffsize+1];	
	while (true)
	{
		glogger.screen(TEXT("\n\n"));
		glogger.info(TEXT("Start Fuzzing ..."));

		nread = nwrite = 0;

		// kill 所有相关线程
		glogger.info(TEXT("Kill all %s-related processes"), fuzztarget.c_str());
		if (!TerminateAllProcess(TEXT("WerFault.exe")))
		{
			glogger.error(TEXT("Cannot kill WerFault.exe, restart fuzz."));
			continue;
		}
		if (!TerminateAllProcess(TEXT("cdb.exe")))
		{
			glogger.error(TEXT("Cannot kill cdb, restart fuzz."));
			continue;
		}
		if (!TerminateAllProcess(appName))
		{
			glogger.error(TEXT("Cannot kill %s, restart fuzz."), fuzztarget.c_str());
			continue;
		}

		// 启动浏览器
		glogger.info(TEXT("Start ") + fuzztarget);
		STARTUPINFO si_edge = { sizeof(STARTUPINFO) };
		PROCESS_INFORMATION pi_edge;
		si_edge.dwFlags = STARTF_USESHOWWINDOW;
		si_edge.wShowWindow = TRUE; //TRUE表示显示创建的进程的窗口
		TCHAR cmdline[1024];
		_stprintf_s(cmdline, TEXT("%s http://%s:%d"), appPath.c_str(), webserver.c_str(), LISTEN_PORT);
		BOOL bRet = CreateProcess(NULL, cmdline,
			NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si_edge, &pi_edge);
		if (!bRet)
		{
			glogger.error(TEXT("Cannot start ") + fuzztarget);
			exit(_getch());
		}
		Sleep(500); // 尽量等待一段时间

		// 获取PID
		vector<DWORD> procIDs = GetAllProcessId(appName);
		if (procIDs.empty())
		{
			glogger.error(TEXT("Cannot start the browser, restart fuzz."));
			continue;
		}

		// attach调试器	
		tstring sCommandLine = TEXT("cdb.exe");
		sCommandLine.append(TEXT(" -o -p "));
		sCommandLine += to_tstring(procIDs[0]);
		
		glogger.info(TEXT("Attach ") + sCommandLine);
		STARTUPINFO si_cdb = { sizeof(STARTUPINFO) };
		si_cdb.dwFlags |= STARTF_USESTDHANDLES;
		si_cdb.hStdInput = inputPipeR;
		si_cdb.hStdOutput = outputPipeW;
		si_cdb.hStdError = outputPipeW;
		PROCESS_INFORMATION pi_cdb = {};
		if (!CreateProcess(NULL, (LPWSTR)sCommandLine.c_str(),
			NULL, NULL, TRUE, 0, NULL, NULL, &si_cdb, &pi_cdb))
		{
			glogger.error(TEXT("Cannot attach debugger, restart fuzz."));
			exit(_getch());
		}

		// attach剩余的pid:  .attach 0nxxx;g;|1s; ~*m; .childdbg 1;
		for (size_t i = 1; i < procIDs.size(); i++)
		{
			sCommandLine = TEXT(".attach 0n") + to_tstring(procIDs[i]) + TEXT("\n");
			WriteFile(inputPipeW, WStringToString(sCommandLine).c_str(), sCommandLine.size(), &nwrite, NULL);
			WriteFile(inputPipeW, "g\n", 2, &nwrite, NULL);
			sCommandLine = TEXT("|") + to_tstring(i) + TEXT("s\n");
			WriteFile(inputPipeW, WStringToString(sCommandLine).c_str(), sCommandLine.size(), &nwrite, NULL);
			WriteFile(inputPipeW, "~*m\n", 4, &nwrite, NULL);
			sCommandLine = TEXT(".childdbg1\n");
			WriteFile(inputPipeW, WStringToString(sCommandLine).c_str(), sCommandLine.size(), &nwrite, NULL);
		}

		// debug信息：|*\n
		if (debug_level > 0)
		{
			while (GetDebugInfo(outputPipeR, rbuff, buffsize, 100));
			WriteFile(inputPipeW, "|*\n", 3, &nwrite, NULL);
			if (GetDebugInfo(outputPipeR, rbuff, buffsize, 200) > 0)
			{
				size_t pos = 0;
				size_t bufflen = strlen(rbuff);
				for (size_t i = 0; i < bufflen; i++)
				{
					if (rbuff[i] == '\n')
					{
						rbuff[i] = 0;
						printf("+1 [main] %s\n", rbuff + pos);
						pos = i + 1;
					}
				}
			}
		}

		// 设置symbol path
		sCommandLine = TEXT(".sympath \"") + symPath + TEXT("\";g;\n"); // 同时加入g; 防止后面出现异常
		WriteFile(inputPipeW, WStringToString(sCommandLine).c_str(), sCommandLine.size(), &nwrite, NULL);
		Sleep(100);

		// 监听cdg循环
		glogger.info(TEXT("Fuzzing ..."));
		pbuff[0] = 0;
		uint32_t idletime = 0;
		while (true)
		{
			nread = GetDebugInfo(outputPipeR, rbuff, buffsize, READ_DBGINFO_TIMEOUT);
			if (nread == buffsize)
			{
				idletime = 0;
				memcpy(pbuff, rbuff, nread);
				pbuff[nread] = 0;
				continue;
			}
			else if (nread > 0)
			{			
				idletime = 0;
				memcpy(pbuff + strlen(pbuff), rbuff, nread+1);
			}

			size_t pbufflen = strlen(pbuff);
			if (pbufflen < 2)
			{
				pbuff[0] = 0;
				idletime += READ_DBGINFO_TIMEOUT;
				if (idletime >= FUZZ_TIMEOUT)
				{
					glogger.warning(TEXT("browser seems dead, restart fuzz ..."));
					break;
				}
				continue;
			}

			if (pbuff[pbufflen-2] == '>' && pbuff[pbufflen - 1] == ' ')
			{
				// 进程异常
				if (CheckC3Ret(pbuff))
				{	
					glogger.warning(TEXT("break @ \"ret\", continue"));
					//break;
				}

				// 软件中断，g
				if (CheckCCInt3(pbuff))
				{
					glogger.warning(TEXT("break @ \"int 3\", continue"));
					WriteFile(inputPipeW, "g\n", 2, &nwrite, NULL);
					pbuff[0] = 0;
					continue;
				}

				// No runnable debuggees
				if (strstr(pbuff, "No runnable debuggees") != NULL)
				{
					glogger.warning(TEXT("No runnable debuggees"));
					break;
				}

				// 判定为crash 
				glogger.error(TEXT("!! find crash !!"));
				char* poc = htmlGenThread.GetPrevHtml();
				if (debug_level > 0)
				{
					printf("+1 [main] %s\n", pbuff);
				}
				
				// 生成文件名
				TCHAR filename[11];
				time_t ct = time(NULL);
				_itot(ct, filename, 10);

				// 获取崩溃位置作为目录名
				tstring crashpos = GetCrashPos(inputPipeW, outputPipeR);
				tstring module = crashpos.substr(0, crashpos.find_first_of('_'));
				htmlPath.assign(outPath);
				htmlPath.append(crashpos);
				htmlPath.append(TEXT("\\"));
				CreateDirectory(htmlPath.c_str(), NULL);
				glogger.info(TEXT("crash = ") + crashpos);				
				if (crashpos != TEXT("unknown") &&
					GetFilecountInDir(htmlPath, TEXT("html")) >= MAX_POC_COUNT)
				{
					glogger.warning(TEXT("this crash already logged, restart fuzz ..."));
					break;
				}
				glogger.info(TEXT("create html and log ..."));

				// 补全文件名
				htmlPath.append(filename);
				htmlPath.append(TEXT(".html"));
				logPath.assign(htmlPath);
				logPath.append(TEXT(".log"));
				
				//char* jmp_start;
				//while ((jmp_start = strstr(poc, "http://localhost:")) != NULL)
				//{
				//	char* jmp_end = strstr(jmp_start, "'");
				//	if (jmp_end == NULL)
				//		jmp_end = jmp_start+17;
				//	for (char* i = jmp_start; i < jmp_end; i++)
				//	{
				//		*i = ' ';
				//	}
				//}
				
				// 写入html文件
				FILE* htmlFile;
				_tfopen_s(&htmlFile, htmlPath.c_str(), TEXT("w"));
				fwrite(poc, 1, strlen(poc), htmlFile);
				fclose(htmlFile);

				// 写入log文件
				FILE* logFile;
				_tfopen_s(&logFile, logPath.c_str(), TEXT("w"));
				fwrite("*** mixFuzzer ***\n", 1, 18, logFile);
				fwrite(pbuff, 1, strlen(pbuff), logFile);

				fwrite("\n\n*** crash info ***\n", 1, 21, logFile);
				WriteFile(inputPipeW, "r\n", 2, &nwrite, NULL);
				if (GetDebugInfo(outputPipeR, pbuff, 2 * buffsize)> 0)
					fwrite(pbuff, 1, strlen(pbuff), logFile);
				
				// *** stack tracing ***
				fwrite("\n\n*** stack tracing ***\n", 1, 24, logFile);
				WriteFile(inputPipeW, "kb\n", 3, &nwrite, NULL);
				while (GetDebugInfo(outputPipeR, pbuff, buffsize) > 0)
				{
					fwrite(pbuff, 1, strlen(pbuff), logFile);
				}				
				
				// *** module info ***
				fwrite("\n\n*** module info ***\n", 1, 22, logFile);
				sCommandLine = TEXT("lmDvm ");
				sCommandLine.append(module);
				sCommandLine.append(TEXT("\n"));
				WriteFile(inputPipeW, WStringToString(sCommandLine).c_str(), sCommandLine.size(), &nwrite, NULL);
				if(GetDebugInfo(outputPipeR, pbuff, 2*buffsize)> 0)
					fwrite(pbuff, 1, strlen(pbuff), logFile);
				
				fclose(logFile);
				break;
			}
			
			pbuff[0] = 0;
		}
	}
		
	delete[] rbuff;
	delete[] pbuff;
	exit(_getch());
}

tstring GetCrashPos(HANDLE hinPipeW, HANDLE houtPipeR)
{
	DWORD nwrite,nread;
	char rbuff[1024+1];
	WriteFile(hinPipeW, "u eip L1\n", 9, &nwrite, NULL);
	nread = GetDebugInfo(houtPipeR, rbuff, 1024);
	if (nread == 0)
		return tstring(TEXT("unknown"));
	
	size_t i = 0, start = 0;
	for (i = 0; i < strlen(rbuff); i++)
	{
		if (rbuff[i] == '!' || rbuff[i] == '+')
		{
			while (i > 0 && rbuff[--i] != '\n');
			start = i;
			break;
		}
	}

	if (i!=start)
	{
		return tstring(TEXT("unknown"));
	}

	for (i = start; i < strlen(rbuff); i++)
	{
		if (rbuff[i] == ':')
		{
			rbuff[i] = '_';
		}

		if (rbuff[i] == '\n')
		{
			rbuff[i-1] = 0;
		}
	}

	return StringToWString(string(rbuff+start));
}

bool CheckCCInt3(char* buff)
{
	// cc	int 3
	char* pcc = strstr(buff, " cc ");
	if (pcc == NULL)
		return false;

	char* pint = strstr(pcc, " int ");
	if (pint == NULL)
		return false;
	for (size_t i = 0; i < pint-pcc-4; i++)
	{
		if (pcc[i + 4] != ' ')
			return false;
	}

	char* p3 = strstr(pint, " 3\n");
	if (p3 == NULL)
		return false;
	for (size_t i = 0; i < p3 - pint - 5; i++)
	{
		if (pint[i + 5] != ' ')
			return false;
	}

	return true;
}

bool CheckC3Ret(char* buff)
{
	// c3	ret
	char* pc3 = strstr(buff, " c3 ");
	if (pc3 == NULL)
		return false;

	char* pret = strstr(pc3, " ret\n");
	if (pret == NULL)
		return false;
	for (size_t i = 0; i < pret - pc3 - 4; i++)
	{
		if (pc3[i + 4] != ' ')
			return false;
	}

	return true;
}

int GetDebugInfo(HANDLE hPipe, char* buff, int size, int timeout)
{
	int count = timeout/100;
	DWORD nread = 0;
	while (count--)
	{
		Sleep(100);
		if (!PeekNamedPipe(hPipe, buff, size, &nread, 0, 0))
		{
			continue;
		}

		if (nread == size)
		{
			break;
		}		
	}

	if (nread == 0)
	{
		return 0;
	}

	nread = 0;
	ReadFile(hPipe, buff, size, &nread, NULL);
	if (nread>0)
	{
		buff[nread] = 0;
	}
	return nread;
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

vector<DWORD> GetAllProcessId(LPCTSTR pszProcessName)
{
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;
	vector<DWORD> pids;

	// Enumerate all processes
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		return vector<DWORD>();

	cProcesses = cbNeeded / sizeof(DWORD);
	TCHAR szEXEName[MAX_PATH] = { 0 };
	for (i = 0; i < cProcesses; i++)
	{
		// Get a handle to the process
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
			PROCESS_VM_READ, FALSE, aProcesses[i]);

		// Get the process name
		if (NULL != hProcess)
		{
			HMODULE hMod;
			DWORD cbNeeded;

			if (EnumProcessModules(hProcess, &hMod,
				sizeof(hMod), &cbNeeded))
			{
				//Get the name of the exe file
				GetModuleBaseName(hProcess, hMod, szEXEName,
					sizeof(szEXEName) / sizeof(TCHAR));

				if (_tcsicmp(szEXEName, pszProcessName) == 0)
				{
					pids.push_back(aProcesses[i]);
				}
			}
			CloseHandle(hProcess);
		}
	}
	return pids;
}

bool TerminateAllProcess(LPCTSTR pszProcessName)
{
	bool ret = false;
	vector<DWORD> pids = GetAllProcessId(pszProcessName);
	for each (DWORD pid in pids)
	{
		ret = false;
		if (pid != 0)
		{
			HANDLE hProcess = OpenProcess(
				PROCESS_TERMINATE |
				PROCESS_QUERY_LIMITED_INFORMATION |
				SYNCHRONIZE, FALSE, pid);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 0);
				ret = true;
			}
		}
	}
	
	int count = 0;
	do
	{
		if (count >= 10)
			return false;
		Sleep(100);
		pids = GetAllProcessId(pszProcessName);
		count++;
	} while (!pids.empty());
	return true;
}

uint32_t GetFilecountInDir(tstring dir, tstring fileext)
{
	_tfinddata_t FileInfo;
	tstring strfind = dir + TEXT("\\*.") + fileext;
	intptr_t hh = _tfindfirst(strfind.c_str(), &FileInfo);
	int count = 0;

	if (hh == -1L)
	{
		return count;
	}

	do {
		//判断是否有子目录
		if (FileInfo.attrib & _A_SUBDIR)
		{
			continue;
		}
		else
		{
			count++;
		}
	} while (_tfindnext(hh, &FileInfo) == 0);

	_findclose(hh);
	return count;
}

void LoudTemplate(vector<char*> & templs, int maxBuffSize)
{
	templs.clear();

	_finddata_t FileInfo;
	string strfind = ".\\template*.html";
	intptr_t hh = _findfirst(strfind.c_str(), &FileInfo);
	if (hh == -1L)
		return;

	do 
	{
		//判断是否有子目录
		if (FileInfo.attrib & _A_SUBDIR)
			continue;
		else
		{
			FILE* ftempl;
			if (fopen_s(&ftempl, FileInfo.name, "r") != 0)
			{
				glogger.error(TEXT("failed to open template.html"));
				exit(_getch());
			}

			char* htmlTempl = new char[maxBuffSize + 1];
			size_t tmplsize = fread_s(htmlTempl, maxBuffSize, 1, maxBuffSize - 1, ftempl);
			fclose(ftempl);
			if (tmplsize == 0)
			{
				glogger.warning(TEXT("failed to read template.html"));
				continue;
			}
			htmlTempl[tmplsize] = 0;

			templs.push_back(htmlTempl);
		}
	} while (_findnext(hh, &FileInfo) == 0);

	_findclose(hh);
}