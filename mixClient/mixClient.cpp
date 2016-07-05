#ifdef __WINDOWS__   
#include <WinSock2.h>
#endif   

#ifdef __LINUX__   
#include <sys/socket.h>
typedef int SOCKET;
typedef int HANDLE;
#define SOCKET_ERROR (-1)   
#endif   

#include <string>
#include <string.h>  
#include <vector>
#include <stdint.h>  // uint32_t
#include <time.h>	 // time
#include <stdarg.h>  // va_list
#include <stdio.h>   // printf
#include <stdlib.h>  // atoi
//#include "tstream.h"

//#pragma comment(lib,"Ws2_32.lib")

#define SOFT_NAME "mixClient"
#define SOFT_VER "v1.3"
#define SOFT_LOGO "===============================================================================\n|                        Wellcome to " SOFT_NAME " " SOFT_VER "                           |\n===============================================================================\n\n"

#define CDB_X86 "cdb_x86.exe"
#define CDB_X64 "cdb_x64.exe"
#define GFLAGS_X86 "tools\\gflags_x86.exe"
#define GFLAGS_X64 "tools\\gflags_x64.exe"

using namespace std;
//using namespace gcommon;

class TempGLogger
{
public:
	// 输出错误信息
	void error(const string format, ...)
	{
		va_list ap;
		va_start(ap, format);
		string newformat = " x [xx] " + format + "\n";
		vprintf(newformat.c_str(), ap);
		va_end(ap);
	}

	// 输出警告信息
	void warning(const string format, ...)
	{
		va_list ap;
		va_start(ap, format);
		string newformat = " ! [xx] " + format + "\n";
		vprintf(newformat.c_str(), ap);
		va_end(ap);
	}

	// 输出普通信息
	void info(const string format, ...)
	{
		va_list ap;
		va_start(ap, format);
		string newformat = "   [xx] " + format + "\n";
		vprintf(newformat.c_str(), ap);
		va_end(ap);
	}

	// 只输出调试等级1的信息
	void debug1(const string format, ...)
	{
		va_list ap;
		va_start(ap, format);
		string newformat = "+1 [xx] " + format + "\n";
		vprintf(newformat.c_str(), ap);
		va_end(ap);
	}

	// 输出调试等级1/2的信息
	void debug2(const string format, ...)
	{
		va_list ap;
		va_start(ap, format);
		string newformat = "+2 [xx] " + format + "\n";
		vprintf(newformat.c_str(), ap);
		va_end(ap);
	}

	// 输出调试等级1/2/3的信息
	void debug3(const string format, ...)
	{
		va_list ap;
		va_start(ap, format);
		string newformat = "+3 [xx] " + format + "\n";
		vprintf(newformat.c_str(), ap);
		va_end(ap);
	}

	// 输出原始信息到屏幕（不添加任何前导字符）
	void screen(const string format, ...)
	{
		va_list ap;
		va_start(ap, format);
		vprintf(format.c_str(), ap);
		va_end(ap);
	}
};

TempGLogger glogger;

string GetCurrentDirPath();
string GetConfigPara(string strConfigFilePath, string key, string dft);

int GetDebugInfo(void* hPipe, char* buff, int size, int timeout = 2000);
string GetCrashPos(void* hinPipeW, void* houtPipeR);
bool CheckCCInt3(char* buff);
bool CheckC3Ret(char* buff);
vector<uint32_t> GetAllProcessId(const char* pszProcessName, vector<uint32_t> ids);
bool TerminateAllProcess(const char* pszProcessName);
uint32_t GetFilecountInDir(string dir, string fileext);
uint32_t GetHTMLFromServer(const string& serverip, uint16_t port, const string& name, char* buff);
uint32_t SendFile(string serverip, uint16_t port,
	time_t time, const string &crashpos, uint8_t type, char* data, int datalen);
uint32_t LogFile(const string &outpath, const string &crashpos,
	const string &endstr, char* data, int datalen, time_t ct);
bool IsWow64();

const static uint32_t MAX_SENDBUFF_SIZE = 1024 * 200;
const static uint32_t MAX_PATH_SIZE = 256;

#pragma pack(push,1)
typedef struct _file_pack
{
	uint32_t time;
	uint32_t dirLen;
	uint8_t type;
	char data[0];
}FILEPACK, *PFILEPACK;
#pragma pack(pop)

int main(int argc, char** argv)
{
	const uint32_t BUFF_SIZE = 1024 * 100;
	const uint32_t READ_DBGINFO_TIMEOUT = 1000;

	string configFile = ("config.ini");
	string symPath = ("srv*");
	string outPath = ("crash");
	string htmlPath;
	string prevHtmlPath;
	string logPath;
	string appPath = ("explorer Microsoft-Edge:");
	string parentProcName = ("MicrosoftEdge.exe");
	string webProcName = ("MicrosoftEdgeCP.exe");

	//PRINT_TARGET print_target = PRINT_TARGET::BOTH;
	int debug_level = 0;
	uint32_t deadTimeout = 5000; // 浏览器卡死超时
	uint32_t waitTime = 2000;    // 浏览器启动等待时间
	uint32_t minWaitTime = 1000;
	int serverPort = 12228; // http服务端口
	uint32_t maxPocCount = 10;   // 同一个目录中最大poc数量（以log文件计数）
	string log_file = ("mixfuzz.log");
	string mode = ("local");
	string serverIP = ("127.0.0.1");
	string fuzztarget = ("");
	int pageheap = 1;

	string cdb_exe = CDB_X86;
	string gflags_exe = GFLAGS_X86;

	// 初始化glogger	
	//glogger.setDebugLevel(debug_level);
	//glogger.setHeader(("main"));
	//glogger.enableColor();
	//glogger.setLogFile(log_file);
	//glogger.setTarget(print_target);

	// 初始化console显示
	string title = SOFT_NAME;
	title.append((" "));
	title.append(SOFT_VER);
	//SetConsoleTitle(title.c_str());
	glogger.screen(SOFT_LOGO);

	// 创建debug Pipe
	HANDLE inputPipeR = 0, inputPipeW = 0;
	HANDLE outputPipeR = 0, outputPipeW = 0;
#ifdef __WINDOWS__
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
	CreatePipe(&inputPipeR, &inputPipeW, &saAttr, 0);
	CreatePipe(&outputPipeR, &outputPipeW, &saAttr, 0);
#endif

#ifdef __LINUX__
	HANDLE inputFD[2] = { 0 }, outputFD[2] = { 0 };
	pipe(inputFD);
	pipe(outputFD);
	inputPipeR = inputFD[0];
	inputPipeW = inputFD[1];
	outputPipeR = outputFD[0];
	outputPipeW = outputFD[1];
#endif	

	if (inputPipeR == 0 || inputPipeW == 0 ||
		outputPipeR == 0 || outputPipeW == 0)
	{
		glogger.error(("failed to create pipe"));
		exit(fgetc(stdin));
	}

	exit(fgetc(stdin));
	
	// 获取当前文件夹路径		
	string currentDir = GetCurrentDirPath();
	if (currentDir.empty())
	{
		glogger.warning(("can not get current dir, use default dir"));
		currentDir = (".\\");
	}
	//SetCurrentDirectory(currentDir.c_str());

	// 读取config文件	
	webProcName = GetConfigPara(currentDir + configFile, ("WEBCONTENT_EXE"), webProcName);
	parentProcName = GetConfigPara(currentDir + configFile, ("PARENT_EXE"), webProcName);
	pageheap = atoi(GetConfigPara(currentDir + configFile, ("PAGE_HEAP"), ("1")).c_str());
	debug_level = atoi(GetConfigPara(currentDir + configFile, ("DEBUG_LEVEL"), ("0")).c_str());
	deadTimeout = atoi(GetConfigPara(currentDir + configFile, ("DEAD_TIMEOUT"), ("5000")).c_str());
	waitTime = minWaitTime = atoi(GetConfigPara(currentDir + configFile, ("WAIT_TIME"), ("1000")).c_str());
	serverPort = atoi(GetConfigPara(currentDir + configFile, ("WEB_SERVER_PORT"), ("12228")).c_str());
	maxPocCount = atoi(GetConfigPara(currentDir + configFile, ("MAX_POC_COUNT"), ("10")).c_str());
	fuzztarget = GetConfigPara(currentDir + configFile, ("FUZZ_APP"), parentProcName.substr(0, parentProcName.size() - 4));
	appPath = GetConfigPara(currentDir + configFile, ("APP_PATH"), appPath);
	symPath = GetConfigPara(currentDir + configFile, ("SYMBOL_PATH"), symPath);
	outPath = GetConfigPara(currentDir + configFile, ("OUT_PATH"), outPath);
	mode = GetConfigPara(currentDir + configFile, ("MODE"), mode);
	serverIP = GetConfigPara(currentDir + configFile, ("WEB_SERVER_IP"), serverIP);
	//glogger.setDebugLevel(debug_level);
	glogger.info(("symbol path: ") + symPath);
	glogger.info((" ouput path: ") + outPath);
	if (outPath.back() != '\\')
		outPath.append(("\\"));

	// 创建crash目录
	// CreateDirectory(outPath.c_str(), NULL);

	// semaphore
	//void* semaphorep = CreateSemaphore(NULL, 1, 1, ("mixfuzzer_sem_htmlbuff_p"));
	//void* semaphorec = CreateSemaphore(NULL, 0, 1, ("mixfuzzer_sem_htmlbuff_c"));

	// client模式
	if (mode != ("client"))
	{
		// 读取模板文件
	}

	// 打开page heap, 关闭内存保护, ...
	string sCommandLine;
	if (pageheap)
	{
		sCommandLine = gflags_exe + (" /p /enable ") + webProcName + (" /full >nul");
		//_tsystem(sCommandLine.c_str());
	}
	else
	{
		sCommandLine = gflags_exe + (" /p /disable ") + webProcName + (" /full >nul");
		//_tsystem(sCommandLine.c_str());
	}


	if (fuzztarget == ("edge"))
	{
		webProcName = ("MicrosoftEdgeCP.exe");
		appPath = ("explorer Microsoft-Edge:");
	}
	else
	{
		string startop;
		if (appPath.rfind((".exe ")) != string::npos)
		{
			startop = appPath.substr(appPath.rfind((".exe ")) + 5);
			appPath = appPath.substr(0, appPath.rfind((".exe ")) + 4);
			appPath = ("\"") + appPath + ("\" ") + startop + (" ");
		}
		else
			appPath = ("\"") + appPath + ("\" ");
	}

	// fuzz循环
	uint32_t nwrite, nread;
	uint32_t buffsize = 1024;
	char* rbuff = new char[buffsize + 1];
	char* pbuff = new char[2 * buffsize + 1];
	char* pocbuff = new char[MAX_SENDBUFF_SIZE + 1];
	char* prevpocbuff = new char[MAX_SENDBUFF_SIZE + 1];
	char* logbuff = new char[MAX_SENDBUFF_SIZE + 1];
	while (true)
	{
		glogger.screen(("\n\n"));
		//glogger.insertCurrentTime();
		glogger.info(("Start Fuzzing ..."));

		nread = nwrite = 0;

		// kill 所有相关线程
		glogger.info(("Kill all %s-related processes"), fuzztarget.c_str());
		glogger.debug1(("kill WerFault.exe ..."));
		if (!TerminateAllProcess(("WerFault.exe")))
		{
			glogger.error(("Cannot kill WerFault.exe, restart fuzz."));
			continue;
		}
		glogger.debug1(("kill %s ..."), cdb_exe.c_str());
		if (!TerminateAllProcess(cdb_exe.c_str()))
		{
			glogger.error(("Cannot kill cdb, restart fuzz."));
			continue;
		}
		glogger.debug1(("kill explorer.exe ..."));
		if (!TerminateAllProcess(("explorer.exe")))
		{
			//glogger.warning(("Cannot kill explorer, restart fuzz."));
			//continue;
		}
		glogger.debug1(("kill %s ..."), webProcName.c_str());
		if (!TerminateAllProcess(webProcName.c_str()))
		{
			glogger.debug1(("kill %s ..."), parentProcName.c_str());
			if (!TerminateAllProcess(parentProcName.c_str()))
			{
				glogger.error(("Cannot kill %s, restart fuzz."), fuzztarget.c_str());
				continue;
			}
		}
		glogger.debug1(("kill %s ..."), parentProcName.c_str());
		if (!TerminateAllProcess(parentProcName.c_str()))
		{
			glogger.error(("Cannot kill %s, restart fuzz."), fuzztarget.c_str());
			continue;
		}

		// 启动浏览器
		glogger.info(("Start ") + fuzztarget);
		//STARTUPINFO si_edge = { sizeof(STARTUPINFO) };
		//PROCESS_INFORMATION pi_edge;
		//si_edge.dwFlags = STARTF_USESHOWWINDOW;
		//si_edge.wShowWindow = TRUE; //TRUE表示显示创建的进程的窗口
		char cmdline[1024];
		sprintf(cmdline, ("%shttp://%s:%d"), appPath.c_str(), serverIP.c_str(), serverPort);
		glogger.debug1(("CreateProcess: %s"), cmdline);
		//bool bRet = CreateProcess(NULL, cmdline,
		//	NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si_edge, &pi_edge);
		//if (pi_edge.hProcess)
		//	Closevoid*(pi_edge.hProcess);
		//if (pi_edge.hThread)
		//	Closevoid*(pi_edge.hThread);
		//if (!bRet)
		if(false)
		{
			glogger.error(("Cannot start ") + fuzztarget);
			glogger.error(("path=") + appPath);
			//exit(_getch());
		}
		//Sleep(waitTime); // 尽量等待一段时间
		if (waitTime > minWaitTime)
			waitTime -= 100;

		// 获取PID
		vector<uint32_t> procIDs = GetAllProcessId(webProcName.c_str(), vector<uint32_t>());
		vector<uint32_t> procIDs_new;
		if (procIDs.empty())
		{
			glogger.error(("Cannot start the browser, restart fuzz."));
			if (waitTime < 2 * minWaitTime)
				waitTime += 100;
			continue;
		}

		// attach调试器	
		sCommandLine = ("tools\\") + cdb_exe + (" -o -p ") + to_string(procIDs[0]);
		glogger.info(("Attach ") + cdb_exe);
		glogger.info(("  -pid:") + to_string(procIDs[0]));
		//STARTUPINFO si_cdb = { sizeof(STARTUPINFO) };
		//si_cdb.dwFlags |= STARTF_USESTDvoid*S;
		//si_cdb.hStdInput = inputPipeR;
		//si_cdb.hStdOutput = outputPipeW;
		//si_cdb.hStdError = outputPipeW;
		//PROCESS_INFORMATION pi_cdb = {};
		//if (!CreateProcess(NULL, (LPTSTR)sCommandLine.c_str(),
		//	NULL, NULL, TRUE, 0, NULL, NULL, &si_cdb, &pi_cdb))
		//{
		//	glogger.error(("Cannot attach debugger, restart fuzz."));
		//	exit(_getch());
		//}
		//if (pi_cdb.hProcess)
		//	Closevoid*(pi_cdb.hProcess);
		//if (pi_cdb.hThread)
		//	Closevoid*(pi_cdb.hThread);

		// attach剩余的pid:  .attach 0nxxx;g;|1s; ~*m; .childdbg 1;
		for (size_t i = 1; i < procIDs.size(); i++)
		{
			glogger.info(("  -pid:") + to_string(procIDs[i]));

			sCommandLine = (".attach 0n") + to_string(procIDs[i]) + ("\n");
			glogger.debug1(("windbg command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
			//WriteFile(inputPipeW, stringToString(sCommandLine).c_str(), (uint32_t)sCommandLine.size(), &nwrite, NULL);

			glogger.debug1(("windbg command: g"));
			//WriteFile(inputPipeW, "g\n", 2, &nwrite, NULL);

			sCommandLine = ("|") + to_string(i) + ("s\n");
			glogger.debug1(("windbg command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
			//WriteFile(inputPipeW, stringToString(sCommandLine).c_str(), (uint32_t)sCommandLine.size(), &nwrite, NULL);

			glogger.debug1(("windbg command: ~*m"));
			//WriteFile(inputPipeW, "~*m\n", 4, &nwrite, NULL);

			sCommandLine = (".childdbg1\n");
			glogger.debug1(("windbg command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
			//WriteFile(inputPipeW, stringToString(sCommandLine).c_str(), (uint32_t)sCommandLine.size(), &nwrite, NULL);
		}

		// debug信息：|*\n
		if (debug_level > 0)
		{
			while (GetDebugInfo(outputPipeR, rbuff, buffsize, 100));
			glogger.debug1(("windbg command: |*"));
			//WriteFile(inputPipeW, "|*\n", 3, &nwrite, NULL);
			if (GetDebugInfo(outputPipeR, rbuff, buffsize) > 0)
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
		sCommandLine = (".sympath \"") + symPath + ("\";g;\n"); // 同时加入g; 防止后面出现异常
		glogger.debug1(("windbg command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
		//WriteFile(inputPipeW, stringToString(sCommandLine).c_str(), (uint32_t)sCommandLine.size(), &nwrite, NULL);
		//Sleep(100);

		// 监听cdg循环
		glogger.info(("Fuzzing ..."));
		pbuff[0] = 0;
		uint32_t idletime = 0;
		while (true)
		{
			// 查看是否存在新的进程
			procIDs_new = GetAllProcessId(webProcName.c_str(), procIDs);
			if (!procIDs_new.empty())
			{
				// 暂停调试器
				//SendMessage(,);

				// attach剩余的pid:  .attach 0nxxx;g;|1s; ~*m; .childdbg 1;
				for (size_t i = 0; i < procIDs_new.size(); i++)
				{
					glogger.warning(("find new pid:") + to_string(procIDs_new[i]));
					procIDs.push_back(procIDs_new[i]);
				}
				procIDs_new.clear();
				glogger.info(("restart fuzz ..."));
				if (waitTime < 3 * minWaitTime)
					waitTime += 500;
				break;
			}

			// 获取调试器输出
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
				memcpy(pbuff + strlen(pbuff), rbuff, nread + 1);
			}

			size_t pbufflen = strlen(pbuff);
			if (pbufflen < 2)
			{
				pbuff[0] = 0;
				idletime += READ_DBGINFO_TIMEOUT;
				if (idletime >= deadTimeout)
				{
					glogger.warning(("browser seems dead, restart fuzz ..."));
					break;
				}
				continue;
			}

			if (pbuff[pbufflen - 2] == '>' && pbuff[pbufflen - 1] == ' ')
			{
				// 进程异常
				if (CheckC3Ret(pbuff))
				{
					glogger.warning(("break @ \"ret\", continue"));
					glogger.debug1(("windbg command: g"));
					//WriteFile(inputPipeW, "g\n", 2, &nwrite, NULL);
					pbuff[0] = 0;
					continue;
				}

				// 软件中断，g
				if (CheckCCInt3(pbuff))
				{
					glogger.warning(("break @ \"int 3\", continue"));
					glogger.debug1(("windbg command: g"));
					//WriteFile(inputPipeW, "g\n", 2, &nwrite, NULL);
					pbuff[0] = 0;
					continue;
				}

				// No runnable debuggees
				if (strstr(pbuff, "No runnable debuggees") != NULL)
				{
					glogger.warning(("No runnable debuggees"));
					break;
				}

				// 判定为crash 
				glogger.error(("!! find crash !!"));
				if (debug_level > 0)
				{
					printf("+1 [main] %s\n", pbuff);
				}

				// 获取崩溃位置作为目录名
				string crashpos = GetCrashPos(inputPipeW, outputPipeR);

				htmlPath = outPath + crashpos + ("\\");
				//CreateDirectory(htmlPath.c_str(), NULL);

				glogger.info(("crash = ") + crashpos);
				if (crashpos != ("unknown") &&
					GetFilecountInDir(htmlPath, ("log")) >= maxPocCount)
				{
					glogger.warning(("this crash already logged, restart fuzz ..."));
					break;
				}
				glogger.info(("create html and log ..."));
				pocbuff[0] = 0;
				GetHTMLFromServer(serverIP, serverPort, ("prev.html"), prevpocbuff);
				GetHTMLFromServer(serverIP, serverPort, ("current.html"), pocbuff);
				if (pocbuff == NULL || strlen(pocbuff) == 0 ||
					prevpocbuff == NULL || strlen(prevpocbuff) == 0)
				{
					glogger.warning(("can not get POC"));
				}

				// log文件                
				logbuff[0] = 0;
				strcat(logbuff, "*** mixFuzzer ***\n");
				strcat(logbuff, pbuff);

				strcat(logbuff, "\n\n*** crash info ***\n");
				glogger.debug1(("windbg command: r"));
				//WriteFile(inputPipeW, "r\n", 2, &nwrite, NULL);
				if (GetDebugInfo(outputPipeR, pbuff, 2 * buffsize) > 0)
				{
					strcat(logbuff, pbuff);
				}

				strcat(logbuff, "\n\n*** stack tracing ***\n");
				glogger.debug1(("windbg command: kb"));
				//WriteFile(inputPipeW, "kb\n", 3, &nwrite, NULL);
				while (GetDebugInfo(outputPipeR, pbuff, buffsize) > 0)
				{
					strcat(logbuff, pbuff);
				}

				strcat(logbuff, "\n\n*** module info ***\n");
				sCommandLine = ("lmDvm ");
				sCommandLine.append(crashpos.substr(0, crashpos.find_first_of('!'))); // mshtml!xxx__xxx+0x1234
				glogger.debug1(("windbg command: ") + sCommandLine);
				sCommandLine.append(("\n"));
				//WriteFile(inputPipeW, stringToString(sCommandLine).c_str(),
				//	(uint32_t)sCommandLine.size(), &nwrite, NULL);
				if (GetDebugInfo(outputPipeR, pbuff, 2 * buffsize) > 0)
				{
					strcat(logbuff, pbuff);
				}

				// 生成时间戳
				time_t ct = time(NULL);

				// 写入文件
				if (pocbuff) LogFile(outPath, crashpos, (".html"), pocbuff, strlen(pocbuff), ct);
				if (logbuff) LogFile(outPath, crashpos, (".log"), logbuff, strlen(logbuff), ct);
				if (prevpocbuff) LogFile(outPath, crashpos, ("_prev.html"), prevpocbuff, strlen(prevpocbuff), ct);

				// 发送至服务端
				if (mode == ("client"))
				{
					if (pocbuff) SendFile(serverIP, 12220, ct, crashpos, 'H', pocbuff, (int)strlen(pocbuff));
					if (logbuff) SendFile(serverIP, 12220, ct, crashpos, 'L', logbuff, (int)strlen(logbuff));
					if (prevpocbuff) SendFile(serverIP, 12220, ct, crashpos, 'P', pocbuff, (int)strlen(prevpocbuff));
				}

				break;
			}

			pbuff[0] = 0;
		}
	}

	delete[] rbuff;
	delete[] pbuff;
	//exit(_getch());
}

string GetCrashPos(void* hinPipeW, void* houtPipeR)
{
	uint32_t nwrite, nread;
	char rbuff[1024 + 1];
	GetDebugInfo(houtPipeR, rbuff, 1024, 500);
	glogger.debug1(("windbg command: u eip L1"));
	//WriteFile(hinPipeW, "u eip L1\n", 9, &nwrite, NULL);
	nread = GetDebugInfo(houtPipeR, rbuff, 1024);
	if (nread == 0)
		return string(("unknown"));

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

	if (i != start)
	{
		return string(("unknown"));
	}

	for (i = start; i < strlen(rbuff); i++)
	{
		if (rbuff[i] == '\n' && i > 0)
		{
			rbuff[i - 1] = 0;
			break;
		}

		// 非法字符过滤
		if (rbuff[i] == ':')
			rbuff[i] = '_';
		else if (rbuff[i] == '*')
			rbuff[i] = '.';
		else if (rbuff[i] == '/')
			rbuff[i] = '-';
		else if (rbuff[i] == '\\')
			rbuff[i] = '-';
		else if (rbuff[i] == '?')
			rbuff[i] = '.';
		else if (rbuff[i] == '"')
			rbuff[i] = '\'';
		else if (rbuff[i] == '<')
			rbuff[i] = '[';
		else if (rbuff[i] == '>')
			rbuff[i] = ']';
		else if (rbuff[i] == '|')
			rbuff[i] = '-';
	}

	return string(rbuff + start);
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
	for (int i = 0; i < pint - pcc - 4; i++)
	{
		if (pcc[i + 4] != ' ')
			return false;
	}

	char* p3 = strstr(pint, " 3\n");
	if (p3 == NULL)
		return false;
	for (int i = 0; i < p3 - pint - 5; i++)
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
	for (int i = 0; i < pret - pc3 - 4; i++)
	{
		if (pc3[i + 4] != ' ')
			return false;
	}

	return true;
}

int GetDebugInfo(void* hPipe, char* buff, int size, int timeout)
{
	int count = timeout / 100;
	uint32_t nread = 0;
	while (count--)
	{
		//Sleep(100);
		//if (!PeekNamedPipe(hPipe, buff, size, &nread, 0, 0))
		//	continue;

		if (nread == size)
			break;
	}

	if (nread == 0)
		return 0;

	nread = 0;
	//ReadFile(hPipe, buff, size, &nread, NULL);
	if (nread>0)
		buff[nread] = 0;

	return nread;
}

string GetCurrentDirPath()
{
	string strCurrentDir;
	char* pCurrentDir = new char[MAX_PATH_SIZE + 1];
	memset(pCurrentDir, 0, MAX_PATH_SIZE + 1);
	//uint32_t nRet = GetModuleFileName(NULL, pCurrentDir, MAX_PATH);
	//if (nRet == 0)
	if(false)
	{
		delete[] pCurrentDir;
		return (".\\");
	}

	(strrchr(pCurrentDir, '\\'))[1] = 0;
	strCurrentDir = pCurrentDir;
	delete[] pCurrentDir;

	return strCurrentDir;
}

vector<uint32_t> GetAllProcessId(const char* pszProcessName, vector<uint32_t> ids)
{
	uint32_t aProcesses[1024], cbNeeded, cProcesses;
	uint32_t i;
	vector<uint32_t> pids;

	// Enumerate all processes
	//if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	//	return vector<uint32_t>();

	cProcesses = cbNeeded / sizeof(uint32_t);
	char szEXEName[MAX_PATH_SIZE] = { 0 };
	for (i = 0; i < cProcesses; i++)
	{
		// Get a void* to the process
		void* hProcess;
		//void* hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		//	PROCESS_VM_READ, FALSE, aProcesses[i]);

		// Get the process name
		if (NULL != hProcess)
		{
			void* hMod;
			uint32_t cbNeeded;

			//if (EnumProcessModules(hProcess, &hMod,
			//	sizeof(hMod), &cbNeeded))
			if(false)
			{
				//Get the name of the exe file
				//GetModuleBaseName(hProcess, hMod, szEXEName,
				//	sizeof(szEXEName) / sizeof(char));

				if (strcmp(szEXEName, pszProcessName) == 0)
				{
					bool find = false;
					for (uint32_t id : ids)
					{
						if (id == aProcesses[i])
						{
							find = true;
							break;
						}
					}
					if (!find)
						pids.push_back(aProcesses[i]);
				}
			}
			//Closevoid*(hProcess);
		}
	}
	return pids;
}

bool TerminateAllProcess(const char* pszProcessName)
{
	bool ret = false;
	vector<uint32_t> pids = GetAllProcessId(pszProcessName, vector<uint32_t>());
	for (uint32_t pid : pids)
	{
		ret = false;
		if (pid != 0)
		{
			//void* hProcess = OpenProcess(
			//	PROCESS_TERMINATE |
			//	PROCESS_QUERY_LIMITED_INFORMATION |
			//	SYNCHRONIZE, FALSE, pid);
			//if (hProcess != NULL)
			//{
			//	TerminateProcess(hProcess, 0);
			//	ret = true;
			//}
		}
	}

	int count = 0;
	do
	{
		if (count >= 10)
			return false;
		//Sleep(100);
		pids = GetAllProcessId(pszProcessName, vector<uint32_t>());
		count++;
	} while (!pids.empty());
	return true;
}

uint32_t GetFilecountInDir(string dir, string fileext)
{
	//_tfinddata_t FileInfo;
	//string strfind = dir + ("\\*.") + fileext;
	//intptr_t hh = _tfindfirst(strfind.c_str(), &FileInfo);
	//int count = 0;
	//
	//if (hh == -1L)
	//{
	//	return count;
	//}
	//
	//do {
	//	//判断是否有子目录
	//	if (FileInfo.attrib & _A_SUBDIR)
	//	{
	//		continue;
	//	}
	//	else
	//	{
	//		count++;
	//	}
	//} while (_tfindnext(hh, &FileInfo) == 0);
	//
	//_findclose(hh);
	//return count;
}

uint32_t GetHTMLFromServer(const string& serverip, uint16_t port, const string& name, char* buff)
{
	//// Initialize Winsock
	//WSADATA wsaData;
	//int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	//if (iResult != NO_ERROR)
	//{
	//	glogger.error(("WSAStartup failed with error: %d"), WSAGetLastError());
	//	return 0;
	//}
	//
	//// socket
	//SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	//if (sock == INVALID_SOCKET)
	//{
	//	glogger.error(("socket failed with error: %d"), WSAGetLastError());
	//	WSACleanup();
	//	return 0;
	//}
	//
	////构建本地地址信息  
	//struct sockaddr_in saServer;
	//saServer.sin_family = AF_INET;
	//saServer.sin_port = htons(port);
	//saServer.sin_addr.S_un.S_addr = inet_addr(serverip.c_str());
	//
	//// 连接服务器
	//int ret = connect(sock, (sockaddr *)&saServer, sizeof(saServer));
	//if (ret == SOCKET_ERROR)
	//{
	//	closesocket(sock);
	//	WSACleanup();
	//	return 0;
	//}
	//
	//// 发送请求
	//string sendbuff = "GET /" + name +
	//	" HTTP/1.1\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: Mozilla/5.0\r\nConnection: Keep-Alive\r\n\r\n";
	//ret = send(sock, sendbuff.c_str(), sendbuff.size(), 0);
	//if (ret != sendbuff.size())
	//{
	//	glogger.error(("send failed with error: %d"), WSAGetLastError());
	//	closesocket(sock);
	//	WSACleanup();
	//	return 0;
	//}
	//
	//// 接收数据
	//ret = recv(sock, buff, MAX_SENDBUFF_SIZE, 0);
	//if (ret > 0)
	//{
	//	buff[ret] = 0;
	//	closesocket(sock);
	//	WSACleanup();
	//	return ret;
	//}
	//
	//closesocket(sock);
	//WSACleanup();
	//return 0;
}

uint32_t SendFile(string serverip, uint16_t port,
	time_t time, const string & crashpos, uint8_t type, char * data, int datalen)
{
	//if (data == NULL || datalen == 0)
	//	return 0;
	//
	//// Initialize Winsock
	//WSADATA wsaData;
	//int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	//if (iResult != NO_ERROR)
	//{
	//	glogger.error(("WSAStartup failed with error: %d"), WSAGetLastError());
	//	return 0;
	//}
	//
	//// socket
	//SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	//if (sock == INVALID_SOCKET)
	//{
	//	glogger.error(("socket failed with error: %d"), WSAGetLastError());
	//	WSACleanup();
	//	return 0;
	//}
	//
	////构建本地地址信息  
	//struct sockaddr_in saServer;
	//saServer.sin_family = AF_INET;
	//saServer.sin_port = htons(port);
	//saServer.sin_addr.S_un.S_addr = inet_addr(serverip.c_str());
	//
	//// 连接服务器
	//int ret = connect(sock, (sockaddr *)&saServer, sizeof(saServer));
	//if (ret == SOCKET_ERROR)
	//{
	//	closesocket(sock);
	//	WSACleanup();
	//	return 0;
	//}
	//
	//// 发送请求
	//char* sendBuff = new char[sizeof(FILEPACK) + crashpos.size() + datalen];
	//PFILEPACK filepacket = (PFILEPACK)sendBuff;
	//filepacket->type = type;
	//filepacket->time = (uint32_t)time;
	//filepacket->dirLen = (uint32_t)crashpos.size();
	//memcpy(filepacket->data, crashpos.c_str(), crashpos.size());
	//memcpy(filepacket->data + crashpos.size(), data, datalen);
	//
	//ret = send(sock, sendBuff, (int)(sizeof(FILEPACK) + crashpos.size() + datalen), 0);
	//delete[] sendBuff;
	//closesocket(sock);
	//WSACleanup();
	//
	//if (ret != sizeof(FILEPACK) + crashpos.size() + datalen)
	//{
	//	glogger.error(("send file error: %s"), crashpos.c_str());
	//	return 0;
	//}
	//return ret;
}

uint32_t LogFile(const string &outpath, const string &crashpos,
	const string &endstr, char* data, int datalen, time_t ct)
{
	if (data == NULL || datalen == 0)
		return 0;

	string filepath = outpath + crashpos + ("\\") + to_string(ct) + endstr;
	FILE* htmlFile = fopen(filepath.c_str(), "w");
	if (htmlFile == NULL)
	{
		glogger.warning(("can not create html file: ") + crashpos + ("\\") + to_string(ct) + endstr);
		filepath = outpath + ("unknown\\") + to_string(ct) + endstr;
		htmlFile = fopen(filepath.c_str(), "w");
		if (htmlFile == NULL)
		{
			glogger.error(("can not create html file: unknown\\") + to_string(ct) + endstr);
			return 0;
		}
	}
	if (htmlFile)
	{
		fwrite(data, 1, datalen, htmlFile);
		fclose(htmlFile);
	}
	return 0;
}

bool IsWow64()
{
#ifdef _X64
	return true;
#else
	return false;
#endif
}

string GetConfigPara(string strConfigFilePath, string key, string dft)
{
	return string();
}