#ifdef __LINUX__   
#include <sys/types.h>  
#include <sys/socket.h>
#include <sys/stat.h> 
#include <arpa/inet.h> 
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>  
#include <sys/wait.h>
typedef int SOCKET;
typedef int HANDLE;
#define SOCKET_ERROR (-1)   
#define INVALID_SOCKET (-1)
#define SOCKET_ERRNO errno
#else
#include <WinSock2.h>
#include <io.h>
#include <tchar.h>
#include <Psapi.h>
#pragma comment(lib,"Ws2_32.lib")
#define SOCKET_ERRNO WSAGetLastError()
#endif   

#include <string>
#include <string.h>  
#include <vector>
#include <stdint.h>  // uint32_t
#include <time.h>	 // time
#include <stdarg.h>  // va_list
#include <stdio.h>   // printf
#include <stdlib.h>  // atoi
#include "common.h"
#include "glogger.h"


#define SOFT_NAME TEXT("mixClient")
#define SOFT_VER TEXT("v1.3")
#define SOFT_LOGO TEXT("===============================================================================\n|                        Wellcome to " SOFT_NAME " " SOFT_VER "                           |\n===============================================================================\n\n")

#define CDB_X86 TEXT("cdb_x86.exe")
#define CDB_X64 TEXT("cdb_x64.exe")
#define GFLAGS_X86 TEXT("tools\\gflags_x86.exe")
#define GFLAGS_X64 TEXT("tools\\gflags_x64.exe")

using namespace std;
using namespace gcommon;

GLogger glogger;

void CreateDir(const tstring& path);

int GetDebugInfo(HANDLE hPipe, char* buff, int size, int timeout = 2000);
void DebugCommand(HANDLE hPipe, const char* cmd);
tstring GetCrashPos(HANDLE hinPipeW, HANDLE houtPipeR);
bool CheckCCInt3(char* buff);
bool CheckC3Ret(char* buff);
bool CheckEnds(const char* buff, const char* ends);
vector<uint32_t> GetAllProcessId(const tchar* pszProcessName, vector<uint32_t> ids);
bool TerminateAllProcess(const tchar* pszProcessName);
bool StartProcess(const tstring& path, const tstring& arg);
uint32_t GetFilecountInDir(tstring dir, tstring fileext);
uint32_t GetHTMLFromServer(const tstring& serverip, uint16_t port, const tstring& name, char* buff);
uint32_t SendFile(tstring serverip, uint16_t port,
	time_t time, const tstring &crashpos, uint8_t type, char* data, int datalen);
uint32_t LogFile(const tstring &outpath, const tstring &crashpos,
	const tstring &endstr, char* data, int datalen, time_t ct);

bool IsWow64();
void GSleep(uint32_t ms);

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

	tstring configFile = TEXT("client.ini");
	tstring symPath = TEXT("srv*");
	tstring outPath = TEXT("crash");
	tstring htmlPath;
	tstring prevHtmlPath;
	tstring logPath;
	tstring appPath = TEXT("explorer Microsoft-Edge:");
	tstring parentProcName = TEXT("MicrosoftEdge.exe");
	tstring webProcName = TEXT("MicrosoftEdgeCP.exe");
	tstring killProc = TEXT("");

	PRINT_TARGET print_target = PRINT_TARGET::BOTH;
	int debug_level = 0;
	uint32_t deadTimeout = 5000; // 浏览器卡死超时
	uint32_t waitTime = 2000;    // 浏览器启动等待时间
	uint32_t minWaitTime = 1000;
	int serverPort = 12228; // http服务端口
	uint32_t maxPocCount = 10;   // 同一个目录中最大poc数量（以log文件计数）
	tstring log_file = TEXT("mixclient.log");
	tstring serverIP = TEXT("127.0.0.1");
	tstring fuzztarget = TEXT("");
	int pageheap = 1;

#ifdef __LINUX__
	tstring debugger = TEXT("gdb");
	string cmd_continue = "c\n";
#else
	tstring debugger = IsWow64() ? CDB_X64 : CDB_X86;
	tstring gflags_exe = IsWow64() ? GFLAGS_X64 : GFLAGS_X86;
	string cmd_continue = "g\n";
#endif // 

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
	//SetConsoleTitle(title.c_str());
	glogger.screen(SOFT_LOGO);

	// 创建debug Pipe
	HANDLE inputPipeR = 0, inputPipeW = 0;
	HANDLE outputPipeR = 0, outputPipeW = 0;

#ifdef __LINUX__
	if(mkfifo("/tmp/mixfuzz_input", 0777) != 0 && errno != 17)
	{
		glogger.warning(TEXT("failed to create input pipe: %d"), errno);
		exit(fgetc(stdin));
	}
	if(mkfifo("/tmp/mixfuzz_output", 0777) != 0 && errno != 17)
	{
		glogger.error(TEXT("failed to create output pipe: %d"), errno);
		exit(fgetc(stdin));
	}
	inputPipeW = open("/tmp/mixfuzz_input", O_RDWR | O_NONBLOCK);
	outputPipeR = open("/tmp/mixfuzz_output", O_RDWR | O_NONBLOCK);
#else
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
	CreatePipe(&inputPipeR, &inputPipeW, &saAttr, 0);
	CreatePipe(&outputPipeR, &outputPipeW, &saAttr, 0);
	if (inputPipeR == 0 || inputPipeW == 0 ||
		outputPipeR == 0 || outputPipeW == 0)
	{
		glogger.error(TEXT("failed to create pipe"));
		exit(fgetc(stdin));
	}
#endif		
	
	// 获取当前文件夹路径		
	tstring currentDir = GetCurrentDirPath();
	if (currentDir.empty())
	{
		glogger.warning(TEXT("can not get current dir, use default dir"));
		currentDir = TEXT(".\\");
	}
	glogger.debug1(TEXT("current dir: ") + currentDir);
#ifndef __LINUX__
	SetCurrentDirectory(currentDir.c_str());
#endif

	// 读取config文件	
	if (taccess((currentDir + configFile).c_str(), 4) != 0)
		glogger.warning(TEXT("can not find config file: ") + configFile);
	webProcName = GetConfigString(currentDir + configFile, TEXT("WEBCONTENT_EXE"), webProcName);
	parentProcName = GetConfigString(currentDir + configFile, TEXT("PARENT_EXE"), webProcName);
	pageheap = GetConfigInt(currentDir + configFile, TEXT("PAGE_HEAP"), TEXT("1"));
	debug_level = GetConfigInt(currentDir + configFile, TEXT("DEBUG_LEVEL"), TEXT("0"));
	deadTimeout = GetConfigInt(currentDir + configFile, TEXT("DEAD_TIMEOUT"), TEXT("5000"));
	waitTime = minWaitTime = GetConfigInt(currentDir + configFile, TEXT("WAIT_TIME"), TEXT("1000"));
	serverPort = GetConfigInt(currentDir + configFile, TEXT("WEB_SERVER_PORT"), TEXT("12228"));
	maxPocCount = GetConfigInt(currentDir + configFile, TEXT("MAX_POC_COUNT"), TEXT("10"));
	fuzztarget = GetConfigString(currentDir + configFile, TEXT("FUZZ_APP"), parentProcName);
	appPath = GetConfigString(currentDir + configFile, TEXT("APP_PATH"), appPath);
	symPath = GetConfigString(currentDir + configFile, TEXT("SYMBOL_PATH"), symPath);
	outPath = GetConfigString(currentDir + configFile, TEXT("OUT_PATH"), outPath);
	serverIP = GetConfigString(currentDir + configFile, TEXT("WEB_SERVER_IP"), serverIP);
	killProc = GetConfigString(currentDir + configFile, TEXT("KILL_PROCESS"), killProc);
	debugger = GetConfigString(currentDir + configFile, TEXT("DEBUGGER"), debugger);
	glogger.setDebugLevel(debug_level);
	glogger.info(TEXT("symbol path: ") + symPath);
	glogger.info(TEXT(" ouput path: ") + outPath);
	glogger.info(TEXT(" fuzztarget: ") + fuzztarget);
	if (outPath.back() != '\\')
		outPath.append(TEXT("\\"));

	// 创建crash目录
	CreateDir(outPath);

	// 打开page heap, 关闭内存保护, ...
	tstring sCommandLine;
#ifndef __LINUX__
	if (pageheap)
	{
		sCommandLine = gflags_exe + TEXT(" /p /enable ") + webProcName + TEXT(" /full >nul");
		tsystem(sCommandLine.c_str());
	}
	else
	{
		sCommandLine = gflags_exe + TEXT(" /p /disable ") + webProcName + TEXT(" /full >nul");
		tsystem(sCommandLine.c_str());
	}

	if (fuzztarget == TEXT("edge"))
	{
		webProcName = TEXT("MicrosoftEdgeCP.exe");
		appPath = TEXT("explorer Microsoft-Edge:");
	}
	else
	{
		tstring startop;
		if (appPath.rfind(TEXT(".exe ")) != tstring::npos)
		{
			startop = appPath.substr(appPath.rfind(TEXT(".exe ")) + 5);
			appPath = appPath.substr(0, appPath.rfind(TEXT(".exe ")) + 4);
			appPath = TEXT("\"") + appPath + TEXT("\" ") + startop + TEXT(" ");
		}
		else
			appPath = TEXT("\"") + appPath + TEXT("\" ");
	}
#endif

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
		glogger.screen(TEXT("\n\n"));
		glogger.insertCurrentTime();
		glogger.info(TEXT("Start Fuzzing ..."));

		nread = nwrite = 0;

		// kill 所有相关线程
		glogger.info(TEXT("Kill all %s-related processes"), fuzztarget.c_str());
		vector<tstring> killProcesses = SplitString(killProc, ' ');
		killProcesses.push_back(debugger);
		killProcesses.push_back(webProcName);
		killProcesses.push_back(parentProcName);
		for (auto proc: killProcesses)
		{
			if (proc.empty())
				continue;

			glogger.debug1(TEXT("kill %s ..."), proc.c_str());
			if (!TerminateAllProcess(proc.c_str()))
			{
				glogger.warning(TEXT("Cannot kill %s"), proc.c_str());
				continue;
			}
		}

		// 启动浏览器
		glogger.info(TEXT("Start ") + fuzztarget);
		bool startSuccess = StartProcess(appPath, TEXT("http://") + serverIP + TEXT(":") + to_tstring(serverPort));
		if (!startSuccess)
		{
			glogger.error(TEXT("Cannot start ") + fuzztarget);
			glogger.error(TEXT("path=") + appPath);
			exit(fgetc(stdin));
		}
		GSleep(waitTime); // 尽量等待一段时间
		if (waitTime > minWaitTime)
			waitTime -= 100;

		// 获取PID
		vector<uint32_t> procIDs = GetAllProcessId(webProcName.c_str(), vector<uint32_t>());
		vector<uint32_t> procIDs_new;
		if (procIDs.empty())
		{
			glogger.error(TEXT("Cannot start the browser, restart fuzz."));
			if (waitTime < 2 * minWaitTime)
				waitTime += 100;
			continue;
		}

		// attach调试器	
		bool attachSuccess = false;
		glogger.info(TEXT("Attach ") + debugger);
		glogger.info(TEXT("  -pid:") + to_tstring(procIDs[0]));
#ifdef __LINUX__
		if (fork() == 0)
		{
			int fd_input = open("/tmp/mixfuzz_input", O_RDWR);
			int fd_output = open("/tmp/mixfuzz_output", O_RDWR);
			dup2(fd_input, 0);
			dup2(fd_output, 1);
			dup2(fd_output, 2);
			execlp(debugger.c_str(), debugger.c_str(), (char*)0);
			glogger.warning(TEXT("debugger quit: %d"), errno);
			exit(0);
		}

		sCommandLine = "attach " + to_string(procIDs[0]) + "\n";
		glogger.debug1(TEXT("debugger command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
		DebugCommand(inputPipeW, sCommandLine.c_str());
		do {
			nread = GetDebugInfo(outputPipeR, rbuff, buffsize, 100);
			if (nread == 0)
				break;
			
			glogger.debug3(rbuff);
			if (CheckEnds(rbuff, "(gdb) "))
			{
				attachSuccess = true;
				break;
			}
		} while (true);
		
		if (!attachSuccess)
		{
			glogger.error(TEXT("Cannot attach debugger, restart fuzz."));
			continue;
		}

		// 设置symbol path	
		sCommandLine = TEXT("set solib-search-path ") + symPath + TEXT("\n"); // 同时加入g; 防止后面出现异常
		glogger.debug1(TEXT("debugger command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
		DebugCommand(inputPipeW, TStringToString(sCommandLine).c_str());
		GSleep(1000);
#else
		sCommandLine = TEXT("tools\\") + debugger + TEXT(" -o -p ") + to_tstring(procIDs[0]);
		STARTUPINFO si_cdb = { sizeof(STARTUPINFO) };
		si_cdb.dwFlags |= STARTF_USESTDHANDLES;
		si_cdb.hStdInput = inputPipeR;
		si_cdb.hStdOutput = outputPipeW;
		si_cdb.hStdError = outputPipeW;
		PROCESS_INFORMATION pi_cdb = {};
		if (!CreateProcess(NULL, (LPTSTR)sCommandLine.c_str(),
			NULL, NULL, TRUE, 0, NULL, NULL, &si_cdb, &pi_cdb))
		{
			glogger.error(TEXT("Cannot attach debugger, restart fuzz."));
			continue;
		}
		if (pi_cdb.hProcess)
			CloseHandle(pi_cdb.hProcess);
		if (pi_cdb.hThread)
			CloseHandle(pi_cdb.hThread);	

		// windbg attach剩余的pid:  .attach 0nxxx;g;|1s; ~*m; .childdbg 1;
		for (size_t i = 1; i < procIDs.size(); i++)
		{
			glogger.info(TEXT("  -pid:") + to_tstring(procIDs[i]));

			sCommandLine = TEXT(".attach 0n") + to_tstring(procIDs[i]) + TEXT("\n");
			glogger.debug1(TEXT("debugger command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
			DebugCommand(inputPipeW, TStringToString(sCommandLine).c_str());

			glogger.debug1(TEXT("debugger command: g"));
			DebugCommand(inputPipeW, "g\n");

			sCommandLine = TEXT("|") + to_tstring(i) + TEXT("s\n");
			glogger.debug1(TEXT("debugger command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
			DebugCommand(inputPipeW, TStringToString(sCommandLine).c_str());

			glogger.debug1(TEXT("debugger command: ~*m"));
			DebugCommand(inputPipeW, "~*m\n");

			glogger.debug1(TEXT("debugger command: .childdbg1"));
			DebugCommand(inputPipeW, ".childdbg1\n");
		}

		// debug信息：|*\n
		if (debug_level > 0)
		{
			while (GetDebugInfo(outputPipeR, rbuff, buffsize, 100));
			glogger.debug1(TEXT("debugger command: |*"));
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
		sCommandLine = TEXT(".sympath \"") + symPath + TEXT("\";g;\n"); // 同时加入g; 防止后面出现异常
		glogger.debug1(TEXT("debugger command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
		DebugCommand(inputPipeW, TStringToString(sCommandLine).c_str());
		GSleep(100);		
#endif				

		// 监听debugger输出信息
		glogger.debug1(TEXT("debugger command: continue"));
		DebugCommand(inputPipeW, cmd_continue.c_str()); // continue
		glogger.info(TEXT("Fuzzing ..."));		
		pbuff[0] = 0;
		uint32_t idletime = 0;
		while (true)
		{
			// 查看是否存在新的进程
			procIDs_new = GetAllProcessId(webProcName.c_str(), procIDs);
			if (!procIDs_new.empty())
			{
				for (size_t i = 0; i < procIDs_new.size(); i++)
				{
					glogger.warning(TEXT("find new pid:") + to_tstring(procIDs_new[i]));
					procIDs.push_back(procIDs_new[i]);
				}
				procIDs_new.clear();
				glogger.info(TEXT("restart fuzz ..."));
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
					glogger.warning(TEXT("browser seems dead, restart fuzz ..."));
					break;
				}
				continue;
			}

			if (pbuff[pbufflen - 2] == '>' && pbuff[pbufflen - 1] == ' ')
			{
				// 进程异常
				if (CheckC3Ret(pbuff))
				{
					glogger.warning(TEXT("break @ \"ret\", continue"));
					glogger.debug1(TEXT("debugger command: continue"));
					DebugCommand(inputPipeW, cmd_continue.c_str()); 
					pbuff[0] = 0;
					continue;
				}

				// 软件中断，g
				if (CheckCCInt3(pbuff))
				{
					glogger.warning(TEXT("break @ \"int 3\", continue"));
					glogger.debug1(TEXT("debugger command: continue"));
					DebugCommand(inputPipeW, cmd_continue.c_str());
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
				if (debug_level > 0)
				{
					printf("+1 [main] %s\n", pbuff);
				}

				// 获取崩溃位置作为目录名
				tstring crashpos = GetCrashPos(inputPipeW, outputPipeR);

				htmlPath = outPath + crashpos + TEXT("\\");
				CreateDir(htmlPath);

				glogger.info(TEXT("crash = ") + crashpos);
				if (crashpos != TEXT("unknown") &&
					GetFilecountInDir(htmlPath, TEXT("log")) >= maxPocCount)
				{
					glogger.warning(TEXT("this crash already logged, restart fuzz ..."));
					break;
				}
				glogger.info(TEXT("create html and log ..."));
				pocbuff[0] = 0;
				GetHTMLFromServer(serverIP, serverPort, TEXT("prev.html"), prevpocbuff);
				GetHTMLFromServer(serverIP, serverPort, TEXT("current.html"), pocbuff);
				if (pocbuff == NULL || strlen(pocbuff) == 0 ||
					prevpocbuff == NULL || strlen(prevpocbuff) == 0)
				{
					glogger.warning(TEXT("can not get POC"));
				}

				// log文件                
				logbuff[0] = 0;
				strcat(logbuff, "*** mixFuzzer ***\n");
				strcat(logbuff, pbuff);

				strcat(logbuff, "\n\n*** crash info ***\n");
#ifdef __LINUX__
				glogger.debug1(TEXT("debugger command: i r"));
				DebugCommand(inputPipeW, "i r\n");
#else
				glogger.debug1(TEXT("debugger command: r"));
				DebugCommand(inputPipeW, "r\n");
#endif
				if (GetDebugInfo(outputPipeR, pbuff, 2 * buffsize) > 0)
				{
					strcat(logbuff, pbuff);
				}

				strcat(logbuff, "\n\n*** stack tracing ***\n");
#ifdef __LINUX__
				glogger.debug1(TEXT("debugger command: bt"));
				DebugCommand(inputPipeW, "bt\n");
#else
				glogger.debug1(TEXT("debugger command: kb"));
				DebugCommand(inputPipeW, "kb\n");
#endif
				while (GetDebugInfo(outputPipeR, pbuff, buffsize) > 0)
				{
					strcat(logbuff, pbuff);
				}

				strcat(logbuff, "\n\n*** module info ***\n");
#ifdef __LINUX__
#else
				sCommandLine = TEXT("lmDvm ");
				sCommandLine.append(crashpos.substr(0, crashpos.find_first_of('!'))); // mshtml!xxx__xxx+0x1234
				glogger.debug1(TEXT("debugger command: ") + sCommandLine);
				sCommandLine.append(TEXT("\n"));
				DebugCommand(inputPipeW, TStringToString(sCommandLine).c_str());
#endif				
				if (GetDebugInfo(outputPipeR, pbuff, 2 * buffsize) > 0)
				{
					strcat(logbuff, pbuff);
				}

				// 生成时间戳
				time_t ct = time(NULL);

				// 写入文件
				if (pocbuff) LogFile(outPath, crashpos, TEXT(".html"), pocbuff, strlen(pocbuff), ct);
				if (logbuff) LogFile(outPath, crashpos, TEXT(".log"), logbuff, strlen(logbuff), ct);
				if (prevpocbuff) LogFile(outPath, crashpos, TEXT("_prev.html"), prevpocbuff, strlen(prevpocbuff), ct);

				// 发送至服务端
				if (pocbuff) SendFile(serverIP, 12220, ct, crashpos, 'H', pocbuff, (int)strlen(pocbuff));
				if (logbuff) SendFile(serverIP, 12220, ct, crashpos, 'L', logbuff, (int)strlen(logbuff));
				if (prevpocbuff) SendFile(serverIP, 12220, ct, crashpos, 'P', pocbuff, (int)strlen(prevpocbuff));

				break;
			}

			pbuff[0] = 0;
		}
	}

	delete[] rbuff;
	delete[] pbuff;
	exit(fgetc(stdin));
}

tstring GetCrashPos(HANDLE hinPipeW, HANDLE houtPipeR)
{
	uint32_t nread;
	char rbuff[1024 + 1];
	GetDebugInfo(houtPipeR, rbuff, 1024, 500);
#ifdef __LINUX__
	glogger.debug1(TEXT("debugger command: x/i $pc"));
	DebugCommand(hinPipeW, "x/i $pc\n");
#else
	glogger.debug1(TEXT("debugger command: u eip L1"));
	DebugCommand(hinPipeW, "u eip L1\n");
#endif	
	nread = GetDebugInfo(houtPipeR, rbuff, 1024);
	if (nread == 0)
		return tstring(TEXT("unknown"));
	rbuff[nread] = 0;
	glogger.debug2(StringToTString(string(rbuff)));

	size_t i = 0, start = 0;
	for (i = 0; i < strlen(rbuff); i++)
	{
		if (rbuff[i] == '!' || rbuff[i] == '+')
		{
			while (i > 0 && rbuff[--i] != '\n');
			if (rbuff[i] == '\n')
				start = ++i;
			else
				start = i;
			break;
		}
	}

	if (i != start)
	{
		return tstring(TEXT("unknown"));
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

	return StringToTString(string(rbuff + start));
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

bool CheckEnds(const char * buff, const char* ends)
{
	if(buff == NULL || ends == NULL)
		return false;
	if (strlen(buff) == 0 || strlen(ends) == 0 ||
		strlen(buff) < strlen(ends))
		return false;

	const char* back = buff + strlen(buff) - strlen(ends);
	if (strcmp(back, ends) == 0)
		return true;

	return false;
}

int GetDebugInfo(HANDLE hPipe, char* buff, int size, int timeout)
{
	buff[0] = 0;
	int count = timeout / 100;
	int nread = 0;

#ifdef __LINUX__
	GSleep(timeout);
	nread = (uint32_t)read(hPipe, buff, size);
	if (nread > 0)
	{
		buff[nread] = 0;
		return nread;
	}
	else
		return 0;
#else
	while (count--)
	{
		GSleep(100);
		if (!PeekNamedPipe(hPipe, buff, size, (DWORD*)&nread, 0, 0))
			continue;
		if (nread == size)
			break;
	}
	if (nread == 0)
		return 0;

	nread = 0;
	ReadFile(hPipe, buff, size, (DWORD*)&nread, NULL);
	if (nread>0)
		buff[nread] = 0;
#endif

	return nread;
}

void DebugCommand(HANDLE hPipe, const char * cmd)
{
#ifdef __LINUX__
	write(hPipe, cmd, strlen(cmd));
#else
	DWORD nwrite;
	WriteFile(hPipe, cmd, strlen(cmd), &nwrite, NULL);
#endif
}

void CreateDir(const tstring & path)
{	
#ifdef __LINUX__
	tstring newpath = path;
	ReplaseAllSubString(newpath, TEXT("\\"), TEXT("/"));
	mkdir(newpath.c_str(), 0777);
#else
	CreateDirectory(path.c_str(), NULL);
#endif
}

vector<uint32_t> GetAllProcessId(const tchar* pszProcessName, vector<uint32_t> ids)
{
	vector<uint32_t> pids;

#ifdef __LINUX__
	int pnlen = strlen(pszProcessName);

	/* Open the /proc directory. */
	DIR* dir = opendir("/proc");
	if (!dir)
	{
		glogger.error("cannot open /proc");
		return pids;
	}

	/* Walk through the directory. */
	char            *s;
	int             pid;
	struct dirent   *d;
	while ((d = readdir(dir)) != NULL) 
	{
		char exe[MAX_PATH + 1];
		char path[MAX_PATH + 1];
		int len;
		int namelen;

		/* See if this is a process */
		if ((pid = atoi(d->d_name)) == 0)       
			continue;

		snprintf(exe, sizeof(exe), "/proc/%s/exe", d->d_name);
		if ((len = readlink(exe, path, PATH_MAX)) < 0)
			continue;
		path[len] = '\0';

		/* Find ProcName */
		s = strrchr(path, '/');
		if (s == NULL)
			continue;
		s++;

		/* we don't need small name len */
		namelen = strlen(s);
		if (namelen < pnlen)     
			continue;

		if (!strncmp(pszProcessName, s, pnlen)) 
		{
			/* to avoid subname like search proc tao but proc taolinke matched */
			if (s[pnlen] == ' ' || s[pnlen] == '\0') 
			{
				bool find = false;
				for (uint32_t id : ids)
				{
					if (id == pid)
					{
						find = true;
						break;
					}
				}
				if (!find)
					pids.push_back(pid);
			}
		}
	}
	closedir(dir);

#else
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	uint32_t i;

	// Enumerate all processes
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		return vector<uint32_t>();

	cProcesses = cbNeeded / sizeof(uint32_t);
	tchar szEXEName[MAX_PATH_SIZE] = { 0 };
	for (i = 0; i < cProcesses; i++)
	{
		// Get the process
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
					sizeof(szEXEName) / sizeof(char));

				
				if (tcsicmp(szEXEName, pszProcessName) == 0)
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
			CloseHandle(hProcess);
		}
	}
#endif // 
	return pids;
}

bool TerminateAllProcess(const tchar* pszProcessName)
{
	vector<uint32_t> pids = GetAllProcessId(pszProcessName, vector<uint32_t>());
	for (uint32_t pid : pids)
	{
		if (pid != 0)
		{
			glogger.debug2(TEXT("kill %d"), pid);			
#ifdef __LINUX__
			string s = "/bin/kill -9 " + to_string(pid);
			system(s.c_str());
#else
			void* hProcess = OpenProcess(
				PROCESS_TERMINATE |
				PROCESS_QUERY_LIMITED_INFORMATION |
				SYNCHRONIZE, FALSE, pid);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 0);
			}
#endif	
		}
	}

	int count = 0;
	do
	{
		if (count >= 10)
			return false;
		GSleep(100);
		pids = GetAllProcessId(pszProcessName, vector<uint32_t>());
		count++;
	} while (!pids.empty());

	return true;
}

bool StartProcess(const tstring& path, const tstring& arg)
{
	glogger.debug1(TEXT("CreateProcess: %s %s"), path.c_str(), arg.c_str());
#ifdef __LINUX__
	if (fork() == 0)
	{
		int fd = open("/dev/null", O_RDWR);
		dup2(fd, 1); 
		dup2(fd, 2);
		execl(path.c_str(), path.c_str(), arg.c_str(), (char*)0);
		glogger.warning(TEXT("browser quit: %d"), errno);
		exit(0);
	}
	else
	{
		return true;
	}
#else
	tchar cmdline[1024];
	stprintf(cmdline, TEXT("%s%s"), path.c_str(), arg.c_str());
	STARTUPINFO si_edge = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi_edge;
	si_edge.dwFlags = STARTF_USESHOWWINDOW;
	si_edge.wShowWindow = TRUE; //TRUE表示显示创建的进程的窗口	
	BOOL bRet = CreateProcess(NULL, cmdline,
		NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si_edge, &pi_edge);
	if (pi_edge.hProcess)
		CloseHandle(pi_edge.hProcess);
	if (pi_edge.hThread)
		CloseHandle(pi_edge.hThread);
	return bRet!=0;
#endif
}

#ifdef __LINUX__
uint32_t GetHTMLFromServer(const tstring& serverip, uint16_t port, const tstring& name, char* buff)
{	
	// socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		glogger.error(TEXT("socket failed with error: %d"), SOCKET_ERRNO);
		return 0;
	}
	
	////构建本地地址信息  
	struct sockaddr_in saServer;
	memset(&saServer, 0,  sizeof(saServer));
	saServer.sin_family = AF_INET;
	saServer.sin_port = gcommon::htons(port);
	saServer.sin_addr.s_addr = inet_addr(serverip.c_str());
	
	// 连接服务器
	int ret = connect(sock, (sockaddr *)&saServer, sizeof(saServer));
	if (ret == SOCKET_ERROR)
	{
		close(sock);
		return 0;
	}
	
	// 发送请求
	string sendbuff = "GET /" + name +
		" HTTP/1.1\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: Mozilla/5.0\r\nConnection: Keep-Alive\r\n\r\n";
	ret = send(sock, sendbuff.c_str(), sendbuff.size(), 0);
	if (ret != sendbuff.size())
	{
		glogger.error(TEXT("send failed with error: %d"), SOCKET_ERRNO);
		close(sock);
		return 0;
	}
	
	// 接收数据
	ret = recv(sock, buff, MAX_SENDBUFF_SIZE, 0);
	if (ret > 0)
	{
		buff[ret] = 0;
	}
	
	close(sock);
	return ret;
}

uint32_t SendFile(tstring serverip, uint16_t port,
	time_t time, const tstring & crashpos, uint8_t type, char * data, int datalen)
{
	if (data == NULL || datalen == 0)
		return 0;

	// socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		glogger.error(TEXT("socket failed with error: %d"), SOCKET_ERRNO);
		return 0;
	}

	//构建本地地址信息  
	struct sockaddr_in saServer;
	saServer.sin_family = AF_INET;
	saServer.sin_port = gcommon::htons(port);
	saServer.sin_addr.s_addr = inet_addr(serverip.c_str());

	// 连接服务器
	int ret = connect(sock, (sockaddr *)&saServer, sizeof(saServer));
	if (ret == SOCKET_ERROR)
	{
		close(sock);
		return 0;
	}

	// 发送请求
	char* sendBuff = new char[sizeof(FILEPACK) + crashpos.size() + datalen];
	PFILEPACK filepacket = (PFILEPACK)sendBuff;
	filepacket->type = type;
	filepacket->time = (uint32_t)time;
	filepacket->dirLen = (uint32_t)crashpos.size();
	memcpy(filepacket->data, TStringToString(crashpos).c_str(), crashpos.size());
	memcpy(filepacket->data + crashpos.size(), data, datalen);

	ret = send(sock, sendBuff, (int)(sizeof(FILEPACK) + crashpos.size() + datalen), 0);
	delete[] sendBuff;
	close(sock);

	if (ret != sizeof(FILEPACK) + crashpos.size() + datalen)
	{
		glogger.error(TEXT("send file error: %s"), crashpos.c_str());
		return 0;
	}
	return ret;
}

uint32_t GetFilecountInDir(tstring dir, tstring fileext)
{
	struct dirent *ptr;
	DIR *odir;
	odir = opendir(dir.c_str());
	int count = 0;
	while ((ptr = readdir(odir)) != NULL)
	{
		if (ptr->d_name[0] == '.')
			continue;

		char* back = ptr->d_name + strlen(ptr->d_name) - fileext.size();
		if (strcmp(back, fileext.c_str()) == 0)
		{
			count++;
		}
	}
	closedir(odir);
	return count;
}

#else
uint32_t GetHTMLFromServer(const tstring& serverip, uint16_t port, const tstring& name, char* buff)
{
	// Initialize Winsock
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR)
	{
		glogger.error(TEXT("WSAStartup failed with error: %d"), SOCKET_ERRNO);
		return 0;
	}

	// socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		glogger.error(TEXT("socket failed with error: %d"), SOCKET_ERRNO);
		WSACleanup();
		return 0;
	}

	////构建本地地址信息  
	struct sockaddr_in saServer;
	memset(&saServer, 0, sizeof(saServer));
	saServer.sin_family = AF_INET;
	saServer.sin_port = gcommon::htons(port);
	saServer.sin_addr.S_un.S_addr = inet_ttol(serverip.c_str());

	// 连接服务器
	int ret = connect(sock, (sockaddr *)&saServer, sizeof(saServer));
	if (ret == SOCKET_ERROR)
	{
		closesocket(sock);
		WSACleanup();
		return 0;
	}

	// 发送请求
	string sendbuff = "GET /" + TStringToString(name) +
		" HTTP/1.1\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: Mozilla/5.0\r\nConnection: Keep-Alive\r\n\r\n";
	ret = send(sock, sendbuff.c_str(), sendbuff.size(), 0);
	if (ret != sendbuff.size())
	{
		glogger.error(TEXT("send failed with error: %d"), SOCKET_ERRNO);
		closesocket(sock);
		WSACleanup();
		return 0;
	}

	// 接收数据
	ret = recv(sock, buff, MAX_SENDBUFF_SIZE, 0);
	if (ret > 0)
	{
		buff[ret] = 0;
	}

	closesocket(sock);
	WSACleanup();
	return ret;
}

uint32_t SendFile(tstring serverip, uint16_t port,
	time_t time, const tstring & crashpos, uint8_t type, char * data, int datalen)
{
	if (data == NULL || datalen == 0)
		return 0;

	// Initialize Winsock
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR)
	{
		glogger.error(TEXT("WSAStartup failed with error: %d"), SOCKET_ERRNO);
		return 0;
	}

	// socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		glogger.error(TEXT("socket failed with error: %d"), SOCKET_ERRNO);
		WSACleanup();
		return 0;
	}

	//构建本地地址信息  
	struct sockaddr_in saServer;
	saServer.sin_family = AF_INET;
	saServer.sin_port = gcommon::htons(port);
	saServer.sin_addr.S_un.S_addr = inet_ttol(serverip.c_str());

	// 连接服务器
	int ret = connect(sock, (sockaddr *)&saServer, sizeof(saServer));
	if (ret == SOCKET_ERROR)
	{
		closesocket(sock);
		WSACleanup();
		return 0;
	}

	// 发送请求
	char* sendBuff = new char[sizeof(FILEPACK) + crashpos.size() + datalen];
	PFILEPACK filepacket = (PFILEPACK)sendBuff;
	filepacket->type = type;
	filepacket->time = (uint32_t)time;
	filepacket->dirLen = (uint32_t)crashpos.size();
	memcpy(filepacket->data, TStringToString(crashpos).c_str(), crashpos.size());
	memcpy(filepacket->data + crashpos.size(), data, datalen);

	ret = send(sock, sendBuff, (int)(sizeof(FILEPACK) + crashpos.size() + datalen), 0);
	delete[] sendBuff;
	closesocket(sock);
	WSACleanup();

	if (ret != sizeof(FILEPACK) + crashpos.size() + datalen)
	{
		glogger.error(TEXT("send file error: %s"), crashpos.c_str());
		return 0;
	}
	return ret;
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
#endif

uint32_t LogFile(const tstring &outpath, const tstring &crashpos,
	const tstring &endstr, char* data, int datalen, time_t ct)
{
	if (data == NULL || datalen == 0)
		return 0;

	tstring filepath = outpath + crashpos + TEXT("\\") + to_tstring(ct) + endstr;
	FILE* htmlFile = tfopen(filepath.c_str(), TEXT("w"));
	if (htmlFile == NULL)
	{
		glogger.warning(TEXT("can not create html file: ") + crashpos + TEXT("\\") + to_tstring(ct) + endstr);
		filepath = outpath + TEXT("unknown\\") + to_tstring(ct) + endstr;
		htmlFile = tfopen(filepath.c_str(), TEXT("w"));
		if (htmlFile == NULL)
		{
			glogger.error(TEXT("can not create html file: unknown\\") + to_tstring(ct) + endstr);
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

void GSleep(uint32_t ms)
{
#ifdef __LINUX__
	usleep(ms*1000);
#else
	Sleep(ms);
#endif
}



