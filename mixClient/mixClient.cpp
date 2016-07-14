// mixClient.cpp

#include "function.h"

#ifdef __LINUX__
#else
#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"User32.lib")
#endif

#define SOFT_NAME TEXT("mixClient")
#define SOFT_VER TEXT("v1.4")

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
	uint32_t killexplorer = 10;

#ifdef __LINUX__
	tstring debugger = TEXT("gdb");
	tstring cmd_continue = TEXT("c\n");
	tstring slash = TEXT("/");
#else
	tstring debugger = IsWow64() ? CDB_X64 : CDB_X86;
	tstring gflags_exe = IsWow64() ? GFLAGS_X64 : GFLAGS_X86;
	tstring cmd_continue = TEXT("g\n");
	tstring slash = TEXT("\\");
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
	glogger.screen(SOFT_LOGO);
#ifndef __LINUX__
	SetConsoleTitle(title.c_str());
#endif // !__LINUX__

	// 创建debug Pipe
	HANDLE inputPipeR = 0, inputPipeW = 0;
	HANDLE outputPipeR = 0, outputPipeW = 0;
	if (!InitDebugPipe(&inputPipeR, &inputPipeW, &outputPipeR, &outputPipeW))
	{
		glogger.warning(TEXT("failed to create debug pipe: %d"), errno);
		exit(fgetc(stdin));
	}
	
	// 获取当前文件夹路径		
	tstring currentDir = GetCurrentDirPath();
	if (currentDir.empty())
	{
		glogger.warning(TEXT("can not get current dir, use default dir"));
		currentDir = TEXT(".") + slash;
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
	killexplorer = GetConfigInt(currentDir + configFile, TEXT("KILL_EXPLORER_RATE"), TEXT("10"));

	glogger.setDebugLevel(debug_level);
	glogger.info(TEXT("symbol path: ") + symPath);
	glogger.info(TEXT(" ouput path: ") + outPath);
	glogger.info(TEXT(" fuzztarget: ") + fuzztarget);
	if (outPath.back() != slash.front())
		outPath += slash;

	// 创建crash目录
	CreateDir(outPath);
	
#ifndef __LINUX__
	// 打开page heap, 关闭内存保护, ...
	PageHeapSwitch(pageheap, webProcName, gflags_exe);

	// 处理appPath
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
	uint32_t fuzzcount = 0;
	uint32_t nwrite, nread;
	uint32_t buffsize = 1024;
	char* rbuff = new char[buffsize + 1];
	char* pocbuff = new char[MAX_SENDBUFF_SIZE + 1];
	char* prevpocbuff = new char[MAX_SENDBUFF_SIZE + 1];
	char* logbuff = new char[MAX_SENDBUFF_SIZE + 1];
	while (true)
	{
		fuzzcount++;
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
		for (auto proc : killProcesses)
		{
			if (proc.empty())
				continue;

			if (proc == TEXT("explorer.exe"))
			{
				if (killexplorer <= fuzzcount)
				{
					glogger.debug1(TEXT("kill %s ..."), proc.c_str());
					TerminateAllProcess(proc.c_str());
					fuzzcount = 0;
				}
			}
			else
			{
				glogger.debug1(TEXT("kill %s ..."), proc.c_str());
				if (!TerminateAllProcess(proc.c_str()))
				{
					glogger.warning(TEXT("Cannot kill %s"), proc.c_str());
					continue;
				}
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
		uint32_t dbgpid;
		glogger.info(TEXT("Attach ") + debugger + TEXT(" ..."));	
		dbgpid = AttachDebugger(procIDs, debugger, symPath, inputPipeR, inputPipeW, outputPipeR, outputPipeW);
		if (dbgpid == 0)
		{
			glogger.error(TEXT("Cannot attach debugger, restart fuzz."));
			continue;
		}		

		// 监听debugger输出信息
		DebugCommand(inputPipeW, outputPipeR, cmd_continue); // running
		glogger.info(TEXT("Fuzzing ..."));
		uint32_t idletime = 0;
		time_t fuzztime = time(NULL);
		while (true)
		{
			// 判断是否达到fuzz时间上限
			if (time(NULL) - fuzztime > 500)
			{
				glogger.info(TEXT("fuzz timeout, restart fuzz ..."));
				break;
			}

			// 查看是否存在新的进程
			bool restart = false;
			procIDs_new = GetAllProcessId(webProcName.c_str(), procIDs);
			if (!procIDs_new.empty())
			{
				for (size_t i = 0; i < procIDs_new.size(); i++)
				{
					glogger.warning(TEXT("find new pid:") + to_tstring(procIDs_new[i]));
					procIDs.push_back(procIDs_new[i]);
					if (!AttachNewPid(dbgpid, procIDs_new[i], outputPipeR, inputPipeW))
					{						
						restart = true;
						break;
					}
				}
				procIDs_new.clear();
				if (restart)
				{
					if (waitTime < 3 * minWaitTime)
						waitTime += 500;
					glogger.info(TEXT("restart fuzz ..."));
					break;
				}
			}

			// 获取调试器输出
			int debugstate = CheckDebuggerOutput(rbuff, buffsize, outputPipeR, inputPipeW, deadTimeout);
			if (debugstate == 0)
				continue;
			else if (debugstate == 2) 
			{
				glogger.info(TEXT("restart fuzz ..."));
				break;
			}
			else if (debugstate == 3)
			{				
				DebugCommand(inputPipeW, outputPipeR, cmd_continue.c_str());
				continue;
			}
			else if(debugstate == 1)			
			{
				// 判定为crash 
				glogger.error(TEXT("!! find crash !!"));
				glogger.debug2(StringToTString(string(rbuff)));

				// 获取崩溃位置作为目录名
				tstring crashpos = GetCrashPos(inputPipeW, outputPipeR);

				htmlPath = outPath + crashpos + slash;
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

				// 获取crash信息         
				GetCrashInfo(logbuff, MAX_SENDBUFF_SIZE, crashpos, rbuff, buffsize, outputPipeR, inputPipeW);

				// 生成时间戳
				time_t ct = time(NULL);

				// 写入文件
				if (pocbuff) LogFile(outPath, crashpos, slash, TEXT(".html"), pocbuff, strlen(pocbuff), ct);
				if (logbuff) LogFile(outPath, crashpos, slash, TEXT(".log"), logbuff, strlen(logbuff), ct);
				if (prevpocbuff) LogFile(outPath, crashpos, slash, TEXT("_prev.html"), prevpocbuff, strlen(prevpocbuff), ct);

				// 发送至服务端
				if (pocbuff) SendFile(serverIP, 12220, ct, crashpos, 'H', pocbuff, (int)strlen(pocbuff));
				if (logbuff) SendFile(serverIP, 12220, ct, crashpos, 'L', logbuff, (int)strlen(logbuff));
				if (prevpocbuff) SendFile(serverIP, 12220, ct, crashpos, 'P', pocbuff, (int)strlen(prevpocbuff));

				break;
			}
			else
			{
				glogger.info(TEXT("unknown error, restart fuzz ..."));
				break;
			}
		}
	}

	delete[] rbuff;
	exit(fgetc(stdin));
}