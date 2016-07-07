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
#include "fileRecvThread.h"

#define SOFT_NAME TEXT("mixFuzzer")
#define SOFT_VER TEXT("v1.3")
#define SOFT_LOGO TEXT(\
	"===============================================================================\n"\
	"|                        Wellcome to " SOFT_NAME " " SOFT_VER "                           |\n"\
	"===============================================================================\n\n")

#define CDB_X86 TEXT("cdb_x86.exe")
#define CDB_X64 TEXT("cdb_x64.exe")
#define GFLAGS_X86 TEXT("tools\\gflags_x86.exe")
#define GFLAGS_X64 TEXT("tools\\gflags_x64.exe")

using namespace std;
using namespace gcommon;

GLogger glogger;
int GetDebugInfo(HANDLE hPipe, char* buff, int size, int timeout = 2000);
tstring GetCrashPos(HANDLE hinPipeW, HANDLE houtPipeR);
bool CheckCCInt3(char* buff);
bool CheckC3Ret(char* buff);
vector<DWORD> GetAllProcessId(LPCTSTR pszProcessName, vector<DWORD> &ids= vector<DWORD>());
bool TerminateAllProcess(LPCTSTR pszProcessName);
uint32_t GetFilecountInDir(tstring dir, tstring fileext);
void LoudTemplate(vector<PTMPL_NODE> &templnodes, vector<char*> &templs, int maxBuffSize);
uint32_t GetHTMLFromServer(const tstring& serverip, uint16_t port, const tstring& name, char* buff);
uint32_t SendFile(tstring serverip, uint16_t port, 
	time_t time, const tstring &crashpos, byte type, char* data, int datalen);
uint32_t LogFile(const tstring &outpath, const tstring &crashpos, 
	const tstring &endstr, char* data, int datalen, time_t ct);
bool IsWow64();


int main(int argc, tchar** argv)
{
    //const tchar* sAUMID = TEXT("Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge");
    const tchar* sMicrosoftEdgeExecutable = TEXT("MicrosoftEdge.exe");
    const tchar* sBrowserBrokerExecutable = TEXT("browser_broker.exe");
    const tchar* sRuntimeBrokerExecutable = TEXT("RuntimeBroker.exe");
    const tchar* sMicrosoftEdgeCPExecutable = TEXT("MicrosoftEdgeCP.exe");

    const uint32_t BUFF_SIZE = 1024 * 100;
    const uint32_t READ_DBGINFO_TIMEOUT = 1000;

    char* htmlBuff = new char[BUFF_SIZE + 1]; // http packet buff
    vector<PTMPL_NODE> htmlTemplNodes; // html template buff
    vector<char*> htmlTempls;

    tstring configFile = TEXT("config.ini");
    tstring symPath = TEXT("srv*");
    tstring outPath = TEXT("crash");
    tstring htmlPath;
	tstring prevHtmlPath;
    tstring logPath;
    tstring appPath = TEXT("explorer Microsoft-Edge:");
	tstring parentProcName = TEXT("MicrosoftEdge.exe");
	tstring webProcName = TEXT("MicrosoftEdgeCP.exe");

    PRINT_TARGET print_target = PRINT_TARGET::BOTH;
    int debug_level = 0;
	uint32_t deadTimeout = 5000; // 浏览器卡死超时
	uint32_t waitTime = 2000;    // 浏览器启动等待时间
	uint32_t minWaitTime = 1000;
    int serverPort = 12228; // http服务端口
	uint32_t maxPocCount = 10;   // 同一个目录中最大poc数量（以log文件计数）
    tstring log_file = TEXT("mixfuzz.log");
    tstring mode = TEXT("local");
    tstring serverIP = TEXT("127.0.0.1");
    tstring fuzztarget = TEXT("");	
	int pageheap = 1;
	int killexplorer = 1;
    bool isWow64 = IsWow64();

    tstring cdb_exe = isWow64 ? CDB_X64 : CDB_X86;
    tstring gflags_exe = isWow64 ? GFLAGS_X64 : GFLAGS_X86;

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
	killexplorer = GetConfigInt(currentDir + configFile, TEXT("KILL_EXPLORER"), TEXT("10"));
	fuzztarget = GetConfigString(currentDir + configFile, TEXT("FUZZ_APP"), parentProcName.substr(0,parentProcName.size()-4));
    appPath = GetConfigString(currentDir + configFile, TEXT("APP_PATH"), appPath);
    symPath = GetConfigString(currentDir + configFile, TEXT("SYMBOL_PATH"), symPath);
    outPath = GetConfigString(currentDir + configFile, TEXT("OUT_PATH"), outPath);
    mode = GetConfigString(currentDir + configFile, TEXT("MODE"), mode);
    serverIP = GetConfigString(currentDir + configFile, TEXT("WEB_SERVER_IP"), serverIP);
	
	glogger.setDebugLevel(debug_level);
    glogger.info(TEXT("symbol path: ") + symPath);
    glogger.info(TEXT(" ouput path: ") + outPath);
    if (outPath.back() != '\\')
        outPath.append(TEXT("\\"));

    // 创建crash目录
    CreateDirectory(outPath.c_str(), NULL);

    // semaphore
    HANDLE semaphorep = CreateSemaphore(NULL, 1, 1, TEXT("mixfuzzer_sem_htmlbuff_p"));
    HANDLE semaphorec = CreateSemaphore(NULL, 0, 1, TEXT("mixfuzzer_sem_htmlbuff_c"));    

    // client模式
	if (mode != TEXT("client"))
	{
		// 读取模板文件
		LoudTemplate(htmlTemplNodes, htmlTempls, BUFF_SIZE);
		if (htmlTempls.size() == 0)
		{
			glogger.error(TEXT("no template available"));
			exit(_getch());
		}
	}
    HTTPSERV_THREAD_PARA httpServPara;
    httpServPara.htmlBuff = htmlBuff;
    httpServPara.semHtmlbuff_c = semaphorec;
    httpServPara.semHtmlbuff_p = semaphorep;
    httpServPara.port = serverPort;
    httpServPara.debugLevel = debug_level;
    httpServPara.outPath = outPath;
	httpServPara.mode = mode;
    HTMLGEN_THREA_PARA htmlGenPara;
    htmlGenPara.buffSize = BUFF_SIZE;
    htmlGenPara.htmlBuff = htmlBuff;
    htmlGenPara.htmlTemplNodes = htmlTemplNodes;
    htmlGenPara.htmlTempls = htmlTempls;
    htmlGenPara.semHtmlbuff_c = semaphorec;
    htmlGenPara.semHtmlbuff_p = semaphorep;
    htmlGenPara.serverip = TStringToString(serverIP);
    htmlGenPara.port = serverPort;
    htmlGenPara.debugLevel = debug_level;
	htmlGenPara.mode = mode;
	FILERECV_THREAD_PARA fileRecvPara;
	fileRecvPara.debugLevel = debug_level;
	fileRecvPara.outPath = outPath;
    HttpServThread httpServThread(&httpServPara);
    HtmlGenThread htmlGenThread(&htmlGenPara);
	FileRecvThread fileRecvThread(&fileRecvPara);
    if (mode != TEXT("client"))
    {
        // 启动http服务线程            
        if (!httpServThread.Run())
        {
            glogger.error(TEXT("failed to create [Serv] thread"));
            exit(_getch());
        }

        // 启动html生成线程             
        if (!htmlGenThread.Run())
        {
            glogger.error(TEXT("failed to create [Fuzz] thread"));
            exit(_getch());
        }
		
    }   

    // 进入server模式
    if (mode == TEXT("server"))
    {
		// 启动file接收线程
		if (!fileRecvThread.Run())
		{
			glogger.error(TEXT("failed to create [Recv] thread"));
			exit(_getch());
		}

        glogger.info(TEXT("webserver mode"));
		glogger.info(TEXT("try to visit http://%s:%d"), serverIP.c_str(), serverPort);
        while (true)
        {
            Sleep(100);
        }
    }    

    // 打开page heap, 关闭内存保护, ...
	tstring sCommandLine;
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

    // fuzz循环
	uint32_t fuzzcount = 0;
    DWORD nwrite, nread;
    uint32_t buffsize = 1024;
    char* rbuff = new char[buffsize + 1];
    char* pbuff = new char[2 * buffsize + 1];
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
		glogger.debug1(TEXT("kill WerFault.exe ..."));
        if (!TerminateAllProcess(TEXT("WerFault.exe")))
        {
            glogger.error(TEXT("Cannot kill WerFault.exe, restart fuzz."));
            continue;
        }
		glogger.debug1(TEXT("kill %s ..."), cdb_exe.c_str());
        if (!TerminateAllProcess(cdb_exe.c_str()))
        {
            glogger.error(TEXT("Cannot kill cdb, restart fuzz."));
            continue;
        }
		if (killexplorer <= fuzzcount)
		{
			glogger.debug1(TEXT("kill explorer.exe ..."));
			if (!TerminateAllProcess(TEXT("explorer.exe")))
			{
				//glogger.warning(TEXT("Cannot kill explorer, restart fuzz."));
				//continue;
			}
			fuzzcount = 0;
		}
		glogger.debug1(TEXT("kill %s ..."), webProcName.c_str());
		if (!TerminateAllProcess(webProcName.c_str()))
		{
			glogger.debug1(TEXT("kill %s ..."), parentProcName.c_str());
			if (!TerminateAllProcess(parentProcName.c_str()))
			{
				glogger.error(TEXT("Cannot kill %s, restart fuzz."), fuzztarget.c_str());
				continue;
			}
		}
		glogger.debug1(TEXT("kill %s ..."), parentProcName.c_str());
		if (!TerminateAllProcess(parentProcName.c_str()))
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
        tchar cmdline[1024];
        stprintf(cmdline, TEXT("%shttp://%s:%d"), appPath.c_str(), serverIP.c_str(), serverPort);
		glogger.debug1(TEXT("CreateProcess: %s"), cmdline);
        BOOL bRet = CreateProcess(NULL, cmdline,
            NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si_edge, &pi_edge);
		if (pi_edge.hProcess) 
			CloseHandle(pi_edge.hProcess);
		if (pi_edge.hThread)
			CloseHandle(pi_edge.hThread);
        if (!bRet)
        {
            glogger.error(TEXT("Cannot start ") + fuzztarget);
			glogger.error(TEXT("path=") + appPath);
            exit(_getch());
        }
        Sleep(waitTime); // 尽量等待一段时间
		if (waitTime > minWaitTime)
			waitTime -= 100;

        // 获取PID
        vector<DWORD> procIDs = GetAllProcessId(webProcName.c_str());
        vector<DWORD> procIDs_new;
        if (procIDs.empty())
        {
            glogger.error(TEXT("Cannot start the browser, restart fuzz."));		
			if (waitTime < 2 * minWaitTime)
				waitTime += 100;
            continue;
        }

        // attach调试器	
        sCommandLine = TEXT("tools\\") + cdb_exe + TEXT(" -o -p ") + to_tstring(procIDs[0]);
        glogger.info(TEXT("Attach ") + cdb_exe + TEXT(" to ") + webProcName +TEXT(" ..."));
        glogger.info(TEXT("  -pid:") + to_tstring(procIDs[0]));
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
            exit(_getch());
        }
		if (pi_cdb.hProcess)
			CloseHandle(pi_cdb.hProcess);
		if (pi_cdb.hThread)
			CloseHandle(pi_cdb.hThread);

        // attach剩余的pid:  .attach 0nxxx;g;|1s; ~*m; .childdbg 1;
        for (size_t i = 1; i < procIDs.size(); i++)
        {
            glogger.info(TEXT("  -pid:") + to_tstring(procIDs[i]));			
            
			sCommandLine = TEXT(".attach 0n") + to_tstring(procIDs[i]) + TEXT("\n");			
			glogger.debug1(TEXT("windbg command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
            WriteFile(inputPipeW, TStringToString(sCommandLine).c_str(), (uint32_t)sCommandLine.size(), &nwrite, NULL);
			
			glogger.debug1(TEXT("windbg command: g"));
			WriteFile(inputPipeW, "g\n", 2, &nwrite, NULL);            
			
			sCommandLine = TEXT("|") + to_tstring(i) + TEXT("s\n");			
			glogger.debug1(TEXT("windbg command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
			WriteFile(inputPipeW, TStringToString(sCommandLine).c_str(), (uint32_t)sCommandLine.size(), &nwrite, NULL);
			
			glogger.debug1(TEXT("windbg command: ~*m"));
			WriteFile(inputPipeW, "~*m\n", 4, &nwrite, NULL);

            sCommandLine = TEXT(".childdbg1\n");
			glogger.debug1(TEXT("windbg command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
            WriteFile(inputPipeW, TStringToString(sCommandLine).c_str(), (uint32_t)sCommandLine.size(), &nwrite, NULL);
        }

        // debug信息：|*\n
		Sleep(100);
        if (debug_level > 1)
        {
            while (GetDebugInfo(outputPipeR, rbuff, buffsize, 100));
			glogger.debug2(TEXT("windbg command: |*"));
            WriteFile(inputPipeW, "|*\n", 3, &nwrite, NULL);
            if (GetDebugInfo(outputPipeR, rbuff, buffsize) > 0)
            {
				glogger.debug2(StringToTString(string(rbuff)));
            }
        }

        // 设置symbol path		
        sCommandLine = TEXT(".sympath \"") + symPath + TEXT("\";g;\n"); // 同时加入g; 防止后面出现异常
		glogger.debug1(TEXT("windbg command: ") + sCommandLine.substr(0, sCommandLine.size() - 1));
        WriteFile(inputPipeW, TStringToString(sCommandLine).c_str(), (uint32_t)sCommandLine.size(), &nwrite, NULL);
        Sleep(100);

        // 监听cdg循环
        glogger.info(TEXT("Fuzzing ..."));
        pbuff[0] = 0;
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
            procIDs_new = GetAllProcessId(webProcName.c_str(), procIDs);
            if (!procIDs_new.empty())
            {
                // 暂停调试器
                //SendMessage(,);

                // attach剩余的pid:  .attach 0nxxx;g;|1s; ~*m; .childdbg 1;
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
					glogger.debug1(TEXT("windbg command: g"));
                    WriteFile(inputPipeW, "g\n", 2, &nwrite, NULL);
                    pbuff[0] = 0;
                    continue;
                }

                // 软件中断，g
                if (CheckCCInt3(pbuff))
                {
                    glogger.warning(TEXT("break @ \"int 3\", continue"));
					glogger.debug1(TEXT("windbg command: g"));
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
                glogger.debug2(StringToTString(string(pbuff)));				               

                // 获取崩溃位置作为目录名
                tstring crashpos = GetCrashPos(inputPipeW, outputPipeR);
                
                htmlPath = outPath + crashpos + TEXT("\\");
				CreateDirectory(htmlPath.c_str(), NULL);

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
				glogger.debug1(TEXT("windbg command: r"));
                WriteFile(inputPipeW, "r\n", 2, &nwrite, NULL);
				if (GetDebugInfo(outputPipeR, pbuff, 2 * buffsize) > 0)
				{
					strcat(logbuff, pbuff);
				}

                strcat(logbuff, "\n\n*** stack tracing ***\n");
				glogger.debug1(TEXT("windbg command: kb"));
                WriteFile(inputPipeW, "kb\n", 3, &nwrite, NULL);
                while (GetDebugInfo(outputPipeR, pbuff, buffsize) > 0)
                {
					strcat(logbuff, pbuff);
                }

                strcat(logbuff, "\n\n*** module info ***\n");
                sCommandLine = TEXT("lmDvm ");
                sCommandLine.append(crashpos.substr(0, crashpos.find_first_of('!'))); // mshtml!xxx__xxx+0x1234
				glogger.debug1(TEXT("windbg command: ") + sCommandLine);
				sCommandLine.append(TEXT("\n"));
                WriteFile(inputPipeW, TStringToString(sCommandLine).c_str(), 
					(uint32_t)sCommandLine.size(), &nwrite, NULL);
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
				if (mode == TEXT("client"))
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
    exit(_getch());
}

tstring GetCrashPos(HANDLE hinPipeW, HANDLE houtPipeR)
{
    DWORD nwrite, nread;
    char rbuff[1024 + 1];
	GetDebugInfo(houtPipeR, rbuff, 1024, 500);
	glogger.debug1(TEXT("windbg command: u eip L1"));
    WriteFile(hinPipeW, "u eip L1\n", 9, &nwrite, NULL);
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

    for (i = start; i < strlen(rbuff+start); i++)
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

int GetDebugInfo(HANDLE hPipe, char* buff, int size, int timeout)
{
	buff[0] = 0;
    int count = timeout / 100;
    DWORD nread = 0;
    while (count--)
    {
        Sleep(100);
        if (!PeekNamedPipe(hPipe, buff, size, &nread, 0, 0))
            continue;

        if (nread == size)
            break;
    }

	if (nread == 0)
	{
		buff[0] = 0;
		return 0;
	}

    nread = 0;
    ReadFile(hPipe, buff, size, &nread, NULL);
    if (nread>0)
        buff[nread] = 0;

    return nread;
}


vector<DWORD> GetAllProcessId(LPCTSTR pszProcessName, vector<DWORD> &ids)
{
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    uint32_t i;
    vector<DWORD> pids;

    // Enumerate all processes
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return vector<DWORD>();

    cProcesses = cbNeeded / sizeof(DWORD);
    tchar szEXEName[MAX_PATH] = { 0 };
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
                    sizeof(szEXEName) / sizeof(tchar));

                if (tcsicmp(szEXEName, pszProcessName) == 0) 
                {
                    bool find = false;
                    for each (DWORD id in ids)
                    {
                        if (id == aProcesses[i])
                        {
                            find = true;
                            break;
                        }
                    }
                    if(!find)
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

void LoudTemplate(vector<PTMPL_NODE> & templnodes, vector<char*> &templs, int maxBuffSize)
{
    templs.clear();

    _finddata_t FileInfo;
    string strfind = ".\\template\\template*.html";
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
            string filepath = ".\\template\\";
            filepath.append(FileInfo.name);
            if (fopen_s(&ftempl, filepath.c_str(), "r") != 0)
            {
                glogger.warning(TEXT("failed to open %s"), FileInfo.name);
                continue;
            }
			if (ftempl == NULL)
			{
				glogger.warning(TEXT("failed to read %s"), FileInfo.name);
				continue;
			}

            char* htmlTempl = new char[maxBuffSize + 1];
            char* htmlTemplBak = new char[maxBuffSize + 1];
            size_t tmplsize = fread_s(htmlTempl, maxBuffSize, 1, maxBuffSize - 1, ftempl);
            fclose(ftempl);
            if (tmplsize == 0)
            {
                glogger.warning(TEXT("failed to read %s"), FileInfo.name);
                delete[] htmlTempl;
                continue;
            }
            htmlTempl[tmplsize] = 0;
            strcpy(htmlTemplBak, htmlTempl);
            templs.push_back(htmlTemplBak);

            PTMPL_NODE head = new TMPL_NODE();
            PTMPL_NODE current = head;
            head->offset = 0;
            head->next = NULL;
            head->type = 0;
            head->data = htmlTempl;
            for (uint32_t i = 0; i < tmplsize - 4; i++)
            {
                uint32_t tmp = *(uint32_t*)(htmlTempl + i) & 0xff0000ff;
                if (tmp == *(uint32_t*)"[\0\0]")
                {
                    current->next = new TMPL_NODE();
                    current = current->next;
                    current->offset = i;
                    current->type = gcommon::ntohl(*(uint32_t*)(htmlTempl + i));
                    current->data = htmlTempl + i + 4;
                    current->next = NULL;
                    htmlTempl[i] = 0;
                }                
            }
            templnodes.push_back(head);
        }
    } while (_findnext(hh, &FileInfo) == 0);

    _findclose(hh);
}

uint32_t GetHTMLFromServer(const tstring& serverip, uint16_t port, const tstring& name, char* buff)
{
    // Initialize Winsock
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR)
    {
        glogger.error(TEXT("WSAStartup failed with error: %d"), WSAGetLastError());
        return 0;
    }

    // socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        glogger.error(TEXT("socket failed with error: %d"), WSAGetLastError());
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
    string sendbuff = "GET /" + gcommon::TStringToString(name) + 
		" HTTP/1.1\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: Mozilla/5.0\r\nConnection: Keep-Alive\r\n\r\n";
    ret = send(sock, sendbuff.c_str(), sendbuff.size(), 0);
    if (ret != sendbuff.size())
    {
		glogger.error(TEXT("send failed with error: %d"), WSAGetLastError());
		closesocket(sock);
		WSACleanup();
        return 0;
    }

    // 接收数据
    ret = recv(sock, buff, MAX_SENDBUFF_SIZE, 0);   
    if (ret > 0)
    {
        buff[ret] = 0;
		closesocket(sock);
		WSACleanup();
        return ret;
    }

	closesocket(sock);
	WSACleanup();
    return 0;
}

uint32_t SendFile(tstring serverip, uint16_t port, 
	time_t time, const tstring & crashpos, byte type, char * data, int datalen)
{
	if (data == NULL || datalen == 0)
		return 0;

	// Initialize Winsock
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR)
	{
		glogger.error(TEXT("WSAStartup failed with error: %d"), WSAGetLastError());
		return 0;
	}

	// socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		glogger.error(TEXT("socket failed with error: %d"), WSAGetLastError());
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
	memcpy(filepacket->data, gcommon::TStringToString(crashpos).c_str(), crashpos.size());
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