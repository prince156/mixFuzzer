// mixFuzzer.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "function.h"
#include "httpServThread.h"
#include "htmlGenThread.h"
#include "fileRecvThread.h"

#pragma comment(lib,"Ws2_32.lib")

#define SOFT_NAME TEXT("mixFuzzer")
#define SOFT_VER TEXT("v1.4")

int main(int argc, tchar** argv)
{
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
	tstring killProc = TEXT("");

    PRINT_TARGET print_target = PRINT_TARGET::BOTH;
    int debug_level = 0;
	uint32_t deadTimeout = 5000; // �����������ʱ
	uint32_t waitTime = 2000;    // ����������ȴ�ʱ��
	uint32_t minWaitTime = 1000;
    int serverPort = 12228; // http����˿�
	uint32_t maxPocCount = 10;   // ͬһ��Ŀ¼�����poc��������log�ļ�������
    tstring log_file = TEXT("mixfuzz.log");
    tstring mode = TEXT("local");
    tstring serverIP = TEXT("127.0.0.1");
    tstring fuzztarget = TEXT("");	
	int pageheap = 1;
	uint32_t killexplorer = 10;

    tstring debugger = IsWow64() ? CDB_X64 : CDB_X86;
    tstring gflags_exe = IsWow64() ? GFLAGS_X64 : GFLAGS_X86;

    // ��ʼ��glogger	
    glogger.setDebugLevel(debug_level);
    glogger.setHeader(TEXT("main"));
    glogger.enableColor();
    glogger.setLogFile(log_file);
    glogger.setTarget(print_target);

    // ��ʼ��console��ʾ
    tstring title = SOFT_NAME;
    title.append(TEXT(" "));
    title.append(SOFT_VER);
    SetConsoleTitle(title.c_str());
    glogger.screen(SOFT_LOGO);

    // ����debug Pipe
    HANDLE inputPipeR, inputPipeW;
    HANDLE outputPipeR, outputPipeW;
	if (!InitDebugPipe(&inputPipeR, &inputPipeW, &outputPipeR, &outputPipeW))
	{
		glogger.warning(TEXT("failed to create debug pipe: %d"), errno);
		exit(fgetc(stdin));
	}

    // ��ȡ��ǰ�ļ���·��		
    tstring currentDir = GetCurrentDirPath();
    if (currentDir.empty())
    {
        glogger.warning(TEXT("can not get current dir, use default dir"));
        currentDir = TEXT(".\\");
    }
	glogger.debug1(TEXT("current dir: ") + currentDir);
    SetCurrentDirectory(currentDir.c_str());

    // ��ȡconfig�ļ�	
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
	killexplorer = GetConfigInt(currentDir + configFile, TEXT("KILL_EXPLORER_RATE"), TEXT("10"));
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

    // ����crashĿ¼
	CreateDir(outPath);

    // semaphore
    HANDLE semaphorep = CreateSemaphore(NULL, 1, 1, TEXT("mixfuzzer_sem_htmlbuff_p"));
    HANDLE semaphorec = CreateSemaphore(NULL, 0, 1, TEXT("mixfuzzer_sem_htmlbuff_c"));    

    // clientģʽ
	if (mode != TEXT("client"))
	{
		// ��ȡģ���ļ�
		LoudTemplate(htmlTemplNodes, htmlTempls, BUFF_SIZE);
		if (htmlTempls.size() == 0)
		{
			glogger.error(TEXT("no template available"));
			exit(fgetc(stdin));
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
        // ����http�����߳�            
        if (!httpServThread.Run())
        {
            glogger.error(TEXT("failed to create [Serv] thread"));
            exit(fgetc(stdin));
        }

        // ����html�����߳�             
        if (!htmlGenThread.Run())
        {
            glogger.error(TEXT("failed to create [Fuzz] thread"));
            exit(fgetc(stdin));
        }
		
    }   

    // ����serverģʽ
    if (mode == TEXT("server"))
    {
		// ����file�����߳�
		if (!fileRecvThread.Run())
		{
			glogger.error(TEXT("failed to create [Recv] thread"));
			exit(fgetc(stdin));
		}

        glogger.info(TEXT("webserver mode"));
		glogger.info(TEXT("try to visit http://%s:%d"), serverIP.c_str(), serverPort);
        while (true)
        {
            Sleep(100);
        }
    }    

    // ��page heap, �ر��ڴ汣��, ...
	PageHeapSwitch(pageheap, webProcName, gflags_exe);

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

    // fuzzѭ��
	uint32_t fuzzcount = 0;
    DWORD nwrite, nread;
    uint32_t buffsize = 4096;
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

        // kill ��������߳�
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

        // ���������
		glogger.info(TEXT("Start ") + fuzztarget);
		bool startSuccess = StartProcess(appPath, TEXT("http://") + serverIP + TEXT(":") + to_tstring(serverPort));
		if (!startSuccess)
		{
			glogger.error(TEXT("Cannot start ") + fuzztarget);
			glogger.error(TEXT("path=") + appPath);
			exit(fgetc(stdin));
		}
		GSleep(waitTime); // �����ȴ�һ��ʱ��
		if (waitTime > minWaitTime)
			waitTime -= 100;

        // ��ȡPID
        vector<uint32_t> procIDs = GetAllProcessId(webProcName.c_str(), vector<uint32_t>());
        vector<uint32_t> procIDs_new;
        if (procIDs.empty())
        {
            glogger.error(TEXT("Cannot start the browser, restart fuzz."));		
			if (waitTime < 2 * minWaitTime)
				waitTime += 100;
            continue;
        }

        // attach������	
		glogger.info(TEXT("Attach ") + debugger + TEXT(" ..."));
		if (!AttachDebugger(procIDs, debugger, symPath, inputPipeR, inputPipeW, outputPipeR, outputPipeW))
		{
			glogger.error(TEXT("Cannot attach debugger, restart fuzz."));
			continue;
		}

        // ����cdgѭ��
		glogger.debug1(TEXT("debugger command: g"));
		DebugCommand(inputPipeW, "g\n"); // running
        glogger.info(TEXT("Fuzzing ..."));
		uint32_t idletime = 0;
		time_t fuzztime = time(NULL);
        while (true)
        {
			// �ж��Ƿ�ﵽfuzzʱ������
			if (time(NULL) - fuzztime > 500)
			{
				glogger.info(TEXT("fuzz timeout, restart fuzz ..."));
				break;
			}

            // �鿴�Ƿ�����µĽ���
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

            // ��ȡ���������
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
				glogger.debug1(TEXT("debugger command: g"));
				DebugCommand(inputPipeW, "g\n");
				continue;
			}
			else if (debugstate == 1)
            {                
                // �ж�Ϊcrash 
                glogger.error(TEXT("!! find crash !!"));				
                glogger.debug2(StringToTString(string(rbuff)));				               

                // ��ȡ����λ����ΪĿ¼��
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
				
				// ��ȡcrash��Ϣ         
				GetCrashInfo(logbuff, MAX_SENDBUFF_SIZE, crashpos, rbuff, buffsize, outputPipeR, inputPipeW);

				// ����ʱ���
				time_t ct = time(NULL);

				// д���ļ�
				if (pocbuff) LogFile(outPath, crashpos, TEXT("\\"), TEXT(".html"), pocbuff, strlen(pocbuff), ct);
				if (logbuff) LogFile(outPath, crashpos, TEXT("\\"), TEXT(".log"), logbuff, strlen(logbuff), ct);
				if (prevpocbuff) LogFile(outPath, crashpos, TEXT("\\"), TEXT("_prev.html"), prevpocbuff, strlen(prevpocbuff), ct);

				// �����������
				if (mode == TEXT("client"))
				{					
					if (pocbuff) SendFile(serverIP, 12220, ct, crashpos, 'H', pocbuff, (int)strlen(pocbuff));
					if (logbuff) SendFile(serverIP, 12220, ct, crashpos, 'L', logbuff, (int)strlen(logbuff));
					if (prevpocbuff) SendFile(serverIP, 12220, ct, crashpos, 'P', pocbuff, (int)strlen(prevpocbuff));
				}

                break;
            }
        }
    }

    delete[] rbuff;
    exit(fgetc(stdin));
}
