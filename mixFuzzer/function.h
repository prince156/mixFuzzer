#pragma once
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
#define LAST_ERRNO errno
#else
#include <WinSock2.h>
#include <io.h>
#include <tchar.h>
#include <Psapi.h>
#define SOCKET_ERRNO WSAGetLastError()
#define LAST_ERRNO GetLastError()
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
#include "others.h"

using namespace std;
using namespace gcommon;

bool InitDebugPipe(HANDLE *inputPipeR, HANDLE *inputPipeW, HANDLE *outputPipeR, HANDLE *outputPipeW);
void PageHeapSwitch(bool pageheap, const tstring& procname, const tstring& gflagpath);
bool AttachDebugger(const vector<uint32_t> & procIDs, const tstring& debugger, const tstring& symPath,
	HANDLE inputPipeR, HANDLE inputPipeW, HANDLE outputPipeR, HANDLE outputPipeW);
int CheckDebuggerOutput(char* rbuff, uint32_t size, HANDLE outputPipeR, HANDLE inputPipeW, uint32_t deadTimeout);
int GetCrashInfo(char* logbuff, uint32_t logbuffsize, const tstring& crashpos,
	char* rbuff, uint32_t rbuffsize,
	HANDLE outputPipeR, HANDLE inputPipeW);
void CreateDir(const tstring& path);
int GetDebugInfo(HANDLE hPipe, char* buff, int size, int timeout = 1000);
bool DebugCommand(HANDLE hPipe, const tstring& cmd);
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
uint32_t LogFile(const tstring &outpath, const tstring &crashpos, const tstring& slash,
	const tstring &endstr, char* data, int datalen, time_t ct);
bool IsWow64();
void GSleep(uint32_t ms);

GLogger glogger;

tstring GetCrashPos(HANDLE hinPipeW, HANDLE houtPipeR)
{
	uint32_t nread;
	char rbuff[1024 + 1];
	GetDebugInfo(houtPipeR, rbuff, 1024, 500);
#ifdef __LINUX__
	DebugCommand(hinPipeW, TEXT("x/i $pc\n"));
#else
	DebugCommand(hinPipeW, TEXT("u eip L1\n"));
#endif	
	nread = GetDebugInfo(houtPipeR, rbuff, 1024);
	if (nread == 0)
		return tstring(TEXT("unknown"));
	rbuff[nread] = 0;
	glogger.debug2(StringToTString(string(rbuff)));

	size_t i = 0, start = 0;
	for (i = 0; i < strlen(rbuff); i++)
	{
		if (rbuff[i] == '!' || rbuff[i] == '+' || rbuff[i] == ':')
		{
			while (i > 0 && rbuff[i] != '\n' && rbuff[i] != '\r' && rbuff[i] != '<')
				i--;
			if (rbuff[i] == '\n' || rbuff[i] == '\r' || rbuff[i] == '<')
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
#ifdef __LINUX__
		if (rbuff[i] == '>' && i > 0)
		{
			rbuff[i] = 0;
			break;
		}
#endif
		if ((rbuff[i] == '\n' || rbuff[i] == '\r') && i > 0)
		{
			rbuff[i] = 0;
			if (rbuff[i - 1] == '_') // windbg
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

		if (rbuff[i] < 33 || rbuff[i] > 125)
			rbuff[i] = ' ';
	}

	tstring crashpos = StringToTString(string(rbuff + start));
	RemoveAllChar(crashpos, ' ');
	return crashpos;
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
	if (buff == NULL || ends == NULL)
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

bool DebugCommand(HANDLE hPipe, const tstring& cmd)
{
	glogger.debug1(TEXT("debugger command: ") + cmd.substr(0, cmd.size() - 1));
	string command = TStringToString(cmd);
#ifdef __LINUX__
	if (write(hPipe, command.c_str(), command.size()) != -1)
		return true;
#else
	DWORD nwrite;
	if (WriteFile(hPipe, command.c_str(), command.size(), &nwrite, NULL))
		return true;
#endif
	glogger.warning(TEXT("write debug command error: %d"), LAST_ERRNO);
	return false;
}

bool InitDebugPipe(HANDLE * inputPipeR, HANDLE * inputPipeW, HANDLE * outputPipeR, HANDLE * outputPipeW)
{
#ifdef __LINUX__
	if (mkfifo("/tmp/mixfuzz_input", 0777) != 0 && errno != 17)
	{
		return false;
	}
	if (mkfifo("/tmp/mixfuzz_output", 0777) != 0 && errno != 17)
	{
		return false;
	}
	*inputPipeW = open("/tmp/mixfuzz_input", O_RDWR | O_NONBLOCK);
	*outputPipeR = open("/tmp/mixfuzz_output", O_RDWR | O_NONBLOCK);
#else
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
	CreatePipe(inputPipeR, inputPipeW, &saAttr, 0);
	CreatePipe(outputPipeR, outputPipeW, &saAttr, 0);
	if (inputPipeR == 0 || inputPipeW == 0 ||
		outputPipeR == 0 || outputPipeW == 0)
	{
		return false;
	}
#endif		
	return true;
}

void PageHeapSwitch(bool pageheap, const tstring& procname, const tstring& gflagpath)
{
#ifndef __LINUX__
	tstring command;
	if (pageheap)
	{
		command = gflagpath + TEXT(" /p /enable ") + procname + TEXT(" /full >nul");
		tsystem(command.c_str());
}
	else
	{
		command = gflagpath + TEXT(" /p /disable ") + procname + TEXT(" /full >nul");
		tsystem(command.c_str());
	}
#endif
}

bool AttachDebugger(const vector<uint32_t> & procIDs, const tstring& debugger, const tstring& symPath,
	HANDLE inputPipeR, HANDLE inputPipeW, HANDLE outputPipeR, HANDLE outputPipeW)
{
	bool attachSuccess = false;
	tstring sCommandLine;
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
	DebugCommand(inputPipeW, sCommandLine.c_str());
	char* rbuff = new char[1025];
	bool wait = false;
	do {
		if (GetDebugInfo(outputPipeR, rbuff, 1024, 100) == 0)
		{
			if (!wait) // 使用wait，防止误认为attach失败
				break;
			else
				continue;
		}

		glogger.debug3(rbuff);
		if (CheckEnds(rbuff, "(gdb) "))
		{
			attachSuccess = true;
			break;
		}
		if (CheckEnds(rbuff, "..."))
		{
			wait = true;
			continue;
		}
		wait = false;
	} while (true);
	delete[] rbuff;
	if (!attachSuccess)
	{
		return false;
	}

	// 设置symbol path	
	sCommandLine = TEXT("set solib-search-path ") + symPath + TEXT("\n"); // 同时加入g; 防止后面出现异常
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
		return false;
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
		DebugCommand(inputPipeW, sCommandLine);
		DebugCommand(inputPipeW, TEXT("g\n"));
		sCommandLine = TEXT("|") + to_tstring(i) + TEXT("s\n");
		DebugCommand(inputPipeW, sCommandLine);
		DebugCommand(inputPipeW, TEXT("~*m\n"));
		DebugCommand(inputPipeW, TEXT(".childdbg1\n"));
	}

	// 设置symbol path		
	sCommandLine = TEXT(".sympath \"") + symPath + TEXT("\"\n"); // 同时加入g; 防止后面出现异常
	DebugCommand(inputPipeW, sCommandLine);
	GSleep(100);
#endif
	return true;
}

// 0=normal, 1=crash, 2=restart, 3=continue
int CheckDebuggerOutput(char* rbuff, uint32_t size, HANDLE outputPipeR, HANDLE inputPipeW, uint32_t deadTimeout)
{
	if (rbuff == NULL)
	{
		glogger.error(TEXT(""));
		return -1;
	}

	static uint32_t idletime = 0;
	uint32_t nread = GetDebugInfo(outputPipeR, rbuff, size, 1000);
	if (nread > 0)
	{
		glogger.debug3(StringToTString(string(rbuff)));
		idletime = 0;
	}
	rbuff[nread] = 0;

	size_t bufflen = strlen(rbuff);
	if (bufflen < 3)
	{
		idletime += 1000;
		if (idletime >= deadTimeout)
		{
			idletime = 0;
			glogger.warning(TEXT("browser seems dead"));
			return 2; // dead
		}
		return 0;
	}

#ifdef __LINUX__
	if (CheckEnds(rbuff, "(gdb) "))
		return 1;
#else
	// windbg
	if (rbuff[bufflen - 3] != '-' &&  // 防止 firefox 误报 （ xxx -> yyy）
		rbuff[bufflen - 2] == '>' && 
		rbuff[bufflen - 1] == ' ')
	{
		// 进程异常
		if (CheckC3Ret(rbuff))
		{
			glogger.warning(TEXT("break @ \"ret\""));			
			return 3;
		}

		// 软件中断，g
		if (CheckCCInt3(rbuff))
		{
			glogger.warning(TEXT("break @ \"int 3\""));
			return 3;
		}

		// No runnable debuggees
		if (strstr(rbuff, "No runnable debuggees") != NULL)
		{
			glogger.warning(TEXT("No runnable debuggees"));
			return 2;
		}

		return 1; // crash !!
	}
#endif

	return 0;
}
 int GetCrashInfo(char* logbuff, uint32_t logbuffsize, const tstring& crashpos,
	 char* rbuff, uint32_t rbuffsize,
	 HANDLE outputPipeR, HANDLE inputPipeW)
{
	logbuff[0] = 0;
	if (logbuffsize > strlen(logbuff) + 18)
		strcat(logbuff, "*** mixFuzzer ***\n");
	if (logbuffsize > strlen(logbuff) + strlen(rbuff))
		strcat(logbuff, rbuff);

	if (logbuffsize > strlen(logbuff) + 21)
		strcat(logbuff, "\n\n*** crash info ***\n");
#ifdef __LINUX__
	DebugCommand(inputPipeW, TEXT("i r\n"));
#else
	DebugCommand(inputPipeW, TEXT("r\n"));
#endif
	while (GetDebugInfo(outputPipeR, rbuff, rbuffsize) > 0)
	{
		glogger.debug2(StringToTString(string(rbuff)));
		if (logbuffsize > strlen(logbuff) + strlen(rbuff))
			strcat(logbuff, rbuff);
	}

	if (logbuffsize > strlen(logbuff) + 24)
		strcat(logbuff, "\n\n*** stack tracing ***\n");
#ifdef __LINUX__
	DebugCommand(inputPipeW, TEXT("bt\n"));
#else
	DebugCommand(inputPipeW, TEXT("kb\n"));
#endif
	while (GetDebugInfo(outputPipeR, rbuff, rbuffsize) > 0)
	{
		glogger.debug2(StringToTString(string(rbuff)));
		if (logbuffsize > strlen(logbuff) + strlen(rbuff))
			strcat(logbuff, rbuff);
	}

	if (logbuffsize > strlen(logbuff) + 23)
		strcat(logbuff, "\n\n*** module info ***\n");
#ifdef __LINUX__
#else
	tstring sCommandLine = TEXT("lmDvm ");
	sCommandLine.append(crashpos.substr(0, crashpos.find_first_of('!'))); // mshtml!xxx__xxx+0x1234
	sCommandLine.append(TEXT("\n"));
	DebugCommand(inputPipeW, sCommandLine);
#endif				
	while (GetDebugInfo(outputPipeR, rbuff, rbuffsize) > 0)
	{
		glogger.debug2(StringToTString(string(rbuff)));
		if (logbuffsize > strlen(logbuff) + strlen(rbuff))
			strcat(logbuff, rbuff);
	}
	return strlen(logbuff);
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
	tchar szEXEName[MAX_PATH] = { 0 };
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
#endif 
	return pids;
}

bool TerminateAllProcess(const tchar* pszProcessName)
{
	vector<uint32_t> pids = GetAllProcessId(pszProcessName, vector<uint32_t>());
	for (uint32_t pid : pids)
	{
		if (pid != 0)
		{
			glogger.debug2(TEXT("  -pid:%d"), pid);
#ifdef __LINUX__
			string s = "/bin/kill -9 " + to_string(pid);
			system(s.c_str());
#else
			HANDLE hProcess = OpenProcess(
				PROCESS_TERMINATE |
				PROCESS_QUERY_LIMITED_INFORMATION |
				SYNCHRONIZE, FALSE, pid);
			if (hProcess != NULL)
			{
				if (TerminateProcess(hProcess, 0) != 0)
				{
					WaitForSingleObject(hProcess, 1000);
				}
				CloseHandle(hProcess);
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
	return bRet != 0;
#endif
	return false;
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
	memset(&saServer, 0, sizeof(saServer));
	saServer.sin_family = AF_INET;
	saServer.sin_port = gcommon::g_htons(port);
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
	ret = recv(sock, buff, MAX_SENDBUFF_SIZE, MSG_WAITALL);
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
	saServer.sin_port = gcommon::g_htons(port);
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
					current->type = gcommon::g_ntohl(*(uint32_t*)(htmlTempl + i));
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
	saServer.sin_port = gcommon::g_htons(port);
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
	saServer.sin_port = gcommon::g_htons(port);
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

uint32_t LogFile(const tstring &outpath, const tstring &crashpos, const tstring& slash,
	const tstring &endstr, char* data, int datalen, time_t ct)
{
	if (data == NULL || datalen == 0)
		return 0;

	tstring filepath = outpath + crashpos + slash + to_tstring(ct) + endstr;
	FILE* htmlFile = tfopen(filepath.c_str(), TEXT("w"));
	if (htmlFile == NULL)
	{
		glogger.warning(TEXT("can not create html file: ") + crashpos + slash + to_tstring(ct) + endstr);
		filepath = outpath + TEXT("unknown") + slash +  to_tstring(ct) + endstr;
		htmlFile = tfopen(filepath.c_str(), TEXT("w"));
		if (htmlFile == NULL)
		{
			glogger.error(TEXT("can not create html file: unknown") + slash + to_tstring(ct) + endstr);
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
	usleep(ms * 1000);
#else
	Sleep(ms);
#endif
}