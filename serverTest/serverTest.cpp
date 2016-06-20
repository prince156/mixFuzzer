// serverTest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <conio.h>
#include <Ws2tcpip.h>
#include "common.h"

#pragma comment(lib,"Ws2_32.lib")
#define MAX_SENDBUFF_SIZE 1024*200

int main(int argc, char** argv)
{
    char* buff = new char[MAX_SENDBUFF_SIZE];
    char* ip = "127.0.0.1";
    int port = 12228;

    if (argc == 3)
    {
        ip = argv[1];
        port = atoi(argv[2]);
    }
    printf("[##] target: %s:%d\n",ip,port);

    // Initialize Winsock
    WSADATA wsaData;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != NO_ERROR)
    {
        printf(("[##] WSAStartup failed with error: %d\n"), WSAGetLastError());
        return false;
    }    

    //构建地址信息  
    struct sockaddr_in saServer;
    saServer.sin_family = AF_INET;
    saServer.sin_port = htons(port);
    saServer.sin_addr.S_un.S_addr = gcommon::inet_ttol(ip);    

    int count = 0;
    printf("[##] test start, wait about 10s \n...\n");

    time_t dt = time(NULL);
	time_t dt_end;
	SYSTEMTIME tt, tt2;
	ULARGE_INTEGER ft, ft2;
    GetSystemTime(&tt);
    while(true)
    { 
        // socket
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
        {
            printf(("[##] socket failed with error: %d\n"), WSAGetLastError());
            WSACleanup();
            return 0;
        }

        ret = connect(sock, (struct sockaddr *)&saServer, sizeof(saServer));
        if (ret == SOCKET_ERROR)
        {
            printf(("[##] connect failed with error: %d\n"), WSAGetLastError());
            closesocket(sock);
            WSACleanup();
            return 0;
        }

        // 发送请求
        char* sendbuff = "GET / HTTP/1.1\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: Mozilla/5.0\r\nConnection: Keep-Alive\r\n\r\n";
        ret = send(sock, sendbuff, strlen(sendbuff), 0);
        if (ret == SOCKET_ERROR || ret != strlen(sendbuff))
        {
            printf(("[##] send failed with error: %d\n"), WSAGetLastError());
            break;
        }

        // 接收数据
        do {
            ret = recv(sock, buff, MAX_SENDBUFF_SIZE, 0);
            if (ret == SOCKET_ERROR)
            {
                printf(("[##] recv failed with error: %d\n"), WSAGetLastError());                
            }
        } while (ret == 0);

        //shutdown(sock, SD_BOTH);
        closesocket(sock);
        
        count++;
		dt_end = time(NULL);
        if (dt_end - dt > 10)
        {
            printf("[##] test end\n");
            break;
        }
    }
    GetSystemTime(&tt2);
	SystemTimeToFileTime(&tt, (FILETIME*)&ft);
	SystemTimeToFileTime(&tt2, (FILETIME*)&ft2);
	unsigned long long ms = (ft2.QuadPart - ft.QuadPart)/10000; // 1ms == 1000000ns, FILETIME use 100ns

	printf("[##] rate: %d c/s\n", count * 1000 / ms);
	printf("[press any key to exit ...]");
    exit(_getch());
}

