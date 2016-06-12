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
    printf("target: %s:%d\n",ip,port);

    // Initialize Winsock
    WSADATA wsaData;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != NO_ERROR)
    {
        printf(("WSAStartup failed with error: %d\n"), WSAGetLastError());
        return false;
    }    

    //构建地址信息  
    struct sockaddr_in saServer;
    saServer.sin_family = AF_INET;
    saServer.sin_port = htons(port);
    saServer.sin_addr.S_un.S_addr = gcommon::inet_ttol(ip);    

    int count = 0;
    printf("## test start\n");

    WORD dsec, dmsec;
    time_t dt = time(NULL);
    SYSTEMTIME tt,tt2;
    GetSystemTime(&tt);
    while(true)
    { 
        // socket
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
        {
            printf(("socket failed with error: %d\n"), WSAGetLastError());
            WSACleanup();
            return 0;
        }

        ret = connect(sock, (struct sockaddr *)&saServer, sizeof(saServer));
        if (ret == SOCKET_ERROR)
        {
            printf(("connect failed with error: %d\n"), WSAGetLastError());
            closesocket(sock);
            WSACleanup();
            return 0;
        }

        // 发送请求
        char* sendbuff = "GET / HTTP/1.1\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: Mozilla/5.0\r\nConnection: Keep-Alive\r\n\r\n";
        ret = send(sock, sendbuff, strlen(sendbuff), 0);
        if (ret == SOCKET_ERROR || ret != strlen(sendbuff))
        {
            printf(("send failed with error: %d\n"), WSAGetLastError());
            break;
        }

        // 接收数据
        do {
            ret = recv(sock, buff, MAX_SENDBUFF_SIZE, 0);
            if (ret == SOCKET_ERROR)
            {
                printf(("recv failed with error: %d\n"), WSAGetLastError());                
            }
        } while (ret == 0);

        //shutdown(sock, SD_BOTH);
        closesocket(sock);
        
        count++;
        if (time(NULL) - dt > 10)
        {
            printf("## test end\n");
            break;
        }
    }
    GetSystemTime(&tt2);
    if (tt2.wSecond <= tt.wSecond)
    {
        dsec = 0;
        dmsec = 0;
    }
    else if (tt2.wMilliseconds < tt.wMilliseconds)
    {
        dsec = tt2.wSecond - tt.wSecond - 1;
        dmsec = tt2.wSecond + 1000 - tt.wMilliseconds;
    }
    else
    {
        dsec = tt2.wSecond - tt.wSecond;
        dmsec = tt2.wMilliseconds - tt.wMilliseconds;
    }
    printf("time used %d.%d sec for %d connections\n", dsec, dmsec, count);

    exit(_getch());
}

