#ifndef CLIENT_H
#define CLIENT_H
//#define WIN32_LEAN_AND_MEAN

// WindowsSocketsExperiments.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#pragma warning(disable : 4996)


//Client
#include "pch.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>
#include <fstream>
#include <string>

#include "NetworkCommon.h"

// link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")



class Client {
public:
	Client(char* servername, unsigned int p)
	{
		port = p;
		szServerName = servername;
		ConnectSocket = INVALID_SOCKET;
	}

	bool connect() {
		WSADATA wsaData;

		// Initialize Winsock
		int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0)
		{
			printf("WSAStartup failed: %d\n", iResult);
			return false;
		}

		struct addrinfo	*result = NULL,
			*ptr = NULL,
			hints;

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		// Resolve the server address and port
		iResult = getaddrinfo(szServerName, port, &hints, &result);
		if (iResult != 0)
		{
			printf("getaddrinfo failed: %d\n", iResult);
			WSACleanup();
			return false;
		}

		ptr = result;

		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

		if (ConnectSocket == INVALID_SOCKET)
		{
			printf("Error at socket(): %d\n", WSAGetLastError());
			freeaddrinfo(result);
			WSACleanup();
			return false;
		}

		// Connect to server
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);

		if (iResult == SOCKET_ERROR)
		{
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
		}

		freeaddrinfo(result);

		if (ConnectSocket == INVALID_SOCKET)
		{
			printf("Unable to connect to server!\n");
			WSACleanup();
			return false;
		}

		return true;
	};

	Client::~Client(){
		shutdown();
	}

	// Free the resouces
	void shutdown() {
		int iResult = shutdown(ConnectSocket, SD_SEND);

		if (iResult == SOCKET_ERROR)
		{
			printf("shutdown failed: %d\n", WSAGetLastError());
		}

		closesocket(ConnectSocket);
		WSACleanup();
	};

	// Send message to server
	bool Send(char* szMsg)
	{

		int iResult = send(ConnectSocket, szMsg, strlen(szMsg), 0);

		if (iResult == SOCKET_ERROR)
		{
			printf("send failed: %d\n", WSAGetLastError());
			Stop();
			return false;
		}

		return true;
	};

	// Receive message from server
	bool RecvFile(std::ofstream & of)
	{
		int iResult = 1;
		while (iResult) {
			char recvbuf[DEFAULT_BUFFER_LENGTH];
			iResult = recv(ConnectSocket, recvbuf, DEFAULT_BUFFER_LENGTH, 0);
			of << recvbuf;
		}
		if (iResult == SOCKET_ERROR) {
			std::cerr << "Socket error in receiving file" << std::endl;
			return false;
		}

		return true;
	}

	bool RecvFileNamed(const std::string & outfile){
		std::ofstream ofs(outfile);
		if(!ofs.good()){
			std::cerr << "ERROR with output file " << outfile << std::endl;
			return false;
		}
		return RecvFile(ofs);
	}

	SOCKET getSocket(){
		return ConnectSocket;
	}
	

private:
	char* szServerName;
	unsigned int port;
	SOCKET ConnectSocket;
};


#endif