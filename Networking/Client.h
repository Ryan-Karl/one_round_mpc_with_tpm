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
	Client(char* servername)
	{
		szServerName = servername;
		ConnectSocket = INVALID_SOCKET;
	}

	bool Start() {
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
		iResult = getaddrinfo(szServerName, DEFAULT_PORT, &hints, &result);
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

	// Free the resouces
	void Stop() {
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
	

private:
	char* szServerName;
	SOCKET ConnectSocket;
};

//Takes in a filename to write to
int main(int argc, CHAR* argv[])
{

	if (argc != 2) {
		std::cout << "No filename given as input!" << std::endl;
		return 0;
	}

	std::string msg;
	//TODO take in string as parameter
	std::string ip = "127.0.0.1";
	char * ip_pointer = new char[ip.size() + 1];
	std::copy(ip.begin(), ip.end(), ip_pointer);
	ip_pointer[ip.size()] = '\0'; // don't forget the terminating 0

	Client client(ip_pointer);

	if (!client.Start())
		return 1;

	std::ofstream os(argv[1]);
	if (!os.good()) {
		std::cout << "Error with file " << argv[1] << std::endl;
		return 1;
	}
	if (!client.RecvFile(os, std::cout)) {
		std::cout << "Error sending file";
		return 1;
	}

	client.Stop();

	// don't forget to free the string after finished using it
	delete[] ip_pointer;

	return 0;
}


#endif