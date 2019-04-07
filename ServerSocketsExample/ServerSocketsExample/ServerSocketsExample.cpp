//#define WIN32_LEAN_AND_MEAN

// ServerSocketsExample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#pragma warning(disable : 4996)

#include "pch.h"


#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <fstream>
//using std::cout;
//using std::endl;
//using std::string;
//using std::ifstream;


// link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_PORT "27015"
#define DEFAULT_BUFFER_LENGTH	512


int accept_and_send(SOCKET & ListenSocket, std::ifstream & ifs) {
	// Accept a client socket
	SOCKET ClientSocket = accept(ListenSocket, NULL, NULL);

	if (ClientSocket == INVALID_SOCKET)
	{
		printf("accept failed: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return -1;
	}

	std::cout << "Accepted connection" << std::endl;

	char recvbuf[DEFAULT_BUFFER_LENGTH];
	int iSendResult;

	std::string fileData;
	while (std::getline(ifs, fileData)) {
		//Need newline plus null terminator
		char * msg = new char[fileData.size() + 2];
		std::copy(fileData.begin(), fileData.end(), msg);
		msg[fileData.size()] = '\n';
		msg[fileData.size()+1] = '\0';

		iSendResult = send(ClientSocket, msg, fileData.size() + 1, 0);

		delete[] msg;

		if (iSendResult == SOCKET_ERROR) {
			printf("send failed: %d\n", WSAGetLastError());
			closesocket(ClientSocket);
			WSACleanup();
			return 1;
		}

	}



	/*
	//  until the client shutdown the connection
	do {
		iResult = recv(ClientSocket, recvbuf, DEFAULT_BUFFER_LENGTH, 0);
		if (iResult > 0)
		{
			char msg[DEFAULT_BUFFER_LENGTH];
			memset(&msg, 0, sizeof(msg));
			strncpy(msg, recvbuf, iResult);

			printf("Received: %s\n", msg);

			iSendResult = send(ClientSocket, recvbuf, iResult, 0);

			if (iSendResult == SOCKET_ERROR)
			{
				printf("send failed: %d\n", WSAGetLastError());
				closesocket(ClientSocket);
				WSACleanup();
				return 1;
			}

			printf("Bytes sent: %ld\n", iSendResult);
		}
		else if (iResult == 0)
			printf("Connection closed\n");
		else
		{
			printf("recv failed: %d\n", WSAGetLastError());
			closesocket(ClientSocket);
			WSACleanup();
			//return 1;
		}
	} while (iResult > 0);

	*/

	closesocket(ClientSocket);
	return 0;
}

//First arg is file to send, second is number of parties
int main(int argc, char ** argv) {

	if (argc != 3) {
		std::cout << "No file given!" << std::endl;
		return 0;
	}
#define MIN_PARTIES 1
	if (atoi(argv[2]) < MIN_PARTIES) {
		std::cout << "Not enough parties: " << atoi(argv[2]) << std::endl;
		return 0;
	}

	WSADATA wsaData;

	// Initialize Winsock
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		printf("WSAStartup failed: %d\n", iResult);
		return 1;
	}

	struct addrinfo	*result = NULL,
		hints;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;		// Internet address family is unspecified so that either an IPv6 or IPv4 address can be returned
	hints.ai_socktype = SOCK_STREAM;	// Requests the socket type to be a stream socket for the TCP protocol
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the local address and port to be used by the server
	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
	if (iResult != 0)
	{
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	SOCKET ListenSocket = INVALID_SOCKET;

	// Create a SOCKET for the server to listen for client connections
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	if (ListenSocket == INVALID_SOCKET)
	{
		printf("Error at socket(): %d\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);

	if (iResult == SOCKET_ERROR)
	{
		printf("bind failed: %d", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	// To listen on a socket
	if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("listen failed: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	/*
	SOCKET ClientSocket;

	ClientSocket = INVALID_SOCKET;

	// Accept a client socket
	ClientSocket = accept(ListenSocket, NULL, NULL);

	if (ClientSocket == INVALID_SOCKET)
	{
		printf("accept failed: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	*/

	char recvbuf[DEFAULT_BUFFER_LENGTH];
	int iSendResult;

	unsigned int num_parties = atoi(argv[2]);
	for (unsigned int i = 0; i < num_parties; i++) {
		std::cout << "Starting upload " << i << std::endl;
		std::ifstream ifs (argv[1]);
		if (!ifs.good()) {
			std::cout << "Unspecified error opening file " << argv[1] << std::endl;
			return 0;
		}
		if (accept_and_send(ListenSocket, ifs)) {
			return 1;
		}
		std::cout << "Finished upload " << i << std::endl;
	}


	// Free the resouces
	closesocket(ListenSocket);
	WSACleanup();

	getchar();
	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
