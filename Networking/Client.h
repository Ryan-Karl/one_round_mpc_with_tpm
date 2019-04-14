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
	Client(const char * servername, unsigned int p)
	{
		port = p;
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
		std::ostringstream convertPort;
		convertPort << port;
		iResult = getaddrinfo(szServerName, convertPort.str().c_str(), &hints, &result);
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
	const char* szServerName;
	unsigned int port;
	SOCKET ConnectSocket;
};

//TODO also return string?
//Here partynum refers to the party we are recieving things from
int receive_file(int * ret, const std::string & hostname, 
	unsigned int port, unsigned int partynum){
	//Construct output filename
	std::string fname = BASE_LABELFILE;
	std::string partystr;
	std::ostringstream os;
	os << partynum;
	partystr = os.str();
	fname += partystr;
	fname += LABELS_EXTENSION;
	std::ofstream ofs(fname);
	if(!ofs.good()){
		std::cerr << "ERROR opening output file " << fname << std::endl;
		return *ret = 1;
	}
	char * host_cstr = new char(hostname.size()+1);
	memcpy(host_cstr, hostname.c_str(), hostname.size()+1);
	Client c(host_cstr, port);
	c.init();
	c.RecvFileNamed(fname);
	c.Stop();
	delete[] host_cstr;
	return *ret = 0;
}


#endif