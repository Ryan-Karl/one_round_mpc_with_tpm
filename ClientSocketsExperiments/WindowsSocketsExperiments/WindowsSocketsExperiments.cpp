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

// link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_PORT "27015" 
#define DEFAULT_BUFFER_LENGTH	512

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
			std::cout << "Socket error in receiving file" << std::endl;
		}

		return true;
		/*
		char recvbuf[DEFAULT_BUFFER_LENGTH];
		int iResult = recv(ConnectSocket, recvbuf, DEFAULT_BUFFER_LENGTH, 0);

		if (iResult > 0)
		{
			char msg[DEFAULT_BUFFER_LENGTH];
			memset(&msg, 0, sizeof(msg));
			strncpy(msg, recvbuf, iResult);

			printf("Received: %s\n", msg);

			return true;
		}


		return false;

		*/
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
	//char* ip = "127.0.0.1";

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
	if (!client.RecvFile(os)) {
		std::cout << "Error sending file";
		return 1;
	}

	client.Stop();

	getchar();


	// don't forget to free the string after finished using it
	delete[] ip_pointer;

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
