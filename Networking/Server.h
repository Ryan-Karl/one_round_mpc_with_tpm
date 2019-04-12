#ifndef SERVER_H
#define SERVER_H

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
#include <thread>

#include "NetworkCommon.h"

// link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")


class Server{
private:
	unsigned int port;
	WSADATA wsaData;
	struct addrinfo hints;
	SOCKET ListenSocket;

	int send_file(int * ret, char ** filename, SOCKET * ClientSocket);

public:
	Server(unsigned int p);
	int init() ;
	int broadcast(unsigned int num_connections, char ** filename);	

}


Server::Server(unsigned int p){
	port = p;
	ListenSocket = INVALID_SOCKET;
	ZeroMemory(&hints, sizeof(hints));
}

int Server::init(){
	// Initialize Winsock
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult)
	{
		printf("WSAStartup failed: %d\n", iResult);
		return 1;
	}

	//Initialize hints
	hints.ai_family = AF_INET;		// Internet address family is unspecified so that either an IPv6 or IPv4 address can be returned
	hints.ai_socktype = SOCK_STREAM;	//Use TCP
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	struct addrinfo	*result = NULL;
	// Resolve the local address and port to be used by the server
	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
	if (iResult)
	{
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for the server to listen for client connections
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET)
	{
		printf("Error at socket(): %d\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Bind the socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR)
	{
		printf("bind failed: %d", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	//Free up some memory
	freeaddrinfo(result);

	// Start listening
	if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR){
		printf("listen failed: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	return 0;

}

int Server::broadcast(unsigned int num_connections, char ** filename){
	std::thread * thread_list = new thread[num_connections];
	int * returns = new int[num_connections];
	SOCKET * ClientSockets = new ClientSockets[num_connections];
	for(unsigned int i = 0; i < num_connections; i++){
		ClientSockets[i] = INVALID_SOCKET;
		ClientSockets[i] = accept(ListenSocket, NULL, NULL);
		if (ClientSockets[i] == INVALID_SOCKET){
			printf("accept failed: %d\n", WSAGetLastError());
			//Keep this line? A single failure will end the whole system
			closesocket(ListenSocket);
			WSACleanup();
			return -1;
		}
		//Hope the passing by pointer works...
		//send_file closes the socket once the file is sent
		thread_list[i] = std::thread(&Server::send_file, this, &(returns[i]), filename, &(ClientSockets[i]));
	}
	//Join threads
	for(auto & x : thread_list){
		x.join();
	}
	//TODO more info if a connection fails
	for(int r : returns){
		if(!r){
			std::cout << "Error with connection " << r << std::endl;
			exit(1);
		}
	}

	delete[] thread_list;
	delete[] returns;
}

int Server::send_file(int * ret, char ** filename, SOCKET * ClientSocket){
	std::ifstream ifs(filename);
	if(!ifs.good()){
		std::cout << "Error opening file " << filename << std::endl;
		exit(1);
	}

	if (*ClientSocket == INVALID_SOCKET)
	{
		printf("accept failed: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return ret = -1;
	}

	char recvbuf[DEFAULT_BUFFER_LENGTH];
	int iSendResult;

	std::string fileData;
	while (std::getline(ifs, fileData)) {
		//Need newline plus null terminator
		char * msg = new char[fileData.size() + 2];
		std::copy(fileData.begin(), fileData.end(), msg);
		msg[fileData.size()] = '\n';
		msg[fileData.size()+1] = '\0';
		//Send data
		iSendResult = send(*ClientSocket, msg, fileData.size() + 2, 0);

		delete[] msg;

		if (iSendResult == SOCKET_ERROR) {
			printf("send failed: %d\n", WSAGetLastError());
			closesocket(*ClientSocket);
			WSACleanup();
			return ret = 1;
		}
	}
	closesocket(*ClientSocket);
	return 0;

}



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

	char recvbuf[DEFAULT_BUFFER_LENGTH];
	int iSendResult;

	std::string fileData;
	while (std::getline(ifs, fileData)) {
		//Need newline plus null terminator
		char * msg = new char[fileData.size() + 2];
		std::copy(fileData.begin(), fileData.end(), msg);
		msg[fileData.size()] = '\n';
		msg[fileData.size()+1] = '\0';
		//Send data
		iSendResult = send(ClientSocket, msg, fileData.size() + 2, 0);

		delete[] msg;

		if (iSendResult == SOCKET_ERROR) {
			printf("send failed: %d\n", WSAGetLastError());
			closesocket(ClientSocket);
			WSACleanup();
			return 1;
		}
	}
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

#endif