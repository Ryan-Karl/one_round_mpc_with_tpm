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
#include <vector>

#include "NetworkCommon.h"

// link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")


class Server{
private:
	unsigned int port;
	WSADATA wsaData;
	struct addrinfo hints;
	SOCKET ListenSocket;
	unsigned int num_parties;
	PartyInfo * parties;
	std::string circuit_filename;


	//int send_file(int * ret, char * filename, SOCKET * ClientSocket);
	int start_key_threads();


public:
	Server(unsigned int p);
	~Server(){
		close_connections();
	}	
	
	int init() ;
	//int broadcast(unsigned int num_connections, char * filename);
	int receive_key(unsigned int party, int * ret);
	int send_files(unsigned int party, const std::vector<std::string> & filenames, int * ret);	

	

	void close_connections();
	int accept_connections(unsigned int num_connections);
	int broadcast_files(const std::vector<std::string> & filenames);
	int start_key_threads(unsigned int num_connections);

	static std::string key_filename(unsigned int party){
		std::string s = "keyfile_";
		std::ostringstream os;
		os << party;
		s += os.str();
		s += ".txt";
		return s;
	}

	static std::string labels_filename(unsigned int party){
		std::string s = "labels_";
		std::ostringstream os;
		os << party;
		s += os.str();
		s += LABELS_EXTENSION;
		return s;
	}

};



void Server::close_connections(){
	if(parties == nullptr){return;}
	for(unsigned int i = 0; i < num_parties; i++){
		closesocket(parties[i].partySocket);
	}
	closesocket(ListenSocket);
	WSACleanup();
	delete[] parties;
	parties = nullptr;
	return;
}


Server::Server(unsigned int p): port(p){
	ListenSocket = INVALID_SOCKET;
	ZeroMemory(&hints, sizeof(hints));
	parties = nullptr;
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
	//iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	//TODO check bind for errors - won't convert to int
	bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	/*
	if (iResult == SOCKET_ERROR)
	{
		printf("bind failed: %d", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	*/
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

//Receives a key as a file
int Server::receive_key(unsigned int party, int * ret){
	std::string keyfile = Server::key_filename(party);
	std::ofstream ofs(keyfile); //Need to init with C string?
	return *ret = RecvFile(ofs, parties[party].partySocket);
}

//Spins off threads to get key files
int Server::start_key_threads(unsigned int num_connections){
	std::thread * thread_list = new std::thread[num_connections];
	int * returns = new int[num_connections];
	for(unsigned int i = 0; i < num_connections; i++){
		//Hope the passing by pointer works...
		thread_list[i] = std::thread(&Server::receive_key, this, i, &(returns[i]));
	}
	//Join threads
	for (unsigned int j = 0; j < num_connections; j++) {
		thread_list[j].join();
	}
	//TODO more info if a connection fails
	for (unsigned int k = 0; k < num_connections; k++) {
		if(returns[k]){
			std::cout << "Error with connection " << returns[k] << std::endl;
			exit(1);
		}
	}
	//Don't close or clear sockets or related, as we still have sending to do
	delete[] thread_list;
	delete[] returns;
	return 0;
}

//Accepts connections
int Server::accept_connections(unsigned int num_connections){
	/*
	if(num_connections < 2){
		std::cerr << "Not enough parties: " << num_connections << std::endl;
		return 1;
	}
	*/

	//Allocate room for parties
	parties = new PartyInfo[num_connections];
	num_parties = num_connections;

	//Accept connections
	for(unsigned int i = 0; i < num_connections; i++){
		parties[i].partySocket = INVALID_SOCKET;
		parties[i].partySocket = accept(ListenSocket, NULL, NULL);
		if (parties[i].partySocket == INVALID_SOCKET){
			printf("accept failed: %d\n", WSAGetLastError());
			//Keep this line? A single failure will end the whole system
			closesocket(ListenSocket);
			WSACleanup();
			return -1;
		}
	}
	return 0;
}

int Server::send_files(unsigned int party, const std::vector<std::string> & filenames, int * ret){
	int scrap;
	std::string delim_str = "~";
	delim_str[0] = FILE_DELIM;
	int iSendResult;
	for(size_t i = 0; i < filenames.size(); i++){
		//Send file
		if(SendFile(ret, filenames[i], parties[party].partySocket)){
			std::cerr << "Error sending " << filenames[i] << " to party " << party << std::endl;
			return *ret = 1;
		}
		
		//Send delimiter
		iSendResult = send(parties[party].partySocket, delim_str.c_str(), 2, 0);
		if (iSendResult == SOCKET_ERROR) {
			printf("send failed: %d\n", WSAGetLastError());
			closesocket(parties[party].partySocket);
			WSACleanup();
			return *ret = 1;
		}
		std::cout << "Sent file " << filenames[i] << std::endl;
	}
	return *ret = 0;
}

//Spins off threads to send files
int Server::broadcast_files(const std::vector<std::string> & filenames){
	std::thread * thread_list = new std::thread[num_parties];
	int * returns = new int[num_parties];

	for(unsigned int i = 0; i < num_parties; i++){
		//Hope the passing by pointer works...
		thread_list[i] = std::thread(&Server::send_files, this, i, filenames, &(returns[i]));
	}
	//Join threads
	for (unsigned int j = 0; j < num_parties; j++) {
		thread_list[j].join();
	}
	//TODO more info if a connection fails
	for (unsigned int k = 0; k < num_parties; k++) {
		if (returns[k]) {
			std::cout << "Error with connection " << returns[k] << std::endl;
			exit(1);
		}
	}

	//Don't close or clear sockets or related, as we still have sending to do
	delete[] thread_list;
	delete[] returns;
	return 0;
}

//TODO add error checks
int broadcast_file(int * ret, const std::string & filename, unsigned int num_connections, unsigned int port){
	Server s(port);
	s.init();
	s.accept_connections(num_connections);
	std::vector<std::string> fname_v;
	fname_v.emplace_back(filename);
	s.broadcast_files(fname_v);
	return *ret = 0;
}


#endif