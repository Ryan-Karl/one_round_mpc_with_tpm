#ifndef NETWORKCOMMON_H
#define NETWORKCOMMON_H

#include <string>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>

#define DEFAULT_PORTNUM 27015
#define DEFAULT_PORT "27015"
#define DEFAULT_BUFFER_LENGTH	1024
#define LABELS_EXTENSION ".tsv"
#define FILE_DELIM '~'
#define 

typedef struct{
	unsigned int partyNum;
	SOCKET partySocket;
} PartyInfo;

int RecvFile(std::ofstream & of, SOCKET & ConnectSocket){
	int iResult = 1;
	while (iResult) {
		char recvbuf[DEFAULT_BUFFER_LENGTH];
		iResult = recv(ConnectSocket, recvbuf, DEFAULT_BUFFER_LENGTH, 0);
		of << recvbuf;
	}
	if (iResult == SOCKET_ERROR) {
		std::cerr << "Socket error in receiving file" << std::endl;
		return 1;
	}
	return 0;
}

int RecvDelimitedFiles(const std::vector<std::string> & filenames, SOCKET & ConnectSocket, char delim){
	std::ostringstream os;
	int iResult = 1;
	//Recieve all data, store in buffer
	//May not be the best for larger files...
	while (iResult) {
		char recvbuf[DEFAULT_BUFFER_LENGTH];
		iResult = recv(ConnectSocket, recvbuf, DEFAULT_BUFFER_LENGTH, 0);
		if (iResult == SOCKET_ERROR) {
			std::cerr << "Socket error in receiving file" << std::endl;
			return 1;
		}
		os << recvbuf;
	}
	//Output each delimited substring to the file
	for(const auto & fname : filenames){
		std::ofstream ofs(fname);
		std::string partial;
		if(!std::getline(os, partial, delim)){
			std::cerr << "Not enough filenames provided: " << filenames.size() << std::endl;
		}
		ofs << partial;
	}
	return 0;
}

int SendFile(int * ret, const std::string & filename, SOCKET & ClientSocket){
	std::ifstream ifs(filename);
	if(!ifs.good()){
		std::cout << "Error opening file " << filename << std::endl;
		exit(1);
	}

	if (ClientSocket == INVALID_SOCKET)
	{
		printf("accept failed: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return *ret = -1;
	}
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
			closesocket(*ClientSocket);
			WSACleanup();
			return *ret = 1;
		}
	}
	closesocket(ClientSocket);
	return *ret = 0;
}




#endif