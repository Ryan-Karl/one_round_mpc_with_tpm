#ifndef NETWORKCOMMON_H
#define NETWORKCOMMON_H

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>

#define DEFAULT_PORTNUM 27015
#define DEFAULT_PORT "27015"
#define DEFAULT_BUFFER_LENGTH	1024
#define LABELS_EXTENSION ".tsv"
#define FILE_DELIM '~'
#define KEYBUFFER 128
#define BASE_LABELFILE "labels_"

#ifdef WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>



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

//Sends only a single file
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
	//closesocket(ClientSocket);
	return *ret = 0;
}

//TODO add error checks
int broadcast_file(int * ret, const std::string & filename, unsigned int num_connections){
	Server s(port);
	s.init();
	s.accept_connections();
	std::vector<std::string> fname_v;
	fname_v.emplace_back(filename);
	s.broadcast_files(fname_v);
	return *ret = 0;
}

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
	c.shutdown();
	delete[] host_cstr;
	return *ret = 0;
}



int broadcast_and_receive(const std::vector<std::string> & hostnames, const std::vector<unsigned int> & ports,
 const std::string & filename, unsigned int port, unsigned int partynum){
	//Error checks
	if(hostnames.size() != ports.size() || hostnames.size() < 2 || partynum >= hostnames.size()){
		std::cerr << "ERROR: hostnames/ports" << std::endl;
		return 1;
	}
	//Start server thread
	int thread_ret = 0;
	std::thread server_thread(&broadcast_file, thread_ret, filename, hostnames.size()-1);
	//Start client threads
	std::thread * client_threads = new std::thread[hostnames.size()];
	int * rets = new int[hostnames.size()];
	for(unsigned int i = 0; i < hostnames.size(); i++){
		if(i == partynum){
			continue;
		}
		client_threads[i] = std::thread(&receive_file, &(rets[i]), hostnames[i], ports[i], i);
	}
	//Join threads

	for(auto & x : client_threads){
		x.join();
	}
	server_thread.join();

	for(const int & r : rets){
		if(r){
			std::cerr << "ERROR returning from client " << std::endl;
			return 1;
		}
	}
	if(thread_ret){
		std::cerr << "ERROR returning from server" << std::endl;
	}
	delete[] client_threads;
	delete[] rets;
	return 0;
}


void outputToStream(std::ostream & os, const std::vector<BYTE> & bv){
	os << std::hex;
	for(size_t i = 0; i < bv; i++){
		os << bv[i];
		/*
		if((i%4) == 3){
			os << " ";
		}
		*/
	}
}



#else
typedef unsigned char BYTE;
#endif //End of Windows-only code

//Get RSA key from keyfile
//TODO set parameters based on key size - hardcoded right now
//TODO finish
std::vector<BYTE> keyFromFile(const std::string & filename){
	std::string str;
	std::vector<BYTE> vec;
	std::ifstream ifs(filename);
	if(!ifs.good()){
		std::cerr << "ERROR: could not read from file " << filename << std::endl;
	}
	vec.reserve(KEYBUFFER);
	while(ifs >> str){
		if(str == "buffer"){
			break;
		}
	}
	ifs >> str; //Read in the =
	for(unsigned int i = 0; i < 32; i++){
		ifs >> str;
		if(!i){
			str = str.substr(1, str.size()-1);
		}
		else{
			if(i == 31){
				str = str.substr(0, str.size()-1);
			}
		}
		std::istringstream iss(str);
		unsigned int holder = 0;
		iss >> std::hex >> holder;
		vec.push_back((BYTE)(holder >> 24) & 0xFF);
		vec.push_back((BYTE)(holder >> 16) & 0xFF);
		vec.push_back((BYTE)(holder >> 8) & 0xFF);
		vec.push_back((BYTE) holder & 0xFF);
	}

	return vec;
}






#endif