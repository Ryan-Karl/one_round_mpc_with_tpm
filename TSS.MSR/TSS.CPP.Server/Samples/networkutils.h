#ifndef NETWORKUTILS_H
#define NETWORKUTILS_H

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>
#include <cstring>



#ifdef __linux__
typedef int socket_t;
//May not need these defines
#define INVALID_SOCKET (~0)
#define SOCKET_ERROR (-1)
//Are these *nix-only?
#include <unistd.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#elif defined(WIN32)
#include <WinSock2.h>
#include <WS2tcpip.h>
typedef SOCKET socket_t;
#else
#error Unsupported operating system, supported systems are Linux and Windows
#endif

#define DEFAULT_PORTNUM 27015
#define DEFAULT_PORT "27015"
#define DEFAULT_BUFFER_LENGTH	1024
#define LABELS_EXTENSION ".tsv"
#define FILE_DELIM '~'
#define KEYBUFFER 128
#define BASE_LABELFILE "labels_"
#define LOCALHOST "127.0.0.1"

//Abstract base class
class NetworkNode {
protected:
	socket_t sock;
	unsigned int port;

	int sendBytes(socket_t inSock, unsigned int buffer_size, const void * buffer) {
		int bytesSent = 0;
		int sent_tmp = 0;
		while (bytesSent < buffer_size) {
			if ((sent_tmp = send(inSock, (char*)buffer + bytesSent, buffer_size - bytesSent, 0)) < 0) {
				return 1;
			}
			bytesSent += sent_tmp;
		}
		return 0;
	}
	//Assumes buffer contains at least buffer_size bytes
	int recvBytes(socket_t inSock, const unsigned int buffer_size, void * buffer) {
		int bytesRead = 0;
		int read_tmp = 0;
		while (bytesRead < buffer_size) {
			if ((read_tmp = recv(inSock, (char*)buffer + bytesRead, buffer_size - bytesRead, 0)) < 0) {
				return 1;
			}
			bytesRead += read_tmp;
		}
		return 0;
	}

public:

	NetworkNode(unsigned int p_in) : port(p_in) {
		sock = INVALID_SOCKET;
	}

	int sendString(socket_t inSock, unsigned int str_len, const char * str) {
		return sendBuffer(inSock, str_len, (const void*)str);
	}

	int recvString(socket_t inSock, unsigned int & str_len, char ** strloc) {
		return recvBuffer(inSock, str_len, (void **)strloc);
	}

	int sendByteVec(socket_t inSock, const std::vector<BYTE> & v) {
		unsigned int vecLen = v.size();
		return sendBytes(inSock, sizeof(vecLen), &vecLen) ||
			sendBytes(inSock, v.size(), v.data());
	}

	int recvByteVec(socket_t inSock, std::vector<BYTE> & v) {
		v.clear();
		unsigned int msgSize = 0;
		if (recvBytes(inSock, sizeof(msgSize), (void *)&msgSize)) {
			return 1;
		}
		msgSize = ntohl(msgSize);
		v.resize(msgSize);
		return recvBytes(inSock, msgSize, v.data());
	}

	int sendBuffer(socket_t inSock, unsigned int buffer_size, const void * buffer) {
		int size_out = htonl(buffer_size);
		return sendBytes(inSock, sizeof(size_out), &size_out)
			|| sendBytes(inSock, buffer_size, buffer);
	}

	int recvBuffer(socket_t inSock, unsigned int & len, void ** buffer) {
		unsigned int msgSize = 0;
		if (recvBytes(inSock, sizeof(msgSize), (void *)(&msgSize))) {
			return 1;
		}
		len = ntohl(msgSize);
		*buffer = new char[len];
		return recvBytes(inSock, len, (void *)*buffer);
	}


	virtual int init() = 0;
	virtual int stop() = 0;
};

class Client : NetworkNode {
private:
	const char * servername;

public:

	Client(unsigned int p_in, const char * servername_in) :
		NetworkNode(p_in), servername(servername_in) {}

	int sendBuffer(unsigned int buffer_size, void * buffer) {
		return NetworkNode::sendBuffer(sock, buffer_size, buffer);
	}

	int recvBuffer(void ** buffer, unsigned int & len) {
		return NetworkNode::recvBuffer(sock, len, buffer);
	}

	int sendString(unsigned int str_len, const char * str) {
		return NetworkNode::sendString(sock, str_len, str);
	}

	int recvString(unsigned int & str_len, char ** strloc) {
		return NetworkNode::recvString(sock, str_len, strloc);
	}

	int sendByteVec(const std::vector<BYTE> & v) {
		return NetworkNode::sendByteVec(sock, v);
	}

	int recvByteVec(std::vector<BYTE> & v) {
		return NetworkNode::recvByteVec(sock, v);
	}

	int init() {
		int iResult;
#ifdef WIN32
		WSADATA wsaData;

		if (iResult = WSAStartup(MAKEWORD(2, 2), &wsaData)) {
			printf("WSAStartup failed: %d\n", iResult);
			return 1;
		}
		//TODO linux startup, if needed
#endif

		struct addrinfo *result = NULL;
		struct addrinfo *ptr = NULL;
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));

		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		//TODO fill in Linux network setup, if needed

		//Resolving server addr and port
		std::ostringstream convertPort;
		convertPort << port;

		if (iResult = getaddrinfo(servername, convertPort.str().c_str(), &hints, &result)) {
			printf("getaddrinfo failed: %d\n", iResult);
#ifdef WIN32
			WSACleanup();
#endif
			return 1;
		}
		ptr = result;

		//Create socket to connect - Hope this is platform-independent
		if ((sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol)) == INVALID_SOCKET) {
#ifdef WIN32	    
			printf("Error at socket(): %d\n", WSAGetLastError());
			freeaddrinfo(result);
			WSACleanup();
#endif
			freeaddrinfo(result);
			return 1;
		}

		//Connect
		iResult = connect(sock, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
#ifdef WIN32
			closesocket(sock);
#elif defined(__linux__)
			close(sock);
#endif
			sock = INVALID_SOCKET;
		}

		freeaddrinfo(result);
		if (sock == INVALID_SOCKET) {
			printf("Unable to connect to server!\n");
#ifdef WIN32	    
			WSACleanup();
#endif	    
			return 1;
		}
		return 0;
	}

	int stop() {
		int result;
		//Shutdown and disable further sending of data
#ifdef WIN32
		result = shutdown(sock, SD_SEND);
#elif defined(__linux__)
		result = shutdown(sock, SHUT_RD);
#endif    
		if (result == SOCKET_ERROR) {
#ifdef WIN32    	
			printf("shutdown failed: %d\n", WSAGetLastError());
#endif      
			return 1;
		}
#ifdef WIN32
		closesocket(sock);
		WSACleanup();
#elif defined(__linux__)
		close(sock);
#endif
		return 0;
	}

	~Client() {
		stop();
	}

};

class Server : NetworkNode {
private:
	unsigned int num_connections;
	socket_t * connections;

public:

	Server(unsigned int p_in) : NetworkNode(p_in) {
		num_connections = 0;
		connections = nullptr;
	}

	bool hasConnections() {
		return(num_connections && (connections != nullptr));
	}

	int init() {
		int iResult = 0;
#ifdef WIN32  		
		WSADATA wsaData;
		if (iResult = WSAStartup(MAKEWORD(2, 2), &wsaData)) {
			printf("WSAStartup failed: %d\n", iResult);
			return 1;
		}
#endif		
		//Hints
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;
		//Get result w/ address and port of server
		struct addrinfo * result = NULL;
		std::ostringstream convertPort;
		convertPort << port;
		if (iResult = getaddrinfo(NULL, convertPort.str().c_str(), &hints, &result)) {
			printf("getaddrinfo failed: %d\n", iResult);
#ifdef WIN32			
			WSACleanup();
#endif			
			return 1;
		}
		//Create socket
		sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
		if (sock == INVALID_SOCKET) {
#ifdef WIN32			
			printf("Error at socket(): %d\n", WSAGetLastError());
			freeaddrinfo(result);
			WSACleanup();
#elif defined(__linux__)
			printf("Error creating socket");
#endif			
			return 1;
		}
		//Bind socket
		if (bind(sock, result->ai_addr, result->ai_addrlen) == SOCKET_ERROR) {
#ifdef WIN32			
			printf("bind failed: %d", WSAGetLastError());
			freeaddrinfo(result);
			closesocket(sock);
			WSACleanup();
#elif defined(__linux__)
			printf("Error binding socket");
			close(sock);
#endif			
			return 1;
		}
		//Clear up addr info
		freeaddrinfo(result);
		//Start listening (connections are later)
		if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
#ifdef WIN32			
			printf("listen failed: %d\n", WSAGetLastError());
			closesocket(sock);
			WSACleanup();
#elif defined(__linux__)
			printf("Error listening");
			close(sock);
#endif			
			return 1;
		}

		return 0;
	}

	~Server() {
		stop();
	}

	int stop() {
		if (!this->hasConnections()) {
			return 0;
		}
		for (unsigned int i = 0; i < num_connections; i++) {
#ifdef WIN32			
			closesocket(connections[i]);
#elif defined(__linux__)
			close(connections[i]);
#endif			
		}
#ifdef WIN32
		closesocket(sock);
		WSACleanup();
#elif defined(__linux__)
		close(sock);
#endif		
		delete[] connections;
		connections = nullptr;
		num_connections = 0;
		return 0;
	}

	//Need to return an error if server has already accepted connections
	int accept_connections(unsigned int num_cons) {
		//Error if we already have connections
		if (hasConnections() || (!num_cons)) {
			return 1;
		}
		//Allocate dynamic array of connections
		num_connections = num_cons;
		connections = new socket_t[num_connections];
		for (unsigned int i = 0; i < num_connections; i++) {
			connections[i] = INVALID_SOCKET;
			connections[i] = accept(sock, NULL, NULL);
			if (connections[i] == INVALID_SOCKET) {
#ifdef WIN32
				printf("accept failed: %d\n", WSAGetLastError());
				//Keep this line? A single failure will end the whole system
				closesocket(connections[i]);
#elif defined(__linux__)
				printf("Error accepting connection");
				close(connections[i]);
#endif				
				return 1;
			}
		}
		return 0;
	}

	int sendBuffer(unsigned int party, unsigned int buffer_size, void * buffer) {
		if (!hasConnections()) {
			std::cerr << "ERROR: No connections initialized before send" << std::endl;
			return 1;
		}
		if (party >= num_connections) {
			std::cerr << "ERROR: Connection out of bounds: " << party << std::endl;
			return 1;
		}
		return NetworkNode::sendBuffer(connections[party], buffer_size, buffer);
	}

	int recvBuffer(unsigned int party, void ** buffer, unsigned int & len) {
		if (!hasConnections()) {
			std::cerr << "ERROR: No connections initialized before send" << std::endl;
			return 1;
		}
		if (party >= num_connections) {
			std::cerr << "ERROR: Connection out of bounds: " << party << std::endl;
			return 1;
		}
		return NetworkNode::recvBuffer(connections[party], len, buffer);
	}


	int sendString(unsigned int conn, unsigned int str_len, const char * str) {
		return NetworkNode::sendString(connections[conn], str_len, str);
	}

	int recvString(unsigned int conn, unsigned int & str_len, char ** strloc) {
		return NetworkNode::recvString(connections[conn], str_len, strloc);
	}

	int sendByteVec(unsigned int conn, const std::vector<BYTE> & v) {
		return NetworkNode::sendByteVec(connections[conn], v);
	}

	int recvByteVec(unsigned int conn, std::vector<BYTE> & v) {
		return NetworkNode::recvByteVec(connections[conn], v);
	}


};


#endif
