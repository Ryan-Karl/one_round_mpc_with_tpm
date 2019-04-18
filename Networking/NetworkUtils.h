#ifndef NETWORKUTILS_H
#define NETWORKUTILS_H

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>

#ifdef __linux__
typedef socket_t int;
#include <sys/types.h>
#include <sys/socket.h>
#elif defined(WIN32)
#include <WinSock2.h>
#include <WS2tcpip.h>
typedef socket_t SOCKET;
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
class NetworkNode{
protected:
	socket_t sock;
	unsigned int port;
public:
	NetworkNode(unsigned int p_in): port(p_in){
		sock = INVALID_SOCKET;
	}
	int sendBytes(unsigned int buffer_size, void * buffer){
		int bytesSent = 0;
		while(bytes_sent < buffer_size){
			if(send(sock, buffer + bytesSent, buffer_size - bytesSent, 0) < 1){
				return 1;
			}
		}
		return 0;
	}
	//Assumes buffer contains at least buffer_size bytes
	int recvBytes(const unsigned int buffer_size, void * buffer){
		int bytesRead = 0;
		while(bytes_read < buffer_size){
			if(recv(sock, buffer + bytesRead, buffer_size - bytesRead, 0) < 1){
				return 1;
			}
		}
		return 0;
	}

	int sendBuffer(unsigned int buffer_size, void * buffer){
		return sendBytes(sizeof(buffer_size), buffer_size) 
			|| sendBytes(buffer_size, buffer);
	}

	int recvBuffer(void * buffer, int & len){
		unsigned int msgSize = 0;
		if(recvBytes(sizeof(msgSize), (void *) (&msgSize))){
			return 1;
		}
		len = ntohl(msgSize);
		buffer = new char[len];
		return recvBytes(len, (void *) buffer);
	}


	virtual int init() = 0;
	virtual int stop() = 0;
};

class Client: NetworkNode{
private:	
	const char * servername;

public:	

	Client(unsigned int p_in, const char * servername_in):
	 NetworkNode(p_in), servername(servername_in){}

	 int init(){

	 }

};

class Server: NetworkNode{
private:
	unsigned int num_connections;
	socket_t * connections;

public:

	Server(unsigned int p_in): NetworkNode(p_in) {
		num_connections = 0;
		connections = nullptr;
	}

	bool hasConnections(){
		return((!num_connections) && (connections == nullptr));
	}	

	int shutdown(){

	}

	int init(){

	}

	//Need to return an error if server has already accepted connections
	int accept_connections(unsigned int num_cons){
		if(hasConnections){
			return 1;
		}
	}

}








#endif