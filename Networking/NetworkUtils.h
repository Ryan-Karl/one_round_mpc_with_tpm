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
//May not need these defines
#define INVALID_SOCKET (~0)
#define SOCKET_ERROR (-1)
#include <sys/types.h>
#include <sys/socket.h>
#elif defined(WIN32)
#include <WinSock2.h>
#include <WS2tcpip.h>
typedef socket_t SOCKET;
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
class NetworkNode{
protected:
	socket_t sock;
	unsigned int port;


  //TODO rewrite these so they can take in a client socket
	int sendBytes(socket_t inSock, unsigned int buffer_size, void * buffer){
		int bytesSent = 0;
		while(bytes_sent < buffer_size){
			if(send(inSock, buffer + bytesSent, buffer_size - bytesSent, 0) < 1){
				return 1;
			}
		}
		return 0;
	}
	//Assumes buffer contains at least buffer_size bytes
	int recvBytes(socket_t inSock, const unsigned int buffer_size, void * buffer){
		int bytesRead = 0;
		while(bytes_read < buffer_size){
			if(recv(inSock, buffer + bytesRead, buffer_size - bytesRead, 0) < 1){
				return 1;
			}
		}
		return 0;
	}

public:
	NetworkNode(unsigned int p_in): port(p_in){
		sock = INVALID_SOCKET;
	}

	int sendBuffer(socket_t inSock, unsigned int buffer_size, void * buffer){
		return sendBytes(inSock, sizeof(buffer_size), htonl(buffer_size)) 
			|| sendBytes(inSock, buffer_size, buffer);
	}

	int recvBuffer(socket_t inSock, void * buffer, int & len){
		unsigned int msgSize = 0;
		if(recvBytes(inSock, sizeof(msgSize), (void *) (&msgSize))){
			return 1;
		}
		len = ntohl(msgSize);
		buffer = new char[len];
		return recvBytes(inSock, len, (void *) buffer);
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

  int sendBuffer(unsigned int buffer_size, void * buffer){
    return NetworkNode::sendBuffer(sock, buffer_size, buffer);  
  }

  int recvBuffer(void * buffer, int & len){
    return recvBuffer(sock, buffer, len);
  }

	int init(){
    int iResult;
#ifdef WIN32
    WSADATA wasData;
   
   if(iResult = WSAStartup(MAKEWORD(2,2), &wsaData)){
     printf("WSAStartup failed: %d\n", iResult);
     return 1;
   }
#elif defined(__linux__)
//TODO linux startup, if needed
#endif

   struct addrinfo * result = NULL;
   struct addrinfo * ptr = NULL;
   struct addrinfo hints;
   
#ifdef WIN32
   ZeroMemory(&hints, sizeof(hints));
#elif defined(__linux__)
   memset(hints, 0, sizeof(hints));
#endif

   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
	 hints.ai_protocol = IPPROTO_TCP;
#elif defined(__linux__)
   //TODO fill in Linux network setup, if needed
#endif

   //Resolving server addr and port
  std::ostringstream convertPort;
  convertPort << port;

  if(iResult = getaddrinfo(servername, convertPort.str().c_str(), &hints, &result)){
    printf("getaddrinfo failed: %d\n", iResult);
#ifdef WIN32
		WSACleanup();
#endif
    return 1;
  }  
  ptr = result;

  //Create socket to connect - Hope this is platform-independent
  if((sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol)) == INVALID_SOCKET){
    printf("Error at socket(): %d\n", WSAGetLastError());
    freeaddrinfo(result);
#ifdef WIN32
    WSACleanup();
#endif
    return 1;
  }

  //Connect
  iResult = connect(sock, ptr->ai_addr, (int)ptr->ad_addrlen);
  if(iResult == SOCKET_ERROR){
#ifdef WIN32
    closeSocket(sock);
#elif defined(__linux__)
    close(sock);
#endif
    sock = INVALID_SOCKET;
  }
  
  freeaddrinfo(result);
  if(sock == INVALID_SOCKET){
    printf("Unable to connect to server!\n");
    WSACleanup();
    return 1; 
  }
  return 0;
  }

  int stop(){
    int result;
    //Shutdown and disable further sending of data
#ifdef WIN32
    result = shutdown(sock, SD_SEND);
#elif defined(__linux__)
    result = shutdown(sock, SHUT_RD);
#endif    
    if(result == SOCKET_ERROR){
      printf("shutdown failed: %d\n", WSAGetLastError());
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

  ~Client(){
    
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

  int init(){
    
	}

	int shutdown(){

	}

	//Need to return an error if server has already accepted connections
	int accept_connections(unsigned int num_cons){
		if(hasConnections){
			return 1;
		}
	}

}








#endif
