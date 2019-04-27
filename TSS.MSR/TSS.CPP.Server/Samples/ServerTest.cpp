//g++ ServerTest.cpp -o server ../tpm_src/*.o  -lgmp -lssl -lcrypto -g

#define NOMINMAX

//#include "pch.h"
#include <iostream>
//#include "../includes/NetworkUtils.h"
//#include "../includes/utilities.h"
//#include "../includes/TPMWrapper.h"
#include "NetworkUtils.h"
#include "utilities.h"
#include "TPMWrapper.h"


#include <iostream>
#include <fstream>
#include <string>
#include <string.h>
#include <cassert>

#define BASEFILE "basefile.txt"
#define ENCFILE "encfile.txt"
#define KEYFILE "keyfile.txt"
#define NUMPARTIES_DEFAULT 1
#define SERVER_TPM_PORT 2321

using namespace std;

//First arg is port, second is a string to encrypt
int main(int argc, char ** argv) {
	
	if (argc < 3) {
		cout << "First arg is port, second is a string to encrypt" << endl;
		return 0;
	}

	
  //Should not need to call init to start TPM connection
  //myTpm.init(atoi(argv[3]));
	Server s(atoi(argv[1]));
	if (s.init() || s.accept_connections(1)) {
		cout << "Failed server startup";
		return 1;
	}
	else {
		cout << "Server started" << endl;
	}
	//Get key from client
	char * keyStr;
	unsigned int strLen;

	if (s.recvString(0, strLen, (char **)&keyStr)) {
		cout << "Error getting keyStr" << endl;
	}
	else {
		cout << "Server received keyStr" << endl;
	}
	vector<BYTE> keyVec = stringToByteVec(keyStr, strLen);
	
	TPMWrapper myTpm;
	//myTpm.init(30000); //Unneeded for server (hopefully)
	TSS_KEY swKey = myTpm.s_importKey(keyVec);
	char * nd = "Notre Dame";
	std::vector<BYTE> ndVec = stringToByteVec(nd, 10);
	//Encrypt string
	std::vector<BYTE> encVec = myTpm.s_RSA_encrypt(swKey, ndVec);
	//string encStr = ByteVecToString(encVec);
	
	if (s.sendBuffer(0, encVec.size(), encVec.data())) {
		cout << "Error sending encrypted string" << endl;
	}
	else {
		cout << "Sent encrypted string" << endl;
	}
	
	s.stop();


	return 0;
}

