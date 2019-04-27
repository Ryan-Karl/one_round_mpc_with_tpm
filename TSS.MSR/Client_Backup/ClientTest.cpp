//g++ ClientTest.cpp -o client ../tpm_src/*.o  -lgmp -lssl -lcrypto -g
#define NOMINMAX

//#include "pch.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

//#include "../includes/TPMWrapper.h"
//#include "../includes/NetworkUtils.h"
//#include "../includes/utilities.h"

#include "NetworkUtils.h"
#include "utilities.h"
#include "TPMWrapper.h"

#define KEYFILE "keyfile.txt"
#define ENCFILE "encfile.txt"
#define DECFILE "decfile.txt"
#define NUMPARTIES_DEFAULT 1
#define CLIENT_TPM_PORT 30000

using namespace std;

//First arg is server port, second is TPM port, third is the host
int main(int argc, char ** argv) {


	if (argc < 3) {
		cout << "ERROR: provide a server and TPM port" << endl;
		return 0;
	}


	TPMWrapper myTPM;
	myTPM.init(atoi(argv[2]));
	//Get keys
	auto keyPair = myTPM.c_genKeys();
	//Send software key to server
	Client c(atoi(argv[1]), (argc >= 4 ? argv[3] : LOCALHOST));
	if (!c.init()) {
		cout << "Got connection" << endl;
	}
	else {
		cout << "Connection failed!" << endl;
		return 1;
	}
	std::vector<BYTE> keyVec = keyPair.first.ToBuf();
	if (!c.sendBuffer(keyVec.size(), keyVec.data())) {
		cout << "Client sent key vector" << endl;
	}
	else {
		cout << "ERROR in client sending key vector" << endl;
		return 1;
	}
	
	//Receive the encrypted message back from the server
	char * encStr;
	unsigned int encLen;
	c.recvBuffer((void **) &encStr, encLen);
	//Now decrypt the recieved string
	vector<BYTE> encVec = stringToByteVec(encStr, encLen);
	vector<BYTE> decVec = myTPM.c_RSA_decrypt(keyPair.second, encVec);
	string decrypted = ByteVecToString(decVec);
	
	cout << "Client decrypted message: " << decrypted << endl;

	return 0;
}
