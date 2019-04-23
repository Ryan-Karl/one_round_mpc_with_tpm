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

#define BASEFILE "basefile.txt"
#define ENCFILE "encfile.txt"
#define KEYFILE "keyfile.txt"
#define NUMPARTIES_DEFAULT 1
#define SERVER_TPM_PORT 2321

using namespace std;

//First arg is port, second is a string to encrypt, third is the TPM port
int main(int argc, char ** argv) {
	
	if (argc < 4) {
		cout << "First arg is port, second is a string to encrypt, third is the TPM port" << endl;
		return 0;
	}

	TPMWrapper myTpm(atoi(argv[3]));
	Server s(atoi(argv[1]));
	if (s.init() || s.accept_connections(1)) {
		cout << "Failed server startup";
		return 1;
	}
	else {
		cout << "Server started" << endl;
	}
	char * keystr;
	unsigned int strLen;
	if (s.recvString(0, strLen, (char **)&keystr)) {
		cout << "Error getting key string" << endl;
	}
	else {
		cout << "Server received key string" << endl;
	}
	
	
	string jsonStr(keystr);
	cout << "Key string size: " << jsonStr.size() << endl;
	auto key = myTpm.s_readKey(jsonStr);
	vector<BYTE> pad = { 1,2,3,4,5 };
	vector<BYTE> toEncrypt = stringToByteVec(argv[2], strlen(argv[2]));
	vector<BYTE> encryptedVec = myTpm.s_RSA_encrypt(toEncrypt, key, pad);
	string encStr = ByteVecToString(encryptedVec);
	if (s.sendString(0, encStr.size() + 1, encStr.c_str())) {
		cout << "Error sending encrypted string" << endl;
	}
	else {
		cout << "Sent encrypted string" << endl;
	}
	s.stop();



	
	/*
	Client c(LOCALHOST, DEFAULT_PORTNUM);
	if (!c.Start()) {
		cout << "Error starting client" << endl;
		return 1;
	}
	//Accept plaintext, then the key
	vector<string> filenames;
	filenames.push_back(BASEFILE);
	filenames.push_back(KEYFILE);
	SOCKET mySock = c.getSocket();
	RecvDelimitedFiles(filenames, mySock);
  cout << "Received files" << endl;
  c.Stop();
  //Start server immediately
  Server s(DEFAULT_PORTNUM);
  if (s.init()) {
	  cout << "ERROR: server init" << endl;
  }
  else { cout << "Started server" << endl; }
  if (s.accept_connections(NUMPARTIES_DEFAULT)) {
	  cout << "ERROR: accept" << endl;
  }
  else { cout << "Accepted connection" << endl; }

	//Read in and decrypt file
	TPMWrapper myTPM(argc >= 2? atoi(argv[1]) : DEFAULT_TPM_PORT);
	auto key = myTPM.s_readKeyFromFile(KEYFILE);
	ifstream bfs(BASEFILE);
	auto tmp = vectorsFromHexFile(bfs);
	auto plaintext = flatten(tmp);

	//Read key from file
	auto ciphertext = myTPM.s_RSA_encrypt(plaintext, key);

	//Write out and send file
	ofstream os(ENCFILE);
	outputToStream(os, ciphertext);

	int trash;
  
	SendFile(&trash, ENCFILE, mySock);
  s.close_connections();
  */


	return 0;
}

