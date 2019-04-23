//g++ ServerTest.cpp -o server ../tpm_src/*.o  -lgmp -lssl -lcrypto -g

#define NOMINMAX

#include "pch.h"
#include <iostream>
#include "../includes/NetworkUtils.h"
#include "../includes/utilities.h"
#include "../includes/TPMWrapper.h"

#include <iostream>
#include <fstream>
#include <string>
#include <string.h>

#define BASEFILE "basefile.txt"
#define ENCFILE "encfile.txt"
#define KEYFILE "keyfile.txt"
#define NUMPARTIES_DEFAULT 1
#define SERVER_TPM_PORT 31000

using namespace std;

//First arg is port, second is a string to encrypt, third is the TPM port
int main(int argc, char ** argv) {

	if (argc < 4) {
		cout << "First arg is port, second is a string to encrypt, third is the TPM port" << endl;
		return 0;
	}

	TPMWrapper myTpm(atoi(argv[3]));
	Server s(atoi(argv[1]));
	s.init();
	s.accept_connections(1);
	char * keystr;
	unsigned int strLen;
	s.recvString(0, strLen, (char **)&keystr);

	string jsonStr(keystr);
	auto key = myTpm.s_readKey(jsonStr);
	vector<BYTE> toEncrypt = stringToByteVec(argv[2], strlen(argv[2]));
	vector<BYTE> encryptedVec = myTpm.s_RSA_encrypt(toEncrypt, key);
	string encStr = ByteVecToString(encryptedVec);
	s.sendString(0, encStr.size() + 1, encStr.c_str());
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
