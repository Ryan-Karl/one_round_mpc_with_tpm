// ClientTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define NOMINMAX

//#include "pch.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include "../includes/TPMWrapper.h"
#include "../includes/NetworkUtils.h"
#include "../includes/utilities.h"

#define KEYFILE "keyfile.txt"
#define ENCFILE "encfile.txt"
#define DECFILE "decfile.txt"
#define NUMPARTIES_DEFAULT 1
#define CLIENT_TPM_PORT 30000

using namespace std;

//First arg is server port, second is TPM port
int main(int argc, char ** argv) {
	

	if (argc < 3) {
		cout << "ERROR: provide a server and TPM port" << endl;
		return 0;
	}
	

	TPMWrapper myTPM(atoi(argv[2]));
	myTPM.c_createAndStoreKey();
	string keystring = myTPM.c_writeKey();


	Client c(atoi(argv[1]), LOCALHOST);
	c.init();
	c.sendString(keystring.size()+1, keystring.c_str());

	char * encStr;
	unsigned int encLen;
	c.recvString(encLen, &encStr);
	//Now decrypt the recieved string
	vector<BYTE> encVec = stringToByteVec(encStr, encLen);
	vector<BYTE> decVec = myTPM.c_RSA_decrypt(encVec, 10);
	string decrypted = ByteVecToString(decVec);

	cout << decrypted << endl;


	/*
	Server s(DEFAULT_PORTNUM);
	if (s.init()) {
		cout << "ERROR: init" << endl;
	}
	if(s.accept_connections(NUMPARTIES_DEFAULT)) {
		cout << "ERROR: accept" << endl;
	}
	vector<string> filenames;
	//First send the file to encrypt, then the key file
	filenames.push_back(argv[1]);
	filenames.push_back(KEYFILE);
	//Send files to garbler	
	s.broadcast_files(filenames);
  s.close_connections();

	cout << "Finished broadcast" << endl;
	//Get encrypted file
	ofstream file_out(ENCFILE);
  Client c(LOCALHOST, DEFAULT_PORTNUM);
  c.Start();
  SOCKET serversock = c.getSocket();
	RecvFile(file_out, serversock);
  c.Stop();
  */

	//Read file into memory and decrypt it
	/*
	ifstream enc_instream(ENCFILE);
	auto tmp = vectorsFromHexFile(enc_instream);
	auto ciphertext = flatten(tmp);
	auto decrypted = myTPM.c_RSA_decrypt(ciphertext, 10);
	ofstream dec_out(DECFILE);
	outputToStream(dec_out, decrypted);
	*/
	//Verify that the input file and DECFILE are identical

	return 0;
}
