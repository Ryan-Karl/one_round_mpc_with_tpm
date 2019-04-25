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
	
	char * keystr;
	unsigned int strLen;
	
	
	if (s.recvString(0, strLen, (char **)&keystr)) {
		cout << "Error getting key string" << endl;
	}
	else {
		cout << "Server received key string:" << endl;
	}

	vector<BYTE> keyvec = stringToByteVec(keystr, strLen);
	
	
	string jsonStr(keystr); 
    //cout << jsonStr << endl;
	//cout << "Key string size: " << std::dec << jsonStr.size() << endl;
	
	TPMWrapper myTpm;
	myTpm.init(30000);
	auto key = myTpm.s_readKey(keyvec);
	cout << key.outPublic.ToString() << endl;
	std::ofstream jsonout("jsonout.txt");
	std::ofstream reconstout("reconstout.txt");
	/*
	if (jsonStr != key.outPublic.Serialize(SerializationType::JSON)) {
		jsonout << jsonStr;
		jsonout.close();
		reconstout << key.outPublic.Serialize(SerializationType::JSON);
		reconstout.close();
	}
	*/
	assert(keyvec == key.outPublic.ToBuf());
	
	/*
	public_key key = key_from_TPM_string(jsonStr);
	vector<BYTE> pad = { 1,2,3,4,5 };
	char * toSend = argv[2];
	unsigned int sendLength = strlen(argv[2]);
	vector<BYTE> toEncryptByteVec = stringToByteVec(toSend, sendLength);
	mpz_class toEncryptMPZ = ByteVecToMPZ(toEncryptByteVec);
	cout << "toEncryptMPZ: " << toEncryptMPZ << endl;
	cout << "Modulus: " << key.n;
	cout << "Exponent: " << key.e;
	mpz_class ciphertext = encrypt(toEncryptMPZ, key);
	assert(ciphertext != 0);
	vector<BYTE> enc_bytevec = mpz_to_vector(ciphertext);
	*/
	
	//cout << "toEncrypt: " << ByteVecToString(toEncrypt) << endl;
	vector<BYTE> toEncryptByteVec = stringToByteVec(argv[2], strlen(argv[2]));
	auto tpm = myTpm.GetTpm();
	vector<BYTE> NullVec;
	vector<BYTE> encryptedVec = tpm.RSA_Encrypt(key.handle, toEncryptByteVec, TPMS_NULL_ASYM_SCHEME(), NullVec);
	string encStr = ByteVecToString(encryptedVec);
	

	
	if (s.sendString(0, encStr.size()+1, encStr.c_str())) {
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

