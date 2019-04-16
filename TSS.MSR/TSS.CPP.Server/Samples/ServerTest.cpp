// ServerTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define NOMINMAX

//#include "pch.h"
#include <iostream>
#include "NetworkCommon.h"
#include "Networking.h"
#include "utilities.h"
#include "TPMWrapper.h"

#include <iostream>
#include <fstream>

#define BASEFILE "basefile.txt"
#define ENCFILE "encfile.txt"
#define KEYFILE "keyfile.txt"
#define NUMPARTIES_DEFAULT 1
#define DEFAULT_TPM_PORT 2321

using namespace std;


int main(int argc, char ** argv) {
	
	if (argc < 2) {
		cout << "ERROR: no port given" << endl;
		return 0;
	}
	

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


	return 0;
}
