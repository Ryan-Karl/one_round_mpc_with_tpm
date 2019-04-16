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

using namespace std;


int main(int argc, char ** argv) {
	/*
	if (argc < 2) {
		cout << "ERROR: not enough files" << endl;
		return 0;
	}
	*/

	Client c(LOCALHOST, DEFAULT_PORTNUM);
	c.Start();
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

	//Read in and decrypt file
	TPMWrapper myTPM;
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
  if (s.init()) {
		cout << "ERROR: accept" << endl;
	}
	if(s.accept_connections(NUMPARTIES_DEFAULT)) {
		cout << "ERROR: accept" << endl;
	}
	SendFile(&trash, ENCFILE, mySock);
  s.close_connections();


	return 0;
}
