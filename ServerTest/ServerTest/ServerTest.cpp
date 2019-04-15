// ServerTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

#include "Networking.h"
#include "utilities.h"

#include <iostream>
#include <fstream>

#define BASEFILE "basefile.txt"
#define ENCFILE "encfile.txt"
#define KEYFILE "keyfile.txt"

using namespace std;


int main(int argc, char ** argv) {
	if (argc < 1) {
		cout << "ERROR: not enough files" << endl;
		return 0;
	}

	Client c(LOCALHOST, DEFAULT_PORTNUM);
	c.Start();
	//Accept plaintext, then the key
	vector<string> filenames;
	filenames.push_back(BASEFILE);
	filenames.push_back(KEYFILE);
	RecvDelimitedFiles(filenames, c.getSocket);
	//Read in and decrypt file
	TPMWrapper myTPM;
	myTPM.s_readKeyFromFile(KEYFILE);
	ifstream bfs(BASEFILE);
	auto tmp = vectorsFromHexFile(bfs);
	auto plaintext = flatten(tmp);
	auto ciphertext = s_RSA_encrypt(plaintext);
	//Write out and send file
	ofstream os(ENCFILE);
	outputToStream(os, ciphertext);
	int trash;
	SendFile(&trash, ENCFILE, c.getSocket());


	return 0;
}