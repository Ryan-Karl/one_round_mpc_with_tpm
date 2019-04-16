// ClientTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define NOMINMAX

#include "pch.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "TPMWrapper.h"
#include "Networking.h"
#include "utilities.h"

#define KEYFILE "keyfile.txt"
#define ENCFILE "encfile.txt"
#define DECFILE "decfile.txt"
#define NUMPARTIES_DEFAULT 1

using namespace std;

int main(int argc, char ** argv) {
	
	if (argc < 2) {
		cout << "ERROR: provide an output filename" << endl;
		return 0;
	}
	

	TPMWrapper myTPM;
	myTPM.c_createAndStoreKey();
	myTPM.c_writeKeyToFile(KEYFILE);


	Server s(DEFAULT_PORTNUM);
	if (s.init()) {
		cout << "ERROR: accept" << endl;
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
	cout << "Finished broadcast" << endl;
	//Get encrypted file
	ofstream file_out(ENCFILE);
	SOCKET serversock;
	RecvFile(file_out, serversock);
	//Read file into memory and decrypt it
	ifstream enc_instream(ENCFILE);
	auto tmp = vectorsFromHexFile(enc_instream);
	auto ciphertext = flatten(tmp);
	auto decrypted = myTPM.c_RSA_decrypt(ciphertext, 10);
	ofstream dec_out(DECFILE);
	outputToStream(dec_out, decrypted);
	//Verify that the input file and DECFILE are identical

	return 0;
}
