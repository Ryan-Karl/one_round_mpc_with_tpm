// ClientTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "TPMWrapper.h"

#include "Client.h"

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
	vector<string> filenames;
	/*
	string next_filename;
	while (cin >> next_filename) {
		filenames.push_back(next_filename);
	}
	*/
	
	for (int i = 1; i < argc; i++) {
		string s(argv[i]);
		filenames.push_back(s);
	}
	
	SOCKET ClientSock = c.getSocket();
	if (RecvDelimitedFiles(filenames, ClientSock, FILE_DELIM)) {
		cout << "Error recieving files" << endl;
		return 1;
	}
	return 0;
}
// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
