// ServerTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

#include "NetworkCommon.h"
#include "Server.h"

#include <iostream>
#include <fstream>

using namespace std;


int main(int argc, char ** argv) {
	if (argc < 1) {
		cout << "ERROR: not enough files" << endl;
		return 0;
	}

	Server s(DEFAULT_PORTNUM);
	s.init();
	s.accept_connections(1);
	vector<string> filenames;
	for (int i = 1; i < argc; i++) {
		string s(argv[i]);
		filenames.push_back(s);
	}
	if (s.broadcast_files(filenames)) {
		cout << "Broadcast failed" << endl;
		return 1;
	}


	return 0;
}