#include "NetworkCommon.h"
#include "Server.h"
#include "Client.h"

#include <iostream>
#include <fstream>

using namespace std;


int main(int argc, char ** argv){
	if(argc < 1){
		cout << "ERROR: not enough files" << endl;
		return 0;
	}

	Server s(DEFAULT_PORT);
	s.init();
	s.accept_connections(1);
	vector<string> filenames;
	for(int i = 1; i < argc; i++){
		string s(argv[i]);
		filenames.push_back(s);
	}
	if(s.broadcast_files(filenames)){
		cout << "Broadcast failed" << endl;
		return 1;
	}


	return 0;
}