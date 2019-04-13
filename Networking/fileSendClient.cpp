#include "NetworkCommon.h"
#include "Server.h"
#include "Client.h"

#include <iostream>
#include <fstream>

using namespace std;

int main(int argc, char ** argv){
	if(argc < 2){
		cout << "ERROR: not enough files" << endl;
		return 0;
	}
	Client c("127.0.0.1", DEFAULT_PORTNUM);
	c.init();
	vector<string> filenames;
	for(int i = 1; i < argc; i++){
		string s(argv[i]);
		filenames.push_back(s);
	}
	if(RecvDelimitedFiles(filenames, c.getSocket(), FILE_DELIM)){
		cout << "Error recieving files" << endl;
		return 1;
	}
	return 0;
}