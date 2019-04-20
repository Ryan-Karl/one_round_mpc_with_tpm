#include "NetworkUtils.h"

#include <iostream>
#include <fstream>
#include <cstring>

using namespace std;

int main(int argc, char ** argv){
	if(argc < 2){
		cout << "ERROR: no input number given" << endl;
		return 0;
	}
	Client c(DEFAULT_PORTNUM, LOCALHOST);
	if(c.init()){
		cout << "ERROR: init" << endl;
		return 1;
	}

	cout << "Connected to server!" << endl;

	//int toSend = atoi(argv[1]);
	//void * strAddr = &(argv[1]);
	if(c.sendString(strlen(argv[1]), argv[1])){
		cout << "ERROR: send" << endl;
	}
	cout << "Sent " << argv[1] << endl;

	c.stop();



	return 0;
}