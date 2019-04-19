#include "NetworkUtils.h"

#include <iostream>
#include <fstream>

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

	int toSend = atoi(argv[1]);
	if(c.sendBuffer(sizeof(toSend), (void *) & toSend)){
		cout << "ERROR: send" << endl;
	}
	cout << "Sent " << toSend << endl;

	c.stop();



	return 0;
}