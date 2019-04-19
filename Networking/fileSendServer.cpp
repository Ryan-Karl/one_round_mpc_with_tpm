#include "NetworkUtils.h"

#include <iostream>
#include <fstream>
#include <cassert>

using namespace std;


int main(int argc, char ** argv){
	/*
	if(argc < 1){
		cout << "ERROR: not enough files" << endl;
		return 0;
	}
	*/

	Server s(DEFAULT_PORTNUM);
	if(s.init()){
		cout << "Init failed" << endl;
	}

	 if(s.accept_connections(1)){
		cout << "Connection failed!" << endl;
		return 1;
	}
	cout << "Accepted connection!" << endl;
	int * received;
	void * addr_rec = &received;
	unsigned int len = 0;
	if(s.recvBuffer(0, (void **)addr_rec, len)){
		cout << "Error with receive!" << endl;
		return 1;
	}
	assert(len == sizeof(*received));

	cout << "Received " << *received << endl;

	s.stop();

	return 0;
}