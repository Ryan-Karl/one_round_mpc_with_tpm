#include "NetworkUtils.h"

#include <iostream>
#include <fstream>
#include <cassert>
#include <cstring>

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
	//int * received;
	char * str;
	void * addr_rec = &(str);
	unsigned int len = 0;
	if(s.recvString(0, len, &str)){
		cout << "Error with receive!" << endl;
		return 1;
	}
	assert(len == strlen(str));

	cout << "Received " << str << endl;

	s.stop();

	return 0;
}