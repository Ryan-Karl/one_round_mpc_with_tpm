#include "NetworkCommon.h"
#include <vector>
#include <string>
#include <iostream>

using namespace std;

int main(int argc, char ** argv){
	if(argc != 2){
		cout << "File required!" << endl;
		return 0;
	}
	string str(argv[1]);
	vector<BYTE> keyVec = keyFromFile(str);
	cout << std::hex;
	for(size_t i = 0; i < keyVec.size(); i++){
		cout << (int) keyVec[i];
		if((i%4)==3){
			cout << ' ';
		}
	}
	cout << endl;
	return 0;
}