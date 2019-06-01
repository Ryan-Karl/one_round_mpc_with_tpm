//Compile with:
// g++ ./*.cpp -o circuit_tests  -lssl -lcrypto -lgmp -lgmpxx -g


#ifdef __linux__
#include <gmp.h>
#include <gmpxx.h>
#elif defined(WIN32)
#include <mpir.h>
#include <mpirxx.h>
#else
#error OS not defined!
#endif

#include <iostream>
#include <vector>
#include <cassert>


#include "garble_util.h"
#include "player.h"
#include "../includes/utilities.h"

using namespace std;

void print_circuit(std::ostream & os, char * circuitfile, unsigned int num_parties){
	//Hardcode the seed
	srand(1);

	Circuit * circ = new Circuit;
	std::vector<PlayerInfo *> playerInfo(num_parties);
	for (auto & ptr : playerInfo) {
		ptr = new PlayerInfo;
	}
	read_frigate_circuit(circuitfile, circ, &playerInfo, SEC_PARAMETER);
	//print_circuit_trace(circ, os);
	get_garbled_circuit(circ);
	std::vector<unsigned char> circuitByteVec;
	circuit_to_bytevec(circ, &circuitByteVec);
	//Represent the circuit as a number for easier reading
	os << byteVecToNumberString(circuitByteVec) << std::endl; 
	delete circ;
	for(PlayerInfo * p : playerInfo){
		delete p;
	}
}

void test_bytevec(std::ostream & os, char * circuitfile,
 unsigned int num_parties){
srand(1);
	Circuit * circ = new Circuit;
	
	std::vector<PlayerInfo *> playerInfo(num_parties);
	for (auto & ptr : playerInfo) {
		ptr = new PlayerInfo;
	}
	read_frigate_circuit(circuitfile, circ, &playerInfo, SEC_PARAMETER);
	get_garbled_circuit(circ);
	std::vector<unsigned char> circuitByteVec0;
	std::vector<unsigned char> circuitByteVec1;
	circuit_to_bytevec(circ, &circuitByteVec0);
	circuit_to_bytevec(circ, &circuitByteVec1);
	assert(circuitByteVec0 == circuitByteVec1);
}

void test_vectors(std::ostream & os, char * circuitfile, unsigned int num_parties){
	//Testing that bytevec_to_circuit and circuit_to_bytevec are inverses
	//Reseed
	srand(1);
	Circuit * circ = new Circuit;
	
	std::vector<PlayerInfo *> playerInfo(num_parties);
	for (auto & ptr : playerInfo) {
		ptr = new PlayerInfo;
	}
	read_frigate_circuit(circuitfile, circ, &playerInfo, SEC_PARAMETER);
	get_garbled_circuit(circ);
	std::vector<unsigned char> circuitByteVec;
	circuit_to_bytevec(circ, &circuitByteVec);

	Circuit * secondCircuit = new Circuit;
	read_frigate_circuit(circuitfile, secondCircuit, &playerInfo,
	 SEC_PARAMETER);
	//get_garbled_circuit(circ);
	std::vector<PlayerInfo *> playerInfo2(num_parties);
	for (auto & ptr : playerInfo2) {
		ptr = new PlayerInfo;
	}
	bytevec_to_circuit(secondCircuit, &circuitByteVec);
	std::vector<unsigned char> secondVec;
	circuit_to_bytevec(secondCircuit, &secondVec);

	if(secondVec != circuitByteVec){
		os << "Vectors not equal!" << endl;
	}
	delete circ;
	delete secondCircuit;
	for(PlayerInfo * p : playerInfo){
		delete p;
	}
	for(PlayerInfo * p2 : playerInfo2){
		delete p2;
	}
}

void test_top_sort(std::ostream & os, char * circuitfile, 
	unsigned int num_parties){
	std::deque<Wire *> dest;
	Circuit * circ = new Circuit;
	std::vector<PlayerInfo *> playerInfo(num_parties);
	for (auto & ptr : playerInfo) {
		ptr = new PlayerInfo;
	}
	read_frigate_circuit(circuitfile, circ, &playerInfo, SEC_PARAMETER);

	top_sort(dest, circ);
	for(unsigned int i = 0; i < dest.size(); i++){
		os << (dest[i])->gate_number << ' '; 
	}
	os << endl;
}

void trace_circuit(std::ostream & os, char * circuitfile, 
	unsigned int num_parties){
	srand(1);

	Circuit * circ = new Circuit;
	std::vector<PlayerInfo *> playerInfo(num_parties);
	for (auto & ptr : playerInfo) {
		ptr = new PlayerInfo;
	}
	os << "First trace: " << std::endl;
	read_frigate_circuit(circuitfile, circ, &playerInfo, SEC_PARAMETER);
	print_circuit_trace(circ, os);
	get_garbled_circuit(circ);
	os << "Second trace: " << std::endl;
	print_circuit_trace(circ, os);
	delete circ;
	for (auto & ptr : playerInfo) {
		delete ptr;
	}
}

void print_labels(std::ostream & os, char * circuitfile, unsigned int num_parties){
	srand(1);
	Circuit * circ = new Circuit;
	std::vector<PlayerInfo *> playerInfo(num_parties);
	for (auto & ptr : playerInfo) {
		ptr = new PlayerInfo;
	}
	read_frigate_circuit(circuitfile, circ, &playerInfo, SEC_PARAMETER);
	get_garbled_circuit(circ);
	std::deque<Wire *> dest;
	top_sort(dest, circ);
	for(Wire * w : dest){
		os << "Wire " << w->gate_number << std::endl;
		for(unsigned int i = 0; i < 4; i++){
			if(w->garbled_labels[i] != nullptr){
				os << "Label " << i << ": " << w->garbled_labels[i]->bits << std::endl;
			}
			else{
				os << "Label " << i << ": NULL" << std::endl;
			}
		}
		os << std::endl;
		
	}
	delete circ;
	for (auto & ptr : playerInfo) {
		delete ptr;
	}
}	

//Takes in a circuit filename as only argument
int main(int argc, char ** argv){
	if(argc != 3){
		cerr << "ERROR arguments are: filename num_parties" << endl;
		return 0;
	}
	test_vectors(cout, argv[1], atoi(argv[2]));

	return 0;
}