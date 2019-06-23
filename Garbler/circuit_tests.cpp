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
#include <fstream>


#include "garble_util.h"
#include "player.h"
//#include "../includes/utilities.h"

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

void test_bytevec_to_circuit(std::ostream & os, char * circuitfile,
 unsigned int num_parties){
	Circuit * circ = new Circuit;
	
	std::vector<PlayerInfo *> playerInfo(num_parties);
	for (auto & ptr : playerInfo) {
		ptr = new PlayerInfo;
	}
	read_frigate_circuit(circuitfile, circ, &playerInfo, SEC_PARAMETER);
	get_garbled_circuit(circ);
	std::vector<unsigned char> circuitVec;
	circuit_to_bytevec(circ, &circuitVec);

	Circuit * circ2 = new Circuit;
	Circuit * circ3 = new Circuit;
	read_frigate_circuit(circuitfile, circ2, &playerInfo, SEC_PARAMETER);
	read_frigate_circuit(circuitfile, circ3, &playerInfo, SEC_PARAMETER);
	bytevec_to_circuit(circ2, &circuitVec);
	bytevec_to_circuit(circ3, &circuitVec);
	std::vector<unsigned char> circuitVec2, circuitvec3;
	circuit_to_bytevec(circ2, &circuitVec2);
	circuit_to_bytevec(circ3, &circuitvec3);
	assert(circuitvec3 == circuitVec2);
}

void test_circuit_to_bytevec(std::ostream & os, char * circuitfile,
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

	bytevec_to_circuit(circ, &circuitByteVec);
	std::vector<unsigned char> secondVec;
	circuit_to_bytevec(circ, &secondVec);

	if(secondVec != circuitByteVec){
		os << "Vectors not equal!" << endl;
		os << "First vector: " << byteVecToNumberString(circuitByteVec) << std::endl;
		os << "Second vector: " << byteVecToNumberString(secondVec) << std::endl;
		assert(secondVec == circuitByteVec);
	}
	delete circ;
	for(PlayerInfo * p : playerInfo){
		delete p;
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

void test_circuit_eval(std::ostream & os, char * circuitfile, 
	unsigned int num_parties, const std::vector<bool> & choices){
	srand(1);
	Circuit * circ = new Circuit;
	std::vector<PlayerInfo *> playerInfo(num_parties);
	for (auto & ptr : playerInfo) {
		ptr = new PlayerInfo;
	}
	read_frigate_circuit(circuitfile, circ, &playerInfo, SEC_PARAMETER);
	get_garbled_circuit(circ);
	std::vector<std::vector<std::pair<wire_value *, wire_value *> > > labels(num_parties);
	unsigned int choice_idx = 0;
	os << "Choices: ";
	for(bool b : choices){
		os << b << ' ';
	}
	os << std::endl;
	for(PlayerInfo * pi : playerInfo){
		for(Wire * w : pi->input_wires){
			wire_value * wv = wire2garbling(w, choices[choice_idx++]);
			//DEBUGGING
			/*
			std::vector<unsigned char> wv_vec(wv->bits, wv->bits + (wv->len/CHAR_WIDTH) + (wv->len%CHAR_WIDTH? 1:0));
			std::cout << "Wire " << w->gate_number << " wire_value " << byteVecToNumberString(wv_vec) << std::endl;
			*/
			w->label_kp = wv;
		}
	}
	eval_garbled_circuit(circ);
	os << "Circuit answer: ";
	for (Wire * x : circ->output_wires) {
		os << (x->output_value) << ' ';
	}
	os << std::endl;
}

std::vector<bool> parse_choicefile(char * filename) {
	std::ifstream ifs(filename);
	if (!ifs.good()) {
		cerr << "ERROR reading file " << filename << endl;
		return std::vector<bool>();
	}
	int b;
	vector<bool> ret;
	while (ifs >> b) {
		ret.push_back(b > 0);
	}
	return ret;
}

//Takes in a circuit filename as only argument
int main(int argc, char ** argv){
	if(argc != 3){
		cerr << "ERROR arguments are: filename num_parties" << endl;
		return 0;
	}



	std::vector<bool> choices = parse_choicefile("choicefile.txt");

	test_circuit_eval(cout, argv[1], atoi(argv[2]), choices);

	return 0;
}