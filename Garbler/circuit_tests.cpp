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


//Takes in a circuit filename as only argument
int main(int argc, char ** argv){
	if(argc != 2){
		cerr << "ERROR provide exactly one argument (circuit filename)" << endl;
		return 0;
	}
	//Hardcode the seed
	srand(1);

	Circuit * circ = new Circuit;
	unsigned int num_parties = 1;
	std::vector<PlayerInfo *> playerInfo(num_parties);
	for (auto & ptr : playerInfo) {
		ptr = new PlayerInfo;
	}
	read_frigate_circuit(argv[1], circ, &playerInfo, SEC_PARAMETER);
	get_garbled_circuit(circ);
	std::vector<unsigned char> circuitByteVec;
	circuit_to_bytevec(circ, &circuitByteVec);
	//Represent the circuit as a number for easier reading
	mpz_class circuit_mpz = ByteVecToMPZ(circuitByteVec);
	cout << circuit_mpz << endl;
	/*
	for(unsigned char c : circuitByteVec){
		cout << (char)c;
	}
	*/

	//Testing that bytevec_to_circuit and circuit_to_bytevec are inverses
	Circuit * secondCircuit = new Circuit;
	std::vector<PlayerInfo *> playerInfo2(num_parties);
	for (auto & ptr : playerInfo2) {
		ptr = new PlayerInfo;
	}
	bytevec_to_circuit(secondCircuit, &circuitByteVec);
	std::vector<unsigned char> secondVec;
	circuit_to_bytevec(secondCircuit, &secondVec);
	assert(secondVec == circuitByteVec);


	return 0;
}