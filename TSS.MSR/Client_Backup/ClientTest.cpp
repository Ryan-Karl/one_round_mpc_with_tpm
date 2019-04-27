//g++ ClientTest.cpp -o client ../tpm_src/*.o  -lgmp -lssl -lcrypto -g
#define NOMINMAX

//#include "pch.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>

//#include "../includes/TPMWrapper.h"
//#include "../includes/NetworkUtils.h"
//#include "../includes/utilities.h"

#include "NetworkUtils.h"
#include "utilities.h"
#include "TPMWrapper.h"

#define KEYFILE "keyfile.txt"
#define ENCFILE "encfile.txt"
#define DECFILE "decfile.txt"
#define NUMPARTIES_DEFAULT 1
#define CLIENT_TPM_PORT 30000

using namespace std;

//First arg is server port, second is TPM port, third is the host
int main(int argc, char ** argv) {


	if (argc < 3) {
		cout << "ERROR: provide a server and TPM port" << endl;
		return 0;
	}
	//INITIALIZE
	//1. Get key pair
	TPMWrapper myTPM;
	myTPM.init(atoi(argv[2]));
	//Get keys
	auto keyPair = myTPM.c_genKeys();
	//2. Broadcast public key and receive public key
	//Initialize these two parts
	std::vector<std::pair<char *, unsigned int> > parties;
	unsigned int my_party;
	//std::vector<std::vector<BYTE> > keyByteVec;
	//keyByteVec.resize(parties.size());
	std::vector<TSS_KEY> keyVec;
	std::vector<BYTE> keyVec = keyPair.first.ToBuf();
	std::vector<std::thread> sendThreadVec;
	sendThreadVec.resize(parties.size());
	char * server_hostname;
	unsigned int server_port;
	//First send key to server, then accept n-1 keys from server, then garbled circuit
	Client c(server_port, server_hostname);
	c.sendBuffer(keyVec.size(), keyVec.data());
	for (unsigned int i = 0; i < parties.size(); i++) {
		//Skip my party
		if (i == my_party) {
			continue;
		}
		//For each key: get party number, then key
		unsigned int * partyNum;
		unsigned int msgSize;
		if (c.recvBuffer((void **)&partyNum, msgSize) || msgSize != sizeof(unsigned int)) {
			cerr << "ERROR getting party number" << endl;
			throw std::exception("ERROR getting party number");
		}
		char * recBuf;
		if (c.recvBuffer((void **)&recBuf, msgSize)) {
			cerr << "ERROR getting key" << i << endl;
			throw std::exception("ERROR getting key");
		}
		std::vector<BYTE> keyByteVec = stringToByteVec(recBuf, msgSize);
		keyVec[i] = myTPM.s_importKey(keyByteVec);
		delete partyNum;
		delete recBuf;
	}
	//TODO Now accept garbled circuit

	//Now accept wire ciphertexts from garbler
	unsigned int num_wires;
	std::vector<std::pair<std::vector<BYTE>, std::vector<BYTE> > > encLabels;
	//encLabels[i] has the label pair for wire i
	encLabels.resize(num_wires);
	for (unsigned int j = 0; j < num_wires; j++) {
		//Receive c_w,0 and c_w,1 (in that order)
		char * recLabel;
		unsigned int labelSize;
		if (c.recvBuffer((void **)& recLabel, labelSize)) {
			cerr << "ERROR getting label" << j << " 0" << endl;
			throw std::exception("ERROR getting label");
		}
		encLabels[j].first = stringToByteVec(recLabel, labelSize);
		delete recLabel;
		if (c.recvBuffer((void **)& recLabel, labelSize)) {
			cerr << "ERROR getting label" << j << " 1" << endl;
			throw std::exception("ERROR getting label");
		}
		encLabels[j].second = stringToByteVec(recLabel, labelSize);
		delete recLabel;
	}
	//Close connection to garbler
	c.stop();

	//PREPROCESS
	//1. Decrypt
	std::vector<bool> choices;
	std::vector<std::vector<BYTE> > intermediate_ciphertexts;
	intermediate_ciphertexts.resize(choices.size());
	assert(choices.size() == num_wires);
	for (unsigned int k; k < choices.size(); k++) {
		intermediate_ciphertexts[k] =
			myTPM.c_RSA_decrypt(keyPair.second,
			(!choices[k]) ? encLabels[k].first : encLabels[k].second);
	}
	//2. Extract symmetric key (and ciphertext)
	std::vector<std::vector<BYTE> > labels(intermediate_ciphertexts.size());
	std::vector<std::vector<BYTE> > keyShares(intermediate_ciphertexts.size());
	for (unsigned int o = 0; o < intermediate_ciphertexts.size(); o++) {
		splitIntermediate(intermediate_ciphertexts[o], labels[o], keyShares[o]);
	}
	//2b. Combine secret shares

	












	//Send software key to server
	Client c(atoi(argv[1]), (argc >= 4 ? argv[3] : LOCALHOST));
	if (!c.init()) {
		cout << "Got connection" << endl;
	}
	else {
		cout << "Connection failed!" << endl;
		return 1;
	}
	std::vector<BYTE> keyVec = keyPair.first.ToBuf();
	if (!c.sendBuffer(keyVec.size(), keyVec.data())) {
		cout << "Client sent key vector" << endl;
	}
	else {
		cout << "ERROR in client sending key vector" << endl;
		return 1;
	}
	
	//Receive the encrypted message back from the server
	char * encStr;
	unsigned int encLen;
	c.recvBuffer((void **) &encStr, encLen);
	//Now decrypt the recieved string
	vector<BYTE> encVec = stringToByteVec(encStr, encLen);
	vector<BYTE> decVec = myTPM.c_RSA_decrypt(keyPair.second, encVec);
	string decrypted = ByteVecToString(decVec);
	
	cout << "Client decrypted message: " << decrypted << endl;

	return 0;
}

void recv_message(char * hostname, unsigned int port, std::vector<BYTE> & message) {
	Client c(port, hostname);
	if (c.init()) {
		cerr << "ERROR initializing client: " << hostname << ' ' << port << endl;
		throw new std::exception("ERROR initializing client");
	}
	message.clear();
	char * recvData;
	unsigned int dataLen;
	if (c.recvString(dataLen, &recvData)) {
		cerr << "ERROR sending key: " << hostname << ' ' << port << endl;
		throw new std::exception("ERROR sending key");
	}
	message = stringToByteVec(recvData, dataLen);
	c.stop();
	return;
}


void send_message(unsigned int num_connections, unsigned int port, const std::vector<BYTE> & message) {
	Server s(port);
	if (s.init() || s.accept_connections(num_connections)) {
		cerr << "ERROR initializing server: " << port << endl;
			throw new std::exception("ERROR initializing server");
	}
	for (unsigned int i = 0; i < num_connections; i++) {
		s.sendBuffer(i, message.size(), (char *)message.data());
	}
	s.stop();
	return;
}
