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

#include "ShamirSecret.h"
#include "NetworkUtils.h"
#include "utilities.h"
#include "TPMWrapper.h"

#define KEYFILE "keyfile.txt"
#define ENCFILE "encfile.txt"
#define DECFILE "decfile.txt"
#define NUMPARTIES_DEFAULT 1
#define CLIENT_TPM_PORT 30000

using namespace std;

void server_connect(Server & s, unsigned int num_cons, unsigned int me,
	std::vector<std::vector<BYTE> > & downloads,
	const std::vector<BYTE> & upload);

void client_connect(unsigned int me, char * hostname, unsigned int port,
	std::vector<std::vector<BYTE> > & downloads, const std::vector<BYTE> & upload);

//First arg is server port, second is TPM port, third is the host
int main(int argc, char ** argv) {


	if (argc < 3) {
		std::cout << "ERROR: provide a server and TPM port" << endl;
		return 0;
	}
	//INITIALIZE
	//1. Get key pair
	TPMWrapper myTPM;
	myTPM.init(atoi(argv[2]));
	//TODO Ryan find out how to force limited usage
	auto keyPair = myTPM.c_genKeys();
	//2. Broadcast public key and receive public key
	//Initialize these two parts
	std::vector<std::pair<char *, unsigned int> > parties;
	unsigned int my_party = 0; //TODO initialize
	std::vector<BYTE> myKeyVec = keyPair.first.ToBuf();
	std::vector<std::vector<BYTE> > keyVec;
	std::vector<TSS_KEY> other_keys(parties.size());
	std::vector<std::thread> sendThreadVec;
	sendThreadVec.resize(parties.size());
	char * server_hostname = "127.0.0.1"; //TODO change - only to get it to compile
	unsigned int server_port = 0; //TODO change
	//First send key to server, then accept n-1 keys from server, then garbled circuit
	Client c(server_port, server_hostname);
	if (c.init()) {
		cerr << "Failed initializing client for party " << my_party << endl;
		return 1;
	}
	//Send the server our party number so they know who is who
	c.sendBuffer(sizeof(my_party), &my_party);
	//Now send the key vector
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
		other_keys[i] = myTPM.s_importKey(keyByteVec);
		delete partyNum;
		delete recBuf;
	}
	//TODO Now accept garbled circuit

	//Now accept wire ciphertexts from garbler
	unsigned int num_wires = 0; //TODO change
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
	for (unsigned int k = 0; k < choices.size(); k++) {
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
	//Assume secrets are in a concatenated vector
	//First part is x-coord, second is y-coord
	mpz_class prime;
	unsigned int num_shares = 0;
	unsigned int minimum = 0;
	ShamirSecret shamir(prime, num_shares, minimum);
	std::vector<std::pair<mpz_class, mpz_class> > shares;
	for (unsigned int p = 0; p < keyShares.size(); p++) {
		std::vector<BYTE> xVec, yVec;
		splitIntermediate(keyShares[p], xVec, yVec);
		shares.push_back(std::pair<mpz_class, mpz_class>(
			ByteVecToMPZ(xVec), ByteVecToMPZ(yVec)));
	}
	mpz_class recombined_secret = shamir.getSecret(shares);
	//2c. Get AES key from recombined secret
	ByteVec recombinedVec = mpz_to_vector(recombined_secret);
	unsigned int aes_keylen = recombinedVec.size();
	unsigned char * key = new unsigned char[aes_keylen];
	memcpy(key, recombinedVec.data(), aes_keylen);	

	//3. Use AES to decrypt labels based on choices
	//TODO finish once we have a function to convert ByteVec<->label
	std::vector<bool> decryptedLabels(choices.size());
	//Change me later!
	std::vector<int> wires;
	

	//ONLINE
	//1. Broadcast (and receive) labels
	//Each party serves the number of parties - their number
	//Each party is a client to their number
	//Clients receive first, then send
	//Servers send first, then receive
	//Start client threads first
	//TODO how to get my port? CLI arg?
	unsigned int myPort = 0; //TODO change - get my server port
	std::vector<BYTE> upload;
	std::vector<std::vector<BYTE> > downloads(parties.size());
	std::vector<std::thread> client_threads(my_party);
	for (unsigned int u = 0; u < my_party; u++) {
		client_threads[u] = std::thread(&client_connect,
			my_party, parties[u].first, parties[u].second, downloads, upload);
	}
	Server s(myPort);
	s.init();
	std::thread server_thread(&server_connect, s, parties.size() - my_party, my_party,
		downloads, upload);
	for (auto & x : client_threads) {
		x.join();
	}
	server_thread.join();

	//EVALUATE
	//1. Feed each label into the circuit, detect corruption
	



	//Send software key to server
	/*
	Client c(atoi(argv[1]), (argc >= 4 ? argv[3] : LOCALHOST));
	if (!c.init()) {
		std::cout << "Got connection" << endl;
	}
	else {
		std::cout << "Connection failed!" << endl;
		return 1;
	}
	std::vector<BYTE> keyVec = keyPair.first.ToBuf();
	if (!c.sendBuffer(keyVec.size(), keyVec.data())) {
		std::cout << "Client sent key vector" << endl;
	}
	else {
		std::cout << "ERROR in client sending key vector" << endl;
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
	*/

	return 0;
}

bool amIClient(unsigned int me, unsigned int them) {
	return me < them;
}

//Clients receive first, then send
void client_connect(unsigned int me, char * hostname, unsigned int port,
	std::vector<std::vector<BYTE> > & downloads, const std::vector<BYTE> & upload) {
	Client c(port, hostname);
	if (c.init()) {
		cerr << "ERROR initializing client: " << hostname << ' ' << port << endl;
		throw new std::exception("ERROR initializing client");
	}
	//Receive
	//First, receive which party the message is from
	unsigned int * them;
	unsigned int partyLen;
	if (c.recvBuffer((void **) &them, partyLen) || partyLen != sizeof(them)) {
		cerr << "ERROR : receiving" << hostname << ' ' << port << endl;
		throw new std::exception("ERROR receiving");
	}
	//Next, get the actual data
	char * recvData;
	unsigned int dataLen;
	if (c.recvString(dataLen, &recvData)) {
		cerr << "ERROR : receiving" << hostname << ' ' << port << endl;
		throw new std::exception("ERROR receiving");
	}
	downloads[*them] = stringToByteVec(recvData, dataLen);
	//Send
	//First, send which party I am
	if (c.sendBuffer(sizeof(me), (void *)&me)) {
		cerr << "ERROR sending: " << hostname << ' ' << port << endl;
		throw new std::exception("ERROR sending");
	}
	//Next, send my data
	if (c.sendBuffer(upload.size(), (void *)upload.data())) {
		cerr << "ERROR sending: " << hostname << ' ' << port << endl;
		throw new std::exception("ERROR sending");
	}
	c.stop();
}

//Servers send first, then receive
//Assumes server has been created and initialized
void server_connect(Server & s, unsigned int num_cons, unsigned int me,
	std::vector<std::vector<BYTE> > & downloads,
	const std::vector<BYTE> & upload) {
	s.accept_connections(num_cons);
	for (unsigned int i = 0; i < num_cons; i++) {
		//First, send which party I am
		if (s.sendBuffer(i, sizeof(me), (void *)&me)) {
			cerr << "ERROR sending: " << i << endl;
			throw new std::exception("ERROR sending");
		}
		//Next, send my data
		if (s.sendBuffer(i, upload.size(), (void *)upload.data())) {
			cerr << "ERROR sending: " << i;
			throw new std::exception("ERROR sending");
		}
		//Receive
		//First, receive which party the message is from
		unsigned int * them;
		unsigned int partyLen;
		if (s.recvBuffer(i, (void **)&them, partyLen) || partyLen != sizeof(them)) {
			cerr << "ERROR : receiving" << endl;
			throw new std::exception("ERROR receiving");
		}
		//Next, get the actual data
		char * recvData;
		unsigned int dataLen;
		if (s.recvString(i, dataLen, &recvData)) {
			cerr << "ERROR : receiving" << endl;
			throw new std::exception("ERROR receiving");
		}
		downloads[*them] = stringToByteVec(recvData, dataLen);
	}
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
