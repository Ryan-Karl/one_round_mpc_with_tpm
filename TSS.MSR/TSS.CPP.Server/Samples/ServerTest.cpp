//g++ ServerTest.cpp -o server ../tpm_src/*.o  -lgmp -lssl -lcrypto -g

#define NOMINMAX

//#include "pch.h"
#include <iostream>
//#include "../includes/NetworkUtils.h"
//#include "../includes/utilities.h"
//#include "../includes/TPMWrapper.h"
#include "ShamirSecret.h"
#include "NetworkUtils.h"
#include "TPMWrapper.h"
#include "utilities.h"


#include <iostream>
#include <fstream>
#include <string>
#include <string.h>
#include <cassert>
#include <unordered_map>

#define BASEFILE "basefile.txt"
#define ENCFILE "encfile.txt"
#define KEYFILE "keyfile.txt"
#define NUMPARTIES_DEFAULT 1
#define SERVER_TPM_PORT 2321

using namespace std;

//First arg is port, second is a string to encrypt
int main(int argc, char ** argv) {
	
	if (argc < 3) {
		cout << "First arg is port, second is a string to encrypt" << endl;
		return 0;
	}

	//INITIALIZE
	//2. Receive public keys from parties
	char * circuitfile = "circuitfile.txt"; //TODO change
	unsigned int num_parties = 0; //TODO change
	unsigned int port = 0;
	Server s(port);
	if (s.init()) {
		cerr << "ERROR initializing server" << endl;
		return 1;
	}
	if (s.accept_connections(num_parties)) {
		cerr << "ERROR accepting connections" << endl;
		return 1;
	}
	vector<unsigned int> party_to_connection(num_parties);
	vector<vector<BYTE> > partyKeys(num_parties);
	for (unsigned int i = 0; i < num_parties; i++) {
		//Should this be multithreaded?
		//Receive the number of the party
		unsigned int currentParty;
		unsigned int msgLen;
		s.recvBuffer(i, (void **)&currentParty, msgLen);
		assert(msgLen == sizeof(currentParty));
		assert(currentParty < num_parties);
		party_to_connection[currentParty] = i;
		//Receive the key of the party
		char * recvBuf;
		s.recvBuffer(i, (void **)&recvBuf, msgLen);
		partyKeys[currentParty] = stringToByteVec(recvBuf, msgLen);
		delete recvBuf;
	}
	//Distribute all other keys to each party
	for (unsigned int y = 0; y < num_parties; y++) {
		for (unsigned int z = 0; z < num_parties; z++) {
			if (y == z) {
				continue; //Don't bother sending a party its own key
				//Send party z's key to party y
				s.sendBuffer(party_to_connection[y],
					partyKeys[y].size(), partyKeys[y].data());
			}
		}
	}
	//Switch to software keys
	std::vector<TSS_KEY> keyvec(partyKeys.size());
	for (unsigned int u = 0; u < partyKeys.size(); u++) {
		keyvec[u] = TPMWrapper::s_importKey(partyKeys[u]);
	}
	//An error check to do: assert that every entry in the vector is filled

	//3. Compute a garbled circuit and send it

	//4. Select partial keys, get AES key, and split key into W_i shares for each party.
	//(Need to get W_i)
	vector<unsigned int> party_to_numwires(num_parties); //TODO initialize me
	mpz_class prime; //TODO initialize me - send to party? Different for each party?
	//Initialize the TPM to get randomness
	TPMWrapper myTPM;
	//For each party:
	for (unsigned int j = 0; j < num_parties; j++) {
		//Get AES key
		std::vector<BYTE> aes_key, iv;
		aes_key = myTPM.getRandBits(AES_KEY_SIZE);
		iv = myTPM.getRandBits(IV_SIZE);
		mpz_class aes_key_mpz = ByteVecToMPZ(aes_key);
		//Split AES key into shares
		ShamirSecret splitKeys(prime, 2 * party_to_numwires[j], party_to_numwires[j]);
		auto allShares = splitKeys.getShares(aes_key_mpz);
		//std::vector<std::pair<mpz_class, mpz_class> >  shares(allShares.begin(), allShares.begin() + party_to_numwires[j]);
		std::vector<std::pair<std::vector<BYTE>, std::vector<BYTE> > >
			partyLabels(party_to_numwires[j]); //TODO init me - get each pair of labels
		for (unsigned int k = 0; k < partyLabels.size(); k++) {
			//Construct secret share of key as bytevec
			std::vector<BYTE> shareX = mpz_to_vector(allShares[k].first);
			std::vector<BYTE> shareY = mpz_to_vector(allShares[k].second);
			std::vector<BYTE> sharePair = concatenate(shareX, shareY);
			//Construct and send 0 and 1 wire labels, concatenated with secret share
			std::vector<BYTE> wire0share = concatenate(partyLabels[k].first, sharePair);
			std::vector<BYTE> wire1share = concatenate(partyLabels[k].second, sharePair);
			std::vector<BYTE> wire0ctext = TPMWrapper::s_RSA_encrypt(keyvec[k], wire0share);
			std::vector<BYTE> wire1ctext = TPMWrapper::s_RSA_encrypt(keyvec[k], wire1share);
			if (s.sendBuffer(party_to_connection[k], wire0ctext.size(), wire0ctext.data()) ||
				s.sendBuffer(party_to_connection[k], wire0ctext.size(), wire0ctext.data())) {
				cerr << "ERROR sending label/share ciphertexts" << endl;
				return 1;
			}
		}
	}

	//That's all folks!
	s.stop();
	cout << "Garbler finished" << endl;
	return 0;












/*  //Should not need to call init to start TPM connection
  //myTpm.init(atoi(argv[3]));
	Server s(atoi(argv[1]));
	if (s.init() || s.accept_connections(1)) {
		cout << "Failed server startup";
		return 1;
	}
	else {
		cout << "Server started" << endl;
	}
	//Get key from client
	char * keyStr;
	unsigned int strLen;

	if (s.recvString(0, strLen, (char **)&keyStr)) {
		cout << "Error getting keyStr" << endl;
	}
	else {
		cout << "Server received keyStr" << endl;
	}
	vector<BYTE> keyVec = stringToByteVec(keyStr, strLen);
	
	TPMWrapper myTpm;
	//myTpm.init(30000); //Unneeded for server (hopefully)
	TSS_KEY swKey = myTpm.s_importKey(keyVec);
	char * nd = "Notre Dame";
	std::vector<BYTE> ndVec = stringToByteVec(nd, 10);
	//Encrypt string
	std::vector<BYTE> encVec = myTpm.s_RSA_encrypt(swKey, ndVec);
	//string encStr = ByteVecToString(encVec);
	
	if (s.sendBuffer(0, encVec.size(), encVec.data())) {
		cout << "Error sending encrypted string" << endl;
	}
	else {
		cout << "Sent encrypted string" << endl;
	}
	
	s.stop();
	*/

}

