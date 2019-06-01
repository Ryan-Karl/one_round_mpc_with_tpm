//g++ ServerTest.cpp -o server ../tpm_src/*.o  -lgmp -lssl -lcrypto -g

#define NOMINMAX

//#include "pch.h"
#include <iostream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <aes.h>
#include <modes.h>
//We might need these includes for Linux
//#include "../includes/NetworkUtils.h"
//#include "../includes/utilities.h"
//#include "../includes/TPMWrapper.h"
#include "ShamirSecret.h"
#include "NetworkUtils.h"
#include "TPMWrapper.h"
#include "utilities.h"
#include "garble_util.h"
#include "player.h"


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

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext);
void handleErrors(void);

//First arg is port, second is a string to encrypt
int main(int argc, char ** argv) {
	
	srand(1);

	unsigned int num_required_args = 2;
	if (argc < 2 * num_required_args) {
		std::cout << "ERROR: provide all required arguments" << endl;
		return 0;
	}
	char * circuitfile = nullptr; 
	unsigned int num_parties = 0; 
	unsigned int port = 0;
	for (int argx = 0; argx < argc; argx++) {
		if (!strcmp(argv[argx], "--port")) {
			port = atoi(argv[++argx]);
			continue;
		}
		if (!strcmp(argv[argx], "--circuit")) {
			circuitfile = argv[++argx];
			continue;
		}
		if(!strcmp(argv[argx], "--parties")){
			num_parties = atoi(argv[++argx]);
			continue;
		}
	}
	//Error checking
	assert(circuitfile != nullptr);
	assert(num_parties);
	assert(port);

	//Setup a prime number to use
	/*
	gmp_randstate_t state;
	gmp_randinit_mt(state);
	//Get a random seed
	std::random_device rd;
	unsigned int seed = rd();
	gmp_randseed_ui(state, seed);
	*/
	mpz_class field_size = 2;
	mpz_class prime_min;
	mpz_class prime;
	mpz_pow_ui(prime_min.get_mpz_t(), field_size.get_mpz_t(), AES_KEY_SIZE);
	//Deprecated
	mpz_nextprime(prime.get_mpz_t(), prime_min.get_mpz_t());
	//mpz_next_likely_prime(prime.get_mpz_t(), prime_min.get_mpz_t(), state);


	//INITIALIZE
	//3. Compute a garbled circuit (and send it later)
	Circuit * circ = new Circuit;
	std::vector<PlayerInfo *> playerInfo(num_parties);
	for (auto & ptr : playerInfo) {
		ptr = new PlayerInfo;
	}
	read_frigate_circuit(circuitfile, circ, &playerInfo, SEC_PARAMETER);

	//2. Receive public keys from parties	
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
		unsigned int * currentParty;
		unsigned int msgLen;
		s.recvBuffer(i, (void **)&currentParty, msgLen);
		*currentParty = ntohs(*currentParty);
		assert(msgLen == sizeof(unsigned int));
		assert(*currentParty < num_parties);
		party_to_connection[*currentParty] = i;
		//Receive the key of the party
		s.recvByteVec(i, partyKeys[*currentParty]);
		delete currentParty;
		//Send the prime to the party
		std::vector<BYTE> primeVec = mpz_to_vector(prime);
		if (s.sendBuffer(i, primeVec.size(), primeVec.data())) {
			std::cerr << "ERROR sending prime" << std::endl;
		}

	}
	//Distribute all other keys to each party
	for (unsigned int y = 0; y < num_parties; y++) {
		for (unsigned int z = 0; z < num_parties; z++) {
			if (y == z) {
				continue; //Don't bother sending a party its own key
				
			}
			else {
				//Send party z's key to party y
				s.sendBuffer(party_to_connection[y],
					partyKeys[z].size(), partyKeys[z].data());
			}
		}
	}
	//Switch to software keys
	std::vector<TSS_KEY> keyvec(partyKeys.size());
	for (unsigned int u = 0; u < partyKeys.size(); u++) {
		keyvec[u] = TPMWrapper::s_importKey(partyKeys[u]);
	}
	//An error check to do: assert that every entry in the vector is filled

	//Do garbling of circuit
	get_garbled_circuit(circ);
	//Send circuit
	std::vector<BYTE> circuitByteVec;
	circuit_to_bytevec(circ, &circuitByteVec);

	//DEBUGGING
	//std::cout << "Sum of circuit: ";
	//mpz_class circuit_sum = ByteVecToMPZ(circuitByteVec);
	//std::cout << circuit_sum << std::endl;
	//std::cout << "Modded circuit sum: ";
	//mpz_mod_ui(circuit_sum.get_mpz_t(), circuit_sum.get_mpz_t(), 2147483647);
	//std::cout << circuit_sum << std::endl;

	for (unsigned int t = 0; t < num_parties; t++) {
		if (s.sendBuffer(t, circuitByteVec.size(), (void *)circuitByteVec.data())) {
			cerr << "ERROR sending circuit" << endl;
			return 1;
		}
	}	

	//4. Select partial keys, get AES key, and split key into W_i shares for each party.
	//(Need to get W_i)
	vector<unsigned int> party_to_numwires(num_parties); 
	for (unsigned int z = 0; z < num_parties; z++) {
		//Frigate may be off-by-one
		party_to_numwires[z] = playerInfo[z]->input_wires.size();
	}

	//Initialize the TPM to get randomness
	TPMWrapper myTPM;
	//For each party:
	unsigned char iv_str[10]; // = "Notre Dame Computer Science and Engineering";
	memcpy(iv_str, "Notre Dame", 10);
	for (unsigned int j = 0; j < num_parties; j++) {
		//Get AES key
		std::vector<BYTE> aes_key, iv;
		aes_key = myTPM.getRandBytes(AES_KEY_SIZE/CHAR_WIDTH);
		iv = myTPM.getRandBytes(IV_SIZE/CHAR_WIDTH);
		mpz_class aes_key_mpz = ByteVecToMPZ(aes_key);
		//Split AES key into shares - need a n-of-n secret share here
		ShamirSecret splitKeys(prime, party_to_numwires[j], party_to_numwires[j]);
		auto allShares = splitKeys.getShares(aes_key_mpz);
		//Construct labels to be sent
		std::vector<std::pair<std::vector<BYTE>, std::vector<BYTE> > >
			partyLabels(party_to_numwires[j]); 
		for (unsigned int h = 0; h < partyLabels.size(); h++) {
			wire_value * firstlabel = wire2garbling(playerInfo[j]->input_wires[h], 0);
			std::cout << firstlabel->bits << std::endl;
			wire_value * secondlabel = wire2garbling(playerInfo[j]->input_wires[h], 1);
			std::cout << secondlabel->bits << std::endl;
			partyLabels[h].first = firstlabel->to_bytevec();
			partyLabels[h].second = secondlabel->to_bytevec();
			delete firstlabel;
			delete secondlabel;
		}
		std::vector<std::pair<std::vector<BYTE>, std::vector<BYTE> > >
			encPartyLabels(party_to_numwires[j]); //The encrypted labels
		//Encrypt the labels
		for (unsigned int r = 0; r < partyLabels.size(); r++) {
			int ctext0_size = AES_BLOCK_SIZE + partyLabels[r].first.size();
			int ctext1_size = AES_BLOCK_SIZE + partyLabels[r].second.size();
			unsigned char * ciphertext;
			ciphertext = new unsigned char[ctext0_size];
			int label0_size = encrypt(partyLabels[r].first.data(), partyLabels[r].first.size(), aes_key.data(), iv.data(), ciphertext);
			encPartyLabels[r].first = stringToByteVec((char *) ciphertext, label0_size);
			delete ciphertext;
			ciphertext = new unsigned char[ctext1_size];
			int label1_size = encrypt(partyLabels[r].second.data(), partyLabels[r].second.size(), aes_key.data(), iv.data(), ciphertext);
			encPartyLabels[r].second = stringToByteVec((char *) ciphertext, label1_size);
			delete ciphertext;
		}
		for (unsigned int k = 0; k < encPartyLabels.size(); k++) {
			//Construct secret share of key as bytevec
			std::vector<BYTE> shareX = mpz_to_vector(allShares[k].first);
			std::vector<BYTE> shareY = mpz_to_vector(allShares[k].second);
			std::vector<BYTE> sharePair = concatenate(shareX, shareY);
			//Construct and send 0 and 1 wire labels, concatenated with secret share
			std::vector<BYTE> wire0share = concatenate(encPartyLabels[k].first, sharePair);
			std::vector<BYTE> wire1share = concatenate(encPartyLabels[k].second, sharePair);

			//Chunk encryption modification
			std::vector<std::vector<BYTE> > wire0ctext = TPMWrapper::chunk_encrypt(keyvec[j], wire0share, 128);
			std::vector<std::vector<BYTE> > wire1ctext = TPMWrapper::chunk_encrypt(keyvec[j], wire1share, 128);
			
			//Send number of chunks for wire 0 ciphertext
			unsigned int wire0chunks = wire0ctext.size();
			if (s.sendBuffer(party_to_connection[j], sizeof(wire0chunks), &wire0chunks)) {
				cerr << "ERROR sending number of chunks for wire 0 to party " << k << std::endl;
				return 1;
			}
			//Send chunks
			for (unsigned int w0 = 0; w0 < wire0chunks; w0++) {
				if (s.sendBuffer(party_to_connection[j], wire0ctext[w0].size(), wire0ctext[w0].data())) {
					cerr << "ERROR sending chunk " << w0 << " for wire 0 to party " << k << endl;
					return 1;
				}
			}
			//Send number of chunks for wire 1 ciphertext
			unsigned int wire1chunks = wire1ctext.size();
			if (s.sendBuffer(party_to_connection[j], sizeof(wire1chunks), &wire1chunks)) {
				cerr << "ERROR sending number of chunks for wire 1 to party " << k << std::endl;
				return 1;
			}
			//Send chunks
			for (unsigned int w1 = 0; w1 < wire0chunks; w1++) {
				if (s.sendBuffer(party_to_connection[j], wire1ctext[w1].size(), wire1ctext[w1].data())) {
					cerr << "ERROR sending chunk " << w1 << " for wire 0 to party " << k << endl;
					return 1;
				}
			}
		}
	}

	//That's all folks!
	//Cleanup
	for (auto & ptr : playerInfo) {
		delete ptr;
	}
	//Makeshift destructor for the circuit
	//Still need to delete label_kp and label_k from each Wire*
	std::deque<Wire *> wireholder;
	top_sort(wireholder, circ);
	for (Wire * w : wireholder) {
		delete w;
	}
	s.stop();
	std::cout << "Garbler finished" << endl;
	return 0;

}

//AES encryption/decryption from TSS.MSR Samples.cpp
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;
	// Create and initialise the context
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	// Initialise the encryption operation. IMPORTANT - ensure you use a key and IV size appropriate for your cipher. In this example we are using 256 bit AES (i.e. a 256 bit key). The IV size for *most* modes is the same as the block size. For AES this is 128 bits
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();
	// Provide the message to be encrypted, and obtain the encrypted output. EVP_EncryptUpdate can be called multiple times if necessary
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;
	// Finalise the encryption. Further ciphertext bytes may be written at this stage.
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;
	// Clean up

	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	// Create and initialise the context
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	// Initialise the decryption operation. IMPORTANT - ensure you use a key  and IV size appropriate for your cipher.

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();
	// Provide the message to be decrypted, and obtain the plaintext output.
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;
	// Finalise the decryption. Further plaintext bytes may be written at this stage.
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;
	// Clean up
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}
