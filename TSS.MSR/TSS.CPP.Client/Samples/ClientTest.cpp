//g++ ClientTest.cpp -o client ../tpm_src/*.o  -lgmp -lssl -lcrypto -g
#define NOMINMAX

//#include "pch.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <aes.h>
#include <modes.h>
#include <chrono>
#include <unordered_set>

//#include "../includes/TPMWrapper.h"
//#include "../includes/NetworkUtils.h"
//#include "../includes/utilities.h"

#include "ShamirSecret.h"
#include "NetworkUtils.h"
#include "utilities.h"
#include "TPMWrapper.h"
#include "player.h"
#include "garble_util.h"

#define KEYFILE "keyfile.txt"
#define ENCFILE "encfile.txt"
#define DECFILE "decfile.txt"
#define NUMPARTIES_DEFAULT 1
#define CLIENT_TPM_PORT 2321
#define DEFAULT_PROTOCOL_PORT 30000

using namespace std;
using namespace std::chrono;

std::vector<BYTE> get_junk(unsigned int n);

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
	unsigned char* iv, unsigned char* ciphertext);

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
	unsigned char* iv, unsigned char* plaintext);
void handleErrors(void);

void server_connect(Server& s, unsigned int num_cons, unsigned int me,
	std::vector<std::vector<std::vector<BYTE> > >& downloads,
	const std::vector<std::vector<BYTE> >& upload);

void client_connect(unsigned int me, const std::string& hostname, unsigned int port,
	std::vector<std::vector<std::vector<BYTE> > >& downloads, const std::vector<std::vector<BYTE> >& upload);

std::vector<bool> parse_choicefile(char* filename);

int parse_netfile(char* filename, char** server_hostname, unsigned int& server_port,
	std::vector<std::pair<std::string, unsigned int> >& parties);


int main(int argc, char** argv) {

	//START
	srand(time(NULL));
	unsigned int num_required_args = 3;
	if (argc < 2 * num_required_args) {
		std::cout << "ERROR: provide all required arguments" << endl;
		return 0;
	}
	//Vars to be initialized
	unsigned int my_party = 0;
	unsigned int myPort = 0;
	char* server_hostname = "127.0.0.1";
	char* timefile = nullptr;
	unsigned int server_port = 0;
	std::vector<std::pair<std::string, unsigned int> > parties; //Get party info from file
	std::vector<bool> choices;
	char* circuit_filename = "placeholder.txt";
	//Parse arguments
	bool got_party = false;
	for (int argx = 0; argx < argc; argx++) {
		if (!strcmp(argv[argx], "--circuit")) {
			circuit_filename = argv[++argx];
			continue;
		}
		if (!strcmp(argv[argx], "--party")) {
			my_party = atoi(argv[++argx]);
			got_party = true;
			continue;
		}
		if (!strcmp(argv[argx], "--port")) {
			myPort = atoi(argv[++argx]);
			continue;
		}
		if (!strcmp(argv[argx], "--partyinfo")) {
			parse_netfile(argv[++argx], &server_hostname, server_port, parties);
			continue;
		}
		if (!strcmp(argv[argx], "--choices")) {
			choices = parse_choicefile(argv[++argx]);
			continue;
		}
		if (!strcmp(argv[argx], "--timefile")) {
			timefile = argv[++argx];
			continue;
		}
	}
	//Set my port, if not set
	myPort = parties[my_party].second;
	if (!myPort) {
		myPort = DEFAULT_PROTOCOL_PORT;
	}
	//Error checking for reading input
	assert(parties.size());
	assert(choices.size());
	assert(server_port);
	assert(got_party);

	//DEBUGGING
	std::cout << "Choices: ";
	for (bool b : choices) {
		std::cout << b << ' ';
	}
	std::cout << std::endl;


	//INITIALIZE
	std::ostringstream timeOut;
	auto startInitialize = high_resolution_clock::now();
	//1. Get key pair
	TPMWrapper myTPM;
	myTPM.init(2321);
	auto keyPair = myTPM.c_genKeys();
	//2. Broadcast public key and receive public key
	//Initialize these two parts

	std::vector<BYTE> myKeyVec = keyPair.first.ToBuf();
	//std::vector<std::vector<BYTE> > keyVec;
	std::vector<TSS_KEY> other_keys(parties.size());
	std::vector<std::thread> sendThreadVec;
	sendThreadVec.resize(parties.size());


	auto serverStart = high_resolution_clock::now();

	//First send key to server, then accept n-1 keys from server, then garbled circuit
	Client c(server_port, server_hostname);
	if (c.init()) {
		cerr << "Failed initializing client for party " << my_party << endl;
		return 1;
	}
	//Send the server our party number so they know who is who
	c.sendBuffer(sizeof(my_party), &my_party);
	//Now send the key vector
	c.sendBuffer(myKeyVec.size(), myKeyVec.data());
	//Receive the prime
	std::vector<BYTE> primeVec;
	if (c.recvByteVec(primeVec)) {
		std::cerr << "ERROR receiving prime" << std::endl;
	}
	mpz_class prime = ByteVecToMPZ(primeVec);

	//Get key vectors (in party order)
	for (unsigned int i = 0; i < parties.size(); i++) {
		//Skip my party
		if (i == my_party) {
			continue;
		}
		unsigned int msgSize;
		char* recBuf;
		if (c.recvBuffer((void**)& recBuf, msgSize)) {
			cerr << "ERROR getting key " << i << endl;
			throw std::exception("ERROR getting key");
		}
		std::vector<BYTE> keyByteVec = stringToByteVec(recBuf, msgSize);
		other_keys[i] = myTPM.s_importKey(keyByteVec);
		delete recBuf;
	}

	//Now accept garbled circuit data from server
	std::vector<BYTE> circuitBuf;
	if (c.recvByteVec(circuitBuf)) {
		cerr << "ERROR receiving circuit" << endl;
		throw std::exception("ERROR receiving circuit");
	}

	Circuit* circ = new Circuit;
	std::vector<PlayerInfo*> playerInfo(parties.size());
	for (auto& x : playerInfo) {
		x = new PlayerInfo;
	}
	read_frigate_circuit(circuit_filename, circ, &playerInfo, SEC_PARAMETER);
	//Use info from server to complete the circuit description
	bytevec_to_circuit(circ, &circuitBuf);

	std::vector<BYTE> secondBuf;
	circuit_to_bytevec(circ, &secondBuf);
	assert(circuitBuf == secondBuf);


	//Now accept wire ciphertexts from garbler
	unsigned int num_wires = playerInfo[my_party]->input_wires.size(); //Get the total number of wires
	std::vector<std::pair<std::vector<std::vector<BYTE> >, std::vector<std::vector<BYTE> > > > encLabels; //We will decrypt these (later)
	//encLabels[i] has the label pair for wire i
	encLabels.resize(num_wires);
	for (unsigned int j = 0; j < num_wires; j++) {
		//Receive c_w,0 and c_w,1 (in that order)
		//First receive how many chunks we need for wire 0
		unsigned int* numchunks;
		unsigned int recvSize;
		if (c.recvBuffer((void**)& numchunks, recvSize) || recvSize != sizeof(unsigned int)) {
			cerr << "ERROR getting number of chunks for wire 0" << endl;
			return 1;
		}
		encLabels[j].first = std::vector<std::vector<BYTE> >(*numchunks);
		for (unsigned int w0 = 0; w0 < *numchunks; w0++) {
			if (c.recvByteVec(encLabels[j].first[w0])) {
				cerr << "ERROR getting chunk " << w0 << endl;
				return 1;
			}
		}
		delete numchunks;
		//Now get how many chunks we need for wire 1
		if (c.recvBuffer((void**)& numchunks, recvSize) || recvSize != sizeof(unsigned int)) {
			cerr << "ERROR getting number of chunks for wire 1" << endl;
			return 1;
		}
		encLabels[j].second = std::vector<std::vector<BYTE> >(*numchunks);
		for (unsigned int w1 = 0; w1 < *numchunks; w1++) {
			if (c.recvByteVec(encLabels[j].second[w1])) {
				cerr << "ERROR getting chunk " << w1 << endl;
				return 1;
			}
		}
		delete numchunks;
	}
	//Close connection to garbler
	c.stop();
	auto serverStop = high_resolution_clock::now();
	auto serverDuration = duration_cast<microseconds>(serverStart - serverStop);
	cout << "Server communication time: " << serverDuration.count() << endl;

	//CHECKPOINT1
	auto endInitialize = high_resolution_clock::now();
	auto timeInitialize = duration_cast<microseconds>(endInitialize - startInitialize);
	outputTiming(timeOut, "Initialization", timeInitialize);

	//PREPROCESS
	auto startPreprocess = high_resolution_clock::now();
	//1. Decrypt
	std::vector<std::vector<BYTE> > intermediate_ciphertexts;
	intermediate_ciphertexts.resize(choices.size());
	assert(choices.size() == num_wires);
	for (unsigned int k = 0; k < choices.size(); k++) {

		//Chunk decryption modification
		intermediate_ciphertexts[k] = myTPM.chunk_decrypt(keyPair.second, (!choices[k]) ? encLabels[k].first : encLabels[k].second);

		//intermediate_ciphertexts[k] = myTPM.c_RSA_decrypt(keyPair.second, (!choices[k]) ? encLabels[k].first : encLabels[k].second);
	}
	//2. Extract symmetric key (and ciphertext)
	//Ciphertext is first, key share is second
	std::vector<std::vector<BYTE> > labels(intermediate_ciphertexts.size()); //Still encrypted
	std::vector<std::vector<BYTE> > keyShares(intermediate_ciphertexts.size());
	for (unsigned int o = 0; o < intermediate_ciphertexts.size(); o++) {
		splitIntermediate(intermediate_ciphertexts[o], labels[o], keyShares[o]);
	}
	//2b. Combine secret shares
	//Assume secrets are in a concatenated vector
	//First part is x-coord, second is y-coord
	ShamirSecret shamir(prime, num_wires, num_wires);
	std::vector<std::pair<mpz_class, mpz_class> > shares;
	for (unsigned int p = 0; p < keyShares.size(); p++) {
		std::vector<BYTE> xVec, yVec;
		splitIntermediate(keyShares[p], xVec, yVec);
		std::cout << ByteVecToMPZ(xVec) << ' ' << ByteVecToMPZ(yVec) << std::endl;
		shares.push_back(std::pair<mpz_class, mpz_class>(
			ByteVecToMPZ(xVec), ByteVecToMPZ(yVec)));
	}
	mpz_class recombined_secret = shamir.getSecret(shares);
	//2c. Get AES key from recombined secret
	ByteVec aesVec = mpz_to_vector(recombined_secret);
	//DEBUGGING print AES key
	//std::cout << "Client AES key: " << byteVecToNumberString(aesVec) << std::endl;
	//3. Use AES to decrypt labels based on choices
	//TODO finish once we have a function to convert ByteVec<->label
	std::vector<std::vector<BYTE> >
		decryptedLabels(choices.size());
#define AES_BUFFERSIZE 2048
#define IV_LEN 128
	unsigned char iv[IV_LEN / CHAR_WIDTH];
	memcpy(iv, "Notre Dame duLac", IV_LEN / CHAR_WIDTH);
	for (unsigned int g = 0; g < decryptedLabels.size(); g++) {
		decryptedLabels[g].resize(AES_BUFFERSIZE);
		int plaintext_length = decrypt(labels[g].data(), labels[g].size(), (unsigned char*)aesVec.data(), iv, decryptedLabels[g].data());
		assert(plaintext_length <= AES_BUFFERSIZE);
		decryptedLabels[g].resize(plaintext_length);
	}

	//CHECKPOINT2
	auto endPreprocess = high_resolution_clock::now();
	auto timePreprocess = duration_cast<microseconds>(endPreprocess - startPreprocess);
	outputTiming(timeOut, "Preprocessing", timePreprocess);

	//ONLINE
	auto startOnline = high_resolution_clock::now();
	//1. Broadcast (and receive) labels
	//Each party serves the number of parties - their number
	//Each party is a client to their number
	//Clients receive first, then send
	//Servers send first, then receive
	//Start client threads first

	std::vector<std::vector<std::vector<BYTE> > > downloads(parties.size());
	std::vector<std::thread> client_threads(my_party);
	unsigned int client_cons = my_party;
	unsigned int server_cons = parties.size() - client_cons - 1; //-1 so we don't count ourselves
	for (unsigned int u = 0; u < my_party; u++) {
		client_connect(my_party, parties[u].first, parties[u].second, downloads, decryptedLabels);
	}
	if (server_cons) {
		Server s(myPort);
		s.init();
		server_connect(s, server_cons, my_party, downloads, decryptedLabels);
	}
	/*
	for (unsigned int u = 0; u < client_cons; u++) {
		client_threads[u] = std::thread(&client_connect,
			my_party, parties[u].first, parties[u].second, downloads, decryptedLabels);
	}

	if (!server_cons) {
		for (auto& x : client_threads) {
			x.join();
		}
	}
	else {
		Server s(myPort);
		s.init();
		std::thread server_thread(&server_connect, s,
			server_cons, my_party,
			downloads, decryptedLabels);
		for (auto& x : client_threads) {
			x.join();
		}
		server_thread.join();
	}
	*/
	auto evalStart = high_resolution_clock::now();

	//CHECKPOINT3
	auto endOnline = high_resolution_clock::now();
	auto timeOnline = duration_cast<microseconds>(endOnline - endOnline);
	outputTiming(timeOut, "Online", timeOnline);

	//EVALUATE
	//1. Feed each label into the circuit, detect corruption
	for (unsigned int b = 0; b < parties.size(); b++) {
		std::vector<std::vector<BYTE> >* currVec = (b == my_party) ?
			&decryptedLabels : &(downloads[b]);
		unsigned int num_wires_for_player = currVec->size();
		//DEBUGGING
		/*
		std::cout << "Labels for player " << b << std::endl;
		for (const std::vector<BYTE> & v : *currVec) {
			std::cout << byteVecToNumberString(v) << std::endl;
		}
		std::cout << std::endl;
		*/

		for (unsigned int q = 0; q < num_wires_for_player; q++) {
			wire_value* wv = new wire_value(SEC_PARAMETER + 1);
			wv->from_bytevec(&((*currVec)[q]), 0, SEC_PARAMETER + 1);
			playerInfo[b]->input_wires[q]->label_kp = wv;
		}
	}

	//CHECKPOINT4

	//2. Evaluate circuit
	eval_garbled_circuit(circ);

	std::cout << "Circuit answer: " << std::endl;
	for (Wire* x : circ->output_wires) {
		std::cout << (x->output_value) << ' ';
	}
	std::cout << std::endl;
	//TODO clean up memory

	auto evalEnd = high_resolution_clock::now();
	auto evalDuration = duration_cast<microseconds>(evalEnd - evalStart);
	outputTiming(timeOut, "Evaluation", evalDuration);

	//END_TIMING

	if (timefile == nullptr) {
		std::cout << timeOut.str() << std::endl;
	}
	else {
		std::ofstream timeFileOut(timefile);
		timeFileOut << timeOut.str();
	}
	return 0;
}

//Returns random data, prepended with the length
std::vector<BYTE> get_junk(unsigned int n) {
	vector<BYTE> j(n);
	for (auto& x : j) {
		x = (BYTE)rand();
	}
	vector<BYTE> emptyVec;
	return concatenate(j, emptyVec);
}

//First line of file has number of PARTIES
//Following lines contain: partynum (-1 if garbler) hostname portnum
int parse_netfile(char* filename, char** server_hostname, unsigned int& server_port,
	std::vector<std::pair<std::string, unsigned int> >& parties) {
	unsigned int num_parties;
	std::ifstream ifs(filename);
	if (!ifs.good()) {
		cerr << "ERROR reading from netfile " << filename << endl;
		return -1;
	}
	ifs >> num_parties;
	parties.clear();
	parties.resize(num_parties);
	std::string hostname;
	unsigned int port;
	int partynum;
	unsigned int parties_seen = 0;
	bool saw_server = false;
	while (ifs >> partynum >> hostname >> port) {
		if (partynum < 0) {
			*server_hostname = new char[hostname.size() + 1];
			memcpy(*server_hostname, hostname.c_str(), hostname.size() + 1);
			server_port = port;
			saw_server = true;
		}
		else {
			parties[partynum] = std::pair<std::string, unsigned int>(hostname, port);
			parties_seen++;
		}
	}
	if (!saw_server) {
		cerr << "ERROR no server in file" << endl;
		return 1;
	}
	if (parties_seen != num_parties) {
		cerr << "ERROR  number of parties does not match" << endl;
	}
	return 0;
}

std::vector<bool> parse_choicefile(char* filename) {
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

bool amIClient(unsigned int me, unsigned int them) {
	return me < them;
}

//Clients receive first, then send
void client_connect(unsigned int me, const std::string& hostname, unsigned int port,
	std::vector<std::vector<std::vector<BYTE> > >& downloads, const std::vector<std::vector<BYTE> >& upload) {
	Client c(port, hostname.c_str());
	if (c.init()) {
		cerr << "ERROR initializing client: " << hostname << ' ' << port << endl;
		throw new std::exception("ERROR initializing client");
	}
	//Receive
	//First, receive which party the message is from
	unsigned int* them;
	unsigned int partyLen;
	if (c.recvBuffer((void**)& them, partyLen) || partyLen != sizeof(them)) {
		cerr << "ERROR : receiving" << hostname << ' ' << port << endl;
		throw new std::exception("ERROR receiving");
	}
	//Next, get how many choices they will send

	unsigned int* numChoices;
	unsigned int dataLen;
	if (c.recvBuffer((void**)& numChoices, dataLen) || dataLen != sizeof(unsigned int)) {
		cerr << "ERROR : receiving" << hostname << ' ' << port << endl;
		throw new std::exception("ERROR receiving");
	}
	//Then, accept all their choices
	downloads[*them].clear();
	downloads[*them].resize(*numChoices);
	for (unsigned int i = 0; i < *numChoices; i++) {
		if (c.recvByteVec(downloads[*them][i])) {
			cerr << "ERROR : receiving" << hostname << ' ' << port << endl;
			throw new std::exception("ERROR receiving");
		}
	}
	delete numChoices;
	//Send
	//First, send which party I am
	if (c.sendBuffer(sizeof(me), (void*)& me)) {
		cerr << "ERROR sending: " << hostname << ' ' << port << endl;
		throw new std::exception("ERROR sending");
	}
	//Next, send how many choices I am sending
	unsigned int choices = upload.size();
	if (c.sendBuffer(sizeof(unsigned int), (void*)& choices)) {
		cerr << "ERROR sending: " << hostname << ' ' << port << endl;
		throw new std::exception("ERROR sending");
	}
	//Next, send my data
	for (unsigned int j = 0; j < upload.size(); j++) {
		if (c.sendBuffer(upload[j].size(), (void*)upload[j].data())) {
			cerr << "ERROR sending: " << hostname << ' ' << port << endl;
			throw new std::exception("ERROR sending");
		}
	}

	c.stop();
}

//Servers send first, then receive
//Assumes server has been created and initialized
void server_connect(Server& s, unsigned int num_cons, unsigned int me,
	std::vector<std::vector<std::vector<BYTE> > >& downloads,
	const std::vector<std::vector<BYTE> >& upload) {
	if (!num_cons) {
		return;
	}
	s.accept_connections(num_cons);
	for (unsigned int i = 0; i < num_cons; i++) {
		//First, send which party I am
		if (s.sendBuffer(i, sizeof(me), (void*)& me)) {
			cerr << "ERROR sending: " << i << endl;
			throw new std::exception("ERROR sending");
		}
		//Next, send my data
		//First, send how many choices we're going to send
		unsigned int numChoicesToSend = upload.size();
		if (s.sendBuffer(i, sizeof(unsigned int), &numChoicesToSend)) {
			cerr << "ERROR sending: " << i;
			throw new std::exception("ERROR sending");
		}
		//Next, send each choice
		for (unsigned int j = 0; j < upload.size(); j++) {
			if (s.sendBuffer(i, upload[j].size(), (void*)upload[j].data())) {
				cerr << "ERROR sending: " << i;
				throw new std::exception("ERROR sending");
			}
		}
		//Receive
		//First, receive which party the message is from
		unsigned int* them;
		unsigned int partyLen;
		if (s.recvBuffer(i, (void**)& them, partyLen) || partyLen != sizeof(them)) {
			cerr << "ERROR : receiving" << endl;
			throw new std::exception("ERROR receiving");
		}
		//Next, get the actual data
		//char * recvData;
		unsigned int dataLen;
		unsigned int* numChoices;
		//Get the number of choices they will send
		if (s.recvBuffer(i, (void**)& numChoices, dataLen) || dataLen != sizeof(unsigned int)) {
			cerr << "ERROR : receiving" << endl;
			throw new std::exception("ERROR receiving");
		}
		downloads[*them].clear();
		downloads[*them].resize(*numChoices);
		//Receive all their choices
		for (unsigned int k = 0; k < downloads[*them].size(); k++) {
			if (s.recvByteVec(i, downloads[*them][k])) {
				cerr << "ERROR : receiving" << endl;
				throw new std::exception("ERROR receiving");
			}

			/*
			char * buf;
			if (s.recvString(i, dataLen, &buf)) {
				cerr << "ERROR : receiving" << endl;
				throw new std::exception("ERROR receiving");
			}
			downloads[*them][k] = stringToByteVec(buf, dataLen);
			delete buf;
			*/
		}
		//delete recvData;
		delete numChoices;
		delete them;
	}
}



//AES encryption/decryption from TSS.MSR Samples.cpp
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
	unsigned char* iv, unsigned char* ciphertext)
{
	EVP_CIPHER_CTX* ctx;
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

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
	unsigned char* iv, unsigned char* plaintext)
{
	EVP_CIPHER_CTX* ctx;
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
