
/*++

Copyright (c) 2013, 2014  Microsoft Corporation
Microsoft Confidential

*/
#include "stdafx.h"
#include "Samples.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <cstdio>
#include <iostream>
#include <modes.h>
#include <aes.h>
#include "ShamirSecret.h"
#include <vector>
#include <iterator>
#include <cassert>
#include <fstream>


//https://social.msdn.microsoft.com/Forums/vstudio/en-US/9c0cbc07-823a-4ea7-bf7f-e05e13c17fb2/fatal-error-c1083-cannot-open-include-file-opensslcryptoh-no-such-file-or-directory
//https://stackoverflow.com/questions/15203562/crypto-giving-a-compiler-error-in-algparam-h

// The following macro checks that the sample did not leave any keys in the TPM.
#define _check AssertNoLoadedKeys();


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext);
void handleErrors(void);


std::vector<BYTE> stringToByteVec(const char * str, unsigned int strlen) {
	std::vector<BYTE> v;
	v.reserve(strlen);
	for (unsigned int i = 0; i < strlen; i++) {
		v.push_back(str[i]);
	}
	return v;
}

std::vector<BYTE> stringToByteVec(const std::string & s) {
	std::vector<BYTE> v;
	v.reserve(s.size());
	for (unsigned int i = 0; i < s.size(); i++) {
		v.push_back(s[i]);
	}
	return v;
}

std::vector<std::vector<BYTE> > vectorsFromHexFile(std::ifstream & ifs) {
	std::string line;
	std::vector<std::vector<BYTE> > ret;
	while (getline(ifs, line)) {
		std::istringstream iss(line);
		iss >> std::hex;
		std::vector<BYTE> tmp;
		ret.push_back(tmp);
		int byteIn;
		while (iss >> std::hex >> byteIn) {
			ret[ret.size() - 1].push_back(byteIn & 0xFF);
		}
	}
	return ret;
}

void outputToStream(std::ostream & os, const std::vector<BYTE> & bv) {
	os << std::hex;
	for (size_t i = 0; i < bv.size(); i++) {
		os << (int) bv[i];
		os << " ";
		/*
		if((i%4) == 3){
			os << " ";
		}
		*/
	}
}


void RunSamples();

Samples::Samples()
{
	//RunSamples();

	device = new TpmTcpDevice("127.0.0.1", 2321);

	if (!device->Connect()) {
		throw runtime_error("Could not connect to TPM device.");
	}

	tpm._SetDevice(*device);

	// The rest of this routine brings up the simulator.  This is generally not
	// needed for a "real" TPM.

	// If the simulator is not shut down cleanly (e.g. because the test app crashed)
	// this is called a "disorderly shutdown" and the TPM goes into lockout.  The
	// following routine will recover the TPM. This is optional - it just makes
	// debugging more pleasant.
	RecoverFromLockout();

	// Otherwise, power-on the TPM. Note that we power off and then power on
	// because PowerOff cannot fail, but PowerOn fails if the TPM is already
	// "on."
	device->PowerOff();
	device->PowerOn();

	// The following routine installs callbacks so that we can collect stats on
	// commands executed.
	Callback1();

	// Startup the TPM
	tpm.Startup(TPM_SU::CLEAR);

	return;
}

Samples::~Samples()
{
	// A clean shutdown results in fewer lockout errors.
	tpm.Shutdown(TPM_SU::CLEAR);
	device->PowerOff();

	// The following routine finalizes and prints the function stats.
	//Callback2();

	// REVISIT 
	// delete device;
}

void Samples::RunAllSamples()
{
	_check
		//MPC_TPM();
		//SoftwareKeys();
		ImportDuplicate();
	_check;

	//Callback2();
}

void Samples::Announce(const char *testName)
{
	SetCol(0);
	cout << flush;
	cout << "================================================================================" << endl << flush;
	cout << "          " << testName << endl << flush;
	cout << "================================================================================" << endl << flush;
	cout << flush;
	SetCol(1);
}

std::string ByteVecToString(const std::vector<BYTE> &v) {
	std::string str = "";
	for (const auto & c : v) {
		str += c;
	}
	return str;
}

mpz_class ByteVecToMPZ(const std::vector<BYTE> &v){
	mpz_class mcand = 1;
	mpz_class result = 0;
	for(const auto & c : v){
		result += mcand*c;
		//Shift left by 8 bits
		mpz_mul_2exp(mcand.get_mpz_t(), mcand.get_mpz_t(), 8);
	}
	return result;
}


ByteVec mpz_to_vector(const mpz_t x) {
	size_t size = (mpz_sizeinbase(x, 2) + CHAR_BIT - 1) / CHAR_BIT;
	std::vector<BYTE> v(size);
	mpz_export(&v[0], &size, 1, 1, 0, 0, x);
	v.resize(size);
	return v;
}

inline ByteVec mpz_to_vector(mpz_class & x) {
	return mpz_to_vector(x.get_mpz_t());
}

std::vector<BYTE> intToByteVec(int x) {
	std::vector<BYTE> ret;
	ret.reserve(4);
	ret.push_back((x >> 24) && 0xFF);
	ret.push_back((x >> 16) && 0xFF);
	ret.push_back((x >> 8) && 0xFF);
	ret.push_back(x && 0xFF);
	return ret;
}

void Samples::MPC_TPM()
{

//#define RSAKEYSIZE 16384

	Announce("MPC_TPM");

	// We will make a key in the "null hierarchy".
	TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::decrypt |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec,  
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT::NullObject(),
			TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	// Create the key
	CreatePrimaryResponse storagePrimary = tpm.CreatePrimary(
		TPM_HANDLE::FromReservedHandle(TPM_RH::_NULL),
		TPMS_SENSITIVE_CREATE(NullVec, NullVec),
		storagePrimaryTemplate,
		NullVec,
		vector<TPMS_PCR_SELECTION>());

	TPM_HANDLE& keyHandle = storagePrimary.handle;

//	TPM_HANDLE primaryKey = MakeStoragePrimary();
//	TPM_HANDLE signingKey = MakeChildSigningKey(primaryKey, true);
//	ReadPublicResponse pubKey = tpm.ReadPublic(signingKey);


	cout << "New RSA primary key" << endl << storagePrimary.outPublic.ToString() << endl;
	cout << "Name of new key:" << endl;
	cout << " Returned by TPM " << storagePrimary.name << endl;



	int nvIndex = 1000;
	ByteVec nvAuth{ 1, 5, 1, 1 };
	TPM_HANDLE nvHandle = TPM_HANDLE::NVHandle(nvIndex);

	// Try to delete the slot if it exists
	tpm._AllowErrors().NV_UndefineSpace(tpm._AdminOwner, nvHandle);

	TPMS_NV_PUBLIC nvTemplate2(nvHandle,            // Index handle
		TPM_ALG_ID::SHA256,  // Name-alg
		TPMA_NV::AUTHREAD | // Attributes
		TPMA_NV::AUTHWRITE |
		TPMA_NV::COUNTER,
		NullVec,             // Policy
		8);                  // Size in bytes

	tpm.NV_DefineSpace(tpm._AdminOwner, nvAuth, nvTemplate2);

	// We have set the authVal to be nvAuth, so set it in the handle too.
	nvHandle.SetAuth(nvAuth);

	ByteVec toWrite{ 1, 2, 3, 4, 5, 4, 3, 2, 1 };

	// Should not be able to write (increment only)
	tpm._ExpectError(TPM_RC::ATTRIBUTES).NV_Write(nvHandle, nvHandle, toWrite, 0);

	// Should not be able to read before the first increment
	tpm._ExpectError(TPM_RC::NV_UNINITIALIZED).NV_Read(nvHandle, nvHandle, 8, 0);
	
	// Now encrypt using TSS.C++ library functions with padding

	ByteVec secret_Array[5];
	ByteVec enc_Array[5];
	ByteVec dec_Array[5];
	ByteVec pad{ 1, 2, 3, 4, 5, 6, 0 };

	for (int j = 0; j < 5; j++) {

		secret_Array[j] = tpm._GetRandLocal(128);
		enc_Array[j] = storagePrimary.outPublic.Encrypt(secret_Array[j], pad);
	}

	// Get a key attestation.
	
	ByteVec nonce{ 5, 6, 7 };
//	CertifyResponse keyInfo = tpm.Certify(signingKey, signingKey, nonce, TPMS_NULL_SIG_SCHEME());

	// Validate then cerify against the known name of the key
//	bool sigOk = pubKey.outPublic.ValidateCertify(pubKey.outPublic, nonce, keyInfo);

//	if (sigOk) {
//		cout << endl << "Key certification validated" << endl << endl;
//	}
	
	// First increment
	tpm.NV_Increment(nvHandle, nvHandle);

	// Should now be able to read
	ByteVec beforeIncrement = tpm.NV_Read(nvHandle, nvHandle, 8, 0);
	cout << "Initial counter data:     " << beforeIncrement << endl;

	// Should be able to increment
	for (int j = 0; j < 5; j++) {
		//tpm.NV_Increment(nvHandle, nvHandle);

		dec_Array[j] = tpm.RSA_Decrypt(keyHandle, enc_Array[j], TPMS_NULL_ASYM_SCHEME(), pad);
		cout << "My           secret: " << secret_Array[j] << endl;
		cout << "My decrypted secret: " << dec_Array[j] << endl << endl;

		// And make sure that it's good
		ByteVec afterIncrement = tpm.NV_Read(nvHandle, nvHandle, 8, 0);
		cout << "Value after increment:       " << afterIncrement << endl << endl;
		/*
		if (j >= 4)
		{
			tpm.FlushContext(keyHandle);
			cout << endl << "Flushed Key After Monotonic Counter Incremented 5 Times" << endl << endl;

			// And then delete it
			tpm.NV_UndefineSpace(tpm._AdminOwner, nvHandle);

		}
	}
	*/
#define AES_KEY_SIZE 32
#define IV_SIZE 16
		std::vector<BYTE> key, iv;
		key = tpm._GetRandLocal(AES_KEY_SIZE);
		iv = tpm._GetRandLocal(IV_SIZE);

		mpz_class prime;
		mpz_class mpz_key = ByteVecToMPZ(key);
		//May need to initialize prime differently
		std::cout << "DEBUG: key in mpz format is " << mpz_key << std::endl;
		mpz_nextprime(prime.get_mpz_t(), mpz_key.get_mpz_t());


		//placeholders until we determine # of wires owned
		unsigned int number_shares = 6;
		unsigned int minimum = 3;

		//ShamirSecret splitKeys(prime, number_shares, minimum);

		//std::vector<std::pair<mpz_class, mpz_class> > shares = splitKeys.getShares(mpz_key);
		//std::vector<std::pair<mpz_class, mpz_class> > partialShares(std::begin(shares), std::begin(shares) + minimum);


		//mpz_class recombined_secret = splitKeys.getSecret(partialShares);

		//std::cout << "Recombined Key:             " << recombined_secret << std::endl;

		// Message to be encrypted
		unsigned char *plaintext =
			(unsigned char *)"The quick brown fox jumps over the lazy dog";
		// Buffer for ciphertext. Ensure the buffer is long enough for the ciphertext which may be longer than the plaintext, dependant on the algorithm and mode
		cout << "The message is " << plaintext << endl << endl;

		unsigned char ciphertext[128];
		unsigned char decryptedtext[128];
		int decryptedtext_len, ciphertext_len;

		const char * key_str = ByteVecToString(key).c_str();
		const char * iv_str = ByteVecToString(iv).c_str();

		ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), (unsigned char *)key_str, (unsigned char *)iv_str, 
			ciphertext);

		// Do something useful with the ciphertext here
		printf("Ciphertext is:\n");
		BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
		// Decrypt the ciphertext
		decryptedtext_len = decrypt(ciphertext, ciphertext_len, (unsigned char *)key_str, (unsigned char *)iv_str,
			decryptedtext);
		// Add a NULL terminator. We are expecting printable text
		decryptedtext[decryptedtext_len] = '\0';
		// Show the decrypted text
		printf("Decrypted text is:\n");
		printf("%s\n", decryptedtext);



		//Define placeholder wire labels (assume three wires for test)
		unsigned char * wire_0_0 = (unsigned char *)"WIRE_LABEL_0_0";
		unsigned char * wire_0_1 = (unsigned char *)"WIRE_LABEL_0_1";
		unsigned char wire_0_0_ciphertext[64];
		unsigned char wire_0_1_ciphertext[64];

		unsigned char * wire_1_0 = (unsigned char *)"WIRE_LABEL_1_0";
		unsigned char * wire_1_1 = (unsigned char *)"WIRE_LABEL_1_1";
		unsigned char wire_1_0_ciphertext[64];
		unsigned char wire_1_1_ciphertext[64];

		unsigned char * wire_2_0 = (unsigned char *)"WIRE_LABEL_2_0";
		unsigned char * wire_2_1 = (unsigned char *)"WIRE_LABEL_2_1";
		unsigned char wire_2_0_ciphertext[64];
		unsigned char wire_2_1_ciphertext[64];

		//Encrypt wire labels using AES
		int wire_0_0_len = encrypt(wire_0_0, strlen((char *)wire_0_0), (unsigned char *)key_str, (unsigned char *)iv_str, wire_0_0_ciphertext);
		int wire_0_1_len = encrypt(wire_0_1, strlen((char *)wire_0_1), (unsigned char *)key_str, (unsigned char *)iv_str, wire_0_1_ciphertext);

		int wire_1_0_len = encrypt(wire_1_0, strlen((char *)wire_1_0), (unsigned char *)key_str, (unsigned char *)iv_str, wire_1_0_ciphertext);
		int wire_1_1_len = encrypt(wire_1_1, strlen((char *)wire_1_1), (unsigned char *)key_str, (unsigned char *)iv_str, wire_1_1_ciphertext);

		int wire_2_0_len = encrypt(wire_2_0, strlen((char *)wire_2_0), (unsigned char *)key_str, (unsigned char *)iv_str, wire_2_0_ciphertext);
		int wire_2_1_len = encrypt(wire_2_1, strlen((char *)wire_2_1), (unsigned char *)key_str, (unsigned char *)iv_str, wire_2_1_ciphertext);

		//Split AES encrypted wire labels into Shamir shares.
		ShamirSecret splitKeys(prime, number_shares, minimum);

		std::vector<std::pair<mpz_class, mpz_class> > shares_key = splitKeys.getShares(ByteVecToMPZ(key));
		std::vector<std::pair<mpz_class, mpz_class> > shares_iv = splitKeys.getShares(ByteVecToMPZ(iv));

		std::vector<std::pair<mpz_class, mpz_class> > partialShares_key(std::begin(shares_key), std::begin(shares_key) + minimum);
		std::vector<std::pair<mpz_class, mpz_class> > partialShares_iv(std::begin(shares_iv), std::begin(shares_iv) + minimum);

		unsigned int numb_entries = sizeof(int) / sizeof(BYTE);

		std::vector<BYTE> wire_0_0_placeholder(wire_0_0_ciphertext, wire_0_0_ciphertext + 128);
		std::vector<BYTE> wire_0_1_placeholder(wire_0_1_ciphertext, wire_0_1_ciphertext + 128);
		std::vector<BYTE> wire_1_0_placeholder(wire_1_0_ciphertext, wire_1_0_ciphertext + 128);
		std::vector<BYTE> wire_1_1_placeholder(wire_1_1_ciphertext, wire_1_1_ciphertext + 128);
		std::vector<BYTE> wire_2_0_placeholder(wire_2_0_ciphertext, wire_2_0_ciphertext + 128);
		std::vector<BYTE> wire_2_1_placeholder(wire_2_1_ciphertext, wire_2_1_ciphertext + 128);

		//	ByteVec wire_0_0_RSA_ciphertext = tpm.RSA_Encrypt(keyHandle, wire_0_0_ciphertext, TPMS_NULL_ASYM_SCHEME(), NullVec);
			/*
			for (int i = 0; i < partialShares_key.size(); i++)
			{
				ByteVec mpz_result = mpz_to_vector(partialShares_key[i].second);

				for (int j = 0; j < AES_KEY_SIZE; j++)
				{
					if (j < mpz_result.size())
					{
						wire_0_0_placeholder.push_back(mpz_result[j]);
						wire_0_1_placeholder.push_back(mpz_result[j]);
						wire_1_0_placeholder.push_back(mpz_result[j]);
						wire_1_1_placeholder.push_back(mpz_result[j]);
						wire_2_0_placeholder.push_back(mpz_result[j]);
						wire_2_1_placeholder.push_back(mpz_result[j]);
					}
					else
					{
						wire_0_0_placeholder.push_back(0);
						wire_0_1_placeholder.push_back(0);
						wire_1_0_placeholder.push_back(0);
						wire_1_1_placeholder.push_back(0);
						wire_2_0_placeholder.push_back(0);
						wire_2_1_placeholder.push_back(0);
					}

				}
			}*/

			//dec_Array[j] = tpm.RSA_Decrypt(keyHandle, enc_Array[j], TPMS_NULL_ASYM_SCHEME(), pad);
//	ByteVec wire_0_0_RSA_ciphertext = tpm.RSA_Encrypt(keyHandle, wire_0_0_placeholder, TPMS_NULL_ASYM_SCHEME(), NullVec);
		ByteVec wire_0_0_RSA_ciphertext = storagePrimary.outPublic.Encrypt(wire_0_0_placeholder, pad);
		ByteVec wire_0_1_RSA_ciphertext = storagePrimary.outPublic.Encrypt(wire_0_1_placeholder, pad);
		ByteVec wire_1_0_RSA_ciphertext = storagePrimary.outPublic.Encrypt(wire_1_0_placeholder, pad);
		ByteVec wire_1_1_RSA_ciphertext = storagePrimary.outPublic.Encrypt(wire_1_1_placeholder, pad);
		ByteVec wire_2_0_RSA_ciphertext = storagePrimary.outPublic.Encrypt(wire_2_0_placeholder, pad);
		ByteVec wire_2_1_RSA_ciphertext = storagePrimary.outPublic.Encrypt(wire_2_1_placeholder, pad);

		std::ofstream outfile("example.txt", ios::out | ios::binary);

		outputToStream(outfile, wire_0_0_RSA_ciphertext);
		outfile << std::endl;
		outputToStream(outfile, wire_0_1_RSA_ciphertext);
		outfile << std::endl;
		outputToStream(outfile, wire_1_0_RSA_ciphertext);
		outfile << std::endl;
		outputToStream(outfile, wire_1_1_RSA_ciphertext);
		outfile << std::endl;
		outputToStream(outfile, wire_2_0_RSA_ciphertext);
		outfile << std::endl;
		outputToStream(outfile, wire_2_1_RSA_ciphertext);
		outfile << std::endl;

		outfile.close();




		ByteVec wire_0_0_RSA_ciphertext_file;
		ByteVec wire_0_1_RSA_ciphertext_file;
		ByteVec wire_1_0_RSA_ciphertext_file;
		ByteVec wire_1_1_RSA_ciphertext_file;
		ByteVec wire_2_0_RSA_ciphertext_file;
		ByteVec wire_2_1_RSA_ciphertext_file;

		std::ifstream infile("example.txt");

		std::vector<std::vector<BYTE> > RSA_ciphertext = vectorsFromHexFile(infile);

		assert(RSA_ciphertext[0] == wire_0_0_RSA_ciphertext);
		assert(RSA_ciphertext[1] == wire_0_1_RSA_ciphertext);
		assert(RSA_ciphertext[2] == wire_1_0_RSA_ciphertext);
		assert(RSA_ciphertext[3] == wire_1_1_RSA_ciphertext);
		assert(RSA_ciphertext[4] == wire_2_0_RSA_ciphertext);
		assert(RSA_ciphertext[5] == wire_2_1_RSA_ciphertext);

		infile.close();

		std::vector <std::vector <BYTE> > decrypted_RSA_ciphertext_wires;
		decrypted_RSA_ciphertext_wires.resize(6);

		for (unsigned int i = 0; i < 6; i++)
		{
			decrypted_RSA_ciphertext_wires[i] = tpm.RSA_Decrypt(keyHandle, RSA_ciphertext[i], TPMS_NULL_ASYM_SCHEME(), pad);
		}

		assert(wire_0_0_placeholder == decrypted_RSA_ciphertext_wires[0]);
		assert(wire_0_1_placeholder == decrypted_RSA_ciphertext_wires[1]);
		assert(wire_1_0_placeholder == decrypted_RSA_ciphertext_wires[2]);
		assert(wire_1_1_placeholder == decrypted_RSA_ciphertext_wires[3]);
		assert(wire_2_0_placeholder == decrypted_RSA_ciphertext_wires[4]);
		assert(wire_2_1_placeholder == decrypted_RSA_ciphertext_wires[5]);

		ByteVec recover_shares;

		/*for (int i = 0; i < decrypted_RSA_ciphertext_wires.size(); i = (i + 2))
			{
				recover_shares.push_back(decrypted_RSA_ciphertext_wires[i]);
			}

			mpz_class recombined_secret = splitKeys.getSecret(ByteVecToMPZ(recover_shares));
			*/
		//std::cout << "Recombined Key:             " << recombined_secret << std::endl;

		unsigned char decrypted_wire[128];

		for (int k = 1; k < decrypted_RSA_ciphertext_wires.size(); k = (k + 2))
		{
	//FIX THIS		int decryptedWire_len = decrypt((unsigned char *)decrypted_RSA_ciphertext_wires[k].data(),
	//			decrypted_RSA_ciphertext_wires.size(), (unsigned char *)key_str, (unsigned char *)iv_str, decrypted_wire);
		}



	}

	
	tpm.FlushContext(keyHandle);
	//tpm.FlushContext(signingKey);
	
	return;
}

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

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



void Samples::Rand()
{
	Announce("Rand");

	auto rand = tpm.GetRandom(20);
	cout << "random bytes:      " << rand << endl;

	tpm.StirRandom(std::vector<BYTE> {1, 2, 3});

	rand = tpm.GetRandom(20);
	cout << "more random bytes: " << rand << endl;

	return;
}

void Samples::SetCol(UINT16 col)
{
#ifdef _WIN32
	UINT16 fColor;

	switch (col) {
	case 0:
		fColor = FOREGROUND_GREEN;
		break;

	case 1:
		fColor = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED;
		break;

	default:;
	};

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), fColor);
#endif

	return;
}

void Samples::PCR()
{
	Announce("PCR");

	// Modify PCR0 via a PCR_Event, and print out the value
	vector<BYTE> toEvent{ 1, 2, 3 };
	vector<TPMT_HA> afterEvent = tpm.PCR_Event(TPM_HANDLE::PcrHandle(0), toEvent);

	cout << "PCR after event:" << endl << afterEvent[0].ToString() << endl;

	vector<TPMS_PCR_SELECTION> toReadArray{
		TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, 0),
		TPMS_PCR_SELECTION(TPM_ALG_ID::SHA256, 1)
	};

	// Get the initial values of two PCRs: one SHA1, and one SHA256
	auto initVals = tpm.PCR_Read(toReadArray);
	cout << "Initial value:" << endl << initVals.ToString(false) << endl;

	// Used by PCR_Read to read PCR0 in the SHA1 bank
	vector<TPMS_PCR_SELECTION> toReadPcr0{
		TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, 0)
	};

	// Modify PCR0 via event
	auto newVals = tpm.PCR_Event(TPM_HANDLE::PcrHandle(0), toEvent);
	auto pcrVals = tpm.PCR_Read(toReadPcr0);
	cout << "SHA1 After Event:" << endl << pcrVals.pcrValues[0].ToString() << endl;

	// Now modify the SHA1 PCR0 via extend
	TPMT_HA toExtend = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA1, "abc");
	tpm.PCR_Extend(TPM_HANDLE::PcrHandle(0), std::vector<TPMT_HA> {toExtend});

	// Now read SHA1:PCR0 again
	pcrVals = tpm.PCR_Read(toReadPcr0);
	cout << "SHA1 After Extend:" << endl << pcrVals.pcrValues[0].ToString() << endl;
	TPMT_HA pcrAtEnd(TPM_ALG_ID::SHA1, pcrVals.pcrValues[0].buffer);

	//Check that this answer is what we expect
	TPMT_HA pcrSim(TPM_ALG_ID::SHA1, initVals.pcrValues[0].buffer);
	pcrSim.Event(toEvent);
	pcrSim.Extend(toExtend.digest);

	if (pcrSim == pcrAtEnd) {
		cout << "PCR values correct" << endl;
	}
	else {
		cout << "Error: PCR values NOT correct" << endl;
		_ASSERT(FALSE);
	}

	// Extend a resettable PCR
	UINT32 resettablePcr = 16;
	tpm.PCR_Event(TPM_HANDLE::PcrHandle(resettablePcr), ByteVec{ 1, 2, 3 });
	auto resettablePcrVal = tpm.PCR_Read(vector<TPMS_PCR_SELECTION> {TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, resettablePcr)});
	cout << "Resettable PCR before reset: " << resettablePcrVal.pcrValues[0].buffer << endl;

	tpm.PCR_Reset(TPM_HANDLE::PcrHandle(resettablePcr));
	resettablePcrVal = tpm.PCR_Read(vector<TPMS_PCR_SELECTION> {TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, resettablePcr)});
	cout << "After reset:                 " << resettablePcrVal.pcrValues[0].buffer << endl;

	// Check it really is all zeros
	_ASSERT(resettablePcrVal.pcrValues[0].buffer == ByteVec(20));

	return;
}

void Samples::Locality()
{
	Announce("Locality");

	// Extend the resettable PCR
	UINT32 locTwoResettablePcr = 21;

	tpm._GetDevice().SetLocality(2);
	tpm.PCR_Event(TPM_HANDLE::PcrHandle(locTwoResettablePcr), ByteVec{ 1, 2, 3, 4 });
	tpm._GetDevice().SetLocality(0);

	auto resettablePcrVal = tpm.PCR_Read(vector<TPMS_PCR_SELECTION> {TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, locTwoResettablePcr)});
	cout << "PCR before reset at locality 2: " << resettablePcrVal.pcrValues[0].buffer << endl;

	// Should fail - tell Tpm2 not to generate an exception
	tpm._ExpectError(TPM_RC::LOCALITY).PCR_Reset(TPM_HANDLE::PcrHandle(locTwoResettablePcr));

	// Should fail - tell Tpm2 not to generate an exception (second way)
	tpm._DemandError().PCR_Reset(TPM_HANDLE::PcrHandle(locTwoResettablePcr));

	// Should succeed at locality 2
	tpm._GetDevice().SetLocality(2);
	tpm.PCR_Reset(TPM_HANDLE::PcrHandle(locTwoResettablePcr));

	// Return to locality zero
	tpm._GetDevice().SetLocality(0);
	resettablePcrVal = tpm.PCR_Read(vector<TPMS_PCR_SELECTION> {TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, locTwoResettablePcr)});
	cout << "PCR After reset at locality 2:  " << resettablePcrVal.pcrValues[0].buffer << endl;

	return;
}

void Samples::Hash()
{
	Announce("Hash");

	vector<TPM_ALG_ID> hashAlgs{ TPM_ALG_ID::SHA1, TPM_ALG_ID::SHA256 };
	ByteVec accumulator;
	ByteVec data1{ 1, 2, 3, 4, 5, 6 };

	cout << "Simple Hashing" << endl;

	for (auto iterator = hashAlgs.begin(); iterator != hashAlgs.end(); iterator++) {
		auto hashResponse = tpm.Hash(data1, *iterator, TPM_HANDLE::NullHandle());
		auto expected = CryptoServices::Hash(*iterator, data1);

		_ASSERT(hashResponse.outHash == expected);
		cout << "Hash:: " << Tpm2::GetEnumString(*iterator) << endl;
		cout << "Expected:      " << expected << endl;
		cout << "TPM generated: " << hashResponse.outHash << endl;
	}

	cout << "Hash sequences" << endl;

	for (auto iterator = hashAlgs.begin(); iterator != hashAlgs.end(); iterator++) {
		auto hashHandle = tpm.HashSequenceStart(NullVec, *iterator);
		accumulator.clear();

		for (int j = 0; j < 10; j++) {
			// Note the syntax below. If no explicit sessions are provided then the
			// library automatically uses PWAP with the authValue contained in the handle.
			// If you want to mix PWAP and other sessions then you can use the psuedo-PWAP
			// session as below.
			AUTH_SESSION pwapSession = AUTH_SESSION::PWAP();
			tpm._Sessions(pwapSession).SequenceUpdate(hashHandle, data1);
			accumulator = Helpers::Concatenate(accumulator, data1);
		}

		accumulator = Helpers::Concatenate(accumulator, data1);

		// Note that the handle is flushed by the TPM when the sequence is completed
		auto hashVal = tpm.SequenceComplete(hashHandle, data1, TPM_HANDLE::NullHandle());
		auto expected = CryptoServices::Hash(*iterator, accumulator);

		_ASSERT(hashVal.result == expected);
		cout << "Hash:: " << Tpm2::GetEnumString(*iterator) << endl;
		cout << "Expected:      " << expected << endl;
		cout << "TPM generated: " << hashVal.result << endl;
	}

	// We can also do an "event sequence"
	auto hashHandle = tpm.HashSequenceStart(NullVec, TPM_ALG_ID::_NULL);
	accumulator.clear();

	for (int j = 0; j < 10; j++) {
		tpm.SequenceUpdate(hashHandle, data1);
		accumulator = Helpers::Concatenate(accumulator, data1);
	}

	accumulator = Helpers::Concatenate(accumulator, data1);

	// Note that the handle is flushed by the TPM when the sequence is completed
	auto initPcr = tpm.PCR_Read(vector<TPMS_PCR_SELECTION> {TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, 0)});
	auto hashVal2 = tpm.EventSequenceComplete(TPM_HANDLE::PcrHandle(0), hashHandle, data1);
	auto expected = CryptoServices::Hash(TPM_ALG_ID::SHA1, accumulator);
	auto finalPcr = tpm.PCR_Read(vector<TPMS_PCR_SELECTION> {TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, 0)});

	// Is this what we expect?
	TPMT_HA expectedPcr(TPM_ALG_ID::SHA1, initPcr.pcrValues[0].buffer);
	expectedPcr.Extend(expected);

	if (expectedPcr.digest == finalPcr.pcrValues[0].buffer) {
		cout << "EventSequenceComplete gives expected answer:  " << endl << expectedPcr.ToString(false) << endl;
	}

	_ASSERT(expectedPcr.digest == finalPcr.pcrValues[0].buffer);

	return;
}

void Samples::HMAC()
{
	Announce("HMAC");

	// Key and data to be HMACd
	ByteVec key{ 5, 4, 3, 2, 1, 0 };
	ByteVec data1{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
	auto hashAlg = TPM_ALG_ID::SHA1;

	// To do an HMAC we need to load a key into the TPM.  A primary key is easiest.
	// template for signing/symmetric HMAC key with data originating externally
	TPMT_PUBLIC templ(TPM_ALG_ID::SHA256, TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent |
		TPMA_OBJECT::fixedTPM | TPMA_OBJECT::userWithAuth, NullVec,
		TPMS_KEYEDHASH_PARMS(TPMS_SCHEME_HMAC(hashAlg)),
		TPM2B_DIGEST_Keyedhash(NullVec));

	// The key is passed in in the SENSITIVE_CREATE structure
	TPMS_SENSITIVE_CREATE sensCreate(NullVec, key);
	vector<TPMS_PCR_SELECTION> pcrSelect;

	// "Create" they key based on the externally provided keying data
	CreatePrimaryResponse newPrimary = tpm.CreatePrimary(tpm._AdminOwner,
		sensCreate,
		templ,
		NullVec,
		pcrSelect);
	TPM_HANDLE keyHandle = newPrimary.handle;
	TPM_HANDLE hmacHandle = tpm.HMAC_Start(keyHandle, NullVec, TPM_ALG_ID::SHA1);

	tpm.SequenceUpdate(hmacHandle, data1);

	auto hmacDigest = tpm.SequenceComplete(hmacHandle, data1, TPM_HANDLE::NullHandle());
	auto data = Helpers::Concatenate(data1, data1);
	auto expectedHmac = CryptoServices::HMAC(hashAlg, key, data);

	_ASSERT(expectedHmac == hmacDigest.result);

	cout << "HMAC[SHA1] of " << data << endl <<
		"with key      " << key << endl <<
		"           =  " << hmacDigest.result << endl;

	// We can also just TPM2_Sign() with an HMAC key
	SignResponse sig = tpm.Sign(keyHandle, data, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK::NullTicket());
	TPMT_HA *sigIs = dynamic_cast<TPMT_HA *> (sig.signature);

	cout << "HMAC[SHA1] of " << data << endl <<
		"with key      " << key << endl <<
		"           =  " << sigIs->digest << endl;

	// Or use the HMAC signing command
	ByteVec sig3 = tpm.HMAC(keyHandle, data, TPM_ALG_ID::SHA1);
	cout << "HMAC[SHA1] of " << data << endl <<
		"with key      " << key << endl <<
		"           =  " << sig3 << endl;

	tpm.FlushContext(keyHandle);

	return;
}

void Samples::GetCapability()
{
	Announce("GetCapability");

	UINT32 startVal = 0;

	cout << "Algorithms:" << endl;

	// For the first example we show how to get a batch (8) properties at a time.
	// For simplicity, subsequent samples just get one at a time: avoiding the
	// nested loop.
	do {
		GetCapabilityResponse caps = tpm.GetCapability(TPM_CAP::ALGS, startVal, 8);
		TPML_ALG_PROPERTY *props = dynamic_cast<TPML_ALG_PROPERTY *> (caps.capabilityData);

		// Print alg name and properties
		for (auto p = props->algProperties.begin(); p != props->algProperties.end(); p++) {
			cout << setw(16) << Tpm2::GetEnumString(p->alg) <<
				": " << Tpm2::GetEnumString(p->algProperties) << endl;
		}

		if (!caps.moreData) {
			break;
		}

		startVal = ((UINT32)props->algProperties[props->algProperties.size() - 1].alg) + 1;
	} while (true);

	cout << "Commands:" << endl;
	startVal = 0;

	do {
		GetCapabilityResponse caps = tpm.GetCapability(TPM_CAP::COMMANDS, startVal, 32);
		auto comms = dynamic_cast<TPML_CCA *> (caps.capabilityData);

		for (auto iter = comms->commandAttributes.begin(); iter != comms->commandAttributes.end(); iter++) {
			TPMA_CC attr = (TPMA_CC)*iter;
			UINT32 attrVal = (UINT32)attr;

			// Decode the packed structure -
			TPM_CC cc = (TPM_CC)(attrVal & 0xFFFF);
			TPMA_CC maskedAttr = (TPMA_CC)(attrVal & 0xFFff0000);

			cout << "Command:" << Tpm2::GetEnumString(cc) << ": ";
			cout << Tpm2::GetEnumString(maskedAttr) << endl;

			commandsImplemented.push_back(cc);

			startVal = (UINT32)cc;
		}

		cout << endl;

		if (!caps.moreData) {
			break;
		}

		startVal++;
	} while (true);

	startVal = 0;
	cout << "PCRS: " << endl;
	GetCapabilityResponse caps2 = tpm.GetCapability(TPM_CAP::PCRS, 0, 1);
	auto pcrs = dynamic_cast<TPML_PCR_SELECTION *> (caps2.capabilityData);

	for (auto iter = pcrs->pcrSelections.begin(); iter != pcrs->pcrSelections.end(); iter++) {
		cout << Tpm2::GetEnumString(iter->hash) << "\t";
		auto pcrsWithThisHash = iter->ToArray();

		for (auto p = pcrsWithThisHash.begin(); p != pcrsWithThisHash.end(); p++) {
			cout << *p << " ";
		}

		cout << endl;
	}

	return;
}

void Samples::NV()
{
	Announce("NV");

	// Several types of NV-slot use are demonstrated here: simple, counter, bitfield, and extendable

	int nvIndex = 1000;
	ByteVec nvAuth{ 1, 5, 1, 1 };
	TPM_HANDLE nvHandle = TPM_HANDLE::NVHandle(nvIndex);

	// Try to delete the slot if it exists
	tpm._AllowErrors().NV_UndefineSpace(tpm._AdminOwner, nvHandle);

	// CASE 1 - Simple NV-slot: Make a new simple NV slot, 16 bytes, RW with auth
	TPMS_NV_PUBLIC nvTemplate(nvHandle,           // Index handle
		TPM_ALG_ID::SHA256, // Name-alg
		TPMA_NV::AUTHREAD | // Attributes
		TPMA_NV::AUTHWRITE,
		NullVec,            // Policy
		16);                // Size in bytes

	tpm.NV_DefineSpace(tpm._AdminOwner, nvAuth, nvTemplate);

	// We have set the authVal to be nvAuth, so set it in the handle too.
	nvHandle.SetAuth(nvAuth);

	// Write some data
	ByteVec toWrite{ 1, 2, 3, 4, 5, 4, 3, 2, 1 };
	tpm.NV_Write(nvHandle, nvHandle, toWrite, 0);

	// And read it back and see if it is good
	ByteVec dataRead = tpm.NV_Read(nvHandle, nvHandle, 16, 0);
	cout << "Data read from nv-slot:   " << dataRead << endl;

	// And make sure that it's good
	for (size_t j = 0; j < toWrite.size(); j++) {
		_ASSERT(dataRead[j] == toWrite[j]);
	}

	// And then delete it

	// We can also read the public area
	NV_ReadPublicResponse nvPub = tpm.NV_ReadPublic(nvHandle);
	cout << "NV Slot public area:" << endl << nvPub.ToString(false) << endl;

	tpm.NV_UndefineSpace(tpm._AdminOwner, nvHandle);

	// CASE 2 - Counter NV-slot
	TPMS_NV_PUBLIC nvTemplate2(nvHandle,            // Index handle
		TPM_ALG_ID::SHA256,  // Name-alg
		TPMA_NV::AUTHREAD | // Attributes
		TPMA_NV::AUTHWRITE |
		TPMA_NV::COUNTER,
		NullVec,             // Policy
		8);                  // Size in bytes

	tpm.NV_DefineSpace(tpm._AdminOwner, nvAuth, nvTemplate2);

	// We have set the authVal to be nvAuth, so set it in the handle too.
	nvHandle.SetAuth(nvAuth);

	// Should not be able to write (increment only)
	tpm._ExpectError(TPM_RC::ATTRIBUTES).NV_Write(nvHandle, nvHandle, toWrite, 0);

	// Should not be able to read before the first increment
	tpm._ExpectError(TPM_RC::NV_UNINITIALIZED).NV_Read(nvHandle, nvHandle, 8, 0);

	// First increment
	tpm.NV_Increment(nvHandle, nvHandle);

	// Should now be able to read
	ByteVec beforeIncrement = tpm.NV_Read(nvHandle, nvHandle, 8, 0);
	cout << "Initial counter data:     " << beforeIncrement << endl;

	// Should be able to increment
	for (int j = 0; j < 5; j++) {
		tpm.NV_Increment(nvHandle, nvHandle);
	}

	// And make sure that it's good
	ByteVec afterIncrement = tpm.NV_Read(nvHandle, nvHandle, 8, 0);
	cout << "After 5 increments:       " << afterIncrement << endl;

	// And then delete it
	tpm.NV_UndefineSpace(tpm._AdminOwner, nvHandle);

	// CASE 3 - Bitfield
	TPMS_NV_PUBLIC nvTemplate3(nvHandle,            // Index handle
		TPM_ALG_ID::SHA256,  // Name-alg
		TPMA_NV::AUTHREAD | // Attributes
		TPMA_NV::AUTHWRITE |
		TPMA_NV::BITS,
		NullVec,             // Policy
		8);                  // Size in bytes

	tpm.NV_DefineSpace(tpm._AdminOwner, nvAuth, nvTemplate3);

	// We have set the authVal to be nvAuth, so set it in the handle too.
	nvHandle.SetAuth(nvAuth);

	// Should not be able to write (bitfield)
	tpm._ExpectError(TPM_RC::ATTRIBUTES).NV_Write(nvHandle, nvHandle, toWrite, 0);

	// Should not be able to read before first written
	tpm._ExpectError(TPM_RC::NV_UNINITIALIZED).NV_Read(nvHandle, nvHandle, 8, 0);

	// Should not be able to increment
	tpm._ExpectError(TPM_RC::ATTRIBUTES).NV_Increment(nvHandle, nvHandle);

	// Should be able set bits
	cout << "Bit setting:" << endl;
	UINT64 bit = 1;

	for (int j = 0; j < 64; j++) {
		tpm.NV_SetBits(nvHandle, nvHandle, bit);
		ByteVec bits = tpm.NV_Read(nvHandle, nvHandle, 8, 0);
		cout << setfill(' ') << setw(4) << j << " : " << bits << endl;
		bit = bit << 1;
	}

	// And then delete it
	tpm.NV_UndefineSpace(tpm._AdminOwner, nvHandle);

	// CASE 4 - Extendable
	TPMS_NV_PUBLIC nvTemplate4(nvHandle,            // Index handle
		TPM_ALG_ID::SHA1,    // Name+extend-alg
		TPMA_NV::AUTHREAD | // Attributes
		TPMA_NV::AUTHWRITE |
		TPMA_NV::EXTEND,
		NullVec,             // Policy
		20);                 // Size in bytes

	tpm.NV_DefineSpace(tpm._AdminOwner, nvAuth, nvTemplate4);

	// We have set the authVal to be nvAuth, so set it in the handle too.
	nvHandle.SetAuth(nvAuth);

	// Should not be able to write (bitfield)
	tpm._ExpectError(TPM_RC::ATTRIBUTES).NV_Write(nvHandle, nvHandle, toWrite, 0);

	// Should not be able to read before first written
	tpm._ExpectError(TPM_RC::NV_UNINITIALIZED).NV_Read(nvHandle, nvHandle, 8, 0);

	// Should not be able to increment
	tpm._ExpectError(TPM_RC::ATTRIBUTES).NV_Increment(nvHandle, nvHandle);

	// Should be able to extend
	TPMT_HA toExtend = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA256, "abc");
	tpm.NV_Extend(nvHandle, nvHandle, toExtend.digest);

	// Read the extended value and print it
	ByteVec extendedData = tpm.NV_Read(nvHandle, nvHandle, 20, 0);
	cout << "Extended NV-slot:" << extendedData << endl;

	// Check the result is correct
	_ASSERT(extendedData == (TPMT_HA(TPM_ALG_ID::SHA1)).Extend(toExtend.digest).digest);

	// And then delete it
	tpm.NV_UndefineSpace(tpm._AdminOwner, nvHandle);

	// Demonstrating the use of NV_UndefineSpaceSpecial .  We must have a policy...
	PolicyTree p(PolicyCommandCode(TPM_CC::NV_UndefineSpaceSpecial, ""));
	auto policyHash = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

	TPMS_NV_PUBLIC nvTemplate5(nvHandle,                // Index handle
		TPM_ALG_ID::SHA1,        // Name+extend-alg
		TPMA_NV::AUTHREAD |      // Attributes
		TPMA_NV::AUTHWRITE |
		TPMA_NV::EXTEND |
		TPMA_NV::POLICY_DELETE |
		TPMA_NV::PLATFORMCREATE,
		policyHash.digest,       // Policy
		20);                     // Size in bytes

	tpm.NV_DefineSpace(tpm._AdminPlatform, nvAuth, nvTemplate5);

	auto nvPub2 = tpm.NV_ReadPublic(nvHandle);
	nvHandle.SetName(nvPub2.nvName);

	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	AUTH_SESSION pwapSession = AUTH_SESSION::PWAP();

	p.Execute(tpm, s);

	tpm._GetDevice().PPOn();
	tpm._Sessions(s, pwapSession).NV_UndefineSpaceSpecial(nvHandle, tpm._AdminPlatform);
	tpm._GetDevice().PPOff();
	tpm.FlushContext(s);

	// Now demonstrate NV_WriteLock
	TPMS_NV_PUBLIC nvTemplate6(nvHandle,                // Index handle
		TPM_ALG_ID::SHA1,        // Name+extend-alg
		TPMA_NV::AUTHREAD |      // attributes
		TPMA_NV::AUTHWRITE |
		TPMA_NV::PLATFORMCREATE |
		TPMA_NV::WRITEDEFINE,
		NullVec,                 // Policy
		20);                     // Size in bytes

	tpm.NV_DefineSpace(tpm._AdminPlatform, nvAuth, nvTemplate6);

	// We have set the authVal to be nvAuth, so set it in the handle too.
	nvHandle.SetAuth(nvAuth);
	tpm.NV_WriteLock(nvHandle, nvHandle);

	// And then delete it
	tpm.NV_UndefineSpace(tpm._AdminPlatform, nvHandle);

	// Demonstrating NV_ChangeAuth. To issue this command you must use ADMIN auth
	// We must have a policy...
	PolicyTree p3(PolicyCommandCode(TPM_CC::NV_ChangeAuth, ""));
	policyHash = p3.GetPolicyDigest(TPM_ALG_ID::SHA1);

	TPMS_NV_PUBLIC nvTemplate7(nvHandle,           // Index handle
		TPM_ALG_ID::SHA1,   // Name+extend-alg
		TPMA_NV::AUTHREAD | // Attributes
		TPMA_NV::AUTHWRITE,
		policyHash.digest,  // Policy
		20);                // Size in bytes

	tpm.NV_DefineSpace(tpm._AdminOwner, nvAuth, nvTemplate7);

	auto nvPub3 = tpm.NV_ReadPublic(nvHandle);
	nvHandle.SetName(nvPub3.nvName);

	s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p3.Execute(tpm, s);

	tpm.NV_Write(nvHandle, nvHandle, toWrite, 0);

	// Can change the authVal
	ByteVec newAuth{ 3, 1, 4, 1 };
	tpm(s).NV_ChangeAuth(nvHandle, newAuth);
	tpm.FlushContext(s);

	// Can no longer read with old password
	tpm._ExpectError(TPM_RC::AUTH_FAIL).NV_Read(nvHandle, nvHandle, 16, 0);

	// But can read with the new one
	nvHandle.SetAuth(newAuth);
	tpm.NV_Read(nvHandle, nvHandle, 16, 0);

	// And then delete it
	tpm.NV_UndefineSpace(tpm._AdminOwner, nvHandle);

	return;
}

void Samples::TpmCallbackStatic(ByteVec command, ByteVec response, void *context)
{
	((Samples *)context)->TpmCallback(command, response);
}

void Samples::TpmCallback(ByteVec command, ByteVec response)
{
	// Extract the command and responses codes from the buffers.
	// Both are 4 bytes long starting at byte 6
	UINT32 *commandCodePtr = (UINT32 *)&command[6];
	UINT32 *responseCodePtr = (UINT32 *)&response[6];

	TPM_CC comm = (TPM_CC)ntohl(*commandCodePtr);
	TPM_RC resp = (TPM_RC)ntohl(*responseCodePtr);

	// Strip any parameter decorations
	resp = Tpm2::ResponseCodeFromTpmError(resp);

	commandsInvoked[comm]++;
	responses[resp]++;

	return;
}

void Samples::Callback1()
{
	//Announce("Installing callback");

	// Install a callback that is invoked after the TPM command has been executed
	tpm._SetResponseCallback(&Samples::TpmCallbackStatic, this);
}

void Samples::Callback2()
{
	Announce("Processing callback data");

	cout << "Commands invoked:" << endl;

	for (auto i = commandsInvoked.begin(); i != commandsInvoked.end(); i++) {
		cout << dec << setfill(' ') << setw(32) << Tpm2::GetEnumString(i->first) << ": count = " << i->second << endl;;
	}

	cout << endl << "Responses received:" << endl;

	for (auto i = responses.begin(); i != responses.end(); i++) {
		cout << dec << setfill(' ') << setw(32) << Tpm2::GetEnumString(i->first) << ": count = " << i->second << endl;;
	}

	cout << endl << "Commands not exercised:" << endl;

	for (auto i = commandsImplemented.begin(); i != commandsImplemented.end(); i++) {
		if (commandsInvoked.find(*i) == commandsInvoked.end()) {
			cout << dec << setfill(' ') << setw(1) << Tpm2::GetEnumString(*i) << " ";
		}
	}

	cout << endl;

	tpm._SetResponseCallback(NULL, NULL);

	return;
}

void Samples::PrimaryKeys()
{
	Announce("PrimaryKeys");

	// To create a primary key the TPM must be provided with a template.
	// This is for an RSA1024 signing key.
	TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::sign |               // Key attribues
		TPMA_OBJECT::fixedParent |
		TPMA_OBJECT::fixedTPM |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec,                         // No policy
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
			TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA256), 1024, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	// Set the use-auth for the nex key. Note the second parameter is
	// NULL because we are asking the TPM to create a new key.
	ByteVec userAuth = ByteVec{ 1, 2, 3, 4 };
	TPMS_SENSITIVE_CREATE sensCreate(userAuth, NullVec);

	// We don't need to know the PCR-state with the key was created
	vector<TPMS_PCR_SELECTION> pcrSelect;

	// Create the key
	CreatePrimaryResponse newPrimary = tpm.CreatePrimary(tpm._AdminOwner,
		sensCreate,
		templ,
		NullVec,
		pcrSelect);

	// Print out the public data for the new key. Note the parameter to
	// ToString() "pretty-prints" the byte-arrays.
	cout << "New RSA primary key" << endl << newPrimary.outPublic.ToString(true) << endl;

	cout << "Name of new key:" << endl;
	cout << " Returned by TPM " << newPrimary.name << endl;
	cout << " Calculated      " << newPrimary.outPublic.GetName() << endl;
	cout << " Set in handle   " << newPrimary.handle.GetName() << endl;
	_ASSERT(newPrimary.name == newPrimary.outPublic.GetName());

	// Sign something with the new key.  First set the auth-value in the handle
	TPM_HANDLE& signKey = newPrimary.handle;
	signKey.SetAuth(userAuth);

	TPMT_HA dataToSign = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA256, "abc");

	auto sig = tpm.Sign(signKey, dataToSign.digest, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK::NullTicket());
	cout << "Data to be signed:" << dataToSign.digest << endl;
	cout << "Signature:" << endl << sig.ToString(false) << endl;

	// We can put the primary key into NV with EvictControl
	TPM_HANDLE persistentHandle = TPM_HANDLE::PersistentHandle(1000);

	// First delete anything that might already be there
	tpm._AllowErrors().EvictControl(tpm._AdminOwner, persistentHandle, persistentHandle);

	// Make our primary persistent
	tpm.EvictControl(tpm._AdminOwner, newPrimary.handle, persistentHandle);

	// Flush the old one
	tpm.FlushContext(newPrimary.handle);

	// ReadPublic of the new persistent one
	auto persistentPub = tpm.ReadPublic(persistentHandle);
	cout << "Public part of persistent primary" << endl << persistentPub.ToString(false);

	// And delete it
	tpm.EvictControl(tpm._AdminOwner, persistentHandle, persistentHandle);

	return;
}

void Samples::AuthSessions()
{
	Announce("AuthSessions");

	// Start a simple HMAC authorization session (no salt, no encryption, no bound-object)
	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::HMAC, TPM_ALG_ID::SHA1);

	// Perform an operation authorizing with an HMAC
	tpm._Sessions(s).Clear(tpm._AdminPlatform);

	// And again, to check that the nonces rolled OK
	tpm(s).Clear(tpm._AdminPlatform);
	tpm(s).Clear(tpm._AdminPlatform);
	tpm(s).Clear(tpm._AdminPlatform);

	// And clean up
	tpm.FlushContext(s);

	return;
}

void Samples::Async()
{
	Announce("Async");

	// First do a fast operation
	cout << "Waiting for GetRandom()";
	tpm.Async.GetRandom(16);

	while (!tpm._GetDevice().ResponseIsReady()) {
		cout << "." << flush;
		Sleep(30);
	}

	cout << endl << "Done" << endl;
	auto randData = tpm.Async.GetRandomComplete();
	cerr << "Async random data: " << randData << endl;

	// Now do a slow operation
	TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,                   // Name alg
		TPMA_OBJECT::sign |                 // Key attributes
		TPMA_OBJECT::fixedParent |
		TPMA_OBJECT::fixedTPM |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec,                            // No policy
		TPMS_RSA_PARMS(                     // Parms for RSA key
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
			TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA256), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	ByteVec userAuth = ByteVec{ 1, 2, 3, 4 };
	TPMS_SENSITIVE_CREATE sensCreate(userAuth, NullVec);
	vector<TPMS_PCR_SELECTION> pcrSelect;

	// Start the slow key creation
	cout << "Waiting for CreatePrimary()";
	tpm.Async.CreatePrimary(tpm._AdminOwner, sensCreate, templ, NullVec, pcrSelect);

	// Spew dots while we wait...
	while (!tpm._GetDevice().ResponseIsReady()) {
		cout << "." << flush;
		Sleep(30);
	}

	cout << endl << "Done" << endl;
	CreatePrimaryResponse newPrimary = tpm.Async.CreatePrimaryComplete();

	// And show we actually did something
	cout << "Asynchronously created primary key name: " << endl << newPrimary.name << endl;

	tpm.FlushContext(newPrimary.handle);

	return;

}

///<summary>Helper function to make a primary key with usePolicy set as specified</summary>
TPM_HANDLE Samples::MakeHmacPrimaryWithPolicy(TPMT_HA policy, ByteVec useAuth)
{
	TPM_ALG_ID hashAlg = TPM_ALG_ID::SHA1;
	ByteVec key{ 5, 4, 3, 2, 1, 0 };
	TPMA_OBJECT extraAttr = (TPMA_OBJECT)0;

	if (useAuth.size() != 0) {
		extraAttr = TPMA_OBJECT::userWithAuth;
	}

	// HMAC key with policy as specified
	TPMT_PUBLIC templ(policy.hashAlg, TPMA_OBJECT::sign |
		TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM |
		extraAttr, policy.digest,
		TPMS_KEYEDHASH_PARMS(TPMS_SCHEME_HMAC(hashAlg)),
		TPM2B_DIGEST_Keyedhash(NullVec));

	TPMS_SENSITIVE_CREATE sensCreate(useAuth, key);
	vector<TPMS_PCR_SELECTION> pcrSelect;
	CreatePrimaryResponse newPrimary = tpm.CreatePrimary(tpm._AdminOwner,
		sensCreate,
		templ,
		NullVec,
		pcrSelect);
	TPM_HANDLE keyHandle = newPrimary.handle;

	return keyHandle;
}

void Samples::PolicySimplest()
{
	Announce("PolicySimplest");

	// A TPM policy is a list or tree of Policy Assertions represented as a
	// vector<PABase*> in TSS.C++. The simplest policy tree is a single element.
	// The following policy indicates that the only operation that can be
	// performed is TPM2_Sign.
	PolicyTree p(TpmCpp::PolicyCommandCode(TPM_CC::HMAC_Start, ""));

	// Get the policy digest
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

	// Make an object with this policy hash
	TPM_HANDLE hmacKeyHandle = MakeHmacPrimaryWithPolicy(policyDigest, NullVec);

	// Try to use the key using an authValue (not policy) - This should fail
	tpm._ExpectError(TPM_RC::AUTH_UNAVAILABLE).HMAC_Start(hmacKeyHandle, NullVec, TPM_ALG_ID::SHA1);

	// Now use policy
	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);

	// Execute the policy using the session. This issues a sequence of TPM
	// operations to "prove" to the TPM that the policy is satisfied. In this very
	// simple case Execute() will call tpm.PolicyCommandCode(s, TPM_CC:ReadPublic).
	p.Execute(tpm, s);

	// Check that the policy-hash in the session is really what we calculated it to be.
	// If this is not the case then the attempt to use the policy-protected object below will fail.
	ByteVec digest = tpm.PolicyGetDigest(s);
	cout << "Calculated policy digest  : " << policyDigest.digest << endl;
	cout << "TPM reported policy digest: " << digest << endl;

	// Execute ReadPublic - This should succeed
	auto hmacSessionHandle = tpm._Sessions(s).HMAC_Start(hmacKeyHandle, NullVec, TPM_ALG_ID::SHA1);
	tpm.FlushContext(s);
	tpm.FlushContext(hmacSessionHandle);

	// But if we try to use the key in another way this should fail
	s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, s);

	// Note that this command would fail with a different error even if you knew the auth-value.
	tpm._ExpectError(TPM_RC::POLICY_CC)._Sessions(s).Unseal(hmacKeyHandle);

	// Clean up
	tpm.FlushContext(hmacKeyHandle);
	tpm.FlushContext(s);

	return;
}


void Samples::PolicyLocalitySample()
{
	Announce("PolicyLocality");

	// A TPM policy is a list or tree of Policy Assertions represented as a vector<PABase*> in
	// TSS.C++. The simplest policy tree is a single element. The following policy indicates that
	// actions may only be performed at locality 1.
	PolicyTree p(TpmCpp::PolicyLocality(TPMA_LOCALITY::LOC_ONE, ""));

	// Get the policy digest
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

	// Make an object with this policy hash
	TPM_HANDLE hmacKeyHandle = MakeHmacPrimaryWithPolicy(policyDigest, NullVec);

	// Try to use the key using an authValue (not policy) - This should fail
	tpm._ExpectError(TPM_RC::AUTH_UNAVAILABLE).HMAC_Start(hmacKeyHandle, NullVec, TPM_ALG_ID::SHA1);

	// Now use policy and issue at locality 1
	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);

	// Execute the policy using the session. This issues a sequence of TPM operations to
	// "prove" to the TPM that the policy is satisfied. In this very simple case
	// Execute() will call tpm.PolicyLocality(s, TPMA_LOCALITY::LOC_ONE).
	p.Execute(tpm, s);

	// Check that the policy-hash in the session is really what we calculated it to be.
	// If this is not the case then the attempt to use the policy-protected object below will fail.
	ByteVec digest = tpm.PolicyGetDigest(s);
	cout << "Calculated policy digest  : " << policyDigest.digest << endl;
	cout << "TPM reported policy digest: " << digest << endl;

	// Execute at locality 1 with the session should succeed
	tpm._GetDevice().SetLocality(1);
	auto hmacSessionHandle = tpm._Sessions(s).HMAC_Start(hmacKeyHandle, NullVec, TPM_ALG_ID::SHA1);
	tpm._GetDevice().SetLocality(0);

	// Clean up
	tpm.FlushContext(hmacKeyHandle);
	tpm.FlushContext(s);
	tpm.FlushContext(hmacSessionHandle);

	return;
}

void Samples::PolicyPCRSample()
{
	Announce("PolicyPCR");

	// In this sample we show the use of PolicyPcr

	// First set a PCR to a value
	TPM_ALG_ID bank = TPM_ALG_ID::SHA1;
	UINT32 pcr = 15;

	tpm.PCR_Event(TPM_HANDLE::PcrHandle(pcr), ByteVec{ 1, 2, 3, 4 });

	// Read the current value
	vector<TPMS_PCR_SELECTION> pcrSelection = TPMS_PCR_SELECTION::GetSelectionArray(bank, pcr);
	auto startPcrVal = tpm.PCR_Read(pcrSelection);
	auto currentValue = startPcrVal.pcrValues;

	// Create a policy naming this PCR and current PCR value
	PolicyTree p(PolicyPcr(currentValue, pcrSelection));

	// Get the policy digest
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

	// Make an object with this policy hash
	TPM_HANDLE hmacKeyHandle = MakeHmacPrimaryWithPolicy(policyDigest, NullVec);

	// To prove to the TPM that the policy is satisfied we first create a session
	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);

	// Next we execute the policy using the session. This issues a sequence of TPM operations to
	// "prove" to the TPM that the policy is satisfied. In this very simple case
	// Execute() will call tpm.PolicyPcr(...).
	p.Execute(tpm, s);

	// Check that the policy-hash in the session is really what we calculated it to be.
	// If this is not the case then the attempt to use the policy-protected object below will fail.
	ByteVec digest = tpm.PolicyGetDigest(s);
	cout << "Calculated policy digest  : " << policyDigest.digest << endl;
	cout << "TPM reported policy digest: " << digest << endl;

	// Since we have not changed the PCR this should succeed
	TPM_HANDLE hmacSequenceHandle = tpm._Sessions(s).HMAC_Start(hmacKeyHandle, NullVec, TPM_ALG_ID::SHA1);
	tpm.FlushContext(s);

	// Next we change the PCR value, so the action should fail
	tpm.PCR_Event(TPM_HANDLE::PcrHandle(pcr), ByteVec{ 1, 2, 3, 4 });
	s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);

	try {
		p.Execute(tpm, s);
		cerr << "Should NOT get here, because the policy evaluation should fail";
		_ASSERT(FALSE);
	}
	catch (exception) {
		// Expected
	}

	// And the session should not be usable
	tpm._ExpectError(TPM_RC::POLICY_FAIL)._Sessions(s).HMAC_Start(hmacKeyHandle, NullVec, TPM_ALG_ID::SHA1);

	// Clean up
	tpm.FlushContext(hmacKeyHandle);
	tpm.FlushContext(s);
	tpm.FlushContext(hmacSequenceHandle);

	return;
}

void Samples::ChildKeys()
{
	Announce("Child Keys");

	// In this sample we demonstrate how a primary storage key can be used to protect a child key

	// To create the primary storage key the TPM must be provided with a template.
	// Storage keys must be protected decryption keys.
	TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,          // Key nameAlg
		TPMA_OBJECT::decrypt |     // Key attributes
		TPMA_OBJECT::restricted |
		TPMA_OBJECT::fixedParent |
		TPMA_OBJECT::fixedTPM |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec,                   // No policy
		TPMS_RSA_PARMS(            // Key-parms
			// How child keys should be protected
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 256, TPM_ALG_ID::CFB),
			TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	// Set the use-auth for the next key. Note the second parameter is
	// NULL because we are asking the TPM to create a new key.
	ByteVec userAuth = ByteVec{ 1, 2, 3, 4 };
	TPMS_SENSITIVE_CREATE sensCreate(userAuth, NullVec);

	// We don't need to know the PCR-state with the key was created
	vector<TPMS_PCR_SELECTION> pcrSelect;

	// Create the key
	CreatePrimaryResponse storagePrimary = tpm.CreatePrimary(tpm._AdminOwner,
		sensCreate,
		storagePrimaryTemplate,
		NullVec,
		pcrSelect);

	// Note that if we want to use the storage key handle we need the userAuth, as specified above.
	// TSS.C++ sets this when it can, but this is what you have to do if it has not been auto-set.
	storagePrimary.handle.SetAuth(userAuth);
	TPM_HANDLE& primaryHandle = storagePrimary.handle;

	// Print out the public data for the new key. Note the parameter to
	// ToString() "pretty-prints" the byte-arrays.
	cout << "New RSA primary storage key" << endl << storagePrimary.outPublic.ToString(false) << endl;

	// Now we have a primary we can ask the TPM to make child keys. As always, we start with
	// a template. Here we specify a 1024-bit signing key to create a primary key the TPM
	// must be provided with a template.  This is for an RSA1024 signing key.
	TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::sign |                        // Key attribues
		TPMA_OBJECT::fixedParent |
		TPMA_OBJECT::fixedTPM |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec,                                   // No policy
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
			TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1),  // PKCS1.5
			2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	// Ask the TPM to create the key.  For simplicity we will leave the other parameters
	// (apart from the template) the same as for the storage key
	CreateResponse newSigningKey = tpm.Create(primaryHandle,
		sensCreate,
		templ,
		NullVec,
		pcrSelect);

	// Unlike primary keys, child keys must be "loaded" before they can be used. To load
	// a the parent has to also be loaded, and you must have the parents use-auth.
	TPM_HANDLE signKey = tpm.Load(primaryHandle, newSigningKey.outPrivate, newSigningKey.outPublic);

	// Set the auth so we can use it
	signKey.SetAuth(userAuth);

	// And once it is loaded you can use it. In this case we ask it to sign some data
	vector<BYTE> data = vector<BYTE>{ 1, 2, 3 };
	TPMT_HA dataToSign = TPMT_HA::FromHashOfData(TPM_ALG_ID::SHA1, data);

	SignResponse sig = tpm.Sign(signKey, dataToSign.digest,
		TPMS_NULL_SIG_SCHEME(),
		TPMT_TK_HASHCHECK::NullTicket());

	cout << "Data to be signed:" << dataToSign.digest << endl;
	cout << "Signature:" << endl << sig.ToString(false) << endl;

	// Non-primary TPM objects can be context-saved to make space for other keys to be loaded.
	TPMS_CONTEXT keyContext = tpm.ContextSave(signKey);
	tpm.FlushContext(signKey);

	// The key is no longer there...
	tpm._DemandError().ReadPublic(signKey);

	// But we can reload it
	TPM_HANDLE reloadedKey = tpm.ContextLoad(keyContext);
	reloadedKey.SetAuth(userAuth);

	// And now we can read it again
	auto pubInfo = tpm.ReadPublic(reloadedKey);

	// We can also "change" the authValue for a loaded object
	ByteVec newAuth{ 2, 7, 1, 8, 2, 8 };
	auto newPrivate = tpm.ObjectChangeAuth(reloadedKey, primaryHandle, newAuth);

	// Check we can use it with the new Auth
	TPM_HANDLE changedAuthHandle = tpm.Load(primaryHandle, newPrivate, newSigningKey.outPublic);
	changedAuthHandle.SetAuth(newAuth);
	SignResponse sigx = tpm.Sign(changedAuthHandle,
		dataToSign.digest,
		TPMS_NULL_SIG_SCHEME(),
		TPMT_TK_HASHCHECK::NullTicket());

	tpm.FlushContext(changedAuthHandle);

	// Clean up a bit
	tpm.FlushContext(primaryHandle);
	tpm.FlushContext(reloadedKey);

	// Use the TSS.C++ library to validate the signature
	newSigningKey.outPublic.ValidateSignature(dataToSign.digest, *sig.signature);

	// The TPM can also validate signatures. 
	// To validate a signature, only the public part of a key need be loaded.

	// LoadExternal can also load a pub/priv key pair.
	TPM_HANDLE publicKeyHandle = tpm.LoadExternal(TPMT_SENSITIVE::NullObject(),
		newSigningKey.outPublic,
		TPM_HANDLE::FromReservedHandle(TPM_RH::_NULL));

	// Now use the loaded public key to validate the previously created signature
	VerifySignatureResponse sigVerify = tpm._AllowErrors().VerifySignature(publicKeyHandle,
		dataToSign.digest,
		*sig.signature);
	if (tpm._LastOperationSucceeded()) {
		cout << "Signature verification succeeded" << endl;
	}

	// Mess up the signature by flipping a bit
	TPMS_SIGNATURE_RSASSA *rsaSig = dynamic_cast<TPMS_SIGNATURE_RSASSA *>(sig.signature);
	rsaSig->sig[0] ^= 1;

	// This should fail
	sigVerify = tpm._AllowErrors().VerifySignature(publicKeyHandle,
		dataToSign.digest,
		*sig.signature);

	if (!tpm._LastOperationSucceeded()) {
		cout << "Signature verification of bad signature failed, as expected" << endl;
	}

	_ASSERT(!tpm._LastOperationSucceeded());

	// And sofware verification should fail too
	_ASSERT(!newSigningKey.outPublic.ValidateSignature(dataToSign.digest, *sig.signature));

	// Remove the primary key from the TPM
	tpm.FlushContext(publicKeyHandle);

	return;
}

void Samples::PolicyORSample()
{
	Announce("PolicyOR");

	// In this sample we show the use of PolicyOr. We make two policy-branches: one that needs
	// a specific PCR-value, and one that needs physical presence.

	// First set a PCR to a value
	TPM_ALG_ID bank = TPM_ALG_ID::SHA1;
	UINT32 pcr = 15;
	tpm.PCR_Event(TPM_HANDLE::PcrHandle(pcr), ByteVec{ 1, 2, 3, 4 });

	// Read the current value
	vector<TPMS_PCR_SELECTION> pcrSelection = TPMS_PCR_SELECTION::GetSelectionArray(bank, pcr);
	auto startPcrVal = tpm.PCR_Read(pcrSelection);
	auto currentValue = startPcrVal.pcrValues;

	// Create a policy naming the PCR and policy-locality in an OR current PCR value
	PolicyTree branch1(PolicyPcr(currentValue, pcrSelection, "pcr-branch"));
	PolicyTree branch2(PolicyPhysicalPresence("pp-branch"));

	PolicyTree p(PolicyOr(branch1.GetTree(), branch2.GetTree()));

	// Get the policy digest
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

	// Make an object with this policy hash
	TPM_HANDLE hmacKeyHandle = MakeHmacPrimaryWithPolicy(policyDigest, NullVec);

	// Use the PCR-policy branch to authorize use of the key
	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA);
	p.Execute(tpm, s, "pcr-branch");
	tpm._Sessions(s).HMAC(hmacKeyHandle, vector<BYTE> {1, 2, 3, 4}, TPM_ALG_ID::SHA1);
	tpm.FlushContext(s);

	// Now change the PCR so this no longer works
	tpm.PCR_Event(TPM_HANDLE::PcrHandle(pcr), ByteVec{ 1, 2, 3, 4 });
	s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA);

	try {
		p.Execute(tpm, s, "pcr-branch");

		// We should not hit this _ASSERT because the PCR-value is wrong
		_ASSERT(FALSE);
	}
	catch (exception) {
		cerr << "PolicyPcr failed, as expected" << endl;
	}

	tpm._Sessions(s)._ExpectError(TPM_RC::POLICY_FAIL)
		.HMAC(hmacKeyHandle, vector<BYTE> {1, 2, 3, 4}, TPM_ALG_ID::SHA1);

	tpm.FlushContext(s);

	// But we can still use the physical-presence branch, as long as we can assert PP.
	s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA);
	p.Execute(tpm, s, "pp-branch");
	tpm._GetDevice().PPOn();
	tpm._Sessions(s).HMAC(hmacKeyHandle, vector<BYTE> {1, 2, 3, 4}, TPM_ALG_ID::SHA1);
	tpm._GetDevice().PPOff();
	tpm.FlushContext(s);

	// And clean up
	tpm.FlushContext(hmacKeyHandle);

	return;
}

TPM_HANDLE Samples::MakeStoragePrimary()
{
	TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted |
		TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM |
		TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
		NullVec,           // No policy
		TPMS_RSA_PARMS(    // How child keys should be protected
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
			TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	// Create the key
	CreatePrimaryResponse storagePrimary = tpm.CreatePrimary(tpm._AdminOwner,
		TPMS_SENSITIVE_CREATE(NullVec, NullVec), storagePrimaryTemplate,
		NullVec, vector<TPMS_PCR_SELECTION>());

	return storagePrimary.handle;
}

TPM_HANDLE Samples::MakeDuplicatableStoragePrimary(std::vector<BYTE> policy)
{
	TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted |
		TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
		policy,
		TPMS_RSA_PARMS(    // How child keys should be protected
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
			TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	// Create the key
	CreatePrimaryResponse storagePrimary = tpm.CreatePrimary(tpm._AdminOwner,
		TPMS_SENSITIVE_CREATE(NullVec, NullVec), storagePrimaryTemplate,
		NullVec, vector<TPMS_PCR_SELECTION>());

	return storagePrimary.handle;
}

TPM_HANDLE Samples::MakeEndorsementKey()
{
	TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted |
		TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM |
		TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
		NullVec,           // No policy
		TPMS_RSA_PARMS(    // How child keys should be protected
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
			TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	// Create the key
	CreatePrimaryResponse ek = tpm.CreatePrimary(tpm._AdminEndorsement,
		TPMS_SENSITIVE_CREATE(NullVec, NullVec), storagePrimaryTemplate,
		NullVec, vector<TPMS_PCR_SELECTION>());

	return ek.handle;
}

TPM_HANDLE Samples::MakeChildSigningKey(TPM_HANDLE parentHandle, bool restricted)
{
	TPMA_OBJECT restrictedAttribute;

	if (restricted) {
		restrictedAttribute = TPMA_OBJECT::restricted;
	}

	TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent |
		TPMA_OBJECT::fixedTPM | TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth | restrictedAttribute,
		NullVec,  // No policy
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
			TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 2048, 65537), // PKCS1.5
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	CreateResponse newSigningKey = tpm.Create(parentHandle,
		TPMS_SENSITIVE_CREATE(),
		templ,
		NullVec,
		vector<TPMS_PCR_SELECTION>());

	auto signKey = tpm.Load(parentHandle, newSigningKey.outPrivate, newSigningKey.outPublic);
	return signKey;
}

void Samples::CounterTimer()
{
	Announce("CounterTimer");

	int runTime = 5;
	cout << "TPM-time (reading for ~" << runTime << " seconds)" << endl;
	ReadClockResponse startTimeX = tpm.ReadClock();
	int systemStartTime = GetSystemTime(true);

	while (true) {
		ReadClockResponse time = tpm.ReadClock();
		int systemTime = GetSystemTime();
		cout << "(Sytem Time(s), TpmTime(ms)) = (" << dec << systemTime << ", " << time.currentTime.time << ")" << endl;

		if (systemTime > runTime + systemStartTime) {
			break;
		}

		Sleep(1000);
	}

	return;
}

static time_t startTimer = 0;

int Samples::GetSystemTime(bool reset)
{
	time_t timer;

	if (reset) {
		startTimer = time(NULL);
	}

	timer = time(NULL);

	return (int)difftime(timer, startTimer);
}

void Samples::Sleep(int numMillisecs)
{
#ifdef WIN32
	::Sleep(numMillisecs);
#endif

#ifdef __linux__
	usleep(numMillisecs * 1000);
#endif

	return;
}

void Samples::Attestation()
{
	Announce("Attestation");

	// Attestation is the TPM signing internal data structures. The TPM can perform
	// several-types of attestation: we demonstrate signing PCR, keys, and time.

	// To get attestation information we need a restricted signing key and privacy authorization.
	TPM_HANDLE primaryKey = MakeStoragePrimary();
	TPM_HANDLE signingKey = MakeChildSigningKey(primaryKey, true);

	// First PCR-signing (quoting). We will sign PCR-7.
	cout << ">> PCR Quoting" << endl;
	auto pcrsToQuote = TPMS_PCR_SELECTION::GetSelectionArray(TPM_ALG_ID::SHA1, 7);

	// Do an event to make sure the value is non-zero
	tpm.PCR_Event(TPM_HANDLE::PcrHandle(7), ByteVec{ 1, 2, 3 });

	// Then read the value so that we can validate the signature later
	PCR_ReadResponse pcrVals = tpm.PCR_Read(pcrsToQuote);

	// Do the quote.  Note that we provide a nonce.
	ByteVec Nonce = CryptoServices::GetRand(16);
	QuoteResponse quote = tpm.Quote(signingKey, Nonce, TPMS_NULL_SIG_SCHEME(), pcrsToQuote);

	// Need to cast to the proper attestion type to validate
	TPMS_ATTEST qAttest = quote.quoted;
	TPMS_QUOTE_INFO *qInfo = dynamic_cast<TPMS_QUOTE_INFO *> (qAttest.attested);
	cout << "Quoted PCR: " << qInfo->pcrSelect[0].ToString() << endl;
	cout << "PCR-value digest: " << qInfo->pcrDigest << endl;

	// We can use the TSS.C++ library to verify the quote. First read the public key.
	// Nomrmally the verifier will have other ways of determinig the veractity
	// of the public key
	ReadPublicResponse pubKey = tpm.ReadPublic(signingKey);
	bool sigOk = pubKey.outPublic.ValidateQuote(pcrVals, Nonce, quote);

	if (sigOk) {
		cout << "The quote was verified correctly" << endl;
	}

	_ASSERT(sigOk);

	// Now change the PCR and do a new quote
	tpm.PCR_Event(TPM_HANDLE::PcrHandle(7), ByteVec{ 1, 2, 3 });
	quote = tpm.Quote(signingKey, Nonce, TPMS_NULL_SIG_SCHEME(), pcrsToQuote);

	// And check against the values we read earlier
	sigOk = pubKey.outPublic.ValidateQuote(pcrVals, Nonce, quote);

	if (!sigOk) {
		cout << "The changed quote did not match, as expected" << endl;
	}

	_ASSERT(!sigOk);

	// Get a time-attestation
	cout << ">> Time Quoting" << endl;
	ByteVec timeNonce = { 0xa, 0x9, 0x8, 0x7 };
	GetTimeResponse timeQuote = tpm.GetTime(tpm._AdminEndorsement,
		signingKey,
		timeNonce,
		TPMS_NULL_SIG_SCHEME());

	// The TPM returns the siganture block that it signed: interpret it as an 
	// attestation structure then cast down into the nested members...
	TPMS_ATTEST& tm = timeQuote.timeInfo;
	auto tmx = dynamic_cast <TPMS_TIME_ATTEST_INFO *>(tm.attested);
	TPMS_CLOCK_INFO cInfo = tmx->time.clockInfo;

	cout << "Attested Time" << endl;
	cout << "   Firmware Version:" << tmx->firmwareVersion << endl <<
		"   Time:" << tmx->time.time << endl <<
		"   Clock:" << cInfo.clock << endl <<
		"   ResetCount:" << cInfo.resetCount << endl <<
		"   RestartCount:" << cInfo.restartCount << endl;

	sigOk = pubKey.outPublic.ValidateGetTime(timeNonce, timeQuote);

	if (sigOk) {
		cout << "Time-quote validated" << endl;
	}

	_ASSERT(sigOk);

	// Get a key attestation.  For simplicity we have the signingKey self-certify b
	cout << ">> Key Quoting" << endl;
	ByteVec nonce{ 5, 6, 7 };
	CertifyResponse keyInfo = tpm.Certify(signingKey, signingKey, nonce, TPMS_NULL_SIG_SCHEME());

	// The TPM returns the siganture block that it signed: interpret it as an
	// attestation structure then cast down into the nested members...
	TPMS_ATTEST& ky = keyInfo.certifyInfo;

	auto kyx = dynamic_cast <TPMS_CERTIFY_INFO *>(ky.attested);
	cout << "Name of certified key:" << endl << "  " << kyx->name << endl;
	cout << "Qualified name of certified key:" << endl << "  " << kyx->qualifiedName << endl;

	// Validate then cerify against the known name of the key
	sigOk = pubKey.outPublic.ValidateCertify(pubKey.outPublic, nonce, keyInfo);

	if (sigOk) {
		cout << "Key certification validated" << endl;
	}

	_ASSERT(sigOk);

	// CertifyCreation provides a "birth certificate" for a newly createed object
	TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::sign |           // Key attributes
		TPMA_OBJECT::fixedParent |
		TPMA_OBJECT::fixedTPM |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec,                      // No policy
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
			TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	// Ask the TPM to create the key. For simplicity we will leave the other parameters
	// (apart from the template) the same as for the storage key.
	CreateResponse newSigningKey = tpm.Create(primaryKey,
		TPMS_SENSITIVE_CREATE(NullVec, NullVec),
		templ,
		NullVec,
		vector<TPMS_PCR_SELECTION>());

	TPM_HANDLE toCertify = tpm.Load(primaryKey,
		newSigningKey.outPrivate,
		newSigningKey.outPublic);

	CertifyCreationResponse createQuote = tpm.CertifyCreation(signingKey,
		toCertify,
		nonce,
		newSigningKey.creationHash,
		TPMS_NULL_SIG_SCHEME(),
		newSigningKey.creationTicket);
	tpm.FlushContext(toCertify);
	tpm.FlushContext(primaryKey);

	sigOk = pubKey.outPublic.ValidateCertifyCreation(nonce,
		newSigningKey.creationHash,
		createQuote);
	if (sigOk) {
		cout << "Key creation certification validated" << endl;
	}

	_ASSERT(sigOk);

	// NV-index quoting.

	// First make an NV-slot and put some data in it.
	int nvIndex = 1000;
	ByteVec nvAuth{ 1, 5, 1, 1 };
	TPM_HANDLE nvHandle = TPM_HANDLE::NVHandle(nvIndex);

	// Try to delete the slot if it exists
	tpm._AllowErrors().NV_UndefineSpace(tpm._AdminOwner, nvHandle);

	// CASE 1 - Simple NV-slot: Make a new simple NV slot, 16 bytes, RW with auth
	TPMS_NV_PUBLIC nvTemplate(nvHandle,           // Index handle
		TPM_ALG_ID::SHA256, // Name-alg
		TPMA_NV::AUTHREAD | // Attributes
		TPMA_NV::AUTHWRITE,
		NullVec,            // Policy
		16);                // Size in bytes

	tpm.NV_DefineSpace(tpm._AdminOwner, nvAuth, nvTemplate);

	// We have set the authVal to be nvAuth, so set it in the handle too.
	nvHandle.SetAuth(nvAuth);

	// Write some data
	ByteVec toWrite{ 1, 2, 3, 4, 5, 4, 3, 2, 1 };
	tpm.NV_Write(nvHandle, nvHandle, toWrite, 0);

	NV_CertifyResponse nvQuote = tpm.NV_Certify(signingKey,
		nvHandle,
		nvHandle,
		nonce,
		TPMS_NULL_SIG_SCHEME(),
		(UINT16)toWrite.size(),
		0);

	sigOk = pubKey.outPublic.ValidateCertifyNV(nonce, toWrite, 0, nvQuote);

	if (sigOk) {
		cout << "Key creation certification validated" << endl;
	}

	_ASSERT(sigOk);

	tpm.NV_UndefineSpace(tpm._AdminOwner, nvHandle);
	tpm.FlushContext(signingKey);

	return;
}

void Samples::Admin()
{
	Announce("Administration");

	// This sample demonstrates some TPM administration functions.

	// Clearing the TPM.

	// "Clearing" the TPM changes the storage primary seed (among other actions).
	// Since primary keys are deterministically generated from the seed, the primary
	// keys in the storage hierarchy will change.

	// Make two primary keys and show that they are the same
	TPM_HANDLE h1 = MakeStoragePrimary();
	TPM_HANDLE h2 = MakeStoragePrimary();

	auto pub1 = tpm.ReadPublic(h1);
	auto pub2 = tpm.ReadPublic(h2);
	_ASSERT(pub1.name == pub2.name);

	// Clear the TPM
	tpm.Clear(tpm._AdminLockout);
	TPM_HANDLE h3 = MakeStoragePrimary();
	auto pub3 = tpm.ReadPublic(h3);

	cout << "Name before clear " << pub1.name << endl;
	cout << "Name after clear  " << pub3.name << endl;

	_ASSERT(pub1.name != pub3.name);

	tpm.FlushContext(h3);

	// We can do the same thing with the endorsement and platform hierarchies
	tpm.ChangePPS(tpm._AdminPlatform);
	tpm.ChangeEPS(tpm._AdminPlatform);

	// We can change the authValue for the primaries.

	vector<BYTE> newOwnerAuth = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA1, "passw0rd").digest;
	tpm.HierarchyChangeAuth(tpm._AdminOwner, newOwnerAuth);

	// TSS.C++ tracks changes of auth-values and updates the relevant handle.
	_ASSERT(tpm._AdminOwner.GetAuth() == newOwnerAuth);

	// Because we have the new auth-value we can continue managing the TPM
	tpm.HierarchyChangeAuth(tpm._AdminOwner, NullVec);

	// And set the value in the handle so that other tests will work
	tpm._AdminOwner.SetAuth(NullVec);

	// HierarchyControl enables and disables access to a hierarchy
	// First disable the storage hierarchy. This will flush any objects in this hierarchy.
	TPM_HANDLE ha = MakeStoragePrimary();
	tpm.HierarchyControl(tpm._AdminOwner, TPM_HANDLE::FromReservedHandle(TPM_RH::OWNER), 0);
	tpm._ExpectError(TPM_RC::SUCCESS).ReadPublic(ha);

	// Reenable it again
	tpm.HierarchyControl(tpm._AdminPlatform, TPM_HANDLE::FromReservedHandle(TPM_RH::OWNER), 1);

	// Hierarchies can be controlled by policy. Here we say any entity at locality 1 can
	// perform admin actions on the TPM.
	PolicyTree p(::PolicyLocality(TPMA_LOCALITY::LOC_ONE, ""));
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);
	tpm.SetPrimaryPolicy(tpm._AdminOwner, policyDigest.digest, TPM_ALG_ID::SHA1);

	tpm._GetDevice().SetLocality(1);
	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, s);

	// Show that we can set the policy back to NULL
	tpm.SetPrimaryPolicy(tpm._AdminOwner, NullVec, TPM_ALG_ID::_NULL);
	tpm._GetDevice().SetLocality(0);

	tpm.FlushContext(s);

	return;
}

void Samples::DictionaryAttack()
{
	Announce("Dictionary Attack");

	// The TPM maintains global dictionary attack remediation logic. A special
	// authValue is needed to control it. This is LockoutAuth.

	// Reset the lockout
	tpm.DictionaryAttackLockReset(tpm._AdminLockout);

	// And set the TPM to be fairly forgiving for running the tests
	UINT32 newMaxTries = 1000, newRecoverTime = 1, lockoutAuthFailRecoveryTime = 1;
	tpm.DictionaryAttackParameters(tpm._AdminLockout,
		newMaxTries,
		newRecoverTime,
		lockoutAuthFailRecoveryTime);
	return;
}

void Samples::PolicyCpHash()
{
	Announce("PolicyCpHash");

	// PolicyCpHash restricts the actions that can be performed on a secured object to
	// just a specific operation identified by the hash of the command paramters.
	// THis sample demonstrates how TSS.c++ can be used to obtain and use CpHashes.
	// We demonstrate a policy that (effectively) lets anyone do a TPM Clear() operation,
	// but no other admin tasks.

	// The Tpm2 method _CpHash() initiates all normal command processing, but rather
	// than dispatching the command to the TPM, the command-parameter hash is returned.
	TPMT_HA cpHash(TPM_ALG_ID::SHA1);
	tpm._GetCpHash(&cpHash).Clear(tpm._AdminPlatform);

	// We can now make a policy that authorizes this CpHash
	PolicyTree p(::PolicyCpHash(cpHash.digest));

	// Get the policy digest
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

	// Set the platform-admin policy to this value
	tpm.SetPrimaryPolicy(tpm._AdminPlatform, policyDigest.digest, TPM_ALG_ID::SHA1);

	// Now the _AdminLockout authorization is no longer needed to clear the TPM
	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, s);

	tpm._Sessions(s).Clear(tpm._AdminPlatform);
	cout << "Clear authorized using PolicyCpHash session" << endl;

	// Put things back the way they were
	tpm._AdminLockout.SetAuth(NullVec);
	tpm.SetPrimaryPolicy(tpm._AdminOwner, NullVec, TPM_ALG_ID::_NULL);

	// And clean up
	tpm.FlushContext(s);

	return;
}

void Samples::PolicyTimer()
{
	Announce("PolicyTimer");

	// PolicyCounterTimer allows actions to be gated on the TPMs clocks and timers.
	// Here we will demontrate giving a user owner-privileges for ~7 seconds

	TPMS_TIME_INFO startClock = tpm.ReadClock();
	UINT64 nowTime = startClock.time;
	UINT64 endTime = nowTime + 7 * 1000;

	// we can now make a policy that authorizes this CpHash
	PolicyTree p(::PolicyCounterTimer(endTime, 0, TPM_EO::UNSIGNED_LT));

	// Get the policy digest
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);
	tpm.SetPrimaryPolicy(tpm._AdminOwner, policyDigest.digest, TPM_ALG_ID::SHA1);

	// We can now set the owner-admin policy to this value
	cout << "The TPM operations should start failing at about 7 seconds..." << endl;
	int startTime = GetSystemTime(true);

	while (true) {
		int nowTime = GetSystemTime();
		int nowDiff = nowTime - startTime;

		if (nowDiff > 12) {
			break;
		}

		AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);

		try {
			// PolicyCounterTimer will start to fail after 10 seconds
			p.Execute(tpm, s);
		}
		catch (exception) {
			// Expected
		}

		tpm._Sessions(s)._AllowErrors().SetPrimaryPolicy(tpm._AdminOwner,
			policyDigest.digest,
			TPM_ALG_ID::SHA1);
		if (tpm._LastOperationSucceeded()) {
			cout << "Succeeded at " << dec << nowDiff << endl;
		}
		else {
			cout << "Failed at " << dec << nowDiff << endl;
		}

		tpm.FlushContext(s);
		Sleep(1000);
	}

	// Put things back the way they were
	tpm.SetPrimaryPolicy(tpm._AdminOwner, NullVec, TPM_ALG_ID::_NULL);

	return;
}

void Samples::PolicyWithPasswords()
{
	Announce("PolicyWithPasswords");

	// By default authorization uses *either* an auth-value or a policy. The
	// commands PolicyPassword and PolicyAuthValue indicate that both must be used,
	// as demonstrated here.

	// First PolicyPassword (plain-text)
	PolicyPassword pp;
	PolicyTree p(pp);
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);
	ByteVec useAuth = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA1, "password").digest;
	auto hmacHandle = MakeHmacPrimaryWithPolicy(policyDigest, useAuth);

	// First show it works if you know the password
	hmacHandle.SetAuth(useAuth);
	AUTH_SESSION sess = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, sess);
	auto hmacSig = tpm._Sessions(sess).HMAC(hmacHandle, ByteVec{ 1, 2, 3, 4 }, TPM_ALG_ID::SHA1);
	tpm.FlushContext(sess);

	// Now show it fails if you do not know the password
	hmacHandle.SetAuth(NullVec);
	sess = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, sess);
	hmacSig = tpm._Sessions(sess)._ExpectError(TPM_RC::AUTH_FAIL)
		.HMAC(hmacHandle, ByteVec{ 1, 2, 3, 4 }, TPM_ALG_ID::SHA1);

	// Do some cleanup
	tpm.FlushContext(sess);
	tpm.FlushContext(hmacHandle);

	// Now do the same thing with HMAC proof-of-possession
	PolicyTree p2(PolicyAuthValue(""));
	policyDigest = p2.GetPolicyDigest(TPM_ALG_ID::SHA1);
	useAuth = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA1, "password").digest;
	hmacHandle = MakeHmacPrimaryWithPolicy(policyDigest, useAuth);

	// First show it works if you know the password
	hmacHandle.SetAuth(useAuth);
	sess = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p2.Execute(tpm, sess);
	hmacSig = tpm._Sessions(sess).HMAC(hmacHandle, ByteVec{ 1, 2, 3, 4 }, TPM_ALG_ID::SHA1);
	tpm.FlushContext(sess);

	// Now show it fails if you do not know the password
	hmacHandle.SetAuth(NullVec);
	sess = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, sess);
	hmacSig = tpm._Sessions(sess)._ExpectError(TPM_RC::AUTH_FAIL)
		.HMAC(hmacHandle, ByteVec{ 1, 2, 3, 4 }, TPM_ALG_ID::SHA1);

	// And cleanup
	tpm.FlushContext(sess);
	tpm.FlushContext(hmacHandle);

	return;
}

void Samples::Unseal()
{
	Announce("Unseal");

	tpm.DictionaryAttackLockReset(tpm._AdminLockout);

	// Unsealing is reading the private data of an object when an authorization policy is
	// satisfied. The policy can be a simple password (the benefit being that the TPM
	// anti-hammering mechanisms can protect a strong password with a weaker one), or
	// any other policy. Here we demonstrate the classic Unseal() requiring PCR and a
	// auth-value.

	UINT32 pcr = 15;
	TPM_ALG_ID bank = TPM_ALG_ID::SHA1;

	// Set the PCR to something
	tpm.PCR_Event(TPM_HANDLE::PcrHandle(pcr), ByteVec{ 1, 2, 3, 4 });

	// Read the current value
	vector<TPMS_PCR_SELECTION> pcrSelection = TPMS_PCR_SELECTION::GetSelectionArray(bank, pcr);
	auto startPcrVal = tpm.PCR_Read(pcrSelection);
	auto currentValue = startPcrVal.pcrValues;

	// Create a policy naming this PCR and current PCR value
	PolicyTree p(PolicyPcr(currentValue, pcrSelection), PolicyPassword());

	// Get the policy digest
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

	// Now create an object with this policy to read
	ByteVec dataToSeal{ 1, 2, 3, 4, 5, 0xf, 0xe, 0xd, 0xa, 9, 8 };
	ByteVec authValue{ 9, 8, 7, 6, 5 };

	// We will demonstrate sealed data that is the child of a storage key
	TPM_HANDLE storagePrimary = MakeStoragePrimary();

	// Template for new data blob.
	TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM,
		policyDigest.digest,
		TPMS_KEYEDHASH_PARMS(TPMS_NULL_SCHEME_KEYEDHASH()),
		TPM2B_DIGEST_Keyedhash());

	TPMS_SENSITIVE_CREATE sensCreate(authValue, dataToSeal);
	vector<TPMS_PCR_SELECTION> pcrSelect;

	// Ask the TPM to create the key. We don't care about the PCR at creation.
	CreateResponse sealedObject = tpm.Create(storagePrimary,
		sensCreate,
		templ,
		NullVec,
		pcrSelect);

	TPM_HANDLE sealedKey = tpm.Load(storagePrimary,
		sealedObject.outPrivate,
		sealedObject.outPublic);
	sealedKey.SetAuth(authValue);

	// Start an auth-session
	AUTH_SESSION sess = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, sess);

	// And try to read the value
	ByteVec unsealedData = tpm._Sessions(sess).Unseal(sealedKey);
	tpm.FlushContext(sess);
	cout << "Unsealed data: " << unsealedData << endl;
	_ASSERT(unsealedData == dataToSeal);

	// Now show we can't read it without the auth-value
	sealedKey.SetAuth(NullVec);
	sess = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, sess);

	// And try to read the value
	unsealedData = tpm._Sessions(sess)._ExpectError(TPM_RC::AUTH_FAIL).Unseal(sealedKey);
	tpm.FlushContext(sess);

	// Finally show we can't read it if the PCR-value is wrong
	sealedKey.SetAuth(authValue);
	tpm.PCR_Event(TPM_HANDLE::PcrHandle(pcr), ByteVec{ 1, 2, 3, 4 });
	sess = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);

	try {
		p.Execute(tpm, sess);

		// An _ASSERT we shouldn't hit, see catch().
		_ASSERT(FALSE);
	}
	catch (exception) {
		// Error is expected because the PCR values are wrong
	}

	// And try to read the value
	unsealedData = tpm._Sessions(sess)._ExpectError(TPM_RC::POLICY_FAIL).Unseal(sealedKey);
	tpm.FlushContext(sess);

	tpm.FlushContext(storagePrimary);
	tpm.FlushContext(sealedKey);

	return;
}

void Samples::Serializer()
{
	Announce("Serializer");


	// TSS.C++ provides support for all TPM-defined data structures to be serialized and
	// deserialized to binary or to a string form. Binary serialization is via the
	// ToBuf and FromBuf methods. These methods convert to and from the TPM canonical
	// structure representation.

	// String serialization is to JSON (XML coming soon...). The resulting strings can
	// be stored in files or across the network. Here we demonstrate serialization and
	// deserialization of some TPM structures.

	// Start by using the TPM to initialize some data structures, 
	// specifically, PCR-values and a key pair.
	vector<TPMS_PCR_SELECTION> toReadArray{
		TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, 0),
		TPMS_PCR_SELECTION(TPM_ALG_ID::SHA256, 1)
	};

	// Used by PCR_Read to read PCR-0 in the SHA1 bank
	vector<TPMS_PCR_SELECTION> toReadPcr0{
		TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, 0)
	};

	ByteVec toEvent{ 1, 2, 3 };
	tpm.PCR_Event(TPM_HANDLE::PcrHandle(0), toEvent);
	tpm.PCR_Event(TPM_HANDLE::PcrHandle(1), toEvent);

	auto pcrVals = tpm.PCR_Read(toReadArray);

	// Make a storage primary
	TPM_HANDLE primHandle = MakeStoragePrimary();

	// Make a new child signing key
	TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent |  // Key attribues
		TPMA_OBJECT::fixedTPM | TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec, // No policy
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
			TPMS_SCHEME_RSAPSS(TPM_ALG_ID::SHA1), 1024, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	CreateResponse newSigningKey = tpm.Create(primHandle,
		TPMS_SENSITIVE_CREATE(),
		templ,
		NullVec,
		vector<TPMS_PCR_SELECTION>());
	tpm.FlushContext(primHandle);

	// Now demonstrate binary serialization
	// PubKey objects
	TPMT_PUBLIC& pubKey = newSigningKey.outPublic;
	ByteVec pubKeyBinary = pubKey.ToBuf();
	TPMT_PUBLIC reconstitutedPub;
	reconstitutedPub.FromBuf(pubKeyBinary);

	if (reconstitutedPub.ToBuf() == pubKey.ToBuf()) {
		cout << "TPMT_PUBLIC Original and Original->Binary->Reconstituted are the same" << endl;
	}

	_ASSERT(reconstitutedPub.ToBuf() == pubKey.ToBuf());

	// PCR-values
	ByteVec pcrValsBinary = pcrVals.ToBuf();
	PCR_ReadResponse reconstituted;
	reconstituted.FromBuf(pcrValsBinary);
	cout << "PcrVals:" << endl << pcrVals.ToString(false) << endl;
	cout << "Binary form:" << endl << pcrValsBinary << endl;

	// Check that they're the same:
	if (reconstituted.ToBuf() == pcrVals.ToBuf()) {
		cout << "PCR Original and Original->Binary->Reconstituted are the same" << endl;
	}

	_ASSERT(reconstituted.ToBuf() == pcrVals.ToBuf());

	// Next demonstrate JSON serialization
	// First the PCR-values structure
	string pcrValsString = pcrVals.Serialize(SerializationType::JSON);
	reconstituted.Deserialize(SerializationType::JSON, pcrValsString);
	cout << "JSON Serialized PCR values:" << endl << pcrValsString << endl;

	if (reconstituted == pcrVals) {
		cout << "JSON serializer of PCR values OK" << endl;
	}

	_ASSERT(reconstituted == pcrVals);

	// Next a full key (pub + prov)
	string keyContainer = newSigningKey.Serialize(SerializationType::JSON);
	CreateResponse reconstitutedKey;
	reconstitutedKey.Deserialize(SerializationType::JSON, keyContainer);
	cout << "JSON Serialization of key-container:" << keyContainer << endl;

	if (reconstitutedKey == reconstitutedKey) {
		cout << "JSON serializer of TPM key-container is OK" << endl;
	}

	_ASSERT(reconstitutedKey == newSigningKey);

	return;
}

void Samples::SessionEncryption()
{
	Announce("SessionEncryption");

	// Session encryption is essentially transparent to the application programmer.
	// All that is needed is to create a session with the necessary characteristics and
	// TSS.C++ adds all necessary parameter encryption and decryption.

	// At the time of writing only unseeded and unbound session enc and dec are supported.
	// First set up a session that encrypts communications TO the TPM. To do this
	// we tell the TPM to decrypt via TPMA_SESSION::decrypt.
	AUTH_SESSION sess = tpm.StartAuthSession(TPM_SE::HMAC, TPM_ALG_ID::SHA1,
		TPMA_SESSION::continueSession | TPMA_SESSION::decrypt,
		TPMT_SYM_DEF(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB));

	ByteVec stirValue{ 1, 1, 1, 1, 1, 1, 1, 1 };

	// Simplest use of parm encryption - the stirValue buffer will be encrypted
	// Note: because the nonces are transferred in plaintext and because this example
	// does not use a secret auth-value, a MiM could decrypt (but it shows how parm
	// encryption is enabled in TSS.C++.
	tpm._Sessions(sess).StirRandom(stirValue);

	// A bit more complicated: here we set the ownerAuth using parm-encrytion
	ByteVec newOwnerAuth{ 0, 1, 2, 3, 4, 5, 6 };
	tpm._Sessions(sess).HierarchyChangeAuth(tpm._AdminOwner, newOwnerAuth);
	tpm._AdminOwner.SetAuth(newOwnerAuth);

	// But show we can change it back using the encrypting session
	tpm._Sessions(sess).HierarchyChangeAuth(tpm._AdminOwner, NullVec);
	tpm._AdminOwner.SetAuth(NullVec);
	tpm.FlushContext(sess);

	// Now instruct the TPM to encrypt responses. 
	// Create a primary key so we have something to read.
	TPM_HANDLE storagePrimary = MakeStoragePrimary();

	// Read some data unencrypted
	auto plaintextRead = tpm.ReadPublic(storagePrimary);

	// Make an encrypting session
	sess = tpm.StartAuthSession(TPM_SE::HMAC, TPM_ALG_ID::SHA1,
		TPMA_SESSION::continueSession | TPMA_SESSION::encrypt,
		TPMT_SYM_DEF(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB));

	auto encryptedRead = tpm._Sessions(sess).ReadPublic(storagePrimary);

	if (plaintextRead == encryptedRead) {
		cout << "Return parameter encryption succeeded" << endl;
	}

	_ASSERT(plaintextRead == encryptedRead);

	tpm.FlushContext(sess);
	tpm.FlushContext(storagePrimary);

	return;
}

void Samples::PresentationSnippets()
{
	// Connect to a local TPM simulator
	TpmTcpDevice device;

	if (!device.Connect("127.0.0.1", 2321)) {
		cerr << "Could not connect to the TPM device";
		return;
	}

	// We talk to the TPM via a Tpm2 object
	Tpm2 tpm;

	// Associate Tpm2 object with a "device"
	tpm._SetDevice(device);

	// If we are talking to the simulator we need to do some of the
	// things that the BIOS normally does for us.
	device.PowerOn();
	tpm.Startup(TPM_SU::CLEAR);

	vector<BYTE> rand = tpm.GetRandom(20);
	cout << "random bytes: " << rand << endl;

	return;
}

void Samples::ImportDuplicate()
{
	Announce("ImportDuplicate");

	// Make a storage primary
	auto storagePrimaryHandle = MakeStoragePrimary();

	// We will need the public area for import later
	auto storagePrimaryPublic = tpm.ReadPublic(storagePrimaryHandle);

	// Make a duplicatable signing key as a child. Note that duplication
	// *requires* a policy session.
	PolicyTree p(PolicyCommandCode(TPM_CC::Duplicate, ""));
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

	TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::sign |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth |
		TPMA_OBJECT::adminWithPolicy,
		policyDigest.digest,
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
			TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	CreateResponse newSigningKey = tpm.Create(storagePrimaryHandle,
		TPMS_SENSITIVE_CREATE(NullVec, NullVec),
		templ,
		NullVec, vector<TPMS_PCR_SELECTION>());
	// Load the key
	TPM_HANDLE signKey = tpm.Load(storagePrimaryHandle, newSigningKey.outPrivate, newSigningKey.outPublic);

	// Start and then execute the session
	AUTH_SESSION session = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, session);

	// Keys can be duplicated in plaintext or with a symmetric wrapper, or with a symmetric
	// wrapper and encrypted to a loaded pubic key. The simplest: export (duplicate) it
	// specifying no encryption.
	auto duplicatedKey = tpm._Sessions(session).Duplicate(signKey,
		TPM_HANDLE::NullHandle(),
		NullVec,
		TPMT_SYM_DEF_OBJECT::NullObject());

	cout << "Duplicated private key:" << duplicatedKey.ToString(false);

	tpm.FlushContext(session);
	tpm.FlushContext(signKey);

	// Now try to import it (to the same parent)
	auto importedPrivate = tpm.Import(storagePrimaryHandle,
		NullVec,
		newSigningKey.outPublic,
		duplicatedKey.duplicate,
		NullVec,
		TPMT_SYM_DEF_OBJECT::NullObject());

	// And now show that we can load and and use the imported blob
	TPM_HANDLE importedSigningKey = tpm.Load(storagePrimaryHandle,
		importedPrivate,
		newSigningKey.outPublic);

	auto signature = tpm.Sign(importedSigningKey,
		TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA1, "abc").digest,
		TPMS_NULL_SIG_SCHEME(),
		TPMT_TK_HASHCHECK::NullTicket());

	cout << "Signature with imported key: " << signature.ToString(false) << endl;

	tpm.FlushContext(importedSigningKey);

	// Now create and import an externally created key. We will demonstrate
	// creation and import of an RSA signing key.
	TPMT_PUBLIC swKeyDef(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::sign |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth |
		TPMA_OBJECT::adminWithPolicy,
		policyDigest.digest,
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
			TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	TSS_KEY importableKey;
	importableKey.publicPart = swKeyDef;
	importableKey.CreateKey();
	ByteVec swKeyAuthValue{ 4, 5, 4, 5 };

	// We can use TSS.C++ to create an duplication blob that we can Import()
	TPMT_SENSITIVE sens(swKeyAuthValue, NullVec, TPM2B_PRIVATE_KEY_RSA(importableKey.privatePart));
	TPMT_SYM_DEF_OBJECT noInnerWrapper = TPMT_SYM_DEF_OBJECT::NullObject();
	DuplicationBlob dupBlob = storagePrimaryPublic.outPublic.CreateImportableObject(tpm,
		importableKey.publicPart, sens, noInnerWrapper);

	auto newPrivate = tpm.Import(storagePrimaryHandle,
		NullVec,
		importableKey.publicPart,
		dupBlob.DuplicateObject,
		dupBlob.EncryptedSeed,
		noInnerWrapper);

	// We can also import it with an inner wrapper
	TPMT_SYM_DEF_OBJECT innerWrapper = TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB);
	dupBlob = storagePrimaryPublic.outPublic.CreateImportableObject(tpm,
		importableKey.publicPart,
		sens,
		innerWrapper);
	newPrivate = tpm.Import(storagePrimaryHandle,
		dupBlob.InnerWrapperKey,
		importableKey.publicPart,
		dupBlob.DuplicateObject,
		dupBlob.EncryptedSeed,
		innerWrapper);

	// Now load and use it.
	TPM_HANDLE importedSwKey = tpm.Load(storagePrimaryHandle,
		newPrivate,
		importableKey.publicPart);
	importedSwKey.SetAuth(swKeyAuthValue);
	TPMT_HA dataToSign = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA1, "abc");
	auto importedKeySig = tpm.Sign(importedSwKey,
		dataToSign.digest,
		TPMS_NULL_SIG_SCHEME(),
		TPMT_TK_HASHCHECK::NullTicket());
	// And verify
	bool swKeySig = importableKey.publicPart.ValidateSignature(dataToSign.digest,
		*importedKeySig.signature);
	_ASSERT(swKeySig);

	if (swKeySig) {
		cout << "Imported SW-key works" << endl;
	}

	tpm.FlushContext(storagePrimaryHandle);
	tpm.FlushContext(importedSwKey);

	return;
}

void Samples::MiscAdmin()
{
	Announce("MiscAdmin");

	// Demonstrate the use of miscellaneous admin commands

	//
	// Self Testing
	//

	// Note that the simulator does not implement selt-tests, so this sample does
	// nothing more than demonstrate how to use the TPM.
	tpm._AllowErrors().SelfTest(1);
	auto testResult = tpm.GetTestResult();
	auto toBeTested = tpm.IncrementalSelfTest(vector<TPM_ALG_ID> {TPM_ALG_ID::SHA1, TPM_ALG_ID::AES});
	cout << "Algorithms to be tested: " << toBeTested.size() << endl;

	//
	// Clock Management
	//

	ReadClockResponse startClock = tpm.ReadClock();

	// We should be able to set time forward
	int dt = 10000000;
	UINT64 newClock = startClock.currentTime.clockInfo.clock + dt;

	tpm.ClockSet(tpm._AdminOwner, newClock);

	ReadClockResponse nowClock = tpm.ReadClock();

	int dtIs = (int)(nowClock.currentTime.clockInfo.clock -
		startClock.currentTime.clockInfo.clock);

	cout << setw(1) << dec <<
		"Tried to advance the clock by 10000000" << endl <<
		"actual =               " << dtIs << endl;

	// But not back...
	tpm._ExpectError(TPM_RC::VALUE).ClockSet(tpm._AdminOwner, startClock.currentTime.clockInfo.clock);

	// Should be able to speed up and slow down the clock
	tpm.ClockRateAdjust(tpm._AdminOwner, TPM_CLOCK_ADJUST::MEDIUM_SLOWER);
	tpm.ClockRateAdjust(tpm._AdminOwner, TPM_CLOCK_ADJUST::MEDIUM_FASTER);

	//
	// PP-Commands
	//

	// Set the commands that need physical presence. Add TPM2_Clear to the PP-list.
	// By default PP_Commands itself needs PP.
	tpm._GetDevice().PPOn();
	tpm.PP_Commands(tpm._AdminPlatform, vector<TPM_CC> {TPM_CC::Clear}, vector<TPM_CC>());
	tpm._GetDevice().PPOff();

	// Should not be able to execute without PP
	tpm._ExpectError(TPM_RC::PP).Clear(tpm._AdminPlatform);

	// But shold be able to execute with PP
	tpm._GetDevice().PPOn();
	tpm.Clear(tpm._AdminLockout);
	cout << "PP-Clear - OK" << endl;
	tpm._GetDevice().PPOff();

	// And now put things back the way they were
	tpm._GetDevice().PPOn();
	tpm.PP_Commands(tpm._AdminPlatform, vector<TPM_CC>(), vector<TPM_CC> {TPM_CC::Clear});
	tpm._GetDevice().PPOff();
	// check it works without PP
	tpm.Clear(tpm._AdminLockout);

	//
	// PCR stuff
	//

	// Set an auth value for a PCR. We will use pcr-20, generally extendable at Loc3.
	int pcrNum = 20;
	tpm._GetDevice().SetLocality(3);
	ByteVec newAuth = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA1, "password").digest;
	tpm.PCR_SetAuthValue(TPM_HANDLE::PcrHandle(pcrNum), newAuth);

	// This won't work because we have not set the auth in the handle
	tpm._ExpectError(TPM_RC::BAD_AUTH).PCR_Event(TPM_HANDLE::PcrHandle(pcrNum), ByteVec{ 1, 2, 3 });

	TPM_HANDLE pcrHandle = TPM_HANDLE::PcrHandle(pcrNum);
	pcrHandle.SetAuth(newAuth);

	// And now it will work
	tpm.PCR_Event(pcrHandle, ByteVec{ 1, 2, 3 });

	// Set things back the way they were
	tpm.PCR_SetAuthValue(pcrHandle, NullVec);

	// Now set a policy for a PCR. Our policy will be that the PCR can only
	// be Evented (extend won't work) at the start show extend works.
	tpm.PCR_Extend(TPM_HANDLE::PcrHandle(pcrNum), vector<TPMT_HA> {TPMT_HA(TPM_ALG_ID::SHA1)});

	// Create a policy
	PolicyCommandCode XX(TPM_CC::PCR_Event);
	PolicyTree p(PolicyCommandCode(TPM_CC::PCR_Event, ""));
	ByteVec policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1).digest;
	tpm.PCR_SetAuthPolicy(tpm._AdminPlatform, policyDigest,
		TPM_ALG_ID::SHA1, TPM_HANDLE::PcrHandle(pcrNum));

	// Change the use-auth to a random value so that it can no longer be used
	ByteVec randomAuth = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA1, "secret").digest;

	// And now show that we can do event with a policy session
	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, s);
	tpm._Sessions(s).PCR_Event(TPM_HANDLE::PcrHandle(pcrNum), ByteVec{ 1, 2, 3 });
	tpm.FlushContext(s);

	// And set things back the way they were
	tpm.PCR_SetAuthPolicy(tpm._AdminPlatform, NullVec,
		TPM_ALG_ID::_NULL, TPM_HANDLE::PcrHandle(pcrNum));

	tpm.PCR_SetAuthValue(TPM_HANDLE::PcrHandle(pcrNum), NullVec);
	tpm._GetDevice().SetLocality(0);


	//
	// PCR-bank allocations
	//

	// The TPM simulator starts off with SHA256 PCR. Let's delete them.
	// --- REVISIT: The GetCap shows this as not working
	PCR_AllocateResponse resp = tpm.PCR_Allocate(tpm._AdminPlatform, vector<TPMS_PCR_SELECTION> {
		TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, vector<UINT32> { 0, 1, 2, 3, 4 }),
			TPMS_PCR_SELECTION(TPM_ALG_ID::SHA256, vector<UINT32> {0, 23 })
	});

	_ASSERT(resp.allocationSuccess);

	// We have to restart the TPM for this to take effect
	tpm.Shutdown(TPM_SU::CLEAR);
	tpm._GetDevice().PowerOff();
	tpm._GetDevice().PowerOn();
	tpm.Startup(TPM_SU::CLEAR);

	// Now read the PCR
	GetCapabilityResponse caps = tpm.GetCapability(TPM_CAP::PCRS, 0, 1);
	auto pcrs = dynamic_cast<TPML_PCR_SELECTION *> (caps.capabilityData);

	cout << "New PCR-set: " << Tpm2::GetEnumString(pcrs->pcrSelections[0].hash) << "\t";
	auto pcrsWithThisHash = pcrs->pcrSelections[0].ToArray();

	for (auto p = pcrsWithThisHash.begin(); p != pcrsWithThisHash.end(); p++) {
		cout << *p << " ";
	}

	cout << endl << "New PCR-set: " << Tpm2::GetEnumString(pcrs->pcrSelections[1].hash) << "\t";
	pcrsWithThisHash = pcrs->pcrSelections[1].ToArray();

	for (auto p = pcrsWithThisHash.begin(); p != pcrsWithThisHash.end(); p++) {
		cout << *p << " ";
	}

	cout << endl;

	// And put things back the way they were
	vector<UINT32> standardPcr(24);
	std::iota(standardPcr.begin(), standardPcr.end(), 0);
	resp = tpm.PCR_Allocate(tpm._AdminPlatform, vector<TPMS_PCR_SELECTION> {
		TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, standardPcr),
			TPMS_PCR_SELECTION(TPM_ALG_ID::SHA256, standardPcr)
	});

	_ASSERT(resp.allocationSuccess);

	// We have to restart the TPM for this to take effect
	tpm.Shutdown(TPM_SU::CLEAR);
	tpm._GetDevice().PowerOff();
	tpm._GetDevice().PowerOn();
	tpm.Startup(TPM_SU::CLEAR);

	//
	// ClearControl
	//


	// ClearControl disables the use of Clear(). Show we can clear.
	tpm.Clear(tpm._AdminLockout);

	// Disable clear
	tpm.ClearControl(tpm._AdminLockout, 1);
	tpm._ExpectError(TPM_RC::DISABLED).Clear(tpm._AdminLockout);
	tpm.ClearControl(tpm._AdminPlatform, 0);

	// And now it should work again
	tpm.Clear(tpm._AdminLockout);

	return;
}

void Samples::RsaEncryptDecrypt()
{
	Announce("RsaEncryptDecrypt");

	// This sample demostrates the use of the TPM for RSA operations.

	// We will make a key in the "null hierarchy".
	TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::decrypt |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec,  // No policy
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT::NullObject(),
			TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	// Create the key
	CreatePrimaryResponse storagePrimary = tpm.CreatePrimary(
		TPM_HANDLE::FromReservedHandle(TPM_RH::_NULL),
		TPMS_SENSITIVE_CREATE(NullVec, NullVec),
		storagePrimaryTemplate,
		NullVec,
		vector<TPMS_PCR_SELECTION>());

	TPM_HANDLE& keyHandle = storagePrimary.handle;

	ByteVec dataToEncrypt = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA1, "secret").digest;
	cout << "Data to encrypt: " << dataToEncrypt << endl;

	auto enc = tpm.RSA_Encrypt(keyHandle, dataToEncrypt, TPMS_NULL_ASYM_SCHEME(), NullVec);
	cout << "RSA-encrypted data: " << enc << endl;

	auto dec = tpm.RSA_Decrypt(keyHandle, enc, TPMS_NULL_ASYM_SCHEME(), NullVec);
	cout << "decrypted data: " << dec << endl;

	if (dec == dataToEncrypt) {
		cout << "Decryption worked" << endl;
	}

	_ASSERT(dataToEncrypt == dec);

	// Now encrypt using TSS.C++ library functions
	ByteVec mySecret = tpm._GetRandLocal(20);
	enc = storagePrimary.outPublic.Encrypt(mySecret, NullVec);
	dec = tpm.RSA_Decrypt(keyHandle, enc, TPMS_NULL_ASYM_SCHEME(), NullVec);
	cout << "My           secret: " << mySecret << endl;
	cout << "My decrypted secret: " << dec << endl;

	_ASSERT(mySecret == dec);

	// Now with padding
	ByteVec pad{ 1, 2, 3, 4, 5, 6, 0 };
	enc = storagePrimary.outPublic.Encrypt(mySecret, pad);
	dec = tpm.RSA_Decrypt(keyHandle, enc, TPMS_NULL_ASYM_SCHEME(), pad);
	cout << "My           secret: " << mySecret << endl;
	cout << "My decrypted secret: " << dec << endl;

	_ASSERT(mySecret == dec);

	tpm.FlushContext(keyHandle);

	return;
}

void Samples::Audit()
{
	Announce("Audit");

	// The TPM supports two kinds of audit. Command audit - demonstrated first -
	// instructs the TPM to keep a running hash of the commands and responses for
	// all commands in a list.

	// There are four parts to this: (1) instructing the Tpm2 object to keep an
	// audit so that it can later be checked, (2) instructing the TPM to keep
	// an audit, and (3) quoting the TPMaudit, and (4) checking it.

	TPM_ALG_ID auditAlg = TPM_ALG_ID::SHA1;
	vector<TPM_CC> emptyVec;
	tpm.SetCommandCodeAuditStatus(tpm._AdminOwner, TPM_ALG_ID::_NULL, emptyVec, emptyVec);

	// Start the TPM auditing
	vector<TPM_CC> toAudit{ TPM_CC::GetRandom, TPM_CC::StirRandom };
	tpm.SetCommandCodeAuditStatus(tpm._AdminOwner, auditAlg, emptyVec, emptyVec);
	tpm.SetCommandCodeAuditStatus(tpm._AdminOwner, TPM_ALG_ID::_NULL, toAudit, emptyVec);

	// Read the current audit-register value from the TPM and register this
	// as the "start point" with TSS.C++
	GetCommandAuditDigestResponse auditDigestAtStart = tpm.GetCommandAuditDigest(tpm._AdminEndorsement,
		TPM_HANDLE::NullHandle(), NullVec, TPMS_NULL_SIG_SCHEME());

	TPMS_ATTEST& atStart = auditDigestAtStart.auditInfo;
	auto atStartInf = dynamic_cast<TPMS_COMMAND_AUDIT_INFO *> (atStart.attested);
	tpm._StartAudit(TPMT_HA(auditAlg, atStartInf->auditDigest));

	// Audit some commands

	// TSS.C++ does not automatically maintain the list of commands that are audited.
	// You must use _Audit() to tell TSS.C++ to add the rpHash and cpHash to the accumulator.
	tpm._Audit().GetRandom(20);
	tpm._Audit().StirRandom(ByteVec{ 1, 2, 3, 4 });
	tpm._Audit().GetRandom(10);
	tpm._Audit().StirRandom(ByteVec{ 9, 8, 7, 6 });

	// And stop auditing
	tpm._Audit().SetCommandCodeAuditStatus(tpm._AdminOwner, TPM_ALG_ID::_NULL, emptyVec, emptyVec);

	TPMT_HA expectedAuditHash = tpm._GetAuditHash();
	tpm._EndAudit();

	// We can read the audit.
	GetCommandAuditDigestResponse auditDigest = tpm.GetCommandAuditDigest(tpm._AdminEndorsement,
		TPM_HANDLE::NullHandle(), NullVec, TPMS_NULL_SIG_SCHEME());

	TPMS_ATTEST& attest = auditDigest.auditInfo;
	auto auditDigestVal = dynamic_cast<TPMS_COMMAND_AUDIT_INFO *> (attest.attested);

	// Compare this to the value we are maintaining in the TPM context
	cout << "TPM reported command digest:" << auditDigestVal->auditDigest << endl;
	cout << "TSS.C++ calculated         :" << expectedAuditHash.digest << endl;

	_ASSERT(expectedAuditHash.digest == auditDigestVal->auditDigest);

	// And now we can quote the audit. Make a protected signing key.
	TPM_HANDLE primaryKey = MakeStoragePrimary();
	TPM_HANDLE signingKey = MakeChildSigningKey(primaryKey, true);
	tpm.FlushContext(primaryKey);
	ReadPublicResponse pubKey = tpm.ReadPublic(signingKey);

	GetCommandAuditDigestResponse quote = tpm.GetCommandAuditDigest(tpm._AdminEndorsement,
		signingKey, NullVec, TPMS_NULL_SIG_SCHEME());

	bool quoteOk = pubKey.outPublic.ValidateCommandAudit(expectedAuditHash, NullVec, quote);

	if (quoteOk) {
		cout << "Command-audit quote OK." << endl;
	}

	_ASSERT(quoteOk);

	// Session-audit cryptographically tracks commands issued in the context of the session
	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::HMAC,
		TPM_ALG_ID::SHA1,
		TPMA_SESSION::audit |
		TPMA_SESSION::continueSession,
		TPMT_SYM_DEF::NullObject());

	tpm._StartAudit(TPMT_HA(TPM_ALG_ID::SHA1));

	tpm._Audit()._Sessions(s).GetRandom(20);
	tpm._Audit()._Sessions(s).StirRandom(ByteVec{ 1, 2, 3, 4 });

	TPMT_HA expectedHash = tpm._GetAuditHash();
	tpm._EndAudit();

	auto sessionQuote = tpm.GetSessionAuditDigest(tpm._AdminEndorsement,
		signingKey,
		s,
		NullVec,
		TPMS_NULL_SIG_SCHEME());

	quoteOk = pubKey.outPublic.ValidateSessionAudit(expectedHash,
		NullVec,
		sessionQuote);
	if (quoteOk) {
		cout << "Session-audit quote OK." << endl;
	}

	_ASSERT(quoteOk);

	tpm.FlushContext(s);
	tpm.FlushContext(signingKey);

	return;
}

void Samples::Activate()
{
	Announce("ActivateCredential");

	// Make a new EK and get the public key
	TPM_HANDLE ekHandle = MakeEndorsementKey();
	auto ekPubX = tpm.ReadPublic(ekHandle);
	TPMT_PUBLIC& ekPub = ekPubX.outPublic;

	// Make another key that we will "activate"
	TPM_HANDLE srk = MakeStoragePrimary();
	TPM_HANDLE keyToActivate = MakeChildSigningKey(srk, true);
	tpm.FlushContext(srk);

	// Make a secret using the TSS.C++ RNG
	auto secret = tpm._GetRandLocal(20);
	auto nameOfKeyToActivate = keyToActivate.GetName();

	// Use TSS.C++ to get an activation blob
	ActivationData cred = ekPub.CreateActivation(secret, TPM_ALG_ID::SHA1, nameOfKeyToActivate);

	ByteVec recoveredSecret = tpm.ActivateCredential(keyToActivate,
		ekHandle,
		cred.CredentialBlob,
		cred.Secret);

	cout << "Secret:                         " << secret << endl;
	cout << "Secret recovered from Activate: " << recoveredSecret << endl;

	_ASSERT(secret == recoveredSecret);

	// You can also use the TPM to make the activation credential
	MakeCredentialResponse tpmActivator = tpm.MakeCredential(ekHandle,
		secret,
		nameOfKeyToActivate);

	recoveredSecret = tpm.ActivateCredential(keyToActivate,
		ekHandle,
		tpmActivator.credentialBlob,
		tpmActivator.secret);

	cout << "TPM-created activation blob: Secret recovered from Activate: " << recoveredSecret << endl;

	_ASSERT(secret == recoveredSecret);

	tpm.FlushContext(ekHandle);
	tpm.FlushContext(keyToActivate);

	return;
}

///<summary>This routine throws an exception if there is a key or session left in the TPM</summary>
void Samples::AssertNoLoadedKeys()
{
	GetCapabilityResponse caps = tpm.GetCapability(TPM_CAP::HANDLES,
		((UINT32)TPM_HT::TRANSIENT << 24),
		32);

	TPML_HANDLE *handles = dynamic_cast<TPML_HANDLE *>(caps.capabilityData);

	if (handles->handle.size() != 0) {
		throw runtime_error("loaded object");
	}

	GetCapabilityResponse caps2 = tpm.GetCapability(TPM_CAP::HANDLES,
		((UINT32)TPM_HT::LOADED_SESSION << 24),
		32);

	TPML_HANDLE *handles2 = dynamic_cast<TPML_HANDLE *>(caps2.capabilityData);

	if (handles2->handle.size() != 0) {
		throw runtime_error("loaded session");
	}

	return;
}

void Samples::RecoverFromLockout()
{
	device->PowerOff();
	device->PowerOn();
	tpm.Startup(TPM_SU::CLEAR);

	// Clear out any persistent ownerAuth
	tpm.Clear(tpm._AdminPlatform);
	tpm.Shutdown(TPM_SU::CLEAR);

	return;
}

void Samples::SoftwareKeys()
{
	Announce("SoftwareKeys");

	// We will make a key in the "null hierarchy".
	TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::decrypt |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec,
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT::NullObject(),
			TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	// Create the key
	TSS_KEY k;
	k.publicPart = storagePrimaryTemplate;
	k.CreateKey();

	//TPM_HANDLE& keyHandle = storagePrimary.handle;

	TPMT_SENSITIVE s(NullVec, NullVec, TPM2B_PRIVATE_KEY_RSA(k.privatePart));
	TPM_HANDLE h2 = tpm.LoadExternal(s, k.publicPart, TPM_HANDLE::FromReservedHandle(TPM_RH::_NULL));



	// Encrypt with the TPM key
	char * teststr = "Notre Dame";
	ByteVec testvec = stringToByteVec(teststr, 10);
	ByteVec encTest = tpm.RSA_Encrypt(h2, testvec, TPMS_NULL_ASYM_SCHEME(), NullVec);  //(h2, toSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK::NullTicket());

	ByteVec decTest = tpm.RSA_Decrypt(h2, encTest, TPMS_NULL_ASYM_SCHEME(), NullVec);
	cout << ByteVecToString(decTest) << endl;
	return;
}

TSS_KEY *signingKey = NULL;
SignResponse MyPolicySignedCallback(const ByteVec& _nonceTpm,
	UINT32 _expiration,
	const ByteVec& _cpHashA,
	const ByteVec& _policyRef,
	const string& _tag)
{
	// In normal operation, the calling program will check what
	// it is signing before it signs it.  We just sign...
	OutByteBuf toSign;
	toSign << _nonceTpm << _expiration << _cpHashA << _policyRef;
	auto hashToSign = TPMT_HA::FromHashOfData(TPM_ALG_ID::SHA1, toSign.GetBuf());
	auto sig = signingKey->Sign(hashToSign.digest, TPMS_NULL_SIG_SCHEME());

	return sig;
}

PolicyNVCallbackData nvData;

PolicyNVCallbackData MyPolicyNVCallback(const string& _tag)
{
	return nvData;
}

