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


bool c_createAndStoreKey()
{
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
	
}

bool c_writeKeyToFile(const std::string & filename)
{

	// Next a full key (pub + prov)
	string keyContainer = storagePrimary.Serialize(SerializationType::JSON);

	std::ofstream outfile(filename, ios::out | ios::binary);

		outputToStream(outfile, keyContainer);
		outfile << std::endl;
		outfile.close();
	
}

std::vector<BYTE> c_RSA_decrypt(const std::vector<BYTE> & ciphertext)
{
	
	ByteVec plaintext;
	//ByteVec pad{ 1, 2, 3, 4, 5, 6, 0 };
	
	// First increment
	tpm.NV_Increment(nvHandle, nvHandle);

	// Should now be able to read
	ByteVec beforeIncrement = tpm.NV_Read(nvHandle, nvHandle, 8, 0);
	cout << "Initial counter data:     " << beforeIncrement << endl;

	// Should be able to increment
	//for (int j = 0; j < 5; j++) {
		tpm.NV_Increment(nvHandle, nvHandle);

		plaintext = tpm.RSA_Decrypt(keyHandle, ciphertext, TPMS_NULL_ASYM_SCHEME(), NullVec);
		cout << "Decrypted plaintext: " << plaintext << endl << endl;

		// And make sure that it's good
		ByteVec afterIncrement = tpm.NV_Read(nvHandle, nvHandle, 8, 0);
		cout << "Value after increment:       " << afterIncrement << endl << endl;
		
		if (tpm.NV_Read(nvHandle, nvHandle, 8, 0) >= key_limit)
		{
			tpm.FlushContext(keyHandle);
			cout << endl << "Flushed Key After Monotonic Counter Incremented" << endl << endl;

			// And then delete it
			tpm.NV_UndefineSpace(tpm._AdminOwner, nvHandle);

		}
	}
	
}

s_readKeyFromFile(const std::string & filename)
{
	
	std::ifstream infile(filename);
		std::getline(filename, RSA_KEY)
	infile.close();
	
	CreatePrimaryResponse reconstitutedKey;
	reconstitutedKey.Deserialize(SerializationType::JSON, RSA_KEY);

	TPM_HANDLE& keyHandle1 = reconstitutedKey.handle;

	cout << "New RSA primary key" << endl << reconstitutedKey.outPublic.ToString() << endl;	
	
}


std::vector<BYTE> s_RSA_encrypt(const std::vector<BYTE> & plaintext)
{
	ciphertext = reconstitutedKey.outPublic.Encrypt(plaintext, NullVec);
	cout << "Encrypted ciphertext: " << ciphertext << endl;
}