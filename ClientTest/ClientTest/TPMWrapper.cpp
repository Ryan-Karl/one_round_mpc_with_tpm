


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


TPMWrapper::TPMWrapper()
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

TPMWrapper::~TPMWrapper(){
	// A clean shutdown results in fewer lockout errors.
	tpm.Shutdown(TPM_SU::CLEAR);
	device->PowerOff();

	// The following routine finalizes and prints the function stats.
	//Callback2();

	// REVISIT 
	// delete device;
}

void TPMWrapper::Callback1(){
	//Announce("Installing callback");

	// Install a callback that is invoked after the TPM command has been executed
	tpm._SetResponseCallback(&Samples::TpmCallbackStatic, this);
}


TPMT_PUBLIC TPMWrapper::c_createAndStoreKey()
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

	return storagePrimary;
	
}

bool TPMWrapper::c_writeKeyToFile(const std::string & filename, TPMT_PUBLIC& storagePrimary)
{

	// Next a full key (pub + prov)
	string keyContainer = storagePrimary.Serialize(SerializationType::JSON);

	std::ofstream outfile(filename, ios::out | ios::binary);

	outputToStream(outfile, keyContainer);
	outfile << std::endl;
	outfile.close();
	
}

std::vector<BYTE> TPMWrapper::c_RSA_decrypt(const std::vector<BYTE> & ciphertext, uint16_t key_limit)
{
	
	ByteVec plaintext;
	//ByteVec pad{ 1, 2, 3, 4, 5, 6, 0 };
	
	// First increment
	tpm.NV_Increment(nvHandle, nvHandle);

	// Should now be able to read
	ByteVec beforeIncrement = tpm.NV_Read(nvHandle, nvHandle, 8, 0);
	//cout << "Initial counter data:     " << beforeIncrement << endl;

	// Should be able to increment
	//for (int j = 0; j < 5; j++) {
	tpm.NV_Increment(nvHandle, nvHandle);

	plaintext = tpm.RSA_Decrypt(keyHandle, ciphertext, TPMS_NULL_ASYM_SCHEME(), NullVec);
	//cout << "Decrypted plaintext: " << plaintext << endl << endl;

	// And make sure that it's good
	ByteVec afterIncrement = tpm.NV_Read(nvHandle, nvHandle, 8, 0);
	//cout << "Value after increment:       " << afterIncrement << endl << endl;
		
	if (tpm.NV_Read(nvHandle, nvHandle, 8, 0) >= key_limit){
		tpm.FlushContext(keyHandle);
		//cout << endl << "Flushed Key After Monotonic Counter Incremented" << endl << endl;

		// And then delete it
		tpm.NV_UndefineSpace(tpm._AdminOwner, nvHandle);

	}

	return plaintext;
}
	

TPMT_PUBLIC TPMWrapper::s_readKeyFromFile(const std::string & filename)
{
	//Assumes the key is all stored on a single line of the file
	std::string rsa_key;
	std::ifstream infile(filename);
	std::getline(filename, rsa_key);
	infile.close();
	
	CreatePrimaryResponse reconstitutedKey;
	reconstitutedKey.Deserialize(SerializationType::JSON, rsa_key);

	TPM_HANDLE& keyHandle1 = reconstitutedKey.handle;

	//cout << "New RSA primary key" << endl << reconstitutedKey.outPublic.ToString() << endl;	
	//May need to return a different type
	return reconstitutedKey;
	
}


std::vector<BYTE> TPMWrapper::s_RSA_encrypt(const std::vector<BYTE> & plaintext, TPMT_PUBLIC & reconstitutedKey)
{
	ciphertext = reconstitutedKey.outPublic.Encrypt(plaintext, NullVec);
	//cout << "Encrypted ciphertext: " << ciphertext << endl;

	return ciphertext;
}


void TPMWrapper::Announce(const char *testName)
{
	SetCol(0);
	cout << flush;
	cout << "================================================================================" << endl << flush;
	cout << "          " << testName << endl << flush;
	cout << "================================================================================" << endl << flush;
	cout << flush;
	SetCol(1);
}

void TPMWrapper::RecoverFromLockout()
{
	device->PowerOff();
	device->PowerOn();
	tpm.Startup(TPM_SU::CLEAR);

	// Clear out any persistent ownerAuth
	tpm.Clear(tpm._AdminPlatform);
	tpm.Shutdown(TPM_SU::CLEAR);

	return;
}