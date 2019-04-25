#ifndef TPMWRAPPER_H
#define TPMWRAPPER_H
#pragma once

#include <vector>
#include <iostream>
#include <map>
#include <string>

//#include "Samples.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <cstdio>
#include <iostream>
//#include <modes.h>
//#include <aes.h>
#include "ShamirSecret.h"
#include <vector>
#include <iterator>
#include <cassert>
#include <fstream>
#include "utilities.h"
#include "RSA.h"



#ifdef WIN32
#include "stdafx.h"
#include "../Src/Tpm2.h"
#include <mpir.h>
#include <mpirxx.h>
#elif defined(__linux__)
#include "../tpm_src/Tpm2.h"
#include <gmp.h>
#include <gmpxx.h>
#endif

using namespace TpmCpp;

class TPMWrapper {
public:
	TPMWrapper();
	~TPMWrapper();
	Tpm2 & GetTpm() {
		return tpm;
	}

	bool init(unsigned int port = 2321);
	bool stop();

	void RunTests();

	void SetCol(unsigned int col);

	//Server functions
	CreatePrimaryResponse s_readKeyFromFile(const std::string & filename);
	CreatePrimaryResponse s_readKey(const std::string & keystring);
	CreatePrimaryResponse s_readKey(const std::vector<BYTE> & keyvec);
	std::vector<BYTE> s_RSA_encrypt(const std::vector<BYTE> & plaintext, CreatePrimaryResponse & reconstitutedKey);

	//Client functions
	void c_createAndStoreKey();
	bool c_writeKeyToFile(const std::string & filename);
	std::string c_writeKey();
	std::vector<BYTE> c_RSA_decrypt(const std::vector<BYTE> & ciphertext, uint16_t key_limit);

protected:

	void Announce(const char *testName);
	void RecoverFromLockout();
	//TPM_HANDLE MakeStoragePrimary();
	//void TPMWrapper::Callback1();


	bool initialized;

	std::vector<BYTE> NullVec;
	_TPMCPP Tpm2 tpm;
	_TPMCPP TpmTcpDevice *device;

	std::map<_TPMCPP TPM_CC, int> commandsInvoked;
	std::map<_TPMCPP TPM_RC, int> responses;
	std::vector<_TPMCPP TPM_CC> commandsImplemented;

	//Deviate
	CreatePrimaryResponse storagePrimary;
	TPM_HANDLE nvHandle;

};

/*
mpz_class ByteVecToMPZ(const std::vector<BYTE> & v) {
	mpz_class mcand = 1;
	mpz_class result = 0;
	for (const auto & c : v) {
		result += mcand * c;
		//Shift left by 8 bits
		mpz_mul_2exp(mcand.get_mpz_t(), mcand.get_mpz_t(), 8);
	}
	return result;
}
*/

bool TPMWrapper::init(unsigned int port) {
	//RunSamples();

	device = new TpmTcpDevice("127.0.0.1", port);

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
	//Callback1();

	// Startup the TPM
	tpm.Startup(TPM_SU::CLEAR);

	return initialized = true;
}



bool TPMWrapper::stop() {
	// A clean shutdown results in fewer lockout errors.

	if (initialized) {
		tpm.Shutdown(TPM_SU::CLEAR);
		device->PowerOff();

		// REVISIT 
		delete device;
		device = nullptr;
	}

	return true;

	// The following routine finalizes and prints the function stats.
	//Callback2();

	// REVISIT 
	// delete device;
}



void TPMWrapper::SetCol(unsigned int c)
{
#ifdef WIN32
	UINT16 col = c;
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

void TPMWrapper::RunTests() {}

TPMWrapper::TPMWrapper()
{
	initialized = false;
	device = nullptr;
}

TPMWrapper::~TPMWrapper() {
	stop();
}
/*
void TPMWrapper::Callback1() {
	//Announce("Installing callback");

	// Install a callback that is invoked after the TPM command has been executed
	tpm._SetResponseCallback(&TPMWrapper::TpmCallbackStatic, this);
}
*/

void TPMWrapper::c_createAndStoreKey()
{
	Announce("MPC_TPM");

	TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::decrypt |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec,
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT::NullObject(),
			TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	CreatePrimaryResponse storagePrimary = tpm.CreatePrimary(
		TPM_HANDLE::FromReservedHandle(TPM_RH::_NULL),
		TPMS_SENSITIVE_CREATE(NullVec, NullVec),
		storagePrimaryTemplate,
		NullVec,
		vector<TPMS_PCR_SELECTION>());

	TPM_HANDLE& keyHandle = storagePrimary.handle;
	auto storagePrimaryPublic = tpm.ReadPublic(keyHandle);

	PolicyTree p(PolicyCommandCode(TPM_CC::Duplicate, ""));
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

	TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::decrypt |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth |
		TPMA_OBJECT::adminWithPolicy,
		policyDigest.digest,
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
			TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));

	CreateResponse childKey = tpm.Create(keyHandle,
		TPMS_SENSITIVE_CREATE(NullVec, NullVec),
		templ,
		NullVec, vector<TPMS_PCR_SELECTION>());
	// Load the key
	TPM_HANDLE childKeyHandle = tpm.Load(keyHandle, childKey.outPrivate, childKey.outPublic);

	// Start and then execute the session
	AUTH_SESSION session = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, session);

	// Keys can be duplicated in plaintext or with a symmetric wrapper, or with a symmetric
	// wrapper and encrypted to a loaded public key. The simplest: export (duplicate) it
	// specifying no encryption.
	auto duplicatedKey = tpm._Sessions(session).Duplicate(childKeyHandle,
		TPM_HANDLE::NullHandle(),
		NullVec,
		TPMT_SYM_DEF_OBJECT::NullObject());

	cout << "Duplicated private key:" << duplicatedKey.ToString(false);









	// Now try to import it (to the same parent)
	auto importedPrivate = tpm.Import(keyHandle,
		NullVec,
		childKey.outPublic,
		duplicatedKey.duplicate,
		NullVec,
		TPMT_SYM_DEF_OBJECT::NullObject());

	// And now show that we can load and and use the imported blob
	TPM_HANDLE importedSigningKey = tpm.Load(storagePrimaryHandle,
		importedPrivate,
		newSigningKey.outPublic);

	
	//Encrypt and Decrypt

	cout << "Signature with imported key: " << signature.ToString(false) << endl;


	/*
	TSS_KEY importableKey;
	importableKey.publicPart = swKeyDef;
	importableKey.CreateKey();
	ByteVec swKeyAuthValue{ 4, 5, 4, 5 };
	*/














	/*

	int nvIndex = 1000;
	ByteVec nvAuth{ 1, 5, 1, 1 };
	nvHandle = TPM_HANDLE::NVHandle(nvIndex);

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
	*/

}

bool TPMWrapper::c_writeKeyToFile(const std::string & filename)
{

	// Next a full key (pub + prov)
	std::string keyContainer = storagePrimary.Serialize(SerializationType::JSON);

	std::ofstream outfile(filename, ios::out | ios::binary);

	outfile << keyContainer;
	outfile.close();

	return true;
}

//Overwrites its input
std::string TPMWrapper::c_writeKey() {
	//return storagePrimary.Serialize(SerializationType::JSON);
	return storagePrimary.outPublic.ToString();
}

std::vector<BYTE> TPMWrapper::c_RSA_decrypt(const std::vector<BYTE> & ciphertext, uint16_t key_limit)
{

	if (!initialized) {
		throw std::logic_error("Wrapper not properly initialized");
	}


	ByteVec plaintext;
	TPM_HANDLE& keyHandle = storagePrimary.handle;
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
	mpz_class new_value = ByteVecToMPZ(afterIncrement);

	if (new_value >= key_limit) {
		tpm.FlushContext(keyHandle);
		//cout << endl << "Flushed Key After Monotonic Counter Incremented" << endl << endl;

		// And then delete it
		tpm.NV_UndefineSpace(tpm._AdminOwner, nvHandle);

	}

	return plaintext;
}


CreatePrimaryResponse TPMWrapper::s_readKeyFromFile(const std::string & filename)
{
	//Assumes the key is all stored on a single line of the file
	std::string rsa_key;
	std::ifstream infile(filename);
	std::getline(infile, rsa_key);
	infile.close();

	CreatePrimaryResponse reconstitutedKey;
	reconstitutedKey.Deserialize(SerializationType::JSON, rsa_key);

	//TPM_HANDLE& keyHandle1 = reconstitutedKey.handle;

	//cout << "New RSA primary key" << endl << reconstitutedKey.outPublic.ToString() << endl;	
	//May need to return a different type
	return reconstitutedKey;
}

CreatePrimaryResponse TPMWrapper::s_readKey(const std::string & keystring) {
	
	// We will make a key in the "null hierarchy".
	/*TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::decrypt |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec,
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT::NullObject(),
			TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));
	
	CreatePrimaryResponse reconstitutedKey = tpm.CreatePrimary(
		TPM_HANDLE::FromReservedHandle(TPM_RH::_NULL),
		TPMS_SENSITIVE_CREATE(NullVec, NullVec),
		storagePrimaryTemplate,
		NullVec,
		vector<TPMS_PCR_SELECTION>());

	//reconstitutedKey.Deserialize(SerializationType::JSON, keystring);
	assert(reconstitutedKey.Deserialize(SerializationType::JSON, keystring));
	return reconstitutedKey;
}

CreatePrimaryResponse TPMWrapper::s_readKey(const std::vector<BYTE> & keyvec) {


	/*CreatePrimaryResponse reconstitutedKey;
	reconstitutedKey.outPublic.FromBuf(keyvec);
	return reconstitutedKey;*/

	// Import the key into a TSS_KEY. The privvate key is in a an encoded TPM2B_SENSITIVE.
	TPM2B_SENSITIVE sens;
	sens.FromBuf(dup.duplicate.buffer);

	// And the sensitive area is an RSA key in this case
	TPM2B_PRIVATE_KEY_RSA *rsaPriv = dynamic_cast<TPM2B_PRIVATE_KEY_RSA *>(sens.sensitiveArea.sensitive);

	// Put this in a TSS.C++ defined structure for convenience
	TSS_KEY swKey(keyBlob.outPublic, rsaPriv->buffer);

	// Now show that we can sign with the exported SW-key and validate the
	// signature with the pubkey in the TPM.
	TPMS_NULL_SIG_SCHEME nullScheme;
	SignResponse swSig2 = swKey.Sign(toSign, nullScheme);
	auto sigResponse = tpm.VerifySignature(h, toSign, *swSig2.signature);

	// Sign with the TPM key
	sig = tpm.Sign(h2, toSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK::NullTicket());

	// And validate with the SW-key (this only uses the public key, of course).
	swValidatedSig = k.publicPart.ValidateSignature(toSign, *sig.signature);

	if (swValidatedSig) {
		cout << "Key created in the TPM and then exported can sign (as expected)" << endl;
	}

	_ASSERT(swValidatedSig);

	// Now sign with the duplicate key and check that we can validate the
	// sig with the public key still in the TPM.
	auto swSig = k.Sign(toSign, TPMS_NULL_SIG_SCHEME());

	// Check the SW generated sig is validated with the SW verifier
	bool sigOk = k.publicPart.ValidateSignature(toSign, *swSig.signature);

	_ASSERT(sigOk);

	// And finally check that the key still in the TPM can validate the duplicated key sig
	auto sigVerify = tpm.VerifySignature(h2, toSign, *swSig.signature);


	//===================================
	//Taken from Software Keys Sample

	/*// This sample illustrates various forms of import of externally created keys, 
    // and export of a TPM key to TSS.c++ where it can be used for cryptography.

    // First make a software key, and show how it can be imported into the TPM and used.
    TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
                      TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth,
                      NullVec,  // No policy
                      TPMS_RSA_PARMS(
                          TPMT_SYM_DEF_OBJECT::NullObject(),
                          TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 1024, 65537),
                      TPM2B_PUBLIC_KEY_RSA(NullVec));

    TSS_KEY k;
    k.publicPart = templ;
    k.CreateKey();

    TPMT_SENSITIVE s(NullVec, NullVec, TPM2B_PRIVATE_KEY_RSA(k.privatePart));
    TPM_HANDLE h2 = tpm.LoadExternal(s, k.publicPart, TPM_HANDLE::FromReservedHandle(TPM_RH::_NULL));

    ByteVec toSign = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA1, "hello").digest;
    SignResponse sig = tpm.Sign(h2, toSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK::NullTicket());

    bool swValidatedSig = k.publicPart.ValidateSignature(toSign, *sig.signature);

    if (swValidatedSig) {
        cout << "External key imported into the TPM works for signing" << endl;
    }

    _ASSERT(swValidatedSig);

    // Next make an exportable key in the TPM and export it to a SW-key

    auto primHandle = MakeStoragePrimary();

    // Make a duplicatable signing key as a child. Note that duplication *requires* a policy session.
    PolicyTree p(PolicyCommandCode(TPM_CC::Duplicate, ""));
    TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

    // Change the attributes since we want the TPM to make the sensitve area
    templ.objectAttributes = TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin;
    templ.authPolicy = policyDigest.digest;
    CreateResponse keyBlob = tpm.Create(primHandle,
                                        TPMS_SENSITIVE_CREATE(),
                                        templ,
                                        NullVec,
                                        TPMS_PCR_SELECTION::NullSelectionArray());

    TPM_HANDLE h = tpm.Load(primHandle, keyBlob.outPrivate, keyBlob.outPublic);

    // Duplicate. Note we need a policy session.
    AUTH_SESSION session = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
    p.Execute(tpm, session);
    DuplicateResponse dup = tpm._Sessions(session).Duplicate(h, 
                                                             TPM_HANDLE::NullHandle(),
                                                             NullVec,
                                                             TPMT_SYM_DEF_OBJECT::NullObject());
    tpm.FlushContext(session);

    // Import the key into a TSS_KEY. The privvate key is in a an encoded TPM2B_SENSITIVE.
    TPM2B_SENSITIVE sens;
    sens.FromBuf(dup.duplicate.buffer);

    // And the sensitive area is an RSA key in this case
    TPM2B_PRIVATE_KEY_RSA *rsaPriv = dynamic_cast<TPM2B_PRIVATE_KEY_RSA *>(sens.sensitiveArea.sensitive);

    // Put this in a TSS.C++ defined structure for convenience
    TSS_KEY swKey(keyBlob.outPublic, rsaPriv->buffer);

    // Now show that we can sign with the exported SW-key and validate the
    // signature with the pubkey in the TPM.
    TPMS_NULL_SIG_SCHEME nullScheme;
    SignResponse swSig2 = swKey.Sign(toSign, nullScheme);
    auto sigResponse = tpm.VerifySignature(h, toSign, *swSig2.signature);

    // Sign with the TPM key
    sig = tpm.Sign(h2, toSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK::NullTicket());

    // And validate with the SW-key (this only uses the public key, of course).
    swValidatedSig = k.publicPart.ValidateSignature(toSign, *sig.signature);

    if (swValidatedSig) {
        cout << "Key created in the TPM and then exported can sign (as expected)" << endl;
    }

    _ASSERT(swValidatedSig);

    // Now sign with the duplicate key and check that we can validate the
    // sig with the public key still in the TPM.
    auto swSig = k.Sign(toSign, TPMS_NULL_SIG_SCHEME());

    // Check the SW generated sig is validated with the SW verifier
    bool sigOk = k.publicPart.ValidateSignature(toSign, *swSig.signature);

    _ASSERT(sigOk);

    // And finally check that the key still in the TPM can validate the duplicated key sig
    auto sigVerify = tpm.VerifySignature(h2, toSign, *swSig.signature);

    tpm.FlushContext(h);
    tpm.FlushContext(primHandle);
    tpm.FlushContext(h2);

    return;
}*/

	//===================================

}




std::vector<BYTE> TPMWrapper::s_RSA_encrypt(const std::vector<BYTE> & plaintext, CreatePrimaryResponse & reconstitutedKey)
{

	ByteVec ciphertext = reconstitutedKey.outPublic.Encrypt(plaintext, NullVec);
	//cout << "Encrypted ciphertext: " << ciphertext << endl;

	//auto ciphertext = tpm.RSA_Encrypt(reconstitutedKey.handle, plaintext, TPMS_NULL_ASYM_SCHEME(), NullVec);
	return ciphertext;
}


void TPMWrapper::Announce(const char *testName)
{
	//SetCol(0);
	cout << flush;
	cout << "================================================================================" << endl << flush;
	cout << "          " << testName << endl << flush;
	cout << "================================================================================" << endl << flush;
	cout << flush;
	//SetCol(1);
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

#endif

