#ifndef TPMWRAPPER_H
#define TPMWRAPPER_H
#pragma once

#include <vector>
#include <iostream>
#include <map>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <cstdio>
#include <iostream>
#include <vector>
#include <iterator>
#include <cassert>
#include <fstream>
#include <utility>

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

	void SetCol(unsigned int col);

	std::pair<TSS_KEY, TPM_HANDLE> c_genKeys(); 
	std::vector<BYTE> c_RSA_decrypt(TPM_HANDLE & handle, const std::vector<BYTE> & ciphertext);

	TSS_KEY s_importKey(const std::vector<BYTE> & keyVec);
	std::vector<BYTE> s_RSA_encrypt(TSS_KEY & key, const std::vector<BYTE> & message);
	   	
protected:

	void Announce(const char *testName);
	void RecoverFromLockout();

	bool initialized;

	std::vector<BYTE> NullVec;
	_TPMCPP Tpm2 tpm;
	_TPMCPP TpmTcpDevice *device;

	std::map<_TPMCPP TPM_CC, int> commandsInvoked;
	std::map<_TPMCPP TPM_RC, int> responses;
	std::vector<_TPMCPP TPM_CC> commandsImplemented;

	//Monotonic counter memory
	TPM_HANDLE nvHandle;
};

std::pair<TSS_KEY, TPM_HANDLE> TPMWrapper::c_genKeys() {
	if (!initialized) {
		throw std::logic_error("c_genKeys called without a TPM connection!");
	}
	//Create key template
	TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::decrypt |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec,  // No policy
		TPMS_RSA_PARMS(
			TPMT_SYM_DEF_OBJECT::NullObject(),
			TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
		TPM2B_PUBLIC_KEY_RSA(NullVec));
	//Create software key
	TSS_KEY k;
	k.publicPart = templ;
	k.CreateKey();
	//Load key into TPM and get back the handle
	TPMT_SENSITIVE s(NullVec, NullVec, TPM2B_PRIVATE_KEY_RSA(k.privatePart));
	TPM_HANDLE h = tpm.LoadExternal(s, k.publicPart, TPM_HANDLE::FromReservedHandle(TPM_RH::_NULL));
	return std::pair<TSS_KEY, TPM_HANDLE>(k, h);
}
//Will fail if key is not properly initialized
std::vector<BYTE> TPMWrapper::c_RSA_decrypt(TPM_HANDLE & handle, const std::vector<BYTE> & ciphertext) {
	if (!initialized) {
		throw std::logic_error("c_RSA_decrypt called without a TPM connection!");
	}
	return tpm.RSA_Decrypt(handle, ciphertext, TPMS_NULL_ASYM_SCHEME(), NullVec);
}

TSS_KEY TPMWrapper::s_importKey(const std::vector<BYTE> & keyVec) {
	TSS_KEY k;
	k.FromBuf(keyVec);
	return k;
}
//Will fail if key is not properly initialized
std::vector<BYTE> TPMWrapper::s_RSA_encrypt(TSS_KEY & key, const std::vector<BYTE> & message) {
	return key.publicPart.Encrypt(message, NullVec);
}

bool TPMWrapper::init(unsigned int port) {

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
		// REVISIT(?)
		delete device;
		device = nullptr;
	}
	initialized = false;
	return true;
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

TPMWrapper::TPMWrapper()
{
	initialized = false;
	device = nullptr;
}

TPMWrapper::~TPMWrapper() {
	stop();
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

