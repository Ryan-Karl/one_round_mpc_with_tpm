#ifndef TPMWRAPPER_H
#define TPMWRAPPER_H
#pragma once

#include <vector>
#include <iostream>
#include <map>
#include <string>

using namespace TpmCpp;

class TPMWrapper{
public:
  TPMWrapper();
  ~TPMWrapper();
  Tpm2 & GetTpm() const {
    return tpm;
  }
  
  //Server functions
  bool s_readKeyFromFile(const std::string & filename);
  std::vector<BYTE> s_RSA_encrypt(const std::vector<BYTE> & plaintext);
  
  //Client functions
  bool c_createAndStoreKey();
  bool c_writeKeyToFile(const std::string & filename);
  std::vector<BYTE> c_RSA_decrypt(const std::vector<BYTE> & ciphertext);

protected:

void Announce(const char *testName);
void RecoverFromLockout();
TPM_HANDLE MakeStoragePrimary();
void TPMWrapper::Callback1();


vector<BYTE> NullVec;
_TPMCPP Tpm2 tpm;
_TPMCPP TpmTcpDevice *device;

std::map<_TPMCPP TPM_CC, int> commandsInvoked;
std::map<_TPMCPP TPM_RC, int> responses;
std::vector<_TPMCPP TPM_CC> commandsImplemented;

};



#endif
