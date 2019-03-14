	#include "stdafx.h"
	#include "Samples.h"
	

	// The following macro checks that the sample did not leave any keys in the TPM.
	#define _check AssertNoLoadedKeys();
	

	void RunSamples();
	

	Samples::Samples()
	{
	    RunSamples();
	
		// Create a TpmDevice object and attach it to the TPM. Here we
		// attach to a TPM simulator process running on the same host.
	    device = new TpmTcpDevice("127.0.0.1", 2321);
	

	    if (!device->Connect()) {
	        throw runtime_error("Could not connect to TPM device.");
	    }
	

	    tpm._SetDevice(*device);
	

	    // The rest of this routine brings up the simulator.  This is generally not
	    // needed for a "real" TPM.
	    // If the simulator is not shut down cleanly (e.g. because the test app crashed)
	    // this is called a "disorderly shutdown" and the TPM goes into lockout.  The
	    // following routine will recover the TPM. This is optional.
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
	    Callback2();
	}

	
	void Samples::RunAllSamples()
{
    _check
	MPC_TPM();

	//****************************************************************************************
	//Our MPC_TPM can be mostly based off of the four functions RsaEncryptDecrypt(),
    //PrimaryKeys(), SoftwareKeys(), and EncryptDecryptSample() and partially off NV(),
	//PolicySimplest(), PolicyPCRSample(), Attestation(), PolicyCpHash(), SessionEncryption();
	// and ImportDuplicate().
    //****************************************************************************************
	
/*
    RsaEncryptDecrypt();
	PrimaryKeys();
    SoftwareKeys();   
    EncryptDecryptSample();
    _check;


	
    NV();
    PolicySimplest();
    PolicyPCRSample();
    Attestation();
    PolicyCpHash();
    SessionEncryption();
    ImportDuplicate();
*/	
    Callback2();
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


void Samples::Callback1()
{
    Announce("Installing callback");


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

void Samples::MPC_TPM()
{
	Announce("MPC_TPM");
	
	
	// Initialize the counter NV-slot.
    int nvIndex = 1000;
	
	//5 is the number of times we may increment before losing access to the key.
    ByteVec nvAuth { 1, 5, 1, 1 };
    TPM_HANDLE nvHandle = TPM_HANDLE::NVHandle(nvIndex);


    // Try to delete the slot if it exists
    tpm._AllowErrors().NV_UndefineSpace(tpm._AdminOwner, nvHandle);


    // Create Counter NV-slot
    TPMS_NV_PUBLIC nvTemplate2(nvHandle,            // Index handle
                               TPM_ALG_ID::SHA256,  // Name-alg
                               TPMA_NV::AUTHREAD  | // Attributes
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
	

    // To create a primary key the TPM must be provided with a template.
    // This is for an RSA1024 encryption key.
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


    TPM_HANDLE& keyHandle = storagePrimary.objectHandle;


	//Create data to test encryption 
    ByteVec dataToEncrypt = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA1, "secret").digest;
    cout << "Data to encrypt: " << dataToEncrypt << endl;

	//Test encryption/decryption operations
    auto enc = tpm.RSA_Encrypt(keyHandle, dataToEncrypt, TPMS_NULL_ASYM_SCHEME(), NullVec);
    cout << "RSA-encrypted data: " << enc << endl;
    
	auto dec = tpm.RSA_Decrypt(keyHandle, enc, TPMS_NULL_ASYM_SCHEME(), NullVec);
    cout << "decrypted data: " << dec << endl;


    if (dec == dataToEncrypt) {
        cout << "Decryption worked" << endl;
    }


    _ASSERT(dataToEncrypt == dec);


    // Make an AES key
    TPMT_PUBLIC inPublic(TPM_ALG_ID::SHA256,
						 TPMA_OBJECT::decrypt | 
                         TPMA_OBJECT::sensitiveDataOrigin | 
                         TPMA_OBJECT::userWithAuth,
                         NullVec,
                         TPMS_SYMCIPHER_PARMS(
                             TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB)),
                         TPM2B_DIGEST_Symcipher());


    auto aesKey = tpm.Create(prim, 
                             TPMS_SENSITIVE_CREATE(NullVec, NullVec),
                             inPublic, 
                             NullVec,
                             vector<TPMS_PCR_SELECTION>());


    TPM_HANDLE aesHandle = tpm.Load(prim, aesKey.outPrivate, aesKey.outPublic);


	//Create data to test AES encryption
    ByteVec toEncrypt { 1, 2, 3, 4, 5, 4, 3, 2, 12, 3, 4, 5 };
    ByteVec iv(16);


    auto encrypted = tpm.EncryptDecrypt(aesHandle, (BYTE)0, TPM_ALG_ID::CFB, iv, toEncrypt);
    auto decrypted = tpm.EncryptDecrypt(aesHandle, (BYTE)1, TPM_ALG_ID::CFB, iv, encrypted.outData);


    cout << "AES encryption" << endl <<
            "in:  " << toEncrypt << endl <<
            "enc: " << encrypted.outData << endl <<
            "dec: " << decrypted.outData << endl;


    _ASSERT(decrypted.outData == toEncrypt);


    //tpm.FlushContext(prim);
    //tpm.FlushContext(aesHandle);


    // We can put the primary key into NV with EvictControl
    TPM_HANDLE persistentHandle = TPM_HANDLE::PersistentHandle(1000);


    // First delete anything that might already be there
    tpm._AllowErrors().EvictControl(tpm._AdminOwner, persistentHandle, persistentHandle);


    // Make our primary persistent
    tpm.EvictControl(tpm._AdminOwner, newPrimary.objectHandle, persistentHandle);


    // Flush the old one
    tpm.FlushContext(newPrimary.objectHandle);


    // ReadPublic of the new persistent one
    auto persistentPub = tpm.ReadPublic(persistentHandle);
    cout << "Public part of persistent primary" << endl << persistentPub.ToString(false);

	
    // And delete it
    //tpm.EvictControl(tpm._AdminOwner, persistentHandle, persistentHandle);

	
	// Now encrypt something with the rsa key using padding
    ByteVec pad { 1, 2, 3, 4, 5, 6, 0 };
    enc = storagePrimary.outPublic.Encrypt(mySecret, pad);
    dec = tpm.RSA_Decrypt(keyHandle, enc, TPMS_NULL_ASYM_SCHEME(), pad);
    cout << "My           secret: " << mySecret << endl;
    cout << "My decrypted secret: " << dec << endl;


    _ASSERT(mySecret == dec);
	
	



    // Should now be able to read key from NV-index
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
    //tpm.NV_UndefineSpace(tpm._AdminOwner, nvHandle);
	
	
	return;
}






















































/*
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


    TPM_HANDLE& keyHandle = storagePrimary.objectHandle;


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
    ByteVec pad { 1, 2, 3, 4, 5, 6, 0 };
    enc = storagePrimary.outPublic.Encrypt(mySecret, pad);
    dec = tpm.RSA_Decrypt(keyHandle, enc, TPMS_NULL_ASYM_SCHEME(), pad);
    cout << "My           secret: " << mySecret << endl;
    cout << "My decrypted secret: " << dec << endl;


    _ASSERT(mySecret == dec);


    tpm.FlushContext(keyHandle);


    return;
}
*/

















/*
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
    ByteVec userAuth = ByteVec { 1, 2, 3, 4 };
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
    cout << "New RSA primary key" << endl << newPrimary.outPublic.ToString(false) << endl;


    cout << "Name of new key:" << endl;
    cout << " Returned by TPM " << newPrimary.name << endl;
    cout << " Calculated      " << newPrimary.outPublic.GetName() << endl;
    cout << " Set in handle   " << newPrimary.objectHandle.GetName() << endl;
    _ASSERT(newPrimary.name == newPrimary.outPublic.GetName());


    // Sign something with the new key.  First set the auth-value in the handle
    TPM_HANDLE& signKey = newPrimary.objectHandle;
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
    tpm.EvictControl(tpm._AdminOwner, newPrimary.objectHandle, persistentHandle);


    // Flush the old one
    tpm.FlushContext(newPrimary.objectHandle);


    // ReadPublic of the new persistent one
    auto persistentPub = tpm.ReadPublic(persistentHandle);
    cout << "Public part of persistent primary" << endl << persistentPub.ToString(false);


    // And delete it
    tpm.EvictControl(tpm._AdminOwner, persistentHandle, persistentHandle);


    return;
}
*/
















/*
void Samples::SoftwareKeys()
{
    Announce("SoftwareKeys");


    // This sample illustrates various forms of import of externally created keys, 
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
}
*/






























/*
void Samples::EncryptDecryptSample()
{
    Announce("EncryptDecryptSample");


    TPM_HANDLE prim = MakeStoragePrimary();


    // Make an AES key
    TPMT_PUBLIC inPublic(TPM_ALG_ID::SHA256,
						 TPMA_OBJECT::decrypt | TPMA_OBJECT::sign |
                         TPMA_OBJECT::sensitiveDataOrigin | 
                         TPMA_OBJECT::userWithAuth,
                         NullVec,
                         TPMS_SYMCIPHER_PARMS(
                             TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB)),
                         TPM2B_DIGEST_Symcipher());


    auto aesKey = tpm.Create(prim, 
                             TPMS_SENSITIVE_CREATE(NullVec, NullVec),
                             inPublic, 
                             NullVec,
                             vector<TPMS_PCR_SELECTION>());


    TPM_HANDLE aesHandle = tpm.Load(prim, aesKey.outPrivate, aesKey.outPublic);


    ByteVec toEncrypt { 1, 2, 3, 4, 5, 4, 3, 2, 12, 3, 4, 5 };
    ByteVec iv(16);


    auto encrypted = tpm.EncryptDecrypt(aesHandle, (BYTE)0, TPM_ALG_ID::CFB, iv, toEncrypt);
    auto decrypted = tpm.EncryptDecrypt(aesHandle, (BYTE)1, TPM_ALG_ID::CFB, iv, encrypted.outData);


    cout << "AES encryption" << endl <<
            "in:  " << toEncrypt << endl <<
            "enc: " << encrypted.outData << endl <<
            "dec: " << decrypted.outData << endl;


    _ASSERT(decrypted.outData == toEncrypt);


    tpm.FlushContext(prim);
    tpm.FlushContext(aesHandle);


    return;
}
*/



















/*	void Samples::NV()
{
    Announce("NV");


    // Several types of NV-slot use are demonstrated here, but we only display counter.

    int nvIndex = 1000;
    ByteVec nvAuth { 1, 5, 1, 1 };
    TPM_HANDLE nvHandle = TPM_HANDLE::NVHandle(nvIndex);


    // Try to delete the slot if it exists
    tpm._AllowErrors().NV_UndefineSpace(tpm._AdminOwner, nvHandle);


    // CASE 2 - Counter NV-slot
    TPMS_NV_PUBLIC nvTemplate2(nvHandle,            // Index handle
                               TPM_ALG_ID::SHA256,  // Name-alg
                               TPMA_NV::AUTHREAD  | // Attributes
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


    return;
}
*/

/*	
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
*/
	
	
	
	
	
/*	
void Samples::PolicyPCRSample()
{
    Announce("PolicyPCR");


    // In this sample we show the use of PolicyPcr


    // First set a PCR to a value
    TPM_ALG_ID bank = TPM_ALG_ID::SHA1;
    UINT32 pcr = 15;   


    tpm.PCR_Event(TPM_HANDLE::PcrHandle(pcr), ByteVec { 1, 2, 3, 4 });


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
    tpm.PCR_Event(TPM_HANDLE::PcrHandle(pcr), ByteVec { 1, 2, 3, 4 });
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
*/
	
	
	
	
	
	
	
	
	
	
	
	
/*
	
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
    tpm.PCR_Event(TPM_HANDLE::PcrHandle(7), ByteVec { 1, 2, 3 });


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
    tpm.PCR_Event(TPM_HANDLE::PcrHandle(7), ByteVec { 1, 2, 3 });
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
    ByteVec nonce { 5, 6, 7 };
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
    ByteVec nvAuth { 1, 5, 1, 1 };
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
    ByteVec toWrite { 1, 2, 3, 4, 5, 4, 3, 2, 1 };
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
*/


	
	
	
/*
	
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
*/

/*

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


    ByteVec stirValue { 1, 1, 1, 1, 1, 1, 1, 1 };


    // Simplest use of parm encryption - the stirValue buffer will be encrypted
    // Note: because the nonces are transferred in plaintext and because this example
    // does not use a secret auth-value, a MiM could decrypt (but it shows how parm
    // encryption is enabled in TSS.C++.
    tpm._Sessions(sess).StirRandom(stirValue);


    // A bit more complicated: here we set the ownerAuth using parm-encrytion
    ByteVec newOwnerAuth { 0, 1, 2, 3, 4, 5, 6 };
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




*/

/*
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
    ByteVec swKeyAuthValue { 4, 5, 4, 5 };


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
	
*/
