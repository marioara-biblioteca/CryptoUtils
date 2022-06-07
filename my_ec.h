#pragma once
#include "openssl/evp.h"

void create_EC_key(const char* keyPrivatefilename, const char* keyPublickfilename);

void generate_ecdh_keys_Curve25519(unsigned char** pub, int& pubLen, EVP_PKEY** pkey);
void keys_exchange(const char* ecPrivateKeyFilename, const char* ecPubKeyFilename, unsigned char** skey, int& skeyLen);

//void generate_ECDSA_signature(EC_KEY* privatKey, unsigned char* message, int msgLen, unsigned char** signature);
//int verify_ECDSA_signature(EC_KEY* pubicKey, unsigned char* signature, int sigLen, unsigned char* message, int msgLen);

int generate_ECDSA_signature(const unsigned char* message, int msgLen, unsigned char** signature,
    unsigned int&sigLen, EC_KEY* eckey);
int verify_ECDSA_signature(const unsigned char* msg, int msgLen,
    const unsigned char* sigbuf, int sig_len, EC_KEY* eckey);