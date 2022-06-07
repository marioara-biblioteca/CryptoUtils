#pragma once
#include "openssl/evp.h"
#define _AES256_KEY_LEN	32
#define _IV_LENGTH		16
#define	_SALT_LENGTH	100

void generate_PBKDF2(unsigned char* password, int passLen, unsigned char** AESkey, unsigned char** iv);
void hash_sha256(unsigned char* in, int inLen, unsigned char** out);

void read_public_key(const char* filename, EVP_PKEY** pubKey);
void read_private_key(const char* filename, EVP_PKEY** privatKey);

void read_private_key_EC(const char* filename, EC_KEY** privateKey);
void read_public_key_EC(const char* filename, EC_KEY** pubKey);

void save_to_file(const char* keyPrivatefilename, const char* keyPublickfilename, EVP_PKEY* privKey);
void save_to_file_EC(const char* keyPrivatefilename, const char* keyPublickfilename, EC_KEY* privKey);

int shared_key_check(unsigned char* exchangedKey1, unsigned char* exchangedKey2, int len1, int len2);