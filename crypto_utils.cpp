#pragma warning(disable : 4996)
#include "crypto_utils.h"
#include "utils.h"
#include <openssl/evp.h>
#include "openssl/rand.h"
#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include<openssl/pem.h>
					//cheia secreta derivata dupa relizarea cu succes a schimbului de chei ECDH si verificarea autenticitatii cheilor publice 
void generate_PBKDF2(unsigned char* password, int passLen,unsigned char**AESkey, unsigned char**iv)
{
	unsigned char out [_AES256_KEY_LEN + _IV_LENGTH];
	unsigned char salt[_SALT_LENGTH];
	memset(salt, 0x55, _SALT_LENGTH);
	//Salt-ul oferit funcTiei PKDF2 este format din o serie de octeti cu urmatoarea constructie: numele si prenumele celui/celei care implementeaza aplicatia, 
	//urmate de un padding cu valoarea 0x55 pana la lungimea de 100 de octeti
	unsigned char* name = nullptr, * surname = nullptr;
	int nameLen, surnameLen;
	printf("Introduceti numele: ");
	read_input(nameLen, &name);
	printf("Introduceti prenumele: ");
	read_input(surnameLen, &surname);
	memcpy(salt, name, nameLen);
	memcpy(salt + nameLen, surname, surnameLen);
	int status = PKCS5_PBKDF2_HMAC((const char*)password, passLen, salt, _SALT_LENGTH, 1024, EVP_sha384(), _AES256_KEY_LEN + _IV_LENGTH, out);
	if (!status) {
		printf("Error in generating PBKDF2\n");
		return;
	}
    *AESkey = new unsigned char[_AES256_KEY_LEN];
    *iv = new unsigned char[_IV_LENGTH];
	memcpy(*AESkey, out, _AES256_KEY_LEN);
	memcpy(*iv, out + _AES256_KEY_LEN, _IV_LENGTH);
}
void hash_sha256(unsigned char *in,int inLen,unsigned char**out)
{
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	*out = new unsigned char[32];
	*out = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
	EVP_DigestUpdate(ctx, in, inLen);
	EVP_DigestFinal_ex(ctx, *out, NULL);
	EVP_MD_CTX_free(ctx);
}

void save_to_file(const char* keyPrivatefilename, const char* keyPublickfilename, EVP_PKEY* privKey)
{

    FILE* privateFp = fopen(keyPrivatefilename, "w");
    PEM_write_PrivateKey(privateFp, privKey, NULL, NULL, 0, NULL, NULL);
    fclose(privateFp);

    FILE* publickFp = fopen(keyPublickfilename, "w");
    PEM_write_PUBKEY(publickFp, privKey);
    fclose(publickFp);
}
void save_to_file_EC(const char* keyPrivatefilename, const char* keyPublickfilename, EC_KEY* privKey)
{

    FILE* privateFp = fopen(keyPrivatefilename, "w");
    PEM_write_ECPrivateKey(privateFp, privKey, NULL, NULL, 0, NULL, NULL);
    fclose(privateFp);

    FILE* publickFp = fopen(keyPublickfilename, "w");
    PEM_write_EC_PUBKEY(publickFp, privKey);
    fclose(publickFp);
}

void read_public_key(const char* filename, EVP_PKEY** pubKey) {
    FILE* fp = fopen(filename, "r");

    if (fp == NULL) {
        fprintf(stderr, "Null Pointer for %s file\n", filename);
        return;
    }

    PEM_read_PUBKEY(fp, pubKey, NULL, NULL);
    if ((*pubKey) == NULL) {
        fprintf(stderr, "Error on PEM_read_EC_PUBKEY\n");
        return;
    }
    fclose(fp);
}
void read_public_key_EC(const char* filename, EC_KEY** pubKey) {
    FILE* fp = fopen(filename, "r");

    if (fp == NULL) {
        fprintf(stderr, "Null Pointer for %s file\n", filename);
        return;
    }

    PEM_read_EC_PUBKEY(fp, pubKey, NULL, NULL);
    if ((*pubKey) == NULL) {
        printf("Error on PEM_read_EC_PUBKEY\n");
        return;
    }
    fclose(fp);
}

void read_private_key(const char* filename, EVP_PKEY** privateKey) {
    FILE* fp = fopen(filename, "r");

    if (fp == NULL) {
        fprintf(stderr, "Null Pointer for %s file\n", filename);
        return;
    }

    PEM_read_PrivateKey(fp, privateKey, NULL, NULL);
    if ((*privateKey) == NULL) {
        fprintf(stderr, "Error on PEM_read_ECPrivateKey\n");
        return;
    }
    fclose(fp);
}
void read_private_key_EC(const char* filename, EC_KEY** privateKey) {
    FILE* fp = fopen(filename, "r");

    if (fp == NULL) {
        fprintf(stderr, "Null Pointer for %s file\n", filename);
        return;
    }

    PEM_read_ECPrivateKey(fp, privateKey, NULL, NULL);
    if ((*privateKey) == NULL) {
        fprintf(stderr, "Error on PEM_read_ECPrivateKey\n");
        return;
    }
    fclose(fp);
}
    //verificarea proprietatii schimbului de chei DJH
int shared_key_check(unsigned char * exchangedKey1,unsigned char* exchangedKey2,int len1,int len2) {
    if (len1 == len2) {
        if (memcmp(exchangedKey1, exchangedKey2, len1) == 0)
            return 1;
    }
    return 0;
}