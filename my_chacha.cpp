#include "my_chacha.h"
#include "utils.h"

#include"openssl/evp.h"


int encryptCHACHA(unsigned char* data, int dataLen, unsigned char* key, int& encLen, unsigned char** encData, unsigned char** tag)
{
	//default iv size chacha20
	unsigned char iv[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv);

	(*encData) = new unsigned char[dataLen];
	if (!(*encData)) return ERR_MEM;
	int lenUpdate, lenFinal;
	EVP_EncryptUpdate(ctx, (*encData), &lenUpdate, data, dataLen);
	EVP_EncryptFinal(ctx, (*encData) + lenUpdate, &lenFinal);
	(*tag) = new unsigned char[_TAG_LEN];
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, _TAG_LEN, (*tag)); //trebuie pus dupa encryptfinal
	encLen = lenUpdate + lenFinal;
	return 0;
}

int decryptCHACHA(unsigned char* encData, int encLen, unsigned char* key, int& dataLen, unsigned char** data, unsigned char** tag)
{
	unsigned char iv[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	int lenUpdate, lenFinal;
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv);
	unsigned char* check = new unsigned char[encLen];
	if (!check) return ERR_MEM;
	EVP_DecryptUpdate(ctx, check, &lenUpdate, encData, encLen);
	EVP_DecryptFinal(ctx, check + lenUpdate, &lenFinal);
	dataLen = lenUpdate + lenFinal;
	(*data) = new unsigned char[dataLen];
	(*tag) = new unsigned char[_TAG_LEN];
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, _TAG_LEN, (*tag)); //trebuie pus dupa encryptfinal
	memcpy((*data), check, dataLen);
	return 0;
}

int generate_CHACHA_key(const char* fname)
{
	unsigned short  start_state = 0xACE1u;
	unsigned char* key = new unsigned char[_CHACHA20_KEY_LENGTH];
	unsigned short seed = generate_seed(start_state);
	srand(seed);
	for (int i = 0; i < _CHACHA20_KEY_LENGTH; i++) {
		key[i] = rand() % 256;
		if (key[i] == '\n' || key[i] == '\r')
			key[i] = rand() % 256;
	}
	//salva in format TLV
	auto asn1String = ASN1_OCTET_STRING_new();
	ASN1_STRING_set(asn1String, key, _CHACHA20_KEY_LENGTH);
	return save_in_pem_format(fname, asn1String->data, asn1String->length, "KEY STREAM");

}