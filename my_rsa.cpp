#include"my_rsa.h"

void generate_RSA_keypair(int bits, const char* pubFile, const char* privFile)
{
	RSA* rsaKey = RSA_new();
	BIGNUM* e = BN_new();
	BN_set_word(e, 65537);
	while (!RSA_generate_key_ex(rsaKey, bits, e, NULL)) {
		printf("trying again and again...\n");
	}
	FILE* fpub = fopen(pubFile, "wb");
	FILE* fpriv = fopen(privFile, "wb");
	PEM_write_RSAPrivateKey(fpriv, rsaKey, NULL, NULL, 0, NULL, NULL);
	PEM_write_RSA_PUBKEY(fpub, rsaKey);
	fclose(fpub);
	fclose(fpriv);
}
void read_rsa_keypair(const char* pubFile, const char* privFile,RSA** privKey, RSA** pubKey)
{
	FILE* fpub = fopen(pubFile, "rb");
	FILE* fpriv = fopen(privFile, "rb");

	(*privKey) = RSA_new();
	(*pubKey) = RSA_new();
	PEM_read_RSAPrivateKey(fpriv, privKey, NULL, NULL);
	PEM_read_RSA_PUBKEY(fpub, pubKey, NULL, NULL);
	if ((*pubKey) == NULL || (*privKey) == NULL) {
		printf("error reading from file\n");
		return;
	}
	fclose(fpub);
	fclose(fpriv);
}

void encrypt_rsa(RSA* destRsaPubKey, unsigned char* in,int inlen, unsigned char** out, int& outlen)
{
	(*out) = new unsigned char[RSA_size(destRsaPubKey)];
	memset((*out), 0, RSA_size(destRsaPubKey));
	int bytes_enc =RSA_public_encrypt(inlen, in, (*out), destRsaPubKey, RSA_PKCS1_PADDING);
	outlen = bytes_enc;
}

void decrypt_rsa(RSA* privRsaKey, unsigned char* in, int inlen, unsigned char** out, int& outlen)
{
	(*out) = new unsigned char[inlen];
	RSA_private_decrypt(inlen, in, *out, privRsaKey, RSA_PKCS1_PADDING);
}