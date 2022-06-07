void read_rsa_keypair(const char* pubFile, const char* privFile,RSA** privKey, RSA** pubKey);
void generate_RSA_keypair(int bits, const char* pubFile, const char* privFile);

void encrypt_rsa(RSA* destRsaPubKey, unsigned char* in,int inlen, unsigned char** out, int& outlen);
void decrypt_rsa(RSA* privRsaKey, unsigned char* in, int inlen, unsigned char** out, int& outlen);