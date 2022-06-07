
int encryptCHACHA(unsigned char* data, int dataLen, unsigned char* key, int& encLen, unsigned char** encData, unsigned char** tag);
int decryptCHACHA(unsigned char* encData, int encLen, unsigned char* key, int& dataLen, unsigned char** data, unsigned char** tag);
int generate_CHACHA_key(const char* fname);