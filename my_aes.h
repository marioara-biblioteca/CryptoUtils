#pragma once
int aes_encrypt(unsigned char* plaintext, int plainLen, unsigned char* key, unsigned char* iv,
    unsigned char** ciphertext,int&cipherLen);
int aes_decrypt(unsigned char* ciphertext, int cipherLen, unsigned char* key,
    unsigned char* iv, unsigned char** plaintext, int& plainLen);