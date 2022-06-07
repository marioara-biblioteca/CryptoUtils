#include <openssl/evp.h>
#include "utils.h"
#include "my_aes.h"

int aes_encrypt(unsigned char* plaintext, int plainLen, unsigned char* key, unsigned char* iv,
    unsigned char** ciphertext,int &cipherLen)
{
    EVP_CIPHER_CTX* ctx;
    const EVP_CIPHER* cipher = EVP_aes_256_cfb();
    (*ciphertext) = new unsigned char[plainLen];
    int lenUpdate, lenFinal;
    if (!(ctx = EVP_CIPHER_CTX_new())) return ERR_MEM;
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) return ERR_MEM;
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &lenUpdate, plaintext, plainLen)) return ERR_MEM;
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + lenUpdate, &lenFinal)) return ERR_MEM;
    cipherLen = lenUpdate + lenFinal;
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
int aes_decrypt(unsigned char* ciphertext, int cipherLen, unsigned char* key,
    unsigned char* iv, unsigned char** plaintext, int& plainLen)
{
    EVP_CIPHER_CTX* ctx;

    int lenUpdate, lenFinal;
    const EVP_CIPHER* cipher = EVP_aes_256_cfb();
    (*plaintext) = new unsigned char[cipherLen];
    if (!(ctx = EVP_CIPHER_CTX_new())) return ERR_MEM;
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))  return ERR_MEM;

    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &lenUpdate, ciphertext, cipherLen)) return ERR_MEM;
    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + lenUpdate, &lenFinal)) return ERR_MEM;
     plainLen = lenFinal + lenUpdate;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}