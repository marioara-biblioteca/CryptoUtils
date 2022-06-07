#pragma warning(disable : 4996)
#include "my_ec.h"
#include "crypto_utils.h"
#include "utils.h"
#include <openssl/ec.h>
#include<openssl/pem.h>
#include <corecrt_memory.h>

void create_EC_key(const char* keyPrivatefilename, const char* keyPublickfilename)
{
    EC_KEY* key, * pubkey ;
    key = EC_KEY_new_by_curve_name(NID_secp256k1);
    int status = EC_KEY_generate_key(key);

    if (status != 1) {
        fprintf(stderr, "Generation Error Ocurs!\n");
        return;
    }
   
    save_to_file_EC(keyPrivatefilename, keyPublickfilename, key);

}

//aici generam cheia efemera in format raw si obtinem si cheia privata
void generate_ecdh_keys_Curve25519(unsigned char**pub,int &pubLen,EVP_PKEY**pkey)
{
    *pkey = NULL;
    size_t lenCurve25519;
    
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, pkey);
    EVP_PKEY_CTX_free(pctx);

    *pub = new unsigned char[32];
    EVP_PKEY_get_raw_public_key(*pkey, *pub, &lenCurve25519);
    EVP_PKEY* pubKEY = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, *pub, lenCurve25519); // Extragere componenta publica
    pubLen = lenCurve25519;
   
}
//schimb de chei
void keys_exchange(const char* ecPrivateKeyFilename, const char* ecPubKeyFilename,unsigned char**skey,int &skeyLen) {
    EVP_PKEY_CTX* ctx;
   
    size_t skeylen;
   
    EVP_PKEY* privKey = nullptr, * peerKey = nullptr;
    read_private_key(ecPrivateKeyFilename, &privKey);
    read_public_key(ecPubKeyFilename, &peerKey);
    ctx = EVP_PKEY_CTX_new(privKey, NULL); 

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peerKey);
    
    EVP_PKEY_derive(ctx, NULL, &skeylen);

    *skey = (unsigned char*)OPENSSL_malloc(skeylen);

    EVP_PKEY_derive(ctx, *skey, &skeylen);
    skeyLen = skeylen;
}


int generate_ECDSA_signature(const unsigned char* message, int msgLen, unsigned char** signature,
    unsigned int& sigLen, EC_KEY* eckey)
{
    unsigned char hash[32];
    SHA256(message, msgLen, hash);
    sigLen = ECDSA_size(eckey);
    *signature = new unsigned char[sigLen];
    //ECDSA_SIG* sig = ECDSA_do_sign(message, msgLen, eckey);
    int status= ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, *signature, &sigLen, eckey);
    
    return status;
}
int verify_ECDSA_signature(const unsigned char* message, int msgLen,
    const unsigned char* sigbuf, int sig_len, EC_KEY* eckey)
{
    ECDSA_SIG* s;
    unsigned char* der = NULL;
    const unsigned char* p = sigbuf;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL)
        return (ret);
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sigbuf, der, derlen))
        goto err;
    unsigned char hash[32];
    SHA256(message, msgLen, hash);
    ret = ECDSA_do_verify(message, msgLen, s, eckey);

err:
    
    ECDSA_SIG_free(s);
    return (ret);
}