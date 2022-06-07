#include "my_cert.h"


X509* generate_cert(const char*privRSAFile,unsigned char*C,unsigned char*O,unsigned char*CN) //crearea unui cerificat pe baza cheii key_ac.prv
{
	static int serialNumber=0;
	X509* cert = X509_new();
	RSA* rsaKey = RSA_new();
	EVP_PKEY* pkey = EVP_PKEY_new();
	FILE* f = fopen(privRSAFile, "rb");
	PEM_read_RSAPrivateKey(f, &rsaKey, NULL, NULL);
	fclose(f);
	if (!rsaKey) {
		printf("Couldnt read rsa key\n");
		return nullptr; 
	}
	EVP_PKEY_assign_RSA(pkey, rsaKey);
	if (!pkey) {
		printf("Couldnt assing rsa key to evp key\n");
		return nullptr;
	}
	ASN1_INTEGER_set(X509_get_serialNumber(cert), serialNumber++);
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_gmtime_adj(X509_get_notAfter
	(cert), 365 * 24 * 60 * 60);
	X509_set_pubkey(cert, pkey);
	X509_NAME* certName;
	certName = X509_get_subject_name(cert);

	X509_NAME_add_entry_by_txt(certName, "C", MBSTRING_ASC, C, -1, -1, 0);
	X509_NAME_add_entry_by_txt(certName, "O", MBSTRING_ASC, O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(certName, "CN", MBSTRING_ASC, CN, -1, -1, 0);

	X509_set_issuer_name(cert, certName);

	//semnarea certificaului cu prpria cheie, certificat self-signed
	X509_sign(cert, pkey, EVP_sha256());
	return cert;
}

void load_cert_to_file(X509*cert,const char*fname)
{
	BIO* bio = BIO_new_file(fname, "wb");
	PEM_write_bio_X509(bio, cert);
	BIO_free(bio);
}
void load_cert_from_file(const char*fname, X509**cert)
{
	(*cert) = X509_new();
	BIO* bio = BIO_new_file(fname, "rb");
	PEM_read_bio_X509(bio, cert, NULL, NULL);
	BIO_free(bio);
}
void encapsulate_pkcs7(X509*cert,const char*inFile,const char*outFile)
{
	PKCS7* pkcs = PKCS7_new();
	stack_st_X509* certs = sk_X509_new_reserve(NULL, 1); // crearea unei stive cu ceritificatele destinatarilor
	sk_X509_push(certs, cert);

	BIO* in = BIO_new_file(inFile, "rb");
	pkcs = PKCS7_encrypt(certs, in, EVP_aes_256_cbc(), PKCS7_BINARY); 

	BIO* out = BIO_new_file(outFile, "wb");
	PEM_write_bio_PKCS7(out, pkcs); 
	BIO_free(out);
	BIO_free(in);
}