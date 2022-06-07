X509* generate_cert(const char*privRSAFile,unsigned char*C,unsigned char*O,unsigned char*CN);
void load_cert_to_file(X509*cert,const char*fname);

void load_cert_to_file(X509*cert,const char*fname);
void load_cert_from_file(const char*fname, X509**cert);

void encapsulate_pkcs7(X509*cert,const char*inFile,const char*outFile);
