/* Synthetic test-only certificate mutations using official OpenSSL APIs.
 * Not a deployed issuer, PKI service or production runtime dependency. */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include <string.h>

#if OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 5 || OPENSSL_VERSION_PATCH != 9
#error This helper requires exactly OpenSSL 3.5.9
#endif

int main(int argc,char **argv) {
    OSSL_LIB_CTX *lib=NULL; OSSL_PROVIDER *provider=NULL;
    X509 *leaf=NULL; EVP_PKEY *key=NULL,*different=NULL;
    EVP_MD_CTX *signing=NULL; BIO *input=NULL,*key_input=NULL,*output=NULL;
    X509_EXTENSION *ext=NULL;
    int status=1;
    if (argc!=5 || strcmp(OpenSSL_version(OPENSSL_VERSION_STRING),"3.5.9")) goto done;
    lib=OSSL_LIB_CTX_new(); if (!lib || !(provider=OSSL_PROVIDER_load(lib,"default"))) goto done;
    input=BIO_new_file(argv[2],"r");key_input=BIO_new_file(argv[3],"r");
    leaf=X509_new_ex(lib,NULL);
    if (!input || !key_input || !leaf || !PEM_read_bio_X509(input,&leaf,NULL,NULL) ||
        !(key=PEM_read_bio_PrivateKey_ex(key_input,NULL,NULL,NULL,lib,NULL))) goto done;
    if (!strcmp(argv[1],"noncritical-san")) {
        int index=X509_get_ext_by_NID(leaf,NID_subject_alt_name,-1);
        if (index<0 || !X509_EXTENSION_set_critical(X509_get_ext(leaf,index),0)) goto done;
    } else if (!strcmp(argv[1],"duplicate-extension")) {
        int index=X509_get_ext_by_NID(leaf,NID_subject_alt_name,-1);
        if (index<0 || !X509_add_ext(leaf,X509_get_ext(leaf,index),-1)) goto done;
    } else if (!strcmp(argv[1],"unknown-extension")) {
        ext=X509V3_EXT_conf(NULL,NULL,"1.2.3.4","DER:05:00");
        if (!ext || !X509_add_ext(leaf,ext,-1)) goto done;
    } else if (!strcmp(argv[1],"subject-cn")) {
        const unsigned char cn[]="CICADA SYNTHETIC SUBJECT ONLY";
        if (!X509_NAME_add_entry_by_txt(X509_get_subject_name(leaf),"CN",MBSTRING_ASC,cn,-1,-1,0)) goto done;
    } else if (!strcmp(argv[1],"wrong-signature-oid")) {
        different=EVP_PKEY_Q_keygen(lib,NULL,"ML-DSA-44");if (!different) goto done;
    } else goto done;
    signing=EVP_MD_CTX_new();
    if (!signing || EVP_DigestSignInit_ex(signing,NULL,NULL,lib,NULL,different?different:key,NULL)!=1 ||
        X509_sign_ctx(leaf,signing)<=0) goto done;
    output=BIO_new_file(argv[4],"wx");if (!output || !PEM_write_bio_X509(output,leaf)) goto done;
    status=0;
done:
    BIO_free(input);BIO_free(key_input);BIO_free(output);X509_EXTENSION_free(ext);
    EVP_MD_CTX_free(signing);EVP_PKEY_free(different);EVP_PKEY_free(key);X509_free(leaf);
    OSSL_PROVIDER_unload(provider);if (lib) OPENSSL_thread_stop_ex(lib);OSSL_LIB_CTX_free(lib);
    return status;
}
