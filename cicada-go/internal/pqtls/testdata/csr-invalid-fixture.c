/* Synthetic test-only PKCS#10 mutations through official OpenSSL APIs.
 * This program never creates a CA or certificate, and is not shipped. */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include <string.h>

#if OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 5 || OPENSSL_VERSION_PATCH != 9
#error This test helper requires exactly OpenSSL 3.5.9
#endif

int main(int argc, char **argv) {
    OSSL_LIB_CTX *lib = NULL;
    OSSL_PROVIDER *provider = NULL;
    X509_REQ *req = NULL;
    EVP_PKEY *key = NULL, *different_key = NULL;
    EVP_MD_CTX *signing = NULL;
    BIO *input = NULL, *key_input = NULL, *output = NULL;
    STACK_OF(X509_EXTENSION) *extensions = NULL;
    int status = 1;
    if (argc != 5 || strcmp(OpenSSL_version(OPENSSL_VERSION_STRING), "3.5.9")) goto done;
    lib = OSSL_LIB_CTX_new();
    if (!lib || !(provider = OSSL_PROVIDER_load(lib, "default"))) goto done;
    input = BIO_new_file(argv[2], "r"); key_input = BIO_new_file(argv[3], "r");
    req = X509_REQ_new_ex(lib, NULL);
    if (!input || !key_input || !req || !PEM_read_bio_X509_REQ(input, &req, NULL, NULL) ||
        !(key = PEM_read_bio_PrivateKey_ex(key_input, NULL, NULL, NULL, lib, NULL))) goto done;
    if (!strcmp(argv[1], "duplicate-extension")) {
        extensions = X509_REQ_get_extensions(req);
        if (!extensions || sk_X509_EXTENSION_num(extensions) != 4) goto done;
        X509_EXTENSION *duplicate = X509_EXTENSION_dup(sk_X509_EXTENSION_value(extensions, 3));
        if (!duplicate) goto done;
        if (!sk_X509_EXTENSION_push(extensions, duplicate)) { X509_EXTENSION_free(duplicate); goto done; }
        X509_ATTRIBUTE *old = X509_REQ_delete_attr(req, 0);
        X509_ATTRIBUTE_free(old);
        if (!X509_REQ_add_extensions(req, extensions)) goto done;
    } else if (!strcmp(argv[1], "duplicate-attribute")) {
        // add1_attr refuses duplicate OIDs. Use official attribute setters to
        // construct a signed adversarial request without hand-encoding ASN.1.
        X509_ATTRIBUTE *duplicate = X509_ATTRIBUTE_dup(X509_REQ_get_attr(req, 0));
        if (!duplicate) goto done;
        int added = X509_ATTRIBUTE_set1_object(duplicate, OBJ_nid2obj(NID_pkcs9_challengePassword)) &&
                    X509_REQ_add1_attr(req, duplicate);
        X509_ATTRIBUTE_free(duplicate);
        if (!added || !X509_ATTRIBUTE_set1_object(X509_REQ_get_attr(req, 1), OBJ_nid2obj(NID_ext_req))) goto done;
    } else if (!strcmp(argv[1], "extra-attribute")) {
        const unsigned char challenge[] = "CICADA SYNTHETIC ATTRIBUTE ONLY";
        if (!X509_REQ_add1_attr_by_NID(req, NID_pkcs9_challengePassword, MBSTRING_ASC,
                                    challenge, sizeof(challenge)-1)) goto done;
    } else if (!strcmp(argv[1], "wrong-signature-oid")) {
        different_key = EVP_PKEY_Q_keygen(lib, NULL, "ML-DSA-44");
        if (!different_key) goto done;
    } else goto done;
    signing = EVP_MD_CTX_new();
    if (!signing || EVP_DigestSignInit_ex(signing, NULL, NULL, lib, NULL,
                                       different_key ? different_key : key, NULL) != 1 ||
        X509_REQ_sign_ctx(req, signing) <= 0) goto done;
    output = BIO_new_file(argv[4], "wx");
    if (!output || !PEM_write_bio_X509_REQ(output, req)) goto done;
    status = 0;
done:
    BIO_free(input); BIO_free(key_input); BIO_free(output);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    EVP_MD_CTX_free(signing); EVP_PKEY_free(different_key); EVP_PKEY_free(key); X509_REQ_free(req);
    OSSL_PROVIDER_unload(provider);
    if (lib) OPENSSL_thread_stop_ex(lib);
    OSSL_LIB_CTX_free(lib);
    return status;
}
