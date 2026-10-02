//go:build linux && amd64 && cgo && cicada_pqtls

#include "csr_bridge.h"
#include "bridge.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include <limits.h>
#include <string.h>

#if OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 5 || OPENSSL_VERSION_PATCH != 9
#error CICADA requires exactly OpenSSL 3.5.9 headers
#endif

typedef struct { OSSL_LIB_CTX *lib; OSSL_PROVIDER *provider; } csr_context;

static int csr_context_open(csr_context *c) {
    memset(c, 0, sizeof(*c));
    if (!pq_available()) return 0;
    c->lib = OSSL_LIB_CTX_new();
    if (!c->lib) return 0;
    c->provider = OSSL_PROVIDER_load(c->lib, "default");
    return c->provider != NULL;
}

static void csr_context_close(csr_context *c) {
    OSSL_PROVIDER_unload(c->provider);
    if (c->lib) OPENSSL_thread_stop_ex(c->lib);
    OSSL_LIB_CTX_free(c->lib);
    ERR_clear_error();
}

void pq_csr_output_free(pq_csr_output *out) {
    if (!out) return;
    OPENSSL_clear_free(out->private_key, out->private_key_len);
    OPENSSL_free(out->csr_der);
    OPENSSL_free(out->spki_der);
    memset(out, 0, sizeof(*out));
}

// No caller-controlled extension text is parsed: DNS was restricted to the
// exact ASCII DNS grammar in Go; role selects a fixed EKU string.
static STACK_OF(X509_EXTENSION) *csr_extensions(const char *dns, int hub) {
    static const int ids[] = { NID_basic_constraints, NID_key_usage, NID_ext_key_usage, NID_subject_alt_name };
    char san[258];
    const char *values[] = { "critical,CA:FALSE", "critical,digitalSignature", hub ? "serverAuth" : "clientAuth", san };
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    if (!exts || !dns || strlen(dns) < 1 || strlen(dns) > 253) goto fail;
    memcpy(san, "DNS:", 4);
    memcpy(san + 4, dns, strlen(dns) + 1);
    for (size_t i = 0; i < sizeof(ids)/sizeof(ids[0]); i++) {
        X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, ids[i], values[i]);
        if (!ext) goto fail;
        if (!sk_X509_EXTENSION_push(exts, ext)) { X509_EXTENSION_free(ext); goto fail; }
    }
    return exts;
fail:
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return NULL;
}

static int extension_equal(X509_EXTENSION *a, X509_EXTENSION *b) {
    unsigned char *ad = NULL, *bd = NULL;
    int an = i2d_X509_EXTENSION(a, &ad), bn = i2d_X509_EXTENSION(b, &bd);
    int same = an > 0 && an == bn && CRYPTO_memcmp(ad, bd, (size_t)an) == 0;
    OPENSSL_free(ad); OPENSSL_free(bd);
    return same;
}

static int csr_profile(X509_REQ *req, const char *dns, int hub) {
    int ok = 0;
    STACK_OF(X509_EXTENSION) *actual = NULL, *expected = NULL;
    unsigned char *attr_der = NULL;
    if (X509_REQ_get_version(req) != 0 || X509_NAME_entry_count(X509_REQ_get_subject_name(req)) != 0 ||
        X509_REQ_get_attr_count(req) != 1) goto done;
    X509_ATTRIBUTE *attr = X509_REQ_get_attr(req, 0);
    if (!attr || OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attr)) != NID_ext_req || X509_ATTRIBUTE_count(attr) != 1) goto done;
    ASN1_TYPE *value = X509_ATTRIBUTE_get0_type(attr, 0);
    if (!value || value->type != V_ASN1_SEQUENCE) goto done;
    actual = X509_REQ_get_extensions(req);
    expected = csr_extensions(dns, hub);
    if (!actual || !expected || sk_X509_EXTENSION_num(actual) != sk_X509_EXTENSION_num(expected)) goto done;
    // Reject trailing bytes hidden inside extensionRequest as well as outer DER.
    int attr_len = i2d_X509_EXTENSIONS(actual, &attr_der);
    if (attr_len <= 0 || ASN1_STRING_length(value->value.sequence) != attr_len ||
        CRYPTO_memcmp(ASN1_STRING_get0_data(value->value.sequence), attr_der, (size_t)attr_len) != 0) goto done;
    unsigned int seen = 0;
    for (int i = 0; i < sk_X509_EXTENSION_num(actual); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(actual, i);
        int match = -1;
        for (int j = 0; j < sk_X509_EXTENSION_num(expected); j++) {
            if (OBJ_cmp(X509_EXTENSION_get_object(ext), X509_EXTENSION_get_object(sk_X509_EXTENSION_value(expected, j))) == 0) match = j;
        }
        if (match < 0 || (seen & (1U << match)) || !extension_equal(ext, sk_X509_EXTENSION_value(expected, match))) goto done;
        seen |= 1U << match;
    }
    ok = seen == 15;
done:
    OPENSSL_free(attr_der);
    sk_X509_EXTENSION_pop_free(actual, X509_EXTENSION_free);
    sk_X509_EXTENSION_pop_free(expected, X509_EXTENSION_free);
    return ok;
}

static int csr_verify(csr_context *c, X509_REQ *req, const char *dns, int hub, pq_csr_output *out) {
    const ASN1_BIT_STRING *signature = NULL;
    const X509_ALGOR *algorithm = NULL;
    const ASN1_OBJECT *oid = NULL;
    int parameter_type = 0;
    EVP_PKEY *public_key = X509_REQ_get0_pubkey(req);
    if (!public_key || !EVP_PKEY_is_a(public_key, "ML-DSA-65")) return PQ_CSR_PROFILE;
    X509_REQ_get0_signature(req, &signature, &algorithm);
    if (!signature || !algorithm) return PQ_CSR_INVALID;
    if ((signature->flags & ASN1_STRING_FLAG_BITS_LEFT) && (signature->flags & 7)) return PQ_CSR_INVALID;
    X509_ALGOR_get0(&oid, &parameter_type, NULL, algorithm);
    if (OBJ_obj2nid(oid) != NID_ML_DSA_65 || parameter_type != V_ASN1_UNDEF) return PQ_CSR_PROFILE;
    if (!csr_profile(req, dns, hub)) return PQ_CSR_PROFILE;
    if (X509_REQ_verify_ex(req, public_key, c->lib, NULL) != 1) return PQ_CSR_INVALID;
    int n = i2d_PUBKEY(public_key, &out->spki_der);
    if (n <= 0) return PQ_CSR_UNAVAILABLE;
    out->spki_der_len = (size_t)n;
    return PQ_CSR_OK;
}

int pq_csr_generate(const char *dns, int hub, pq_csr_output *out) {
    csr_context c;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *signing = NULL;
    X509_REQ *req = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    BIO *private_bio = NULL;
    char *secret = NULL;
    long secret_len = 0;
    int result = PQ_CSR_UNAVAILABLE;
    memset(out, 0, sizeof(*out));
    if (!csr_context_open(&c)) goto done;
    key = EVP_PKEY_Q_keygen(c.lib, NULL, "ML-DSA-65");
    req = X509_REQ_new_ex(c.lib, NULL);
    signing = EVP_MD_CTX_new();
    exts = csr_extensions(dns, hub);
    if (!key || !req || !signing || !exts || !X509_REQ_set_version(req, 0) ||
        !X509_REQ_set_pubkey(req, key) || !X509_REQ_add_extensions(req, exts) ||
        EVP_DigestSignInit_ex(signing, NULL, NULL, c.lib, NULL, key, NULL) != 1 ||
        X509_REQ_sign_ctx(req, signing) <= 0) goto done;
    result = csr_verify(&c, req, dns, hub, out);
    if (result != PQ_CSR_OK) goto done;
    int n = i2d_X509_REQ(req, &out->csr_der);
    if (n <= 0) { result = PQ_CSR_UNAVAILABLE; goto done; }
    out->csr_der_len = (size_t)n;
    private_bio = BIO_new(BIO_s_mem());
    if (!private_bio || !PEM_write_bio_PKCS8PrivateKey(private_bio, key, NULL, NULL, 0, NULL, NULL)) {
        result = PQ_CSR_UNAVAILABLE; goto done;
    }
    secret_len = BIO_get_mem_data(private_bio, &secret);
    if (secret_len <= 0 || secret_len > 16384 || !(out->private_key = OPENSSL_memdup(secret, (size_t)secret_len))) {
        result = PQ_CSR_UNAVAILABLE; goto done;
    }
    out->private_key_len = (size_t)secret_len;
done:
    if (private_bio) {
        // Also cleanse partially written serialization on every error path.
        secret_len = BIO_get_mem_data(private_bio, &secret);
        if (secret_len > 0) OPENSSL_cleanse(secret, (size_t)secret_len);
    }
    BIO_free(private_bio);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    X509_REQ_free(req); EVP_MD_CTX_free(signing); EVP_PKEY_free(key);
    csr_context_close(&c);
    if (result != PQ_CSR_OK) pq_csr_output_free(out);
    return result;
}

int pq_csr_inspect(const unsigned char *der, size_t len, const char *dns, int hub, pq_csr_output *out) {
    csr_context c;
    X509_REQ *req = NULL;
    const unsigned char *cursor = der;
    int result = PQ_CSR_UNAVAILABLE;
    memset(out, 0, sizeof(*out));
    if (!csr_context_open(&c)) goto done;
    result = PQ_CSR_INVALID;
    if (!der || len < 1 || len > 32768 || len > LONG_MAX) goto done;
    req = X509_REQ_new_ex(c.lib, NULL);
    if (!req) { result = PQ_CSR_UNAVAILABLE; goto done; }
    if (!d2i_X509_REQ(&req, &cursor, (long)len) || cursor != der + len) goto done;
    result = csr_verify(&c, req, dns, hub, out);
done:
    X509_REQ_free(req);
    csr_context_close(&c);
    if (result != PQ_CSR_OK) pq_csr_output_free(out);
    return result;
}
