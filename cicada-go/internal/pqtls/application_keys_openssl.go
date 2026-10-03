//go:build linux && amd64 && cgo && cicada_pqtls

package pqtls

/*
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include "bridge.h"

#if OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 5 || OPENSSL_VERSION_PATCH != 9
#error CICADA requires exactly OpenSSL 3.5.9 headers
#endif

enum { PQ_APP_UNAVAILABLE = 0, PQ_APP_OK = 1, PQ_APP_INVALID = 2, PQ_APP_REUSE = 3, PQ_APP_CERT_INVALID = 4 };
#define PQ_APP_PUBLIC_BYTES 1952
#define PQ_APP_MAX_KEYS 1024

typedef struct { OSSL_LIB_CTX *lib; OSSL_PROVIDER *provider; } pq_app_context;

static int pq_app_context_open(pq_app_context *c) {
    memset(c, 0, sizeof(*c));
    if (!pq_available()) return 0;
    c->lib = OSSL_LIB_CTX_new();
    if (!c->lib) return 0;
    c->provider = OSSL_PROVIDER_load(c->lib, "default");
    return c->provider != NULL;
}

static void pq_app_context_close(pq_app_context *c) {
    OSSL_PROVIDER_unload(c->provider);
    if (c->lib) OPENSSL_thread_stop_ex(c->lib);
    OSSL_LIB_CTX_free(c->lib);
    ERR_clear_error();
}

static void pq_app_public_free(unsigned char *buffer) { OPENSSL_free(buffer); }

// OpenSSL 3.5.9 supplies X509_new_ex + d2i_X509 (no d2i_X509_ex).
// Full DER consumption and key type are required, but extracting a public
// key is not certificate-chain, CA, signature, purpose or time validation.
static int pq_app_issuer_spki(const unsigned char *der, size_t der_len,
                              unsigned char **spki_der, size_t *spki_len) {
    pq_app_context c;
    X509 *cert = NULL;
    int result = PQ_APP_UNAVAILABLE;
    *spki_der = NULL; *spki_len = 0;
    if (!pq_app_context_open(&c)) goto done;
    if (!der || !der_len || der_len > 32768) { result = PQ_APP_CERT_INVALID; goto done; }
    cert = X509_new_ex(c.lib, "provider=default");
    if (!cert) goto done;
    const unsigned char *cursor = der;
    if (!d2i_X509(&cert, &cursor, (long)der_len) || cursor != der + der_len) {
        result = PQ_APP_CERT_INVALID; goto done;
    }
    EVP_PKEY *public_key = X509_get0_pubkey(cert);
    if (!public_key || !EVP_PKEY_is_a(public_key, "ML-DSA-65")) {
        result = PQ_APP_INVALID; goto done;
    }
    int n = i2d_PUBKEY(public_key, spki_der);
    if (n <= 0) goto done;
    *spki_len = (size_t)n;
    result = PQ_APP_OK;
done:
    if (result != PQ_APP_OK) { OPENSSL_free(*spki_der); *spki_der = NULL; *spki_len = 0; }
    X509_free(cert);
    pq_app_context_close(&c);
    return result;
}

// The SPKI was already exported by strict CSR inspection. Re-decode it with
// official APIs, require full consumption, and prove the raw-public import
// roundtrip agrees with both EVP equality and official i2d_PUBKEY output.
static int pq_app_public_from_spki(const unsigned char *der, size_t der_len,
                                  unsigned char *raw) {
    pq_app_context c;
    EVP_PKEY *spki = NULL, *roundtrip = NULL;
    unsigned char *canonical = NULL;
    int result = PQ_APP_UNAVAILABLE;
    if (!pq_app_context_open(&c)) goto done;
    if (!der || !raw || !der_len || der_len > 32768) {
        result = PQ_APP_INVALID; goto done;
    }
    const unsigned char *cursor = der;
    spki = d2i_PUBKEY_ex(NULL, &cursor, (long)der_len, c.lib, "provider=default");
    if (!spki || cursor != der + der_len || !EVP_PKEY_is_a(spki, "ML-DSA-65")) {
        result = PQ_APP_INVALID; goto done;
    }
    size_t raw_len = PQ_APP_PUBLIC_BYTES;
    if (EVP_PKEY_get_raw_public_key(spki, raw, &raw_len) != 1 || raw_len != PQ_APP_PUBLIC_BYTES) goto done;
    roundtrip = EVP_PKEY_new_raw_public_key_ex(c.lib, "ML-DSA-65", "provider=default", raw, raw_len);
    if (!roundtrip || EVP_PKEY_eq(spki, roundtrip) != 1) goto done;
    int canonical_len = i2d_PUBKEY(roundtrip, &canonical);
    if (canonical_len <= 0) goto done;
    if ((size_t)canonical_len != der_len || CRYPTO_memcmp(canonical, der, der_len) != 0) {
        result = PQ_APP_INVALID; goto done;
    }
    result = PQ_APP_OK;
done:
    OPENSSL_free(canonical);
    EVP_PKEY_free(roundtrip);
    EVP_PKEY_free(spki);
    pq_app_context_close(&c);
    return result;
}

// Both inputs are public only. Every inventory entry is imported as an actual
// ML-DSA-65 key in the same private context. Only eq==0 proves distinct keys;
// eq==1 rejects reuse, and any unsupported/error result is unavailable.
static int pq_app_check_separation(const unsigned char *raw, size_t raw_len,
                                   const unsigned char *inventory, size_t inventory_len) {
    pq_app_context c;
    EVP_PKEY *tls = NULL, *application = NULL;
    int result = PQ_APP_UNAVAILABLE;
    if (!pq_app_context_open(&c)) goto done;
    if (!raw || raw_len != PQ_APP_PUBLIC_BYTES || !inventory || !inventory_len ||
        inventory_len % PQ_APP_PUBLIC_BYTES != 0 ||
        inventory_len / PQ_APP_PUBLIC_BYTES > PQ_APP_MAX_KEYS) {
        result = PQ_APP_INVALID; goto done;
    }
    tls = EVP_PKEY_new_raw_public_key_ex(c.lib, "ML-DSA-65", "provider=default", raw, raw_len);
    if (!tls) goto done;
    for (size_t i = 0; i < inventory_len; i += PQ_APP_PUBLIC_BYTES) {
        application = EVP_PKEY_new_raw_public_key_ex(c.lib, "ML-DSA-65", "provider=default",
                                                    inventory + i, PQ_APP_PUBLIC_BYTES);
        if (!application) goto done;
        int equal = EVP_PKEY_eq(tls, application);
        EVP_PKEY_free(application);
        application = NULL;
        if (equal == 1) { result = PQ_APP_REUSE; goto done; }
        if (equal != 0) goto done;
    }
    result = PQ_APP_OK;
done:
    EVP_PKEY_free(application);
    EVP_PKEY_free(tls);
    pq_app_context_close(&c);
    return result;
}
*/
import "C"

import "unsafe"

const tlsApplicationNativeBuild = true

func tlsIssuerSigningSPKIDER(certDER []byte) ([]byte, error) {
	der := C.CBytes(certDER)
	defer C.free(der)
	var spki *C.uchar
	var size C.size_t
	result := C.pq_app_issuer_spki((*C.uchar)(der), C.size_t(len(certDER)), &spki, &size)
	defer C.pq_app_public_free(spki)
	switch result {
	case C.PQ_APP_OK:
		return C.GoBytes(unsafe.Pointer(spki), C.int(size)), nil
	case C.PQ_APP_INVALID:
		return nil, ErrProfile
	case C.PQ_APP_CERT_INVALID:
		return nil, ErrIssuer
	default:
		return nil, ErrUnavailable
	}
}

func tlsApplicationSigningPublicFromSPKI(spki []byte) ([]byte, error) {
	der := C.CBytes(spki)
	defer C.free(der)
	raw := C.malloc(C.size_t(tlsApplicationSigningPublicBytes))
	if raw == nil {
		return nil, ErrUnavailable
	}
	defer C.free(raw)
	switch C.pq_app_public_from_spki((*C.uchar)(der), C.size_t(len(spki)), (*C.uchar)(raw)) {
	case C.PQ_APP_OK:
		return C.GoBytes(raw, C.int(tlsApplicationSigningPublicBytes)), nil
	case C.PQ_APP_INVALID:
		return nil, ErrProfile
	default:
		return nil, ErrUnavailable
	}
}

func checkTLSApplicationSigningPublicSeparation(public, flat []byte) error {
	raw, inventory := C.CBytes(public), C.CBytes(flat)
	defer C.free(raw)
	defer C.free(inventory)
	switch C.pq_app_check_separation((*C.uchar)(raw), C.size_t(len(public)), (*C.uchar)(inventory), C.size_t(len(flat))) {
	case C.PQ_APP_OK:
		return nil
	case C.PQ_APP_REUSE:
		return ErrTLSApplicationKeyReuse
	case C.PQ_APP_INVALID:
		return ErrConfig
	default:
		return ErrUnavailable
	}
}
