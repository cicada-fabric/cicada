#ifndef CICADA_PQTLS_CSR_BRIDGE_H
#define CICADA_PQTLS_CSR_BRIDGE_H
#include <stddef.h>
enum { PQ_CSR_OK = 1, PQ_CSR_PROFILE = 2, PQ_CSR_INVALID = 3, PQ_CSR_UNAVAILABLE = 4 };
typedef struct {
    unsigned char *private_key, *csr_der, *spki_der;
    size_t private_key_len, csr_der_len, spki_der_len;
} pq_csr_output;
int pq_csr_generate(const char *dns, int hub, pq_csr_output *);
int pq_csr_inspect(const unsigned char *der, size_t len, const char *dns, int hub, pq_csr_output *);
void pq_csr_output_free(pq_csr_output *);
#endif
