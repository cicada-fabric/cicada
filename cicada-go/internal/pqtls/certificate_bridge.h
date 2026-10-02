#ifndef CICADA_PQTLS_CERTIFICATE_BRIDGE_H
#define CICADA_PQTLS_CERTIFICATE_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
enum { PQ_CERT_OK=1, PQ_CERT_PROFILE=2, PQ_CERT_INVALID=3, PQ_CERT_ISSUER=4, PQ_CERT_TIME=5, PQ_CERT_UNAVAILABLE=6 };
typedef struct {
    int hub;
    char dns[254];
    unsigned char serial[16],spki[32];
    int64_t not_before,not_after,at;
} pq_certificate_parameters;
typedef struct {
    unsigned char *certificate_der;
    size_t certificate_der_len;
    unsigned char spki[32],issuer[32];
    int64_t verified_not_before,verified_not_after;
} pq_certificate_output;
int pq_certificate_run(int,const unsigned char *,size_t,const unsigned char *,size_t,
                       const unsigned char *,size_t,const unsigned char *,size_t,
                       const pq_certificate_parameters *,pq_certificate_output *);
void pq_certificate_output_free(pq_certificate_output *);
void pq_certificate_secret_free(void *,size_t);
#endif
