#ifndef CICADA_PQTLS_BRIDGE_H
#define CICADA_PQTLS_BRIDGE_H
#include <stddef.h>
typedef struct pq_connection pq_connection;
typedef struct { char dns[254]; unsigned char pin[32]; int spki; } pq_peer;
int pq_peer_set(pq_peer *, const char *, const unsigned char *, int);
typedef struct {
    char version[24], group[48], cipher[48], signature[32], alpn[16];
    long verification;
    unsigned char certificate[32], spki[32];
} pq_state;
int pq_available(void);
pq_connection *pq_new(const char *, const char *, const char *, const char *, int, int, const pq_peer *, size_t);
void pq_free(pq_connection *);
int pq_handshake(pq_connection *);
int pq_read(pq_connection *, void *, size_t, size_t *);
int pq_write(pq_connection *, const void *, size_t, size_t *);
int pq_snapshot(pq_connection *, pq_state *);
int pq_hostname(pq_connection *, const char *);
int pq_localname(pq_connection *, const char *);
int pq_event(void);
void pq_signal(int);
int pq_wait(int, int, int, int);
#endif
