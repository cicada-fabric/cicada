//go:build linux && amd64 && cgo && cicada_pqtls

#include "bridge.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#if OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 5 || OPENSSL_VERSION_PATCH != 9
#error CICADA requires exactly OpenSSL 3.5.9 headers
#endif

struct pq_connection { OSSL_LIB_CTX *lib; OSSL_PROVIDER *provider; SSL_CTX *ctx; SSL *ssl; BIO_METHOD *bio_method; EVP_MD *digest; pq_peer *peers; size_t peer_count; };
static const unsigned char h1[] = {8,'h','t','t','p','/','1','.','1'};

// CGo may run successive calls for one connection on different OS threads.
// Stop this context's thread-local OpenSSL state before each C call returns;
// otherwise freeing the context can leave stale state on other Go runtime
// threads until process exit.
static void pq_thread_stop(pq_connection *c) {
    if (c && c->lib) OPENSSL_thread_stop_ex(c->lib);
}

// Use MSG_NOSIGNAL per write, not a process-global SIGPIPE disposition.
// The BIO owns only its fd metadata. Go owns and closes the socket itself.
static int socket_create(BIO *b) { BIO_set_init(b,0); BIO_set_data(b,NULL); return 1; }
static int socket_destroy(BIO *b) { OPENSSL_free(BIO_get_data(b)); BIO_set_data(b,NULL); BIO_set_init(b,0); return 1; }
static int socket_read(BIO *b,char *buf,int len) {
    BIO_clear_retry_flags(b);
    int n=(int)recv(*(int *)BIO_get_data(b),buf,(size_t)len,0);
    if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) BIO_set_retry_read(b);
    return n;
}
static int socket_write(BIO *b,const char *buf,int len) {
    BIO_clear_retry_flags(b);
    int n=(int)send(*(int *)BIO_get_data(b),buf,(size_t)len,MSG_NOSIGNAL);
    if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) BIO_set_retry_write(b);
    return n;
}
static long socket_ctrl(BIO *b,int cmd,long n,void *p) {
    (void)n;
    if (cmd==BIO_CTRL_FLUSH) return 1;
    if (cmd==BIO_C_GET_FD) { int fd=*(int *)BIO_get_data(b); if(p) *(int *)p=fd; return fd; }
    return 0;
}
static int socket_attach(pq_connection *c,int fd) {
    c->bio_method=BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(),"CICADA owned nonblocking socket");
    if (!c->bio_method || !BIO_meth_set_create(c->bio_method,socket_create) ||
        !BIO_meth_set_destroy(c->bio_method,socket_destroy) || !BIO_meth_set_read(c->bio_method,socket_read) ||
        !BIO_meth_set_write(c->bio_method,socket_write) || !BIO_meth_set_ctrl(c->bio_method,socket_ctrl)) return 0;
    BIO *b=BIO_new(c->bio_method);
    if (!b) return 0;
    int *data=OPENSSL_malloc(sizeof(int));
    if (!data) { BIO_free(b); return 0; }
    *data=fd;BIO_set_data(b,data);BIO_set_init(b,1);
    SSL_set_bio(c->ssl,b,b);
    return 1;
}

int pq_available(void) {
    return strcmp(OpenSSL_version(OPENSSL_VERSION_STRING), "3.5.9") == 0;
}
static int pure_certificate(X509 *x) {
    EVP_PKEY *key = X509_get0_pubkey(x);
    return key && EVP_PKEY_is_a(key, "ML-DSA-65") && X509_get_signature_nid(x) == NID_ML_DSA_65;
}
int pq_peer_set(pq_peer *p,const char *dns,const unsigned char *pin,int spki) {
    if (!p || !dns || !pin || strlen(dns)>=sizeof(p->dns)) return 0;
    memset(p,0,sizeof(*p));strcpy(p->dns,dns);memcpy(p->pin,pin,32);p->spki=spki;
    return 1;
}
static int certificate_digest(pq_connection *c,X509 *x,int spki,unsigned char out[32]) {
    unsigned int n=0;
    if (!spki) return X509_digest(x,c->digest,out,&n) && n==32;
    unsigned char *der=NULL;int size=i2d_PUBKEY(X509_get0_pubkey(x),&der);
    int ok=size>0 && EVP_Digest(der,(size_t)size,out,&n,c->digest,NULL) && n==32;
    OPENSSL_free(der);return ok;
}
// OpenSSL invokes this before the client sends Certificate/CertificateVerify.
// Only C-owned, bounded policy is referenced: no Go callbacks or saved pointers.
static int verify_peer(int preverified,X509_STORE_CTX *store) {
    if (!preverified) return 0;
    SSL *ssl=X509_STORE_CTX_get_ex_data(store,SSL_get_ex_data_X509_STORE_CTX_idx());
    pq_connection *c=ssl ? SSL_get_app_data(ssl) : NULL;
    X509 *x=X509_STORE_CTX_get_current_cert(store);
    if (!c || !x || !pure_certificate(x)) goto deny;
    if (X509_STORE_CTX_get_error_depth(store)!=0) return 1;
    X509 *local=SSL_CTX_get0_certificate(c->ctx);
    if (!local || EVP_PKEY_eq(X509_get0_pubkey(x),X509_get0_pubkey(local))==1) goto deny;
    unsigned char cert[32],spki[32];
    if (!certificate_digest(c,x,0,cert) || !certificate_digest(c,x,1,spki)) goto deny;
    for (size_t i=0;i<c->peer_count;i++) {
        const pq_peer *p=&c->peers[i];
        if (CRYPTO_memcmp(p->pin,p->spki ? spki : cert,32)==0 &&
            X509_check_host(x,p->dns,0,X509_CHECK_FLAG_NO_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,NULL)==1) return 1;
    }
deny:
    X509_STORE_CTX_set_error(store,X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
}
static int alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                const unsigned char *in, unsigned int len, void *arg) {
    (void)ssl; (void)arg;
    if (SSL_select_next_proto((unsigned char **)out,outlen,h1,sizeof(h1),in,len)
            != OPENSSL_NPN_NEGOTIATED || *outlen != 8 || memcmp(*out,"http/1.1",8))
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    return SSL_TLSEXT_ERR_OK;
}
pq_connection *pq_new(const char *cert, const char *key, const char *ca,
                       const char *hostname, int server, int fd,const pq_peer *peers,size_t peer_count) {
    if (!pq_available() || !peers || peer_count==0 || peer_count>64) return NULL;
    pq_connection *c = OPENSSL_zalloc(sizeof(*c));
    if (!c) return NULL;
    c->lib = OSSL_LIB_CTX_new();
    if (!c->lib || !(c->provider = OSSL_PROVIDER_load(c->lib,"default")) ||
        !(c->ctx = SSL_CTX_new_ex(c->lib,NULL,TLS_method())) ||
        !(c->digest=EVP_MD_fetch(c->lib,"SHA256",NULL)) ||
        !(c->peers=OPENSSL_memdup(peers,peer_count*sizeof(*peers)))) goto fail;
    c->peer_count=peer_count;
    if (!SSL_CTX_set_min_proto_version(c->ctx,TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(c->ctx,TLS1_3_VERSION) ||
        !SSL_CTX_set1_groups_list(c->ctx,"MLKEM768") ||
        !SSL_CTX_set1_sigalgs_list(c->ctx,"mldsa65") ||
        !SSL_CTX_set1_client_sigalgs_list(c->ctx,"mldsa65") ||
        !SSL_CTX_set_ciphersuites(c->ctx,"TLS_AES_256_GCM_SHA384")) goto fail;
    SSL_CTX_set_session_cache_mode(c->ctx,SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(c->ctx,SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_num_tickets(c->ctx,0);
    SSL_CTX_set_max_early_data(c->ctx,0);
    SSL_CTX_set_mode(c->ctx,SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_verify(c->ctx,SSL_VERIFY_PEER | (server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0),verify_peer);
    SSL_CTX_set_verify_depth(c->ctx,8);
    if (!SSL_CTX_load_verify_locations(c->ctx,ca,NULL) ||
        !SSL_CTX_use_certificate_chain_file(c->ctx,cert) ||
        !SSL_CTX_use_PrivateKey_file(c->ctx,key,SSL_FILETYPE_PEM) ||
        !SSL_CTX_check_private_key(c->ctx)) goto fail;
    X509 *local = SSL_CTX_get0_certificate(c->ctx);
    if (!local || !pure_certificate(local)) goto fail;
    EVP_PKEY *localkey = SSL_CTX_get0_privatekey(c->ctx);
    if (!localkey || !EVP_PKEY_is_a(localkey,"ML-DSA-65")) goto fail;
    if (server) SSL_CTX_set_alpn_select_cb(c->ctx,alpn,NULL);
    c->ssl = SSL_new(c->ctx);
    if (!c->ssl) goto fail;
    SSL_set_app_data(c->ssl,c);
    if (server) SSL_set_accept_state(c->ssl);
    else {
        SSL_set_connect_state(c->ssl);
        SSL_set_hostflags(c->ssl,X509_CHECK_FLAG_NO_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
        if (!SSL_set1_host(c->ssl,hostname) || !SSL_set_tlsext_host_name(c->ssl,hostname) ||
            SSL_set_alpn_protos(c->ssl,h1,sizeof(h1)) != 0) goto fail;
    }
    // SSL's socket BIO does not own fd. The Go Conn is its sole owner.
    if (fd >= 0 && !socket_attach(c,fd)) goto fail;
    pq_thread_stop(c);
    return c;
fail:
    ERR_clear_error(); pq_free(c); return NULL;
}
void pq_free(pq_connection *c) {
    if (!c) return;
    SSL_free(c->ssl); BIO_meth_free(c->bio_method); SSL_CTX_free(c->ctx); EVP_MD_free(c->digest); OPENSSL_free(c->peers);
    OSSL_PROVIDER_unload(c->provider);
    pq_thread_stop(c);
    OSSL_LIB_CTX_free(c->lib); OPENSSL_free(c);
}
// SSL_get_error must run in the same C call/thread immediately after the IO.
static int result(pq_connection *c, int n) {
    if (n > 0) return 1;
    int e = SSL_get_error(c->ssl,n);
    ERR_clear_error();
    if (e == SSL_ERROR_WANT_READ) return 2;
    if (e == SSL_ERROR_WANT_WRITE) return 3;
    if (e == SSL_ERROR_ZERO_RETURN) return 4;
    return 0;
}
int pq_handshake(pq_connection *c) {
    ERR_clear_error(); int n = SSL_do_handshake(c->ssl); int r=result(c,n); pq_thread_stop(c); return r;
}
int pq_read(pq_connection *c, void *buf, size_t len, size_t *n) {
    ERR_clear_error(); int nread = SSL_read_ex(c->ssl,buf,len,n); int r=result(c,nread); pq_thread_stop(c); return r;
}
int pq_write(pq_connection *c, const void *buf, size_t len, size_t *n) {
    ERR_clear_error(); int nwritten = SSL_write_ex(c->ssl,buf,len,n); int r=result(c,nwritten); pq_thread_stop(c); return r;
}
int pq_snapshot(pq_connection *c, pq_state *s) {
    int ok=0;
    ASN1_TIME *epoch=ASN1_TIME_new();
    memset(s,0,sizeof(*s));
    X509 *peer = SSL_get0_peer_certificate(c->ssl);
    STACK_OF(X509) *chain = SSL_get0_verified_chain(c->ssl);
    int signature=0; const char *signature_name=NULL;
    if (!peer || !pure_certificate(peer) || !chain || sk_X509_num(chain) < 1 ||
        EVP_PKEY_eq(X509_get0_pubkey(peer),X509_get0_pubkey(SSL_get_certificate(c->ssl))) == 1 ||
        SSL_version(c->ssl) != TLS1_3_VERSION ||
        SSL_get_verify_result(c->ssl) != X509_V_OK ||
        !SSL_get_peer_signature_type_nid(c->ssl,&signature) || signature != NID_ML_DSA_65 ||
        !SSL_get0_peer_signature_name(c->ssl,&signature_name) || strcmp(signature_name,"mldsa65") ||
        SSL_session_reused(c->ssl)) goto done;
    if (!epoch || !ASN1_TIME_set_string_X509(epoch,"19700101000000Z")) goto done;
    s->verified_not_before=INT64_MIN;
    s->verified_not_after=INT64_MAX;
    for (int i=0;i<sk_X509_num(chain);i++) {
        X509 *cert=sk_X509_value(chain,i);
        int days=0,seconds=0;
        if (!pure_certificate(cert) ||
            !ASN1_TIME_diff(&days,&seconds,epoch,X509_get0_notBefore(cert))) goto done;
        int64_t before=(int64_t)days*86400+seconds;
        if (!ASN1_TIME_diff(&days,&seconds,epoch,X509_get0_notAfter(cert))) goto done;
        int64_t after=(int64_t)days*86400+seconds;
        if (before>=after) goto done;
        if (before>s->verified_not_before) s->verified_not_before=before;
        if (after<s->verified_not_after) s->verified_not_after=after;
    }
    if (s->verified_not_before>=s->verified_not_after) goto done;
    const char *group = SSL_group_to_name(c->ssl,SSL_get_negotiated_group(c->ssl));
    const char *cipher = SSL_CIPHER_get_name(SSL_get_current_cipher(c->ssl));
    const unsigned char *a=NULL; unsigned int alen=0;
    SSL_get0_alpn_selected(c->ssl,&a,&alen);
    if (!group || strcmp(group,"MLKEM768") || strcmp(cipher,"TLS_AES_256_GCM_SHA384") ||
        alen!=8 || memcmp(a,"http/1.1",8)) goto done;
    if (!certificate_digest(c,peer,0,s->certificate) || !certificate_digest(c,peer,1,s->spki)) goto done;
    strcpy(s->version,SSL_get_version(c->ssl)); strcpy(s->group,group);
    strcpy(s->cipher,cipher); strcpy(s->signature,"ML-DSA-65"); strcpy(s->alpn,"http/1.1");
    s->verification=SSL_get_verify_result(c->ssl);
    ok=1;
done:
    ASN1_TIME_free(epoch);
    pq_thread_stop(c);
    return ok;
}
int pq_hostname(pq_connection *c,const char *host) {
    X509 *peer=SSL_get0_peer_certificate(c->ssl);
    int ok=peer && X509_check_host(peer,host,0,
        X509_CHECK_FLAG_NO_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,NULL)==1;
    pq_thread_stop(c);
    return ok;
}
int pq_localname(pq_connection *c,const char *host) {
    X509 *local=SSL_CTX_get0_certificate(c->ctx);
    int ok=local && X509_check_host(local,host,0,
        X509_CHECK_FLAG_NO_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,NULL)==1;
    pq_thread_stop(c);
    return ok;
}
int pq_event(void) { return eventfd(0,EFD_CLOEXEC | EFD_NONBLOCK); }
void pq_signal(int fd) { uint64_t one=1; ssize_t n; do { n=write(fd,&one,sizeof(one)); } while(n<0 && errno==EINTR); }
// 1 socket ready, 2 deadline/close change, 0 timeout, -1 error, -2 EINTR.
int pq_wait(int fd,int event,int writing,int timeout) {
    struct pollfd p[2]={{fd,writing ? POLLOUT : POLLIN,0},{event,POLLIN,0}};
    int n=poll(p,2,timeout);
    if (n<0) return errno==EINTR ? -2 : -1;
    if (!n) return 0;
    if (p[1].revents) { uint64_t v; (void)read(event,&v,sizeof(v)); return 2; }
    return 1;
}
