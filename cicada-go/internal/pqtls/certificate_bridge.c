//go:build linux && amd64 && cgo && cicada_pqtls

#include "certificate_bridge.h"
#include "csr_bridge.h"
#include "bridge.h"
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#if OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 5 || OPENSSL_VERSION_PATCH != 9
#error CICADA requires exactly OpenSSL 3.5.9 headers
#endif

typedef struct { OSSL_LIB_CTX *lib; OSSL_PROVIDER *provider; EVP_MD *sha256; } cert_context;
static int cert_context_open(cert_context *c) {
    memset(c,0,sizeof(*c));
    if (!pq_available() || !(c->lib=OSSL_LIB_CTX_new()) ||
        !(c->provider=OSSL_PROVIDER_load(c->lib,"default")) ||
        !(c->sha256=EVP_MD_fetch(c->lib,"SHA256",NULL))) return 0;
    return 1;
}
static void cert_context_close(cert_context *c) {
    EVP_MD_free(c->sha256); OSSL_PROVIDER_unload(c->provider);
    if (c->lib) OPENSSL_thread_stop_ex(c->lib);
    OSSL_LIB_CTX_free(c->lib); ERR_clear_error();
}
void pq_certificate_secret_free(void *p,size_t len) { OPENSSL_clear_free(p,len); }
void pq_certificate_output_free(pq_certificate_output *out) {
    if (!out) return;
    OPENSSL_free(out->certificate_der); memset(out,0,sizeof(*out));
}
static X509 *cert_read(cert_context *c,const unsigned char **cursor,size_t len) {
    X509 *x=X509_new_ex(c->lib,NULL);
    if (!x) return NULL;
    if (!d2i_X509(&x,cursor,(long)len)) { X509_free(x); return NULL; }
    return x;
}
static STACK_OF(X509) *cert_chain_read(cert_context *c,const unsigned char *der,size_t len) {
    STACK_OF(X509) *chain=sk_X509_new_null();
    const unsigned char *p=der;
    if (!chain || !der || len<1 || len>131072) goto fail;
    while (p<der+len) {
        if (sk_X509_num(chain)>=4) goto fail;
        X509 *x=cert_read(c,&p,(size_t)(der+len-p));
        if (!x) goto fail;
        if (!sk_X509_push(chain,x)) { X509_free(x); goto fail; }
    }
    if (sk_X509_num(chain)<2) goto fail;
    return chain;
fail:
    sk_X509_pop_free(chain,X509_free); return NULL;
}
static int cert_pure(X509 *x) {
    const ASN1_BIT_STRING *sig=NULL; const X509_ALGOR *alg=NULL;
    const ASN1_OBJECT *oid=NULL; int type=0;
    EVP_PKEY *key=X509_get0_pubkey(x);
    if (!key || !EVP_PKEY_is_a(key,"ML-DSA-65")) return 0;
    X509_get0_signature(&sig,&alg,x);
    if (!sig || !alg || ((sig->flags&ASN1_STRING_FLAG_BITS_LEFT) && (sig->flags&7))) return 0;
    X509_ALGOR_get0(&oid,&type,NULL,alg);
    if (OBJ_obj2nid(oid)!=NID_ML_DSA_65 || type!=V_ASN1_UNDEF) return 0;
    X509_ALGOR_get0(&oid,&type,NULL,X509_get0_tbs_sigalg(x));
    return OBJ_obj2nid(oid)==NID_ML_DSA_65 && type==V_ASN1_UNDEF;
}
static int cert_dates(X509 *x,int64_t *start,int64_t *end) {
    struct tm a,b;
    if (!ASN1_TIME_to_tm(X509_get0_notBefore(x),&a) || !ASN1_TIME_to_tm(X509_get0_notAfter(x),&b)) return 0;
    *start=(int64_t)timegm(&a); *end=(int64_t)timegm(&b);
    return *start>=0 && *start<*end;
}
static int cert_public_hash(cert_context *c,X509 *x,unsigned char out[32]) {
    unsigned char *der=NULL; unsigned int n=0;
    int len=i2d_PUBKEY(X509_get0_pubkey(x),&der);
    int ok=len>0 && EVP_Digest(der,(size_t)len,out,&n,c->sha256,NULL) && n==32;
    OPENSSL_free(der); return ok;
}
static int cert_ca_profile(X509 *x,int hub,int issuing) {
    int crit=-1;
    BASIC_CONSTRAINTS *bc=X509_get_ext_d2i(x,NID_basic_constraints,&crit,NULL);
    int ok=bc && bc->ca && crit==1 && X509_check_ca(x)>0;
    if (ok && issuing) {
        int64_t path=-1;
        ok=bc->pathlen && ASN1_INTEGER_get_int64(&path,bc->pathlen) && path==0;
    }
    BASIC_CONSTRAINTS_free(bc);
    if (!ok) return 0;
    ASN1_BIT_STRING *usage=X509_get_ext_d2i(x,NID_key_usage,&crit,NULL);
    ok=usage && crit==1 && ASN1_BIT_STRING_get_bit(usage,5)==1;
    ASN1_BIT_STRING_free(usage);
    return ok && X509_check_purpose(x,hub?X509_PURPOSE_SSL_SERVER:X509_PURPOSE_SSL_CLIENT,1)==1;
}
static int cert_verify_chain(cert_context *c,X509 *target,STACK_OF(X509) *ca,X509 *root,
                             const pq_certificate_parameters *p,int leaf,pq_certificate_output *out) {
    int result=PQ_CERT_ISSUER;
    X509_STORE *store=X509_STORE_new();
    X509_STORE_CTX *verify=X509_STORE_CTX_new_ex(c->lib,NULL);
    STACK_OF(X509) *untrusted=sk_X509_new_null();
    if (!store || !verify || !untrusted) { result=PQ_CERT_UNAVAILABLE; goto done; }
    if (!X509_STORE_add_cert(store,root)) goto done;
    for (int i=leaf?0:1;i<sk_X509_num(ca)-1;i++) {
        if (!sk_X509_push(untrusted,sk_X509_value(ca,i))) { result=PQ_CERT_UNAVAILABLE; goto done; }
    }
    if (!X509_STORE_CTX_init(verify,store,target,untrusted)) goto done;
    X509_STORE_CTX_set_flags(verify,X509_V_FLAG_X509_STRICT|X509_V_FLAG_CHECK_SS_SIGNATURE);
    X509_STORE_CTX_set_time(verify,0,(time_t)p->at);
    X509_VERIFY_PARAM *params=X509_STORE_CTX_get0_param(verify);
    X509_VERIFY_PARAM_set_depth(params,4);
    X509_VERIFY_PARAM_set_auth_level(params,3);
    if (leaf && !X509_STORE_CTX_set_purpose(verify,p->hub?X509_PURPOSE_SSL_SERVER:X509_PURPOSE_SSL_CLIENT)) goto done;
    if (X509_verify_cert(verify)!=1) {
        int error=X509_STORE_CTX_get_error(verify);
        if (error==X509_V_ERR_CERT_HAS_EXPIRED || error==X509_V_ERR_CERT_NOT_YET_VALID) result=PQ_CERT_TIME;
        goto done;
    }
    STACK_OF(X509) *verified=X509_STORE_CTX_get0_chain(verify);
    if (!verified || sk_X509_num(verified)!=sk_X509_num(ca)+leaf) goto done;
    int64_t start=0,end=INT64_MAX;
    for (int i=0;i<sk_X509_num(verified);i++) {
        X509 *x=sk_X509_value(verified,i);
        X509 *expected=leaf && i==0?target:sk_X509_value(ca,i-leaf);
        int64_t a,b;
        if (X509_cmp(x,expected)!=0 || !cert_pure(x)) { result=PQ_CERT_PROFILE; goto done; }
        if (!cert_dates(x,&a,&b) || p->at<a || p->at>=b) { result=PQ_CERT_TIME; goto done; }
        if (a>start) start=a;
        if (b<end) end=b;
    }
    out->verified_not_before=start; out->verified_not_after=end;
    result=PQ_CERT_OK;
done:
    X509_STORE_CTX_free(verify); X509_STORE_free(store); sk_X509_free(untrusted);
    return result;
}
static int cert_validate_ca(cert_context *c,STACK_OF(X509) *ca,X509 *root,
                            const pq_certificate_parameters *p,pq_certificate_output *out) {
    if (X509_cmp(sk_X509_value(ca,sk_X509_num(ca)-1),root)!=0 || !cert_pure(root) ||
        X509_NAME_cmp(X509_get_subject_name(root),X509_get_issuer_name(root))!=0 ||
        X509_verify(root,X509_get0_pubkey(root))!=1) return PQ_CERT_ISSUER;
    for (int i=0;i<sk_X509_num(ca);i++) {
        X509 *x=sk_X509_value(ca,i);
        int64_t a,b;
        if (!cert_pure(x)) return PQ_CERT_PROFILE;
        if (!cert_ca_profile(x,p->hub,i==0)) return PQ_CERT_ISSUER;
        if (!cert_dates(x,&a,&b) || p->at<a || p->at>=b) return PQ_CERT_TIME;
        for (int j=0;j<i;j++) if (EVP_PKEY_eq(X509_get0_pubkey(x),X509_get0_pubkey(sk_X509_value(ca,j)))==1) return PQ_CERT_ISSUER;
    }
    return cert_verify_chain(c,sk_X509_value(ca,0),ca,root,p,0,out);
}
static EVP_PKEY *cert_private_key(cert_context *c,const unsigned char *der,size_t len) {
    const unsigned char *cursor=der,*secret=NULL;
    int secret_len=0;
    PKCS8_PRIV_KEY_INFO *p8=NULL; EVP_PKEY *key=NULL;
    if (!der || len<1 || len>16384) return NULL;
    p8=d2i_PKCS8_PRIV_KEY_INFO(NULL,&cursor,(long)len);
    if (!p8 || cursor!=der+len) goto done;
    key=EVP_PKCS82PKEY_ex(p8,c->lib,NULL);
    if (key && !EVP_PKEY_is_a(key,"ML-DSA-65")) { EVP_PKEY_free(key); key=NULL; }
done:
    if (p8 && PKCS8_pkey_get0(NULL,&secret,&secret_len,NULL,p8) && secret_len>0) OPENSSL_cleanse((void *)secret,(size_t)secret_len);
    PKCS8_PRIV_KEY_INFO_free(p8); return key;
}
static STACK_OF(X509_EXTENSION) *cert_leaf_extensions(X509 *issuer,X509 *leaf,const pq_certificate_parameters *p) {
    static const int ids[]={NID_basic_constraints,NID_key_usage,NID_ext_key_usage,NID_subject_alt_name,NID_subject_key_identifier,NID_authority_key_identifier};
    char san[267];
    const char *values[]={"critical,CA:FALSE","critical,digitalSignature",p->hub?"serverAuth":"clientAuth",san,"hash","keyid:always"};
    STACK_OF(X509_EXTENSION) *exts=sk_X509_EXTENSION_new_null();
    X509V3_CTX ctx;
    if (!exts || strlen(p->dns)<1 || strlen(p->dns)>253) goto fail;
    memcpy(san,"critical,DNS:",13); memcpy(san+13,p->dns,strlen(p->dns)+1);
    X509V3_set_ctx(&ctx,issuer,leaf,NULL,NULL,0);
    X509V3_set_ctx_nodb(&ctx);
    for (size_t i=0;i<sizeof(ids)/sizeof(ids[0]);i++) {
        X509_EXTENSION *ext=X509V3_EXT_conf_nid(NULL,&ctx,ids[i],values[i]);
        if (!ext) goto fail;
        if (!sk_X509_EXTENSION_push(exts,ext)) { X509_EXTENSION_free(ext); goto fail; }
    }
    return exts;
fail:
    sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free); return NULL;
}
static int cert_extension_equal(X509_EXTENSION *a,X509_EXTENSION *b) {
    unsigned char *ad=NULL,*bd=NULL;
    int an=i2d_X509_EXTENSION(a,&ad),bn=i2d_X509_EXTENSION(b,&bd);
    int ok=an>0 && an==bn && CRYPTO_memcmp(ad,bd,(size_t)an)==0;
    OPENSSL_free(ad); OPENSSL_free(bd); return ok;
}
static int cert_leaf_profile(cert_context *c,X509 *leaf,STACK_OF(X509) *ca,
                              const pq_certificate_parameters *p,pq_certificate_output *out) {
    int result=PQ_CERT_PROFILE;
    STACK_OF(X509_EXTENSION) *expected=NULL;
    BIGNUM *serial=NULL;
    unsigned char actual_serial[16];
    int64_t a,b;
    if (!cert_pure(leaf) || X509_get_version(leaf)!=2 || X509_NAME_entry_count(X509_get_subject_name(leaf))!=0) goto done;
    if (!cert_dates(leaf,&a,&b) || b-a>86400 || a!=p->not_before || b!=p->not_after) goto done;
	if (a<out->verified_not_before || b>out->verified_not_after) { result=PQ_CERT_TIME; goto done; }
    if (p->at<a || p->at>=b) { result=PQ_CERT_TIME; goto done; }
    serial=ASN1_INTEGER_to_BN(X509_get0_serialNumber(leaf),NULL);
    if (!serial || BN_is_negative(serial) || BN_is_zero(serial) || BN_num_bytes(serial)>16 ||
        BN_bn2binpad(serial,actual_serial,16)!=16 || CRYPTO_memcmp(actual_serial,p->serial,16)!=0) goto done;
    if (!cert_public_hash(c,leaf,out->spki) || CRYPTO_memcmp(out->spki,p->spki,32)!=0) goto done;
    for (int i=0;i<sk_X509_num(ca);i++) if (EVP_PKEY_eq(X509_get0_pubkey(leaf),X509_get0_pubkey(sk_X509_value(ca,i)))==1) goto done;
    expected=cert_leaf_extensions(sk_X509_value(ca,0),leaf,p);
    if (!expected || X509_get_ext_count(leaf)!=6) goto done;
    unsigned int seen=0;
    for (int i=0;i<X509_get_ext_count(leaf);i++) {
        X509_EXTENSION *ext=X509_get_ext(leaf,i); int match=-1;
        for (int j=0;j<sk_X509_EXTENSION_num(expected);j++) {
            if (OBJ_cmp(X509_EXTENSION_get_object(ext),X509_EXTENSION_get_object(sk_X509_EXTENSION_value(expected,j)))==0) match=j;
        }
        if (match<0 || (seen&(1U<<match)) || !cert_extension_equal(ext,sk_X509_EXTENSION_value(expected,match))) goto done;
        seen|=1U<<match;
    }
    if (seen!=63 || X509_check_host(leaf,p->dns,0,X509_CHECK_FLAG_NO_WILDCARDS|X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,NULL)!=1) goto done;
    result=PQ_CERT_OK;
done:
    BN_free(serial); sk_X509_EXTENSION_pop_free(expected,X509_EXTENSION_free); return result;
}

int pq_certificate_run(int operation,const unsigned char *chain_der,size_t chain_len,
                       const unsigned char *root_der,size_t root_len,const unsigned char *key_der,size_t key_len,
                       const unsigned char *object_der,size_t object_len,const pq_certificate_parameters *p,pq_certificate_output *out) {
    cert_context c;
    STACK_OF(X509) *ca=NULL;
    X509 *root=NULL,*leaf=NULL;
    X509_REQ *req=NULL;
    EVP_PKEY *key=NULL;
    EVP_MD_CTX *signing=NULL;
    STACK_OF(X509_EXTENSION) *exts=NULL;
    ASN1_INTEGER *serial=NULL;
    BIGNUM *number=NULL;
    pq_csr_output csr;
    const unsigned char *cursor=root_der;
    int result=PQ_CERT_UNAVAILABLE;
    memset(&csr,0,sizeof(csr)); memset(out,0,sizeof(*out));
    if (!cert_context_open(&c)) goto done;
    result=PQ_CERT_INVALID;
    if (!p || (p->hub!=0 && p->hub!=1) || !root_der || root_len<1 || root_len>32768) goto done;
    root=cert_read(&c,&cursor,root_len);
    ca=cert_chain_read(&c,chain_der,chain_len);
    if (!root || cursor!=root_der+root_len || !ca) goto done;
    result=cert_validate_ca(&c,ca,root,p,out);
    if (result!=PQ_CERT_OK) goto done;
    X509 *issuer=sk_X509_value(ca,0);
    unsigned int digest_len=0;
    if (!X509_digest(issuer,c.sha256,out->issuer,&digest_len) || digest_len!=32) { result=PQ_CERT_UNAVAILABLE; goto done; }
    if (operation==1 || operation==2) {
        key=cert_private_key(&c,key_der,key_len);
        if (!key || EVP_PKEY_eq(key,X509_get0_pubkey(issuer))!=1) { result=PQ_CERT_ISSUER; goto done; }
    }
    if (operation==1) {
        if (!cert_public_hash(&c,issuer,out->spki)) result=PQ_CERT_UNAVAILABLE;
        goto done;
    }
    if (operation==2) {
        if (p->not_before<out->verified_not_before || p->not_after>out->verified_not_after ||
            p->not_before>p->at || p->not_after<=p->at || p->not_after<=p->not_before || p->not_after-p->not_before>86400) {
            result=PQ_CERT_TIME; goto done;
        }
        int checked=pq_csr_inspect(object_der,object_len,p->dns,p->hub,&csr);
        if (checked!=PQ_CSR_OK) { result=checked==PQ_CSR_UNAVAILABLE?PQ_CERT_UNAVAILABLE:PQ_CERT_PROFILE; goto done; }
        cursor=object_der;
        req=X509_REQ_new_ex(c.lib,NULL); leaf=X509_new_ex(c.lib,NULL);
        if (!req || !leaf || !d2i_X509_REQ(&req,&cursor,(long)object_len) || cursor!=object_der+object_len) { result=PQ_CERT_INVALID; goto done; }
	    unsigned char requested_spki[32]; unsigned int requested_len=0;
	    if (!EVP_Digest(csr.spki_der,csr.spki_der_len,requested_spki,&requested_len,c.sha256,NULL) || requested_len!=32) { result=PQ_CERT_UNAVAILABLE; goto done; }
	    if (CRYPTO_memcmp(requested_spki,p->spki,32)!=0) { result=PQ_CERT_PROFILE; goto done; }
	    for (int i=0;i<sk_X509_num(ca);i++) if (EVP_PKEY_eq(X509_REQ_get0_pubkey(req),X509_get0_pubkey(sk_X509_value(ca,i)))==1) { result=PQ_CERT_PROFILE; goto done; }
        number=BN_bin2bn(p->serial,16,NULL); serial=number?BN_to_ASN1_INTEGER(number,NULL):NULL;
        if (!number || BN_is_zero(number) || !serial || !X509_set_version(leaf,2) ||
            !X509_set_serialNumber(leaf,serial) || !X509_set_issuer_name(leaf,X509_get_subject_name(issuer)) ||
            !X509_set_pubkey(leaf,X509_REQ_get0_pubkey(req)) ||
            !ASN1_TIME_set(X509_getm_notBefore(leaf),(time_t)p->not_before) ||
            !ASN1_TIME_set(X509_getm_notAfter(leaf),(time_t)p->not_after)) { result=PQ_CERT_UNAVAILABLE; goto done; }
        exts=cert_leaf_extensions(issuer,leaf,p);
        if (!exts) { result=PQ_CERT_UNAVAILABLE; goto done; }
        for (int i=0;i<sk_X509_EXTENSION_num(exts);i++) if (!X509_add_ext(leaf,sk_X509_EXTENSION_value(exts,i),-1)) { result=PQ_CERT_UNAVAILABLE; goto done; }
        signing=EVP_MD_CTX_new();
        if (!signing || EVP_DigestSignInit_ex(signing,NULL,NULL,c.lib,NULL,key,NULL)!=1 || X509_sign_ctx(leaf,signing)<=0) { result=PQ_CERT_UNAVAILABLE; goto done; }
    } else if (operation==3) {
        if (!object_der || object_len<1 || object_len>32768) { result=PQ_CERT_INVALID; goto done; }
        cursor=object_der; leaf=cert_read(&c,&cursor,object_len);
        if (!leaf || cursor!=object_der+object_len) { result=PQ_CERT_INVALID; goto done; }
    } else { result=PQ_CERT_INVALID; goto done; }
    result=cert_leaf_profile(&c,leaf,ca,p,out);
    if (result!=PQ_CERT_OK) goto done;
    result=cert_verify_chain(&c,leaf,ca,root,p,1,out);
    if (result!=PQ_CERT_OK) goto done;
    if (operation==2) {
        int n=i2d_X509(leaf,&out->certificate_der);
        if (n<=0) { result=PQ_CERT_UNAVAILABLE; goto done; }
        out->certificate_der_len=(size_t)n;
    }
done:
    pq_csr_output_free(&csr);
    BN_free(number); ASN1_INTEGER_free(serial);
    sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free);
    EVP_MD_CTX_free(signing); EVP_PKEY_free(key); X509_REQ_free(req); X509_free(leaf); X509_free(root);
    sk_X509_pop_free(ca,X509_free);
    cert_context_close(&c);
    if (result!=PQ_CERT_OK) pq_certificate_output_free(out);
    return result;
}
