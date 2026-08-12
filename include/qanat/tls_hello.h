#ifndef QANAT_TLS_HELLO_H
#define QANAT_TLS_HELLO_H

#include "qanat/tls.h"

#define QN_HELLO_MAX_CIPHERS 40
#define QN_HELLO_MAX_EXTS    32
#define QN_HELLO_MAX_GROUPS  16
#define QN_HELLO_MAX_SIGALGS 24

typedef struct {
    const char *sni;
    qn_tls_fp   fp;
    bool        allow_tls12;
    uint64_t    grease_seed;
    uint8_t     random[32];
    uint8_t     session_id[32];
    uint8_t     key_share[QN_X25519_LEN];
    const uint8_t *cookie;
    uint16_t       cookie_len;
} qn_hello_req;

/* Parsed wire facts; GREASE is excluded as required by JA3 and JA4. */
typedef struct {
    const uint8_t *body; /* handshake message, past the 5-byte record header */
    size_t         body_len;

    uint16_t ciphers[QN_HELLO_MAX_CIPHERS];
    size_t   nciphers;
    uint16_t exts[QN_HELLO_MAX_EXTS];
    size_t   nexts;
    uint16_t groups[QN_HELLO_MAX_GROUPS];
    size_t   ngroups;
    uint16_t keyshares[QN_HELLO_MAX_GROUPS];
    uint16_t keyshare_lens[QN_HELLO_MAX_GROUPS];
    size_t   nkeyshares;
    uint16_t sigalgs[QN_HELLO_MAX_SIGALGS];
    size_t   nsigalgs;
    uint8_t  ecpf[4];
    size_t   necpf;
    uint16_t versions[4];
    size_t   nversions;

    bool has_sni;
    bool has_alpn;
    bool alpn_capable;
    char alpn_first[16];
    /* A parsed list exceeded its bounded representation. */
    bool overflow;
} qn_hello_info;

/* Room for every list at its declared cap. */
#define QN_JA3_STR_MAX 640

int qn_tls_hello_build(const qn_hello_req *req, uint8_t *buf, size_t cap, qn_hello_info *info);
bool qn_tls_hello_inspect(const uint8_t *wire, size_t len, qn_hello_info *info);
bool qn_tls_hello_capability_check(const qn_hello_info *info, bool allow_tls12,
                                   char *error, size_t error_cap);

/* False means the fingerprint cannot be derived exactly from the wire facts. */
bool qn_tls_ja3(const qn_hello_info *info, char *str, size_t strcap, char hash[33]);
bool qn_tls_ja4(const qn_hello_info *info, char out[40]);

#endif /* QANAT_TLS_HELLO_H */
