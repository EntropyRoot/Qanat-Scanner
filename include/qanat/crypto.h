#ifndef QANAT_CRYPTO_H
#define QANAT_CRYPTO_H

#include "qanat/perm.h"

/* Measurement crypto, not a security library. See docs/TLS.md before reusing. */

#define QN_SHA256_LEN 32
#define QN_SHA384_LEN 48
#define QN_SHA512_LEN 64
#define QN_HASH_MAX   QN_SHA384_LEN
#define QN_BLOCK_MAX  128

typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t  buf[64];
    uint32_t n;
} qn_sha256;

void qn_sha256_init(qn_sha256 *s);
void qn_sha256_update(qn_sha256 *s, const void *p, size_t n);
void qn_sha256_final(const qn_sha256 *s, uint8_t out[QN_SHA256_LEN]);

#if defined(QN_CRYPTO_TESTING)
void qn_sha256_blocks_c(uint32_t state[8], const uint8_t *data, size_t blocks);
#endif

typedef struct {
    uint64_t h[8];
    uint64_t len_lo, len_hi;
    uint8_t  buf[128];
    uint32_t n;
    uint32_t outlen;
} qn_sha512;

void qn_sha512_init(qn_sha512 *s, uint32_t outlen);
void qn_sha512_update(qn_sha512 *s, const void *p, size_t n);
void qn_sha512_final(const qn_sha512 *s, uint8_t *out);

typedef enum { QN_HASH_SHA256 = 0, QN_HASH_SHA384 = 1 } qn_hash_id;

typedef struct {
    qn_hash_id id;
    union {
        qn_sha256 s256;
        qn_sha512 s384;
    } u;
} qn_hash;

size_t qn_hash_len(qn_hash_id id);
size_t qn_hash_block(qn_hash_id id);
void   qn_hash_init(qn_hash *h, qn_hash_id id);
void   qn_hash_update(qn_hash *h, const void *p, size_t n);

/* Non-destructive: the TLS transcript is read repeatedly while still growing. */
void qn_hash_final(const qn_hash *h, uint8_t *out);

typedef struct {
    qn_hash inner, outer;
} qn_hmac;

void qn_hmac_init(qn_hmac *m, qn_hash_id id, const uint8_t *key, size_t klen);
void qn_hmac_update(qn_hmac *m, const void *p, size_t n);
void qn_hmac_final(const qn_hmac *m, uint8_t *out);
void qn_hmac_once(qn_hash_id id, const uint8_t *key, size_t klen, const void *msg, size_t mlen,
                  uint8_t *out);

void qn_hkdf_extract(qn_hash_id id, const uint8_t *salt, size_t slen, const uint8_t *ikm,
                     size_t ilen, uint8_t *prk);
bool qn_hkdf_expand(qn_hash_id id, const uint8_t *prk, const uint8_t *info, size_t ilen,
                    uint8_t *out, size_t olen);
bool qn_hkdf_expand_label(qn_hash_id id, const uint8_t *secret, const char *label,
                          const uint8_t *ctx, size_t ctxlen, uint8_t *out, size_t olen);
bool qn_derive_secret(qn_hash_id id, const uint8_t *secret, const char *label,
                      const qn_hash *transcript, uint8_t *out);

/* TLS 1.2 PRF (RFC 5246 5), P_hash over the suite's hash. */
bool qn_tls12_prf(qn_hash_id id, const uint8_t *secret, size_t seclen, const char *label,
                  const uint8_t *seed, size_t seedlen, uint8_t *out, size_t olen);

#define QN_AEAD_IV_LEN  12
#define QN_AEAD_TAG_LEN 16
#define QN_AEAD_KEY_MAX 32

typedef enum {
    QN_AEAD_AES128GCM = 0,
    QN_AEAD_AES256GCM = 1,
    QN_AEAD_CHACHA20POLY1305 = 2
} qn_aead_id;

size_t qn_aead_key_len(qn_aead_id id);

typedef struct {
    uint32_t rk[60];
    uint32_t nr;
    uint64_t hh[16][2]; /* 4-bit GHASH table for the scalar path */
    uint8_t  hp[4][16]; /* H through H^4 for the PMULL path */
} qn_aes_gcm;

/* id 0 is a real algorithm, so a zeroed context needs its own invalid marker. */
typedef struct {
    qn_aead_id id;
    bool       ready;
    union {
        qn_aes_gcm gcm;
        uint8_t    chacha[32];
    } u;
} qn_aead;

bool qn_aead_init(qn_aead *a, qn_aead_id id, const uint8_t *key);
bool qn_aead_seal(const qn_aead *a, const uint8_t iv[QN_AEAD_IV_LEN], const uint8_t *aad,
                  size_t aadlen, const uint8_t *pt, size_t ptlen, uint8_t *out);
bool qn_aead_open(const qn_aead *a, const uint8_t iv[QN_AEAD_IV_LEN], const uint8_t *aad,
                  size_t aadlen, const uint8_t *ct, size_t ctlen, uint8_t *out);

#define QN_X25519_LEN 32

void qn_x25519_base(uint8_t pk[QN_X25519_LEN], const uint8_t sk[QN_X25519_LEN]);
bool qn_x25519(uint8_t out[QN_X25519_LEN], const uint8_t sk[QN_X25519_LEN],
               const uint8_t peer[QN_X25519_LEN]);
bool qn_x25519_keypair(uint8_t sk[QN_X25519_LEN], uint8_t pk[QN_X25519_LEN], qn_rng *rng);

/* Runtime CPU dispatch; the scalar C paths stay as the fallback. */
bool qn_cpu_has_aes(void);
bool qn_cpu_has_pmull(void);
bool qn_cpu_has_sha2(void);
bool qn_cpu_has_neon(void);

/* Fingerprinting only: JA3 is specified as MD5. Never use this for security. */
void qn_md5(const void *data, size_t len, uint8_t out[16]);

/* Handshake secrets fail closed if the OS cannot supply entropy. */
bool qn_random_secure(void *dst, size_t n);

bool qn_ct_eq(const void *a, const void *b, size_t n);
void qn_wipe(void *p, size_t n);

#endif /* QANAT_CRYPTO_H */
