#ifndef QANAT_TLS_H
#define QANAT_TLS_H

#include "qanat/crypto.h"
#include "qanat/mlkem.h"

/* A ciphertext record is at most 2^14 + 256 bytes, plus the 5-byte header. */
#define QN_TLS_REC_MAX 16645

/* Large handshake messages are hashed and dropped; only parsed ones are kept. */
#define QN_TLS_HS_BUF 4096

/* A certificate chain far larger than this is not a chain we need to believe. */
#define QN_TLS_CERT_MAX (256u * 1024u)

/* Matches QN_HELLO_MAX_SIGALGS; the offered list is kept to check the peer's. */
#define QN_TLS_MAX_SIGALGS 24

#define QN_GROUP_X25519_MLKEM768 0x11ECu
#define QN_GROUP_X25519          0x001Du
#define QN_GROUP_P256            0x0017u
#define QN_HYBRID_CLIENT_SHARE_LEN 1216u
#define QN_HYBRID_SERVER_SHARE_LEN 1120u
#define QN_ECH_PAYLOAD_MAX          240u
#define QN_TLS_ALPS_MAX             512u

/* Cursor for the streaming Certificate framing check; see src/net/certscan.h. */
typedef struct {
    uint32_t total, seen, list_left, entry_left, count;
    uint8_t  acc[3], accn, state;
} qn_cert_scan;

typedef struct {
    uint32_t total, seen, list_left, entry_left, extensions_left, count;
    uint8_t  acc[3], accn, state;
} qn_cert13_scan;

typedef enum {
    QN_TLS_FP_CHROME = 0,
    QN_TLS_FP_FIREFOX,
    QN_TLS_FP_SAFARI,
    QN_TLS_FP_RANDOM,
    QN_TLS_FP_COUNT
} qn_tls_fp;

const char *qn_tls_fp_str(qn_tls_fp fp);
bool        qn_tls_fp_parse(const char *s, qn_tls_fp *out);

typedef enum {
    QN_TLS_ST_NEW = 0,
    QN_TLS_ST_WAIT_SH,
    QN_TLS_ST_WAIT_EE,   /* 1.3: encrypted flight */
    QN_TLS_ST_WAIT_CERT, /* 1.2: server flight */
    QN_TLS_ST_WAIT_CCS,  /* 1.2: server ChangeCipherSpec */
    QN_TLS_ST_WAIT_FIN,
    QN_TLS_ST_READY,
    QN_TLS_ST_CLOSED
} qn_tls_st;

typedef enum {
    QN_TLS_RC_OK = 0,
    QN_TLS_RC_MORE,        /* need more inbound bytes */
    QN_TLS_RC_DONE,        /* handshake finished this call */
    QN_TLS_RC_ALERT,       /* peer sent an alert */
    QN_TLS_RC_PROTO,       /* malformed or out-of-order */
    QN_TLS_RC_BADMAC,      /* decryption or Finished check failed */
    QN_TLS_RC_UNSUPPORTED, /* peer chose something we did not offer to complete */
    QN_TLS_RC_SPACE        /* caller buffer too small */
} qn_tls_rc;

const char *qn_tls_rc_str(qn_tls_rc rc);

typedef struct {
    qn_aead  aead;
    uint8_t  iv[QN_AEAD_IV_LEN];
    uint64_t seq;
    bool     on;
} qn_tls_keys;

typedef struct {
    const uint8_t *in;
    size_t         inlen;
    size_t         consumed;

    uint8_t *out; /* bytes the caller must transmit */
    size_t   outcap;
    size_t   outlen;

    uint8_t *app; /* decrypted application data */
    size_t   appcap;
    size_t   applen;
} qn_tls_io;

typedef struct {
    const struct qn_profile_instance *profile;
    const char *sni;
    qn_tls_fp   fp;
    bool        allow_tls12;
    /* Refuse a compressed certificate rather than accept it opaquely. */
    bool        cert_strict;
    qn_rng     *rng; /* non-NULL only for reproducible runs */
} qn_tls_config;

/* OPAQUE: RFC 8879 outer framing was valid and nothing inside it was read. */
typedef enum {
    QN_TLS_CERT_NONE = 0,
    QN_TLS_CERT_PARSED,
    QN_TLS_CERT_OPAQUE
} qn_tls_cert_state;

typedef struct {
    qn_tls_config cfg;

    uint16_t   version; /* 0x0304 or 0x0303 once negotiated */
    uint16_t   suite;
    qn_hash_id hash;
    qn_aead_id aead_id;

    uint8_t x_sk[QN_X25519_LEN];
    uint8_t x_pk[QN_X25519_LEN];
    uint8_t hybrid_x_sk[QN_X25519_LEN];
    uint8_t hybrid_share[QN_HYBRID_CLIENT_SHARE_LEN];
    uint8_t mlkem_sk[QN_MLKEM768_SECRET_LEN];
    uint8_t p256_sk[QN_P256_SECRET_LEN];
    uint8_t p256_pk[QN_P256_PUBLIC_LEN];
    uint8_t ech_enc[QN_X25519_LEN];
    uint8_t ech_payload[QN_ECH_PAYLOAD_MAX];
    uint16_t ech_payload_len;
    uint16_t ech_aead;
    uint8_t ech_config_id;
    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t session_id[32];
    uint8_t session_id_len;

    /* ServerHello fixes the transcript hash, so ClientHello is held until the suite is known. */
    uint8_t  ch[QN_TLS_HS_BUF];
    uint16_t ch_len;
    bool     tr_on;

    qn_hash transcript;
    qn_hash tr_fin; /* transcript as of just before the peer's Finished */

    uint8_t hs_secret[QN_HASH_MAX];
    uint8_t master[QN_HASH_MAX];
    uint8_t c_traffic[QN_HASH_MAX];
    uint8_t s_traffic[QN_HASH_MAX];

    /* TLS 1.2 state: master secret, peer share, and whether EMS was agreed. */
    uint8_t tls12_master[48];
    uint8_t peer_pub[QN_P256_PUBLIC_LEN];
    uint16_t peer_group;
    uint8_t peer_pub_len;
    bool    have_peer;
    bool    ems;

    qn_tls_keys rd, wr;

    uint8_t rec[QN_TLS_REC_MAX];
    size_t  rec_len;

    uint8_t  hs[QN_TLS_HS_BUF];
    uint8_t  hs_hdr[4];
    uint32_t hs_type;
    uint32_t hs_len;
    uint32_t hs_got;
    uint32_t hs_kept;
    bool     hs_active;
    /* Framing cursor for a TLS 1.2 Certificate, which may exceed hs[]. */
    qn_cert_scan cert_scan;
    qn_cert13_scan cert13_scan;

    /* signature_algorithms we sent, so the server's choice can be checked. */
    uint16_t sigalgs[QN_TLS_MAX_SIGALGS];
    uint8_t  nsigalgs;

    uint8_t st;
    /* The selected TLS 1.2 suites require ordered Certificate and ServerKeyExchange messages. */
    uint8_t tls12_step;
    uint8_t alert_desc;
    bool    saw_ccs;
    bool    hrr_done;
    uint64_t hello_grease_seed;
    uint16_t hrr_cookie_len;
    uint16_t hrr_suite;
    uint16_t hrr_group;
    uint8_t  hrr_cookie[512];
    bool    cert_requested;
    bool    saw_certificate;
    bool    saw_cert_verify;
    uint16_t cert_compression_alg; /* Algorithm carried by CompressedCertificate, or zero. */
    /* RFC 8879 framing was valid but the chain was never decompressed. */
    bool    cert_compressed;
    bool    ech_retry_received;
    bool    alps_negotiated;
    uint16_t alps_len;
    uint8_t alps[QN_TLS_ALPS_MAX];

    /* Protocol selected by the peer's ALPN extension (empty means none). */
    char alpn[16];

    /* Who answered, read from the leaf certificate. Nothing is verified. */
    char peer_cn[48];
    char peer_issuer[48];

    char ja3[33]; /* fingerprints of the hello we actually sent */
    char ja4[40];
} qn_tls_session;

void qn_tls_init(qn_tls_session *s, const qn_tls_config *cfg);
void qn_tls_free(qn_tls_session *s);

/* Writes the ClientHello record. Returns bytes written or -1. */
int qn_tls_start(qn_tls_session *s, uint8_t *out, size_t cap);

qn_tls_rc qn_tls_recv(qn_tls_session *s, qn_tls_io *io);

/* Wraps application data in one or more records. Returns bytes or -1. */
int qn_tls_send_app(qn_tls_session *s, const uint8_t *data, size_t len, uint8_t *out, size_t cap);

bool qn_tls_ready(const qn_tls_session *s);

/* OPAQUE means an identity is unavailable by construction, not merely absent. */
qn_tls_cert_state qn_tls_cert_status(const qn_tls_session *s);

bool qn_tls_cert_identity(const uint8_t *der_cert, size_t len, char *cn, size_t cn_cap,
                          char *issuer, size_t issuer_cap);
bool qn_tls_cert_leaf(const uint8_t *msg, size_t len, bool tls13, const uint8_t **out,
                      size_t *outlen);

#endif /* QANAT_TLS_H */
