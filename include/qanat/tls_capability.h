#ifndef QANAT_TLS_CAPABILITY_H
#define QANAT_TLS_CAPABILITY_H

#include "qanat/profile.h"
#include "qanat/tls.h"
#include "qanat/tls_hello.h"

typedef enum {
    QN_TLS_CERT_KEY_NONE = 0,
    QN_TLS_CERT_KEY_RSA,
    QN_TLS_CERT_KEY_ECDSA
} qn_tls_cert_key;

bool qn_tls_capability_suite(uint16_t suite, uint16_t version,
                             qn_hash_id *hash, qn_aead_id *aead,
                             qn_tls_cert_key *cert_key);
bool qn_tls_capability_group(uint16_t group);
bool qn_tls_capability_sigalg(uint16_t sigalg, qn_tls_cert_key *cert_key);
bool qn_tls_capability_extension(uint16_t extension, bool allow_tls12);

/* Offering a shape and being able to finish what it invites are two different
   claims. qn_tls_hello_capability_check answers the first: may we send this at
   all, and is there at least one usable group, share and signature scheme. The
   assessment below answers the second: of everything this hello offered, is any
   of it work we could not finish if the peer took us up on it. */

#define QN_CAPABILITY_MAX_GAPS 16u

typedef enum {
    QN_CAPABILITY_GAP_EXTENSION = 0,
    QN_CAPABILITY_GAP_GROUP,
    QN_CAPABILITY_GAP_SIGALG
} qn_capability_gap_kind;

typedef struct {
    qn_capability_gap_kind kind;
    uint16_t               codepoint;
    const char            *reason; /* static storage; never freed */
} qn_capability_gap;

typedef struct {
    qn_profile_support support;
    qn_capability_gap  gap[QN_CAPABILITY_MAX_GAPS];
    size_t             ngaps;
    bool               truncated; /* more gaps existed than the array holds */
} qn_capability_report;

const char *qn_capability_gap_kind_str(qn_capability_gap_kind kind);

/* True when the peer acting on this extension leaves us nothing we cannot do. */
bool qn_tls_capability_complete_extension(uint16_t extension, const char **reason);

/* EXACT only when the hello owes nothing; UNSUPPORTED when it cannot even start. */
void qn_tls_capability_assess(const qn_hello_info *info, bool allow_tls12,
                              qn_capability_report *report);

#endif /* QANAT_TLS_CAPABILITY_H */
