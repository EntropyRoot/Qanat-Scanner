#ifndef QANAT_TLS_CAPABILITY_H
#define QANAT_TLS_CAPABILITY_H

#include "qanat/tls.h"

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

#endif /* QANAT_TLS_CAPABILITY_H */
