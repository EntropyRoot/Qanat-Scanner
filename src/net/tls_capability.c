#include "qanat/tls_capability.h"

#include "qanat/util.h"

typedef struct {
    uint16_t suite;
    uint16_t version;
    qn_hash_id hash;
    qn_aead_id aead;
    qn_tls_cert_key cert_key;
} suite_capability;

static const suite_capability SUITES[] = {
    { 0x1301u, 0x0304u, QN_HASH_SHA256, QN_AEAD_AES128GCM, QN_TLS_CERT_KEY_NONE },
    { 0x1302u, 0x0304u, QN_HASH_SHA384, QN_AEAD_AES256GCM, QN_TLS_CERT_KEY_NONE },
    { 0x1303u, 0x0304u, QN_HASH_SHA256, QN_AEAD_CHACHA20POLY1305,
      QN_TLS_CERT_KEY_NONE },
    { 0xC02Bu, 0x0303u, QN_HASH_SHA256, QN_AEAD_AES128GCM, QN_TLS_CERT_KEY_ECDSA },
    { 0xC02Fu, 0x0303u, QN_HASH_SHA256, QN_AEAD_AES128GCM, QN_TLS_CERT_KEY_RSA },
    { 0xC02Cu, 0x0303u, QN_HASH_SHA384, QN_AEAD_AES256GCM, QN_TLS_CERT_KEY_ECDSA },
    { 0xC030u, 0x0303u, QN_HASH_SHA384, QN_AEAD_AES256GCM, QN_TLS_CERT_KEY_RSA },
    { 0xCCA9u, 0x0303u, QN_HASH_SHA256, QN_AEAD_CHACHA20POLY1305,
      QN_TLS_CERT_KEY_ECDSA },
    { 0xCCA8u, 0x0303u, QN_HASH_SHA256, QN_AEAD_CHACHA20POLY1305,
      QN_TLS_CERT_KEY_RSA }
};

bool qn_tls_capability_suite(uint16_t suite, uint16_t version,
                             qn_hash_id *hash, qn_aead_id *aead,
                             qn_tls_cert_key *cert_key)
{
    size_t i;

    for (i = 0u; i < QN_ARRAY_LEN(SUITES); i++) {
        if (SUITES[i].suite != suite || SUITES[i].version != version)
            continue;
        if (hash)
            *hash = SUITES[i].hash;
        if (aead)
            *aead = SUITES[i].aead;
        if (cert_key)
            *cert_key = SUITES[i].cert_key;
        return true;
    }
    return false;
}

bool qn_tls_capability_group(uint16_t group)
{
    return group == 0x001Du;
}

bool qn_tls_capability_sigalg(uint16_t sigalg, qn_tls_cert_key *cert_key)
{
    qn_tls_cert_key key;

    switch (sigalg) {
    case 0x0403u: case 0x0503u: case 0x0603u:
        key = QN_TLS_CERT_KEY_ECDSA;
        break;
    case 0x0804u: case 0x0805u: case 0x0806u:
        key = QN_TLS_CERT_KEY_RSA;
        break;
    default:
        return false;
    }
    if (cert_key)
        *cert_key = key;
    return true;
}

bool qn_tls_capability_extension(uint16_t extension, bool allow_tls12)
{
    switch (extension) {
    case 0x0000u: case 0x000Au: case 0x000Bu: case 0x000Du:
    case 0x0010u: case 0x0015u: case 0x002Bu: case 0x002Cu: case 0x0033u:
        return true;
    case 0x0017u:
        return allow_tls12;
    default:
        return false;
    }
}
