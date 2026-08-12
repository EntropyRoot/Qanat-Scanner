#include "qanat/tls_capability.h"

#include "qanat/util.h"

#include <string.h>

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
    return group == QN_GROUP_X25519_MLKEM768 ||
           group == QN_GROUP_X25519 || group == QN_GROUP_P256;
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
    (void)allow_tls12;
    switch (extension) {
    case 0x0000u: case 0x0005u: case 0x000Au: case 0x000Bu:
    case 0x000Du: case 0x0010u: case 0x0012u: case 0x0015u:
    case 0x0017u: case 0x001Bu: case 0x001Cu: case 0x0022u:
    case 0x0023u: case 0x002Bu: case 0x002Cu: case 0x002Du:
    case 0x0033u: case 0x44CDu: case 0xFE0Du: case 0xFF01u:
        return true;
    default:
        return false;
    }
}

const char *qn_capability_gap_kind_str(qn_capability_gap_kind kind)
{
    switch (kind) {
    case QN_CAPABILITY_GAP_EXTENSION: return "extension";
    case QN_CAPABILITY_GAP_GROUP:     return "group";
    case QN_CAPABILITY_GAP_SIGALG:    return "signature-scheme";
    default:                          return "unknown";
    }
}

bool qn_tls_capability_complete_extension(uint16_t extension, const char **reason)
{
    switch (extension) {
    case 0x001Bu:
        /* RFC 8879 outer framing is validated; the chain is never decompressed. */
        if (reason)
            *reason = "compressed certificate chains are never decompressed";
        return false;
    default:
        break;
    }
    return true;
}

static void gap_add(qn_capability_report *report, qn_capability_gap_kind kind,
                    uint16_t codepoint, const char *reason)
{
    if (report->ngaps >= QN_CAPABILITY_MAX_GAPS) {
        report->truncated = true;
        return;
    }
    report->gap[report->ngaps].kind = kind;
    report->gap[report->ngaps].codepoint = codepoint;
    report->gap[report->ngaps].reason = reason;
    report->ngaps++;
}

void qn_tls_capability_assess(const qn_hello_info *info, bool allow_tls12,
                              qn_capability_report *report)
{
    size_t i;

    if (!report)
        return;
    memset(report, 0, sizeof *report);
    report->support = QN_PROFILE_UNSUPPORTED;
    if (!info || !qn_tls_hello_capability_check(info, allow_tls12, NULL, 0u))
        return;

    for (i = 0; i < info->nexts; i++) {
        const char *reason = "not completable";

        if (!qn_tls_capability_complete_extension(info->exts[i], &reason))
            gap_add(report, QN_CAPABILITY_GAP_EXTENSION, info->exts[i], reason);
    }
    /* A group we cannot do is owed work whichever version is negotiated: a 1.2
       server picks the curve, and 1.3 can demand one with a retry. */
    for (i = 0; i < info->ngroups; i++)
        if (!qn_tls_capability_group(info->groups[i]))
            gap_add(report, QN_CAPABILITY_GAP_GROUP, info->groups[i],
                    "offered, but no key exchange implements it");
    /* Signature schemes bind us only where a signature is checked, which here is
       the 1.2 ServerKeyExchange. Offering one we would reject is a gap. */
    if (allow_tls12)
        for (i = 0; i < info->nsigalgs; i++)
            if (!qn_tls_capability_sigalg(info->sigalgs[i], NULL))
                gap_add(report, QN_CAPABILITY_GAP_SIGALG, info->sigalgs[i],
                        "offered, but ServerKeyExchange would reject it");

    /* An overflowed parse never reaches here: the check above refuses it, since
       a truncated hello cannot prove the absence of a gap it never saw. */
    report->support = report->ngaps || report->truncated
                          ? QN_PROFILE_CAPABILITY_CONSTRAINED
                          : QN_PROFILE_EXACT;
}
