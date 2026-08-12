#include "qanat/probe.h"

#include "qanat/profile.h"

#include <string.h>

static int build_hello(uint8_t *buf, size_t cap, const char *sni, qn_rng *rng,
                       qn_tls_fp fp, bool allow_tls12, uint64_t grease_salt)
{
    qn_hello_req  req;
    qn_hello_info info;
    qn_hello_key_share shares[3];
    uint8_t material[QN_HYBRID_CLIENT_SHARE_LEN + QN_X25519_LEN +
                     QN_P256_PUBLIC_LEN + QN_X25519_LEN + QN_ECH_PAYLOAD_MAX];
    uint8_t *hybrid = material;
    uint8_t *x25519 = hybrid + QN_HYBRID_CLIENT_SHARE_LEN;
    uint8_t *p256 = x25519 + QN_X25519_LEN;
    uint8_t *ech_enc = p256 + QN_P256_PUBLIC_LEN;
    uint8_t *ech_payload = ech_enc + QN_X25519_LEN;

    if (!buf || !cap || !sni)
        return -1;
    if (fp >= QN_TLS_FP_COUNT)
        fp = QN_TLS_FP_CHROME;

    memset(&req, 0, sizeof req);
    req.sni         = sni;
    req.fp          = fp;
    req.allow_tls12 = allow_tls12;

    if (rng) {
        req.grease_seed = qn_rng_next(rng);
        qn_rng_bytes(rng, req.random, sizeof req.random);
        qn_rng_bytes(rng, req.session_id, sizeof req.session_id);
        qn_rng_bytes(rng, material, sizeof material);
    } else if (!qn_random_secure(&req.grease_seed, sizeof req.grease_seed) ||
               !qn_random_secure(req.random, sizeof req.random) ||
               !qn_random_secure(req.session_id, sizeof req.session_id) ||
               !qn_random_secure(material, sizeof material)) {
        return -1;
    }
    req.grease_seed ^= grease_salt;

    p256[0] = 0x04u;
    shares[0] = (qn_hello_key_share){ QN_GROUP_X25519_MLKEM768, hybrid,
                                      QN_HYBRID_CLIENT_SHARE_LEN };
    shares[1] = (qn_hello_key_share){ QN_GROUP_X25519, x25519, QN_X25519_LEN };
    shares[2] = (qn_hello_key_share){ QN_GROUP_P256, p256, QN_P256_PUBLIC_LEN };
    req.key_shares = shares;
    req.key_shares_n = (uint8_t)QN_ARRAY_LEN(shares);
    req.ech_config_id = (uint8_t)(req.grease_seed >> 8);
    req.ech_aead = fp == QN_TLS_FP_FIREFOX ? 0x0003u : 0x0001u;
    memcpy(req.ech_enc, ech_enc, QN_X25519_LEN);
    req.ech_payload = ech_payload;
    req.ech_payload_len = fp == QN_TLS_FP_CHROME
                              ? (uint16_t)(144u + 32u * (req.grease_seed & 3u))
                              : (uint16_t)(QN_ECH_PAYLOAD_MAX - 1u);

    return qn_tls_hello_build(&req, buf, cap, &info);
}

int qn_tls_build_hello(uint8_t *buf, size_t cap, const char *sni, qn_rng *rng,
                       qn_tls_fp fp)
{
    if (fp == QN_TLS_FP_RANDOM)
        return -1;
    return build_hello(buf, cap, sni, rng, fp, true, 0u);
}

int qn_tls_build_hello_instance(uint8_t *buf, size_t cap,
                                const qn_profile_instance *profile, qn_rng *rng)
{
    if (!profile || profile->version != QN_PROFILE_INSTANCE_VERSION ||
        profile->support == QN_PROFILE_UNSUPPORTED)
        return -1;
    return build_hello(buf, cap, profile->sni, rng, profile->resolved,
                       profile->allow_tls12, profile->grease_seed);
}

qn_tls_outcome qn_tls_classify(const uint8_t *buf, size_t len)
{
    uint32_t record_len;

    if (len == 0)
        return QN_TLS_SILENCE;
    if (!buf || len < 5u || buf[1] != 0x03u || buf[2] < 0x01u || buf[2] > 0x04u)
        return QN_TLS_GARBAGE;

    record_len = ((uint32_t)buf[3] << 8) | buf[4];
    if (!record_len || record_len > 16640u || len < 5u + record_len)
        return QN_TLS_GARBAGE;

    switch (buf[0]) {
    case 0x16: {
        uint32_t hs_len;
        size_t   body = 9u, off, remain;

        if (record_len < 42u || buf[5] != 0x02u)
            return QN_TLS_GARBAGE;
        hs_len = ((uint32_t)buf[6] << 16) | ((uint32_t)buf[7] << 8) | buf[8];
        if (hs_len < 38u || hs_len + 4u > record_len || len < body + hs_len)
            return QN_TLS_GARBAGE;
        if (buf[body] != 0x03u || buf[body + 1u] < 0x01u || buf[body + 1u] > 0x03u)
            return QN_TLS_GARBAGE;

        /* legacy_version + random, then a bounded legacy session id. */
        off = body + 34u;
        if (off >= body + hs_len || buf[off] > 32u)
            return QN_TLS_GARBAGE;
        off += 1u + buf[off];
        if (off + 3u > body + hs_len)
            return QN_TLS_GARBAGE;
        if ((buf[off] == 0u && buf[off + 1u] == 0u) ||
            (buf[off] == 0u && buf[off + 1u] == 0xffu) || buf[off + 2u] != 0u)
            return QN_TLS_GARBAGE;
        off += 3u; /* selected cipher suite and compression byte */

        remain = body + hs_len - off;
        if (remain) {
            uint32_t ext_len;
            size_t   pos, end;

            if (remain < 2u)
                return QN_TLS_GARBAGE;
            ext_len = ((uint32_t)buf[off] << 8) | buf[off + 1u];
            if (ext_len + 2u != remain)
                return QN_TLS_GARBAGE;
            pos = off + 2u;
            end = pos + ext_len;
            while (pos < end) {
                uint32_t item_len;

                if (end - pos < 4u)
                    return QN_TLS_GARBAGE;
                item_len = ((uint32_t)buf[pos + 2u] << 8) | buf[pos + 3u];
                pos += 4u;
                if (item_len > end - pos)
                    return QN_TLS_GARBAGE;
                pos += item_len;
            }
        }
        return QN_TLS_SERVERHELLO;
    }
    case 0x15:
        if ((record_len & 1u) != 0u)
            return QN_TLS_GARBAGE;
        for (size_t pos = 5u; pos < 5u + record_len; pos += 2u)
            if (buf[pos] != 1u && buf[pos] != 2u)
                return QN_TLS_GARBAGE;
        return QN_TLS_ALERT;
    default:
        return QN_TLS_GARBAGE;
    }
}

const char *qn_tls_outcome_str(qn_tls_outcome o)
{
    switch (o) {
    case QN_TLS_NONE:        return "-";
    case QN_TLS_SERVERHELLO: return "server-hello";
    case QN_TLS_ALERT:       return "alert";
    case QN_TLS_RESET:       return "reset";
    case QN_TLS_SILENCE:     return "silence";
    default:                 return "garbage";
    }
}
