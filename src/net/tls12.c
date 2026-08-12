/* TLS 1.2 client handshake: ECDHE with AEAD suites only. */

#include "tls_int.h"
#include "qanat/tls_capability.h"

#include <string.h>

#define VERIFY_LEN   12

bool qn_tls12_suite(uint16_t suite, qn_hash_id *h, qn_aead_id *a)
{
    return qn_tls_capability_suite(suite, 0x0303u, h, a, NULL);
}

static size_t iv_len_for(qn_aead_id a)
{
    return a == QN_AEAD_CHACHA20POLY1305 ? QN_AEAD_IV_LEN : 4u;
}

static bool explicit_nonce(qn_aead_id a)
{
    return a != QN_AEAD_CHACHA20POLY1305;
}

static void aad_for(uint8_t aad[13], uint64_t seq, uint8_t type, size_t plen)
{
    unsigned i;
    for (i = 0; i < 8; i++)
        aad[i] = (uint8_t)(seq >> (56u - 8u * i));
    aad[8]  = type;
    aad[9]  = 0x03;
    aad[10] = 0x03;
    aad[11] = (uint8_t)(plen >> 8);
    aad[12] = (uint8_t)plen;
}

static void nonce_for(const qn_tls_session *s, const qn_tls_keys *k, const uint8_t *exp,
                      uint8_t out[QN_AEAD_IV_LEN])
{
    unsigned i;
    if (explicit_nonce(s->aead_id)) {
        memcpy(out, k->iv, 4);
        memcpy(out + 4, exp, 8);
    } else {
        memcpy(out, k->iv, QN_AEAD_IV_LEN);
        for (i = 0; i < 8; i++)
            out[QN_AEAD_IV_LEN - 1u - i] ^= (uint8_t)(k->seq >> (8u * i));
    }
}

int qn_tls12_seal(qn_tls_session *s, uint8_t type, const uint8_t *data, size_t len, uint8_t *out,
                  size_t cap)
{
    uint8_t aad[13], nonce[QN_AEAD_IV_LEN];
    size_t  exp  = explicit_nonce(s->aead_id) ? 8u : 0u;
    size_t  body = exp + len + QN_AEAD_TAG_LEN;

    /* The sequence number is the nonce; wrapping it would reuse one. */
    if (!s->wr.on || body > 0xFFFFu || REC_HDR + body > cap || s->wr.seq == UINT64_MAX)
        return -1;

    out[0] = type;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (uint8_t)(body >> 8);
    out[4] = (uint8_t)body;

    aad_for(aad, s->wr.seq, type, len);
    if (exp)
        memcpy(out + REC_HDR, aad, 8); /* explicit nonce is the sequence number */
    nonce_for(s, &s->wr, aad, nonce);

    if (len)
        memcpy(out + REC_HDR + exp, data, len);
    if (!qn_aead_seal(&s->wr.aead, nonce, aad, sizeof aad, out + REC_HDR + exp, len,
                      out + REC_HDR + exp))
        return -1;

    s->wr.seq++;
    return (int)(REC_HDR + body);
}

qn_tls_rc qn_tls12_open(qn_tls_session *s, uint8_t type, size_t *plen)
{
    uint8_t aad[13], nonce[QN_AEAD_IV_LEN];
    size_t  exp  = explicit_nonce(s->aead_id) ? 8u : 0u;
    size_t  body = s->rec_len - REC_HDR;
    size_t  ct;

    if (body < exp + QN_AEAD_TAG_LEN)
        return QN_TLS_RC_PROTO;
    /* Refuse the record that would wrap the read sequence rather than reuse it. */
    if (s->rd.seq == UINT64_MAX)
        return QN_TLS_RC_PROTO;

    ct    = body - exp;
    *plen = ct - QN_AEAD_TAG_LEN;

    aad_for(aad, s->rd.seq, type, *plen);
    nonce_for(s, &s->rd, s->rec + REC_HDR, nonce);

    if (!qn_aead_open(&s->rd.aead, nonce, aad, sizeof aad, s->rec + REC_HDR + exp, ct,
                      s->rec + REC_HDR + exp))
        return QN_TLS_RC_BADMAC;

    s->rd.seq++;
    if (exp)
        memmove(s->rec + REC_HDR, s->rec + REC_HDR + exp, *plen);
    return QN_TLS_RC_OK;
}

qn_tls_rc qn_tls12_setup(qn_tls_session *s)
{
    s->st         = QN_TLS_ST_WAIT_CERT;
    s->tls12_step = T12_EXPECT_CERT;
    return QN_TLS_RC_OK;
}

static bool sigalg_offered(const qn_tls_session *s, uint16_t alg)
{
    uint8_t i;

    for (i = 0; i < s->nsigalgs; i++)
        if (s->sigalgs[i] == alg)
            return true;
    return false;
}

/* RFC 5246 7.4.3: must be offered, and must match the key the suite fixes. */
static qn_tls_rc check_sigalg(const qn_tls_session *s, uint16_t alg)
{
    qn_tls_cert_key got, want;

    if (!qn_tls_capability_sigalg(alg, &got) ||
        !qn_tls_capability_suite(s->suite, 0x0303u, NULL, NULL, &want))
        return QN_TLS_RC_PROTO;
    if (!sigalg_offered(s, alg))
        return QN_TLS_RC_PROTO;
    if (got != want)
        return QN_TLS_RC_PROTO;
    return QN_TLS_RC_OK;
}

/* ServerKeyExchange requires complete ECDH parameters and signature framing even without trust validation. */
static qn_tls_rc on_server_kx(qn_tls_session *s)
{
    const uint8_t *m   = s->hs;
    size_t         n   = s->hs_kept;
    size_t         off;
    uint16_t       siglen;
    uint16_t       group;
    uint8_t        klen;

    if (s->hs_len != s->hs_kept || n < 4u)
        return QN_TLS_RC_PROTO;
    if (m[0] != 0x03)
        return QN_TLS_RC_UNSUPPORTED; /* only named curves */
    group = (uint16_t)((uint16_t)m[1] << 8 | m[2]);
    if (group != QN_GROUP_X25519 && group != QN_GROUP_P256)
        return QN_TLS_RC_UNSUPPORTED;

    klen = m[3];
    if (n < 4u + klen ||
        (group == QN_GROUP_X25519 && klen != QN_X25519_LEN) ||
        (group == QN_GROUP_P256 &&
         (klen != QN_P256_PUBLIC_LEN || m[4] != 0x04u)))
        return QN_TLS_RC_PROTO;
    off = 4u + klen;

    /* TLS 1.2 always carries SignatureAndHashAlgorithm here. */
    if (n < off + 2u)
        return QN_TLS_RC_PROTO;
    {
        uint16_t  alg = (uint16_t)((uint16_t)m[off] << 8 | m[off + 1u]);
        qn_tls_rc rc  = check_sigalg(s, alg);

        if (rc != QN_TLS_RC_OK)
            return rc;
    }
    off += 2u;

    if (n < off + 2u)
        return QN_TLS_RC_PROTO;
    siglen = (uint16_t)((uint16_t)m[off] << 8 | m[off + 1u]);
    off += 2u;
    if (!siglen || n - off < siglen)
        return QN_TLS_RC_PROTO;
    off += siglen;
    if (off != n)
        return QN_TLS_RC_PROTO; /* trailing bytes are malformed framing */

    memcpy(s->peer_pub, m + 4, klen);
    s->peer_group = group;
    s->peer_pub_len = klen;
    s->have_peer = true;
    return QN_TLS_RC_OK;
}

static bool master_secret(qn_tls_session *s, const uint8_t *pms, size_t pmslen)
{
    size_t hlen = qn_hash_len(s->hash);

    if (s->ems) {
        uint8_t sh[QN_HASH_MAX];
        qn_hash_final(&s->transcript, sh);
        return qn_tls12_prf(s->hash, pms, pmslen, "extended master secret", sh, hlen,
                            s->tls12_master, sizeof s->tls12_master);
    }
    {
        uint8_t seed[64];
        memcpy(seed, s->client_random, 32);
        memcpy(seed + 32, s->server_random, 32);
        return qn_tls12_prf(s->hash, pms, pmslen, "master secret", seed, sizeof seed,
                            s->tls12_master, sizeof s->tls12_master);
    }
}

static bool key_block(qn_tls_session *s)
{
    size_t  klen  = qn_aead_key_len(s->aead_id);
    size_t  ivlen = iv_len_for(s->aead_id);
    uint8_t seed[64], kb[2u * QN_AEAD_KEY_MAX + 2u * QN_AEAD_IV_LEN];
    bool    ok;

    memcpy(seed, s->server_random, 32);
    memcpy(seed + 32, s->client_random, 32);

    if (!qn_tls12_prf(s->hash, s->tls12_master, sizeof s->tls12_master, "key expansion", seed,
                      sizeof seed, kb, 2u * klen + 2u * ivlen))
        return false;

    memcpy(s->wr.iv, kb + 2u * klen, ivlen);
    memcpy(s->rd.iv, kb + 2u * klen + ivlen, ivlen);
    ok = qn_aead_init(&s->wr.aead, s->aead_id, kb) &&
         qn_aead_init(&s->rd.aead, s->aead_id, kb + klen);
    s->wr.seq = 0;
    s->rd.seq = 0;

    qn_wipe(kb, sizeof kb);
    return ok;
}

static bool finished_data(qn_tls_session *s, const char *label, const qn_hash *tr,
                          uint8_t out[VERIFY_LEN])
{
    uint8_t th[QN_HASH_MAX];
    qn_hash_final(tr, th);
    return qn_tls12_prf(s->hash, s->tls12_master, sizeof s->tls12_master, label, th,
                        qn_hash_len(s->hash), out, VERIFY_LEN);
}

static qn_tls_rc on_hello_done(qn_tls_session *s, qn_tls_io *io)
{
    static const uint8_t CCS[] = { RT_CCS, 0x03, 0x03, 0x00, 0x01, 0x01 };
    uint8_t              cke[4 + 1 + QN_P256_PUBLIC_LEN];
    uint8_t              fin[4 + VERIFY_LEN];
    uint8_t              pms[QN_P256_SECRET_LEN];
    const uint8_t       *client_pub;
    size_t               client_pub_len;
    size_t               ckelen;
    qn_tls_rc            rc     = QN_TLS_RC_PROTO;
    int                  n;

    if (!s->have_peer)
        return QN_TLS_RC_PROTO;

    if (s->peer_group == QN_GROUP_X25519) {
        client_pub = s->x_pk;
        client_pub_len = QN_X25519_LEN;
    } else if (s->peer_group == QN_GROUP_P256) {
        client_pub = s->p256_pk;
        client_pub_len = QN_P256_PUBLIC_LEN;
    } else {
        return QN_TLS_RC_UNSUPPORTED;
    }
    ckelen = 4u + 1u + client_pub_len;

    cke[0] = HS_CLIENT_KX;
    cke[1] = 0;
    cke[2] = 0;
    cke[3] = (uint8_t)(1u + client_pub_len);
    cke[4] = (uint8_t)client_pub_len;
    memcpy(cke + 5, client_pub, client_pub_len);

    if (io->outlen + REC_HDR + ckelen + sizeof CCS > io->outcap)
        return QN_TLS_RC_SPACE;

    io->out[io->outlen + 0] = RT_HS;
    io->out[io->outlen + 1] = 0x03;
    io->out[io->outlen + 2] = 0x03;
    io->out[io->outlen + 3] = (uint8_t)(ckelen >> 8);
    io->out[io->outlen + 4] = (uint8_t)ckelen;
    memcpy(io->out + io->outlen + REC_HDR, cke, ckelen);
    io->outlen += REC_HDR + ckelen;

    qn_hash_update(&s->transcript, cke, ckelen);

    if ((s->peer_group == QN_GROUP_X25519 &&
         !qn_x25519(pms, s->x_sk, s->peer_pub)) ||
        (s->peer_group == QN_GROUP_P256 &&
         !qn_p256(pms, s->p256_sk, s->peer_pub)))
        return QN_TLS_RC_BADMAC;

    /* With EMS the master secret binds the transcript through ClientKeyExchange. */
    if (!master_secret(s, pms, sizeof pms))
        goto out;
    if (!key_block(s))
        goto out;

    memcpy(io->out + io->outlen, CCS, sizeof CCS);
    io->outlen += sizeof CCS;
    s->wr.on = true;

    fin[0] = HS_FINISHED;
    fin[1] = 0;
    fin[2] = 0;
    fin[3] = VERIFY_LEN;
    if (!finished_data(s, "client finished", &s->transcript, fin + 4))
        goto out;
    qn_hash_update(&s->transcript, fin, sizeof fin);

    n = qn_tls12_seal(s, RT_HS, fin, sizeof fin, io->out + io->outlen, io->outcap - io->outlen);
    if (n < 0) {
        rc = QN_TLS_RC_SPACE;
        goto out;
    }
    io->outlen += (size_t)n;

    s->st = QN_TLS_ST_WAIT_CCS;
    rc    = QN_TLS_RC_OK;

out:
    qn_wipe(pms, sizeof pms);
    qn_wipe(fin, sizeof fin);
    return rc;
}

static qn_tls_rc on_server_finished(qn_tls_session *s)
{
    uint8_t expect[VERIFY_LEN];

    if (s->hs_len != VERIFY_LEN || s->hs_kept != VERIFY_LEN)
        return QN_TLS_RC_PROTO;
    if (!finished_data(s, "server finished", &s->tr_fin, expect))
        return QN_TLS_RC_PROTO;
    if (!qn_ct_eq(expect, s->hs, VERIFY_LEN))
        return QN_TLS_RC_BADMAC;

    s->st = QN_TLS_ST_READY;
    return QN_TLS_RC_DONE;
}

void qn_tls12_on_ccs(qn_tls_session *s)
{
    if (s->st == QN_TLS_ST_WAIT_CCS) {
        s->rd.on  = true;
        s->rd.seq = 0;
        s->st     = QN_TLS_ST_WAIT_FIN;
    }
}

qn_tls_rc qn_tls12_dispatch(qn_tls_session *s, qn_tls_io *io)
{
    switch (s->hs_type) {
    case HS_CERT: {
        const uint8_t *leaf;
        size_t         leaflen;

        /* Exactly once, and first in the flight. */
        if (s->st != QN_TLS_ST_WAIT_CERT || s->tls12_step != T12_EXPECT_CERT)
            return QN_TLS_RC_PROTO;
        /* Framing was checked over every byte, whatever the chain's size. */
        if (!qn_cert_scan_done(&s->cert_scan))
            return QN_TLS_RC_PROTO;
        /* Identity is opportunistic: only the retained prefix can be parsed. */
        if (qn_tls_cert_leaf(s->hs, s->hs_kept, false, &leaf, &leaflen))
            qn_tls_cert_identity(leaf, leaflen, s->peer_cn, sizeof s->peer_cn,
                                 s->peer_issuer, sizeof s->peer_issuer);
        s->saw_certificate = true;
        s->tls12_step      = T12_EXPECT_SERVER_KX;
        return QN_TLS_RC_OK;
    }

    case HS_CERT_REQ:
        /* Client authentication is unsupported and legal only before ServerHelloDone. */
        if (s->st != QN_TLS_ST_WAIT_CERT || s->tls12_step != T12_EXPECT_REQ_OR_DONE ||
            s->cert_requested)
            return QN_TLS_RC_PROTO;
        s->cert_requested = true;
        return QN_TLS_RC_UNSUPPORTED;

    case HS_SERVER_KX:
        if (s->st != QN_TLS_ST_WAIT_CERT || s->tls12_step != T12_EXPECT_SERVER_KX)
            return QN_TLS_RC_PROTO;
        {
            qn_tls_rc rc = on_server_kx(s);

            if (rc != QN_TLS_RC_OK)
                return rc;
        }
        s->tls12_step = T12_EXPECT_REQ_OR_DONE;
        return QN_TLS_RC_OK;

    case HS_HELLO_DONE:
        if (s->st != QN_TLS_ST_WAIT_CERT || s->tls12_step != T12_EXPECT_REQ_OR_DONE)
            return QN_TLS_RC_PROTO;
        if (s->hs_len || s->hs_kept)
            return QN_TLS_RC_PROTO; /* ServerHelloDone carries no body */
        s->tls12_step = T12_FLIGHT_DONE;
        return on_hello_done(s, io);

    case HS_FINISHED:
        if (s->st != QN_TLS_ST_WAIT_FIN)
            return QN_TLS_RC_PROTO;
        return on_server_finished(s);

    case HS_NEW_TICKET:
        if (s->st != QN_TLS_ST_WAIT_CCS || s->hs_len != s->hs_kept || s->hs_kept < 6u)
            return QN_TLS_RC_PROTO;
        if ((size_t)(((uint16_t)s->hs[4] << 8) | s->hs[5]) + 6u != s->hs_kept)
            return QN_TLS_RC_PROTO;
        return QN_TLS_RC_OK;

    default:
        return QN_TLS_RC_PROTO;
    }
}
