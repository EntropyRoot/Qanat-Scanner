/* TLS 1.3 client handshake and record layer. Proves a path carries traffic. */

#include "qanat/tls_hello.h"
#include "qanat/profile.h"
#include "tls_int.h"
#include "qanat/tls_capability.h"

#include <string.h>
#include <errno.h>

#define REC_MAXPT 16384

#define EXT_SUPPORTED_VERSIONS 0x002B
#define EXT_KEY_SHARE          0x0033
#define EXT_EMS                0x0017
#define EXT_ALPN               0x0010
#define EXT_SERVER_NAME        0x0000
#define EXT_COMPRESS_CERT      0x001B
#define EXT_RECORD_SIZE_LIMIT  0x001C
#define EXT_COOKIE             0x002C
#define GROUP_X25519           0x001D

/* RFC 8879: selected when the ClientHello offers compress_certificate. */
#define HS_COMPRESSED_CERT 25u
#define HS_MESSAGE_HASH     254u

/* RFC 8446 4.1.3: the ServerHello random that marks a HelloRetryRequest. */
static const uint8_t HRR_RANDOM[32] = { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
                                        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
                                        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
                                        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };

typedef struct {
    const uint8_t *p;
    size_t         len;
    size_t         off;
    bool           err;
} br;

static void br_init(br *r, const uint8_t *p, size_t len)
{
    r->p   = p;
    r->len = len;
    r->off = 0;
    r->err = false;
}

static const uint8_t *br_take(br *r, size_t n)
{
    const uint8_t *at;
    if (r->err || r->len - r->off < n) {
        r->err = true;
        return NULL;
    }
    at = r->p + r->off;
    r->off += n;
    return at;
}

static uint8_t br_u8(br *r)
{
    const uint8_t *p = br_take(r, 1);
    return p ? p[0] : 0;
}

static uint16_t br_u16(br *r)
{
    const uint8_t *p = br_take(r, 2);
    return p ? (uint16_t)(((uint16_t)p[0] << 8) | p[1]) : 0;
}

static size_t br_left(const br *r)
{
    return r->err ? 0 : r->len - r->off;
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t rd24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

static bool ext_once(uint16_t *seen, size_t *nseen, size_t cap, uint16_t id)
{
    size_t i;

    for (i = 0; i < *nseen; i++)
        if (seen[i] == id)
            return false;
    if (*nseen == cap)
        return false;
    seen[(*nseen)++] = id;
    return true;
}

/* RFC 7301: a server selects exactly one ProtocolName from the offered list. */
static bool parse_selected_alpn(qn_tls_session *s, const uint8_t *p, size_t n)
{
    size_t plen;

    if (n < 3u || rd16(p) != n - 2u)
        return false;
    plen = p[2];
    if (!plen || plen != n - 3u || plen >= sizeof s->alpn)
        return false;
    memcpy(s->alpn, p + 3, plen);
    s->alpn[plen] = '\0';
    /* Every built-in/custom profile currently offers exactly these protocols. */
    return !strcmp(s->alpn, "h2") || !strcmp(s->alpn, "http/1.1");
}

const char *qn_tls_rc_str(qn_tls_rc rc)
{
    switch (rc) {
    case QN_TLS_RC_OK:          return "ok";
    case QN_TLS_RC_MORE:        return "more";
    case QN_TLS_RC_DONE:        return "done";
    case QN_TLS_RC_ALERT:       return "alert";
    case QN_TLS_RC_PROTO:       return "protocol";
    case QN_TLS_RC_BADMAC:      return "bad-mac";
    case QN_TLS_RC_UNSUPPORTED: return "unsupported";
    default:                    return "no-space";
    }
}

bool qn_tls_ready(const qn_tls_session *s)
{
    return s->st == QN_TLS_ST_READY;
}

qn_tls_cert_state qn_tls_cert_status(const qn_tls_session *s)
{
    if (s->saw_certificate)
        return QN_TLS_CERT_PARSED;
    return s->cert_compressed ? QN_TLS_CERT_OPAQUE : QN_TLS_CERT_NONE;
}

static bool suite_params(uint16_t suite, qn_hash_id *h, qn_aead_id *a)
{
    return qn_tls_capability_suite(suite, 0x0304u, h, a, NULL);
}

void qn_tls_init(qn_tls_session *s, const qn_tls_config *cfg)
{
    memset(s, 0, sizeof *s);
    if (cfg)
        s->cfg = *cfg;
    if ((unsigned)s->cfg.fp >= QN_TLS_FP_COUNT)
        s->cfg.fp = QN_TLS_FP_CHROME;
    s->hash    = QN_HASH_SHA256;
    s->aead_id = QN_AEAD_AES128GCM;
    s->st      = QN_TLS_ST_NEW;
}

void qn_tls_free(qn_tls_session *s)
{
    qn_wipe(s, sizeof *s);
}

int qn_tls_start(qn_tls_session *s, uint8_t *out, size_t cap)
{
    qn_hello_req  req;
    qn_hello_info info;
    int           n;

    if (s->st != QN_TLS_ST_NEW || !out)
        return -1;

    memset(&req, 0, sizeof req);
    req.sni = s->cfg.profile ? s->cfg.profile->sni : s->cfg.sni;
    req.fp = s->cfg.profile ? s->cfg.profile->resolved : s->cfg.fp;
    req.allow_tls12 = s->cfg.profile ? s->cfg.profile->allow_tls12
                                     : s->cfg.allow_tls12;

    if (s->cfg.rng) {
        qn_rng_bytes(s->cfg.rng, s->client_random, sizeof s->client_random);
        qn_rng_bytes(s->cfg.rng, s->session_id, sizeof s->session_id);
        req.grease_seed = s->cfg.profile ? s->cfg.profile->grease_seed
                                         : qn_rng_next(s->cfg.rng);
    } else {
        if (!qn_random_secure(s->client_random, sizeof s->client_random) ||
            !qn_random_secure(s->session_id, sizeof s->session_id) ||
            (!s->cfg.profile &&
             !qn_random_secure(&req.grease_seed, sizeof req.grease_seed))) {
            errno = EIO;
            return -1;
        }
        if (s->cfg.profile)
            req.grease_seed = s->cfg.profile->grease_seed;
    }
    s->session_id_len = sizeof s->session_id;
    s->hello_grease_seed = req.grease_seed;
    if (!qn_x25519_keypair(s->x_sk, s->x_pk, s->cfg.rng)) {
        errno = EIO;
        return -1;
    }

    memcpy(req.random, s->client_random, sizeof req.random);
    memcpy(req.session_id, s->session_id, sizeof req.session_id);
    memcpy(req.key_share, s->x_pk, QN_X25519_LEN);

    n = qn_tls_hello_build(&req, out, cap, &info);
    if (n < 0 || info.body_len > sizeof s->ch)
        return -1;

    memcpy(s->ch, info.body, info.body_len);
    s->ch_len = (uint16_t)info.body_len;

    s->nsigalgs = (uint8_t)(info.nsigalgs > QN_TLS_MAX_SIGALGS ? QN_TLS_MAX_SIGALGS
                                                              : info.nsigalgs);
    memcpy(s->sigalgs, info.sigalgs, (size_t)s->nsigalgs * sizeof s->sigalgs[0]);

    {
        char ja3str[QN_JA3_STR_MAX];

        /* An empty string means unknown; a wrong fingerprint would mislead. */
        if (!qn_tls_ja3(&info, ja3str, sizeof ja3str, s->ja3))
            s->ja3[0] = '\0';
        if (!qn_tls_ja4(&info, s->ja4))
            s->ja4[0] = '\0';
    }

    s->st = QN_TLS_ST_WAIT_SH;
    return n;
}

static void tr_update(qn_tls_session *s, const uint8_t *p, size_t n)
{
    if (s->tr_on)
        qn_hash_update(&s->transcript, p, n);
}

static bool derive_keys(qn_tls_session *s, qn_tls_keys *k, const uint8_t *secret)
{
    uint8_t key[QN_AEAD_KEY_MAX];
    size_t  klen = qn_aead_key_len(s->aead_id);
    bool    ok;

    ok = qn_hkdf_expand_label(s->hash, secret, "key", NULL, 0, key, klen) &&
         qn_hkdf_expand_label(s->hash, secret, "iv", NULL, 0, k->iv, QN_AEAD_IV_LEN) &&
         qn_aead_init(&k->aead, s->aead_id, key);
    k->seq = 0;
    k->on  = ok;

    qn_wipe(key, sizeof key);
    return ok;
}

static void nonce_for(const qn_tls_keys *k, uint8_t out[QN_AEAD_IV_LEN])
{
    unsigned i;
    memcpy(out, k->iv, QN_AEAD_IV_LEN);
    for (i = 0; i < 8; i++)
        out[QN_AEAD_IV_LEN - 1u - i] ^= (uint8_t)(k->seq >> (8u * i));
}

/* Builds one protected record; encryption is in place inside out. */
static int seal_record(qn_tls_session *s, uint8_t inner, const uint8_t *data, size_t len,
                       uint8_t *out, size_t cap)
{
    size_t  ct = len + 1u + QN_AEAD_TAG_LEN;
    uint8_t nonce[QN_AEAD_IV_LEN];

    if (!s->wr.on || s->wr.seq == UINT64_MAX || ct > 0xFFFFu || REC_HDR + ct > cap)
        return -1;

    out[0] = RT_APP;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (uint8_t)(ct >> 8);
    out[4] = (uint8_t)ct;
    if (len)
        memcpy(out + REC_HDR, data, len);
    out[REC_HDR + len] = inner;

    nonce_for(&s->wr, nonce);
    if (!qn_aead_seal(&s->wr.aead, nonce, out, REC_HDR, out + REC_HDR, len + 1u, out + REC_HDR))
        return -1;
    s->wr.seq++;
    return (int)(REC_HDR + ct);
}

static qn_tls_rc open_record(qn_tls_session *s, uint8_t *inner, size_t *plen)
{
    uint8_t nonce[QN_AEAD_IV_LEN];
    size_t  body = s->rec_len - REC_HDR;
    size_t  pt;

    if (!s->rd.on || s->rd.seq == UINT64_MAX || body < QN_AEAD_TAG_LEN + 1u)
        return QN_TLS_RC_PROTO;

    nonce_for(&s->rd, nonce);
    if (!qn_aead_open(&s->rd.aead, nonce, s->rec, REC_HDR, s->rec + REC_HDR, body,
                      s->rec + REC_HDR))
        return QN_TLS_RC_BADMAC;
    s->rd.seq++;

    pt = body - QN_AEAD_TAG_LEN;
    while (pt > 0 && s->rec[REC_HDR + pt - 1u] == 0)
        pt--;
    if (pt == 0)
        return QN_TLS_RC_PROTO;

    *inner = s->rec[REC_HDR + pt - 1u];
    *plen  = pt - 1u;
    return QN_TLS_RC_OK;
}

static qn_tls_rc send_second_client_hello(qn_tls_session *s, qn_tls_io *io)
{
    qn_hello_req req;
    qn_hello_info info;
    qn_hash first;
    uint8_t digest[QN_HASH_MAX];
    uint8_t message_hash[4];
    size_t hlen = qn_hash_len(s->hash);
    int written;

    if (!io->out || s->hrr_done || !s->hrr_cookie_len || !hlen)
        return QN_TLS_RC_PROTO;
    qn_hash_init(&first, s->hash);
    qn_hash_update(&first, s->ch, s->ch_len);
    qn_hash_final(&first, digest);
    message_hash[0] = HS_MESSAGE_HASH;
    message_hash[1] = 0u;
    message_hash[2] = 0u;
    message_hash[3] = (uint8_t)hlen;

    qn_hash_init(&s->transcript, s->hash);
    qn_hash_update(&s->transcript, message_hash, sizeof message_hash);
    qn_hash_update(&s->transcript, digest, hlen);
    qn_hash_update(&s->transcript, s->hs_hdr, sizeof s->hs_hdr);
    qn_hash_update(&s->transcript, s->hs, s->hs_kept);

    memset(&req, 0, sizeof req);
    req.sni = s->cfg.profile ? s->cfg.profile->sni : s->cfg.sni;
    req.fp = s->cfg.profile ? s->cfg.profile->resolved : s->cfg.fp;
    req.allow_tls12 = s->cfg.profile ? s->cfg.profile->allow_tls12
                                     : s->cfg.allow_tls12;
    req.grease_seed = s->hello_grease_seed;
    memcpy(req.random, s->client_random, sizeof req.random);
    memcpy(req.session_id, s->session_id, sizeof req.session_id);
    memcpy(req.key_share, s->x_pk, sizeof req.key_share);
    req.cookie = s->hrr_cookie;
    req.cookie_len = s->hrr_cookie_len;
    written = qn_tls_hello_build(&req, io->out + io->outlen,
                                 io->outcap - io->outlen, &info);
    if (written < 0 || info.body_len > sizeof s->ch)
        return QN_TLS_RC_SPACE;
    memcpy(s->ch, info.body, info.body_len);
    s->ch_len = (uint16_t)info.body_len;
    qn_hash_update(&s->transcript, info.body, info.body_len);
    io->outlen += (size_t)written;
    s->tr_on = true;
    s->hrr_done = true;
    qn_wipe(digest, sizeof digest);
    return QN_TLS_RC_OK;
}

static qn_tls_rc on_server_hello(qn_tls_session *s, qn_tls_io *io)
{
    br             r;
    const uint8_t *rnd, *sid, *peer_ks = NULL;
    uint16_t       seen[64];
    size_t         nseen = 0;
    uint16_t       sel_ver = 0x0303;
    uint16_t       legacy_ver;
    uint8_t        sidlen;
    uint8_t        compression;
    size_t         ext_end;
    bool           have_version = false, have_key_share = false, have_cookie = false;
    bool           have_ems = false, have_alpn = false;
    bool           is_hrr;
    uint8_t        shared[QN_X25519_LEN];
    uint8_t        early[QN_HASH_MAX], derived[QN_HASH_MAX], zeros[QN_HASH_MAX];
    qn_hash        empty;
    size_t         hlen;
    qn_tls_rc      rc = QN_TLS_RC_PROTO;

    if (s->st != QN_TLS_ST_WAIT_SH || s->hs_len != s->hs_kept)
        return QN_TLS_RC_PROTO;

    br_init(&r, s->hs, s->hs_kept);
    legacy_ver = br_u16(&r);
    rnd = br_take(&r, 32);
    if (!rnd)
        return QN_TLS_RC_PROTO;
    memcpy(s->server_random, rnd, 32);
    is_hrr = memcmp(s->server_random, HRR_RANDOM, sizeof HRR_RANDOM) == 0;
    if (is_hrr && s->hrr_done)
        return QN_TLS_RC_PROTO;

    /* 1.3 must echo our session id; 1.2 picks its own, so check after versioning. */
    sidlen = br_u8(&r);
    if (sidlen > sizeof s->session_id)
        return QN_TLS_RC_PROTO;
    sid = br_take(&r, sidlen);
    if (!sid)
        return QN_TLS_RC_PROTO;

    s->suite = br_u16(&r);
    compression = br_u8(&r);
    if (r.err || legacy_ver != 0x0303u || compression != 0u)
        return QN_TLS_RC_PROTO;

    /* TLS 1.2 may omit the extensions vector entirely; TLS 1.3 may not. */
    if (!br_left(&r)) {
        ext_end = r.off;
    } else {
        ext_end = (size_t)br_u16(&r);
        if (r.err || ext_end != br_left(&r))
            return QN_TLS_RC_PROTO;
        ext_end += r.off;
    }

    while (r.off + 4u <= ext_end) {
        uint16_t       et = br_u16(&r);
        uint16_t       el = br_u16(&r);
        const uint8_t *ev = br_take(&r, el);

        if (!ev || r.off > ext_end)
            return QN_TLS_RC_PROTO;
        if (!ext_once(seen, &nseen, QN_ARRAY_LEN(seen), et))
            return QN_TLS_RC_PROTO;

        if (et == EXT_SUPPORTED_VERSIONS) {
            if (el != 2u)
                return QN_TLS_RC_PROTO;
            sel_ver = rd16(ev);
            have_version = true;
        } else if (et == EXT_EMS) {
            if (el != 0u)
                return QN_TLS_RC_PROTO;
            s->ems = true;
            have_ems = true;
        } else if (et == EXT_ALPN) {
            if (!parse_selected_alpn(s, ev, el))
                return QN_TLS_RC_PROTO;
            have_alpn = true;
        } else if (et == EXT_KEY_SHARE) {
            if (is_hrr) {
                if (el != 2u)
                    return QN_TLS_RC_PROTO;
                if (rd16(ev) == GROUP_X25519)
                    return QN_TLS_RC_PROTO;
                return QN_TLS_RC_UNSUPPORTED;
            }
            if (el < 4u)
                return QN_TLS_RC_PROTO;
            if (rd16(ev) != GROUP_X25519)
                return QN_TLS_RC_UNSUPPORTED;
            if (rd16(ev + 2) != QN_X25519_LEN || el != 4u + QN_X25519_LEN)
                return QN_TLS_RC_PROTO;
            peer_ks = ev + 4;
            have_key_share = true;
        } else if (et == EXT_COOKIE) {
            uint16_t cookie_len;

            if (!is_hrr || el < 3u)
                return QN_TLS_RC_PROTO;
            cookie_len = rd16(ev);
            if (!cookie_len || cookie_len != el - 2u ||
                cookie_len > sizeof s->hrr_cookie)
                return QN_TLS_RC_PROTO;
            memcpy(s->hrr_cookie, ev + 2u, cookie_len);
            s->hrr_cookie_len = cookie_len;
            have_cookie = true;
        } else if (is_hrr) {
            return QN_TLS_RC_PROTO;
        }
    }
    if (r.err || r.off != ext_end || ext_end != r.len)
        return QN_TLS_RC_PROTO;

    if (is_hrr) {
        if (!have_version || sel_ver != 0x0304u ||
            sidlen != s->session_id_len || memcmp(sid, s->session_id, sidlen) != 0 ||
            have_ems || have_alpn || have_key_share || !have_cookie ||
            !suite_params(s->suite, &s->hash, &s->aead_id))
            return QN_TLS_RC_PROTO;
        s->version = 0x0304u;
        s->hrr_suite = s->suite;
        return send_second_client_hello(s, io);
    }

    if (!have_version) {
        if (!s->cfg.allow_tls12 || !qn_tls12_suite(s->suite, &s->hash, &s->aead_id))
            return QN_TLS_RC_UNSUPPORTED;
        if (have_key_share)
            return QN_TLS_RC_PROTO;
        sel_ver = 0x0303;
    } else if (sel_ver == 0x0304) {
        if (s->hrr_done && s->suite != s->hrr_suite)
            return QN_TLS_RC_PROTO;
        if (sidlen != s->session_id_len || memcmp(sid, s->session_id, sidlen) != 0)
            return QN_TLS_RC_PROTO;
        /* In TLS 1.3 ALPN and EMS are not ServerHello extensions. */
        if (have_ems || have_alpn)
            return QN_TLS_RC_PROTO;
        if (!suite_params(s->suite, &s->hash, &s->aead_id) || !have_key_share || !peer_ks)
            return QN_TLS_RC_UNSUPPORTED;
    } else {
        return QN_TLS_RC_UNSUPPORTED;
    }

    s->version = sel_ver;
    hlen       = qn_hash_len(s->hash);

    /* The suite is known, so the transcript can start with the real hash. */
    if (!s->hrr_done) {
        qn_hash_init(&s->transcript, s->hash);
        s->tr_on = true;
        qn_hash_update(&s->transcript, s->ch, s->ch_len);
        qn_hash_update(&s->transcript, s->hs_hdr, sizeof s->hs_hdr);
        qn_hash_update(&s->transcript, s->hs, s->hs_kept);
    }

    /* 1.2 keeps talking in the clear until its ChangeCipherSpec. */
    if (sel_ver == 0x0303)
        return qn_tls12_setup(s);

    if (!qn_x25519(shared, s->x_sk, peer_ks))
        return QN_TLS_RC_BADMAC;

    memset(zeros, 0, sizeof zeros);
    qn_hash_init(&empty, s->hash);
    qn_hkdf_extract(s->hash, NULL, 0, zeros, hlen, early);

    if (qn_derive_secret(s->hash, early, "derived", &empty, derived)) {
        qn_hkdf_extract(s->hash, derived, hlen, shared, sizeof shared, s->hs_secret);
        if (qn_derive_secret(s->hash, s->hs_secret, "c hs traffic", &s->transcript, s->c_traffic) &&
            qn_derive_secret(s->hash, s->hs_secret, "s hs traffic", &s->transcript, s->s_traffic) &&
            derive_keys(s, &s->rd, s->s_traffic) && derive_keys(s, &s->wr, s->c_traffic)) {
            s->st = QN_TLS_ST_WAIT_EE;
            rc    = QN_TLS_RC_OK;
        }
    }

    qn_wipe(shared, sizeof shared);
    qn_wipe(early, sizeof early);
    qn_wipe(derived, sizeof derived);
    return rc;
}


static qn_tls_rc on_encrypted_extensions(qn_tls_session *s)
{
    br     r;
    size_t end;
    uint16_t seen[64];
    size_t   nseen = 0;

    if (s->st != QN_TLS_ST_WAIT_EE || s->hs_len != s->hs_kept)
        return QN_TLS_RC_PROTO;

    br_init(&r, s->hs, s->hs_kept);
    end = (size_t)br_u16(&r);
    if (r.err || end != br_left(&r))
        return QN_TLS_RC_PROTO;
    end += r.off;

    while (r.off + 4u <= end) {
        uint16_t       et = br_u16(&r);
        uint16_t       el = br_u16(&r);
        const uint8_t *ev = br_take(&r, el);

        if (!ev || r.off > end)
            return QN_TLS_RC_PROTO;
        if (!ext_once(seen, &nseen, QN_ARRAY_LEN(seen), et))
            return QN_TLS_RC_PROTO;
        if (et == EXT_ALPN) {
            if (!parse_selected_alpn(s, ev, el))
                return QN_TLS_RC_PROTO;
        } else if (et == EXT_SERVER_NAME) {
            if (el != 0u)
                return QN_TLS_RC_PROTO;
        } else if (et == EXT_COMPRESS_CERT) {
            if (el != 2u || rd16(ev) != 2u) /* Brotli is the sole offered algorithm. */
                return QN_TLS_RC_PROTO;
        } else if (et == EXT_RECORD_SIZE_LIMIT) {
            uint16_t lim;
            if (el != 2u)
                return QN_TLS_RC_PROTO;
            lim = rd16(ev);
            if (lim < 64u || lim > 16385u)
                return QN_TLS_RC_PROTO;
        }
    }
    if (r.err || r.off != end)
        return QN_TLS_RC_PROTO;

    s->st = QN_TLS_ST_WAIT_FIN;
    return QN_TLS_RC_OK;
}

static qn_tls_rc on_certificate_request(qn_tls_session *s)
{
    br             r;
    const uint8_t *ctx;
    uint8_t        ctxlen;
    size_t         end;
    uint16_t       seen[64];
    size_t         nseen = 0;

    if (s->st != QN_TLS_ST_WAIT_FIN || s->cert_requested || s->saw_certificate ||
        s->hs_len != s->hs_kept)
        return QN_TLS_RC_PROTO;

    br_init(&r, s->hs, s->hs_kept);
    ctxlen = br_u8(&r);
    ctx = br_take(&r, ctxlen);
    if (!ctx || ctxlen != 0u) /* Initial-handshake request context is required to be empty. */
        return QN_TLS_RC_PROTO;
    end = (size_t)br_u16(&r);
    if (r.err || end != br_left(&r))
        return QN_TLS_RC_PROTO;
    end += r.off;

    while (r.off + 4u <= end) {
        uint16_t et = br_u16(&r);
        uint16_t el = br_u16(&r);
        if (!br_take(&r, el) || r.off > end ||
            !ext_once(seen, &nseen, QN_ARRAY_LEN(seen), et))
            return QN_TLS_RC_PROTO;
    }
    if (r.err || r.off != end)
        return QN_TLS_RC_PROTO;

    s->cert_requested = true;
    return QN_TLS_RC_OK;
}

static qn_tls_rc on_certificate(qn_tls_session *s, bool compressed)
{
    if (s->st != QN_TLS_ST_WAIT_FIN || s->saw_certificate || s->saw_cert_verify)
        return QN_TLS_RC_PROTO;

    if (compressed) {
        uint32_t uncompressed, clen;

        /* RFC 8879 lengths are checked against the message even when only a large chain's head is retained. */
        if (s->hs_kept < 8u)
            return QN_TLS_RC_PROTO;
        if (rd16(s->hs) != 2u) /* only brotli was offered */
            return QN_TLS_RC_UNSUPPORTED;
        uncompressed = rd24(s->hs + 2);
        clen         = rd24(s->hs + 5);
        if (!uncompressed || uncompressed > QN_TLS_CERT_MAX)
            return QN_TLS_RC_PROTO;
        if (!clen || (size_t)clen + 8u != s->hs_len)
            return QN_TLS_RC_PROTO;

        /* Sound compressed framing is still unauthenticated because decompression is unsupported. */
        s->cert_compressed = true;
        return s->cfg.cert_strict ? QN_TLS_RC_UNSUPPORTED : QN_TLS_RC_OK;
    }
    {
        const uint8_t *leaf;
        size_t         leaflen;

        if (!qn_cert13_scan_done(&s->cert13_scan))
            return QN_TLS_RC_PROTO;

        /* Display unverified peer identity so a terminating middlebox remains visible. */
        if (qn_tls_cert_leaf(s->hs, s->hs_kept, true, &leaf, &leaflen))
            qn_tls_cert_identity(leaf, leaflen, s->peer_cn, sizeof s->peer_cn, s->peer_issuer,
                                 sizeof s->peer_issuer);
    }
    s->saw_certificate = true;
    return QN_TLS_RC_OK;
}

static qn_tls_rc on_certificate_verify(qn_tls_session *s)
{
    uint16_t algorithm;
    uint16_t siglen;
    uint8_t i;
    bool offered = false;

    /* A compressed chain satisfies sequencing but never proves identity. */
    if (s->st != QN_TLS_ST_WAIT_FIN || (!s->saw_certificate && !s->cert_compressed) ||
        s->saw_cert_verify || s->hs_len != s->hs_kept || s->hs_kept < 5u)
        return QN_TLS_RC_PROTO;
    algorithm = rd16(s->hs);
    for (i = 0u; i < s->nsigalgs; i++)
        if (s->sigalgs[i] == algorithm)
            offered = true;
    if (!offered || !qn_tls_capability_sigalg(algorithm, NULL))
        return QN_TLS_RC_UNSUPPORTED;
    siglen = rd16(s->hs + 2);
    if (!siglen || (size_t)siglen + 4u != s->hs_kept)
        return QN_TLS_RC_PROTO;

    /* CertificateVerify is framed only; Finished still authenticates transcript flow. */
    s->saw_cert_verify = true;
    return QN_TLS_RC_OK;
}

static bool schedule_application(qn_tls_session *s, uint8_t *c_ap, uint8_t *s_ap)
{
    size_t  hlen = qn_hash_len(s->hash);
    uint8_t zeros[QN_HASH_MAX], derived[QN_HASH_MAX];
    qn_hash empty;
    bool    ok;

    memset(zeros, 0, sizeof zeros);
    qn_hash_init(&empty, s->hash);

    if (!qn_derive_secret(s->hash, s->hs_secret, "derived", &empty, derived))
        return false;
    qn_hkdf_extract(s->hash, derived, hlen, zeros, hlen, s->master);

    ok = qn_derive_secret(s->hash, s->master, "c ap traffic", &s->transcript, c_ap) &&
         qn_derive_secret(s->hash, s->master, "s ap traffic", &s->transcript, s_ap);

    qn_wipe(derived, sizeof derived);
    return ok;
}

static qn_tls_rc send_client_flight(qn_tls_session *s, qn_tls_io *io)
{
    static const uint8_t CCS[] = { RT_CCS, 0x03, 0x03, 0x00, 0x01, 0x01 };
    uint8_t              fkey[QN_HASH_MAX], verify[QN_HASH_MAX], th[QN_HASH_MAX];
    uint8_t              msg[4 + QN_HASH_MAX];
    static const uint8_t  EMPTY_CERT[] = { HS_CERT, 0, 0, 4, 0, 0, 0, 0 };
    uint8_t              c_ap[QN_HASH_MAX], s_ap[QN_HASH_MAX];
    size_t               hlen = qn_hash_len(s->hash);
    qn_tls_rc            rc   = QN_TLS_RC_PROTO;
    int                  n;

    {
        size_t cert_wire = s->cert_requested ? REC_HDR + sizeof EMPTY_CERT + 1u + QN_AEAD_TAG_LEN : 0u;
        size_t fin_wire  = REC_HDR + 4u + hlen + 1u + QN_AEAD_TAG_LEN;
        if (io->outlen > io->outcap || io->outcap - io->outlen < sizeof CCS + cert_wire + fin_wire)
            return QN_TLS_RC_SPACE;
    }

    /* Application secrets are fixed at the server Finished boundary. */
    if (!schedule_application(s, c_ap, s_ap))
        goto out;

    if (io->outlen + sizeof CCS > io->outcap)
        return QN_TLS_RC_SPACE;
    memcpy(io->out + io->outlen, CCS, sizeof CCS);
    io->outlen += sizeof CCS;

    if (s->cert_requested) {
        n = seal_record(s, RT_HS, EMPTY_CERT, sizeof EMPTY_CERT, io->out + io->outlen,
                        io->outcap - io->outlen);
        if (n < 0)
            goto out;
        io->outlen += (size_t)n;
        qn_hash_update(&s->transcript, EMPTY_CERT, sizeof EMPTY_CERT);
    }

    if (!qn_hkdf_expand_label(s->hash, s->c_traffic, "finished", NULL, 0, fkey, hlen))
        goto out;

    qn_hash_final(&s->transcript, th);
    qn_hmac_once(s->hash, fkey, hlen, th, hlen, verify);

    msg[0] = HS_FINISHED;
    msg[1] = 0;
    msg[2] = (uint8_t)(hlen >> 8);
    msg[3] = (uint8_t)hlen;
    memcpy(msg + 4, verify, hlen);

    n = seal_record(s, RT_HS, msg, 4u + hlen, io->out + io->outlen, io->outcap - io->outlen);
    if (n < 0) {
        rc = QN_TLS_RC_SPACE;
        goto out;
    }
    io->outlen += (size_t)n;

    qn_hash_update(&s->transcript, msg, 4u + hlen);

    if (!derive_keys(s, &s->wr, c_ap) || !derive_keys(s, &s->rd, s_ap))
        goto out;

    s->st = QN_TLS_ST_READY;
    rc    = QN_TLS_RC_DONE;

out:
    qn_wipe(fkey, sizeof fkey);
    qn_wipe(verify, sizeof verify);
    qn_wipe(th, sizeof th);
    qn_wipe(msg, sizeof msg);
    qn_wipe(c_ap, sizeof c_ap);
    qn_wipe(s_ap, sizeof s_ap);
    return rc;
}

static qn_tls_rc on_server_finished(qn_tls_session *s, qn_tls_io *io)
{
    uint8_t   fkey[QN_HASH_MAX], expect[QN_HASH_MAX], th[QN_HASH_MAX];
    size_t    hlen = qn_hash_len(s->hash);
    qn_tls_rc rc;

    /* A compressed chain proves the flight happened, not who sent it. */
    if ((!s->saw_certificate && !s->cert_compressed) || !s->saw_cert_verify ||
        s->hs_len != hlen || s->hs_kept != hlen)
        return QN_TLS_RC_PROTO;

    if (!qn_hkdf_expand_label(s->hash, s->s_traffic, "finished", NULL, 0, fkey, hlen))
        return QN_TLS_RC_PROTO;

    qn_hash_final(&s->tr_fin, th);
    qn_hmac_once(s->hash, fkey, hlen, th, hlen, expect);

    rc = qn_ct_eq(expect, s->hs, hlen) ? QN_TLS_RC_OK : QN_TLS_RC_BADMAC;

    qn_wipe(fkey, sizeof fkey);
    qn_wipe(expect, sizeof expect);
    qn_wipe(th, sizeof th);

    if (rc != QN_TLS_RC_OK)
        return rc;
    return send_client_flight(s, io);
}

qn_tls_rc qn_tls13_dispatch(qn_tls_session *s, qn_tls_io *io)
{
    if (s->hs_type == HS_SERVER_HELLO)
        return on_server_hello(s, io);
    if (s->version == 0x0303)
        return qn_tls12_dispatch(s, io);

    switch (s->hs_type) {

    case HS_ENCRYPTED_EXT:
        return on_encrypted_extensions(s);

    /* Certificate identity is out of scope; ordering/framing and Finished are not. */
    case HS_CERT:
        return on_certificate(s, false);
    case HS_COMPRESSED_CERT:
        return on_certificate(s, true);
    case HS_CERT_REQ:
        return on_certificate_request(s);
    case HS_CERT_VERIFY:
        return on_certificate_verify(s);

    case HS_FINISHED:
        if (s->st != QN_TLS_ST_WAIT_FIN)
            return QN_TLS_RC_PROTO;
        return on_server_finished(s, io);

    case HS_NEW_TICKET:
        return s->st == QN_TLS_ST_READY ? QN_TLS_RC_OK : QN_TLS_RC_PROTO;

    case HS_KEY_UPDATE:
        /* KeyUpdate is unsupported because accepting it without rekeying would manufacture failures. */
        if (s->st != QN_TLS_ST_READY || s->hs_len != s->hs_kept || s->hs_kept != 1u)
            return QN_TLS_RC_PROTO;
        if (s->hs[0] > 1u)
            return QN_TLS_RC_PROTO; /* only update_not_requested and _requested */
        return QN_TLS_RC_UNSUPPORTED;

    default:
        return QN_TLS_RC_PROTO;
    }
}

static qn_tls_rc hs_feed(qn_tls_session *s, const uint8_t *p, size_t n, qn_tls_io *io,
                         bool *done)
{
    while (n) {
        if (!s->hs_active) {
            size_t take = sizeof s->hs_hdr - s->hs_got;
            if (take > n)
                take = n;
            memcpy(s->hs_hdr + s->hs_got, p, take);
            s->hs_got += (uint32_t)take;
            p += take;
            n -= take;
            if (s->hs_got < sizeof s->hs_hdr)
                return QN_TLS_RC_OK;

            s->hs_type = s->hs_hdr[0];
            s->hs_len  = rd24(s->hs_hdr + 1);

            /* The peer's Finished is checked against the transcript before it. */
            if (s->hs_type == HS_FINISHED)
                s->tr_fin = s->transcript;

            tr_update(s, s->hs_hdr, sizeof s->hs_hdr);
            s->hs_active = true;
            s->hs_got    = 0;
            s->hs_kept   = 0;
            if (s->hs_type == HS_CERT) {
                if (s->version == 0x0303)
                    qn_cert_scan_init(&s->cert_scan, s->hs_len, QN_TLS_CERT_MAX);
                else {
                    qn_cert13_scan_init(&s->cert13_scan, s->hs_len, QN_TLS_CERT_MAX);
                    if (s->cert13_scan.state == QN_CERT13_FAILED)
                        return QN_TLS_RC_PROTO;
                }
            }
        }

        {
            size_t take = s->hs_len - s->hs_got;
            if (take > n)
                take = n;
            tr_update(s, p, take);
            if (s->hs_type == HS_CERT && s->version == 0x0303 &&
                !qn_cert_scan_push(&s->cert_scan, p, take))
                return QN_TLS_RC_PROTO;
            if (s->hs_type == HS_CERT && s->version != 0x0303 &&
                !qn_cert13_scan_push(&s->cert13_scan, p, take))
                return QN_TLS_RC_PROTO;
            if (s->hs_kept < QN_TLS_HS_BUF) {
                size_t keep = QN_TLS_HS_BUF - s->hs_kept;
                if (keep > take)
                    keep = take;
                memcpy(s->hs + s->hs_kept, p, keep);
                s->hs_kept += (uint32_t)keep;
            }
            s->hs_got += (uint32_t)take;
            p += take;
            n -= take;
            if (s->hs_got < s->hs_len)
                return QN_TLS_RC_OK;
        }

        {
            qn_tls_rc rc = qn_tls13_dispatch(s, io);
            s->hs_active = false;
            s->hs_got    = 0;
            if (rc == QN_TLS_RC_DONE)
                *done = true;
            else if (rc != QN_TLS_RC_OK)
                return rc;
        }
    }
    return QN_TLS_RC_OK;
}

static qn_tls_rc handle_record(qn_tls_session *s, qn_tls_io *io, bool *done)
{
    uint8_t  type  = s->rec[0];
    uint8_t  inner = type;
    uint8_t *body  = s->rec + REC_HDR;
    size_t   blen  = s->rec_len - REC_HDR;

    if (type == RT_CCS) {
        if (blen != 1u || body[0] != 1u || s->saw_ccs || s->st == QN_TLS_ST_READY ||
            s->st == QN_TLS_ST_CLOSED)
            return QN_TLS_RC_PROTO;
        s->saw_ccs = true;
        if (s->version == 0x0303)
            qn_tls12_on_ccs(s);
        return QN_TLS_RC_OK;
    }

    if (s->version == 0x0303) {
        if (s->rd.on) {
            qn_tls_rc rc = qn_tls12_open(s, type, &blen);
            if (rc != QN_TLS_RC_OK)
                return rc;
        }
    } else if (s->rd.on) {
        qn_tls_rc rc;

        if (type != RT_APP)
            return QN_TLS_RC_PROTO;
        rc = open_record(s, &inner, &blen);
        if (rc != QN_TLS_RC_OK)
            return rc;
    }

    switch (inner) {
    case RT_ALERT:
        if (blen >= 2)
            s->alert_desc = body[1];
        s->st = QN_TLS_ST_CLOSED;
        return QN_TLS_RC_ALERT;

    case RT_HS:
        return hs_feed(s, body, blen, io, done);

    case RT_APP:
        if (s->st != QN_TLS_ST_READY)
            return QN_TLS_RC_PROTO;
        if (io->applen + blen > io->appcap)
            return QN_TLS_RC_SPACE;
        memcpy(io->app + io->applen, body, blen);
        io->applen += blen;
        return QN_TLS_RC_OK;

    default:
        return QN_TLS_RC_PROTO;
    }
}

qn_tls_rc qn_tls_recv(qn_tls_session *s, qn_tls_io *io)
{
    bool done = false;

    io->consumed = 0;
    io->outlen   = 0;
    io->applen   = 0;

    for (;;) {
        size_t need, take, avail;

        if (s->rec_len < REC_HDR) {
            avail = io->inlen - io->consumed;
            take  = REC_HDR - s->rec_len;
            if (take > avail)
                take = avail;
            memcpy(s->rec + s->rec_len, io->in + io->consumed, take);
            s->rec_len += take;
            io->consumed += take;
            if (s->rec_len < REC_HDR)
                return done ? QN_TLS_RC_DONE : QN_TLS_RC_MORE;
        }

        need = REC_HDR + (size_t)rd16(s->rec + 3);
        if (s->rec[0] < RT_CCS || s->rec[0] > RT_APP || s->rec[1] != 0x03u ||
            s->rec[2] < 0x01u || s->rec[2] > 0x03u || need > QN_TLS_REC_MAX ||
            (!s->rd.on && need - REC_HDR > REC_MAXPT))
            return QN_TLS_RC_PROTO;

        if (s->rec_len < need) {
            avail = io->inlen - io->consumed;
            take  = need - s->rec_len;
            if (take > avail)
                take = avail;
            memcpy(s->rec + s->rec_len, io->in + io->consumed, take);
            s->rec_len += take;
            io->consumed += take;
            if (s->rec_len < need)
                return done ? QN_TLS_RC_DONE : QN_TLS_RC_MORE;
        }

        {
            qn_tls_rc rc = handle_record(s, io, &done);
            s->rec_len   = 0;
            if (rc != QN_TLS_RC_OK)
                return rc;
        }
    }
}

int qn_tls_send_app(qn_tls_session *s, const uint8_t *data, size_t len, uint8_t *out, size_t cap)
{
    size_t written = 0;

    if (s->st != QN_TLS_ST_READY)
        return -1;

    do {
        size_t chunk = len < REC_MAXPT ? len : REC_MAXPT;
        int    n = s->version == 0x0303
                       ? qn_tls12_seal(s, RT_APP, data, chunk, out + written, cap - written)
                       : seal_record(s, RT_APP, data, chunk, out + written, cap - written);
        if (n < 0)
            return -1;
        written += (size_t)n;
        data += chunk;
        len -= chunk;
    } while (len);

    return (int)written;
}
