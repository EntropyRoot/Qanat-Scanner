/* HMAC (RFC 2104), HKDF (RFC 5869), TLS 1.3 Expand-Label and the TLS 1.2 PRF. */

#include "qanat/crypto.h"

#include <string.h>

void qn_hmac_init(qn_hmac *m, qn_hash_id id, const uint8_t *key, size_t klen)
{
    size_t  blk = qn_hash_block(id);
    uint8_t k[QN_BLOCK_MAX];
    uint8_t pad[QN_BLOCK_MAX];
    size_t  i;

    memset(k, 0, sizeof k);
    if (klen > blk) {
        qn_hash t;
        qn_hash_init(&t, id);
        qn_hash_update(&t, key, klen);
        qn_hash_final(&t, k);
    } else if (klen) {
        memcpy(k, key, klen);
    }

    for (i = 0; i < blk; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x36u);
    qn_hash_init(&m->inner, id);
    qn_hash_update(&m->inner, pad, blk);

    for (i = 0; i < blk; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x5cu);
    qn_hash_init(&m->outer, id);
    qn_hash_update(&m->outer, pad, blk);

    qn_wipe(k, sizeof k);
    qn_wipe(pad, sizeof pad);
}

void qn_hmac_update(qn_hmac *m, const void *p, size_t n)
{
    qn_hash_update(&m->inner, p, n);
}

void qn_hmac_final(const qn_hmac *m, uint8_t *out)
{
    uint8_t ih[QN_HASH_MAX];
    qn_hash o = m->outer;

    qn_hash_final(&m->inner, ih);
    qn_hash_update(&o, ih, qn_hash_len(m->inner.id));
    qn_hash_final(&o, out);

    qn_wipe(ih, sizeof ih);
    qn_wipe(&o, sizeof o);
}

void qn_hmac_once(qn_hash_id id, const uint8_t *key, size_t klen, const void *msg, size_t mlen,
                  uint8_t *out)
{
    qn_hmac m;
    qn_hmac_init(&m, id, key, klen);
    qn_hmac_update(&m, msg, mlen);
    qn_hmac_final(&m, out);
    qn_wipe(&m, sizeof m);
}

void qn_hkdf_extract(qn_hash_id id, const uint8_t *salt, size_t slen, const uint8_t *ikm,
                     size_t ilen, uint8_t *prk)
{
    static const uint8_t zero[QN_HASH_MAX] = { 0 };
    if (!salt || !slen) {
        salt = zero;
        slen = qn_hash_len(id);
    }
    qn_hmac_once(id, salt, slen, ikm, ilen, prk);
}

bool qn_hkdf_expand(qn_hash_id id, const uint8_t *prk, const uint8_t *info, size_t ilen,
                    uint8_t *out, size_t olen)
{
    size_t  hlen = qn_hash_len(id);
    size_t  done = 0, tlen = 0;
    uint8_t t[QN_HASH_MAX];
    uint8_t ctr = 1;

    if (olen > 255u * hlen)
        return false;

    while (done < olen) {
        qn_hmac m;
        size_t  take;

        qn_hmac_init(&m, id, prk, hlen);
        if (tlen)
            qn_hmac_update(&m, t, tlen);
        if (ilen)
            qn_hmac_update(&m, info, ilen);
        qn_hmac_update(&m, &ctr, 1);
        qn_hmac_final(&m, t);
        qn_wipe(&m, sizeof m);

        tlen = hlen;
        take = olen - done < hlen ? olen - done : hlen;
        memcpy(out + done, t, take);
        done += take;
        ctr++;
    }

    qn_wipe(t, sizeof t);
    return true;
}

bool qn_hkdf_expand_label(qn_hash_id id, const uint8_t *secret, const char *label,
                          const uint8_t *ctx, size_t ctxlen, uint8_t *out, size_t olen)
{
    uint8_t info[2 + 1 + 255 + 1 + 255];
    size_t  llen = strlen(label);
    size_t  n    = 0;

    if (llen + 6u > 255u || ctxlen > 255u || olen > 0xFFFFu)
        return false;

    info[n++] = (uint8_t)(olen >> 8);
    info[n++] = (uint8_t)olen;
    info[n++] = (uint8_t)(6u + llen);
    memcpy(info + n, "tls13 ", 6);
    n += 6;
    memcpy(info + n, label, llen);
    n += llen;
    info[n++] = (uint8_t)ctxlen;
    if (ctxlen) {
        memcpy(info + n, ctx, ctxlen);
        n += ctxlen;
    }

    return qn_hkdf_expand(id, secret, info, n, out, olen);
}

bool qn_derive_secret(qn_hash_id id, const uint8_t *secret, const char *label,
                      const qn_hash *transcript, uint8_t *out)
{
    uint8_t th[QN_HASH_MAX];
    size_t  hlen = qn_hash_len(id);

    qn_hash_final(transcript, th);
    return qn_hkdf_expand_label(id, secret, label, th, hlen, out, hlen);
}

bool qn_tls12_prf(qn_hash_id id, const uint8_t *secret, size_t seclen, const char *label,
                  const uint8_t *seed, size_t seedlen, uint8_t *out, size_t olen)
{
    size_t  hlen = qn_hash_len(id);
    size_t  llen = strlen(label);
    size_t  done = 0;
    uint8_t a[QN_HASH_MAX];
    qn_hmac m;

    qn_hmac_init(&m, id, secret, seclen);
    qn_hmac_update(&m, label, llen);
    qn_hmac_update(&m, seed, seedlen);
    qn_hmac_final(&m, a);

    while (done < olen) {
        uint8_t blk[QN_HASH_MAX];
        size_t  take;

        qn_hmac_init(&m, id, secret, seclen);
        qn_hmac_update(&m, a, hlen);
        qn_hmac_update(&m, label, llen);
        qn_hmac_update(&m, seed, seedlen);
        qn_hmac_final(&m, blk);

        take = olen - done < hlen ? olen - done : hlen;
        memcpy(out + done, blk, take);
        done += take;
        qn_wipe(blk, sizeof blk);

        qn_hmac_init(&m, id, secret, seclen);
        qn_hmac_update(&m, a, hlen);
        qn_hmac_final(&m, a);
    }

    qn_wipe(a, sizeof a);
    qn_wipe(&m, sizeof m);
    return true;
}
