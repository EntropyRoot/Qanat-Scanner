/* Reads who answered out of the leaf certificate. Verifies nothing. */

#include "qanat/tls.h"

#include <string.h>

#define ASN1_INTEGER  0x02
#define ASN1_BITSTR   0x03
#define ASN1_OID      0x06
#define ASN1_SEQUENCE 0x30
#define ASN1_SET      0x31
#define ASN1_CTX0     0xA0

typedef struct {
    const uint8_t *p, *end;
} der;

/* Reads one TLV; leaves r positioned after it. */
static bool der_next(der *r, uint8_t *tag, const uint8_t **val, size_t *vlen)
{
    size_t len, nb;

    if (r->p + 2 > r->end)
        return false;
    *tag = *r->p++;

    if (*r->p < 0x80u) {
        len = *r->p++;
    } else {
        nb = (size_t)(*r->p++ & 0x7Fu);
        if (!nb || nb > 4u || r->p + nb > r->end)
            return false;
        len = 0;
        while (nb--)
            len = (len << 8) | *r->p++;
    }

    if (len > (size_t)(r->end - r->p))
        return false;
    *val  = r->p;
    *vlen = len;
    r->p += len;
    return true;
}

static bool der_into(der *r, uint8_t want, der *inner)
{
    uint8_t        tag;
    const uint8_t *v;
    size_t         n;

    if (!der_next(r, &tag, &v, &n) || tag != want)
        return false;
    inner->p   = v;
    inner->end = v + n;
    return true;
}

static bool der_skip(der *r)
{
    uint8_t        tag;
    const uint8_t *v;
    size_t         n;
    return der_next(r, &tag, &v, &n);
}

static void copy_text(const uint8_t *v, size_t n, char *out, size_t cap)
{
    size_t i, k = 0;

    for (i = 0; i < n && k + 1u < cap; i++) {
        uint8_t c = v[i];
        out[k++]  = (c >= 0x20u && c < 0x7Fu) ? (char)c : '?';
    }
    out[k] = 0;
}

/* Walks an RDNSequence for one attribute OID and copies its value. */
static bool name_field(der name, const uint8_t *oid, size_t oidlen, char *out, size_t cap)
{
    while (name.p < name.end) {
        der set;

        if (!der_into(&name, ASN1_SET, &set))
            return false;

        while (set.p < set.end) {
            der            pair;
            uint8_t        tag;
            const uint8_t *v;
            size_t         n;

            if (!der_into(&set, ASN1_SEQUENCE, &pair))
                break;
            if (!der_next(&pair, &tag, &v, &n) || tag != ASN1_OID)
                break;
            if (n == oidlen && memcmp(v, oid, oidlen) == 0) {
                if (der_next(&pair, &tag, &v, &n)) {
                    copy_text(v, n, out, cap);
                    return true;
                }
                return false;
            }
        }
    }
    return false;
}

bool qn_tls_cert_identity(const uint8_t *der_cert, size_t len, char *cn, size_t cn_cap,
                          char *issuer, size_t issuer_cap)
{
    static const uint8_t OID_CN[] = { 0x55, 0x04, 0x03 };
    static const uint8_t OID_O[]  = { 0x55, 0x04, 0x0A };
    der                  top, cert, tbs, issuer_name, subject_name;
    uint8_t              tag;
    const uint8_t       *v;
    size_t               n;
    bool                 got = false;

    if (cn_cap)
        cn[0] = 0;
    if (issuer_cap)
        issuer[0] = 0;
    if (!der_cert || len < 16u)
        return false;

    top.p   = der_cert;
    top.end = der_cert + len;
    if (!der_into(&top, ASN1_SEQUENCE, &cert))
        return false;
    if (!der_into(&cert, ASN1_SEQUENCE, &tbs))
        return false;

    /* optional [0] version, then serial and the signature algorithm */
    if (tbs.p < tbs.end && *tbs.p == ASN1_CTX0 && !der_skip(&tbs))
        return false;
    if (!der_next(&tbs, &tag, &v, &n) || tag != ASN1_INTEGER)
        return false;
    if (!der_skip(&tbs))
        return false;

    if (der_into(&tbs, ASN1_SEQUENCE, &issuer_name)) {
        if (name_field(issuer_name, OID_O, sizeof OID_O, issuer, issuer_cap) ||
            name_field(issuer_name, OID_CN, sizeof OID_CN, issuer, issuer_cap))
            got = true;
    }

    if (!der_skip(&tbs)) /* validity */
        return got;
    if (der_into(&tbs, ASN1_SEQUENCE, &subject_name)) {
        if (name_field(subject_name, OID_CN, sizeof OID_CN, cn, cn_cap))
            got = true;
    }

    (void)ASN1_BITSTR;
    return got;
}

/* Only the leaf is used; TLS 1.3 prefixes its certificate list with a request context. */
bool qn_tls_cert_leaf(const uint8_t *msg, size_t len, bool tls13, const uint8_t **out,
                      size_t *outlen)
{
    size_t off = 0, list, one;

    if (tls13) {
        if (len < 1u)
            return false;
        off = 1u + msg[0];
    }
    if (off + 3u > len)
        return false;

    list = ((size_t)msg[off] << 16) | ((size_t)msg[off + 1] << 8) | msg[off + 2];
    off += 3u;
    if (!list || off + 3u > len)
        return false;

    one = ((size_t)msg[off] << 16) | ((size_t)msg[off + 1] << 8) | msg[off + 2];
    off += 3u;
    if (!one || off >= len)
        return false;

    /* A truncated buffer is passed to the bounded DER walker for a clean failure. */
    *out    = msg + off;
    *outlen = one < len - off ? one : len - off;
    return true;
}
