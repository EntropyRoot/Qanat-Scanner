/* JA3 and JA4 over the ClientHello we actually emitted. */

#include "qanat/tls_hello.h"

#include <stdio.h>
#include <string.h>

#define JA4_SNI_EXT  0x0000
#define JA4_ALPN_EXT 0x0010

#define JA4_LIST_MAX     (QN_HELLO_MAX_CIPHERS > QN_HELLO_MAX_EXTS ? QN_HELLO_MAX_CIPHERS : QN_HELLO_MAX_EXTS)

typedef struct {
    char  *p;
    size_t cap, len;
    bool   cut; /* a dropped byte would change the digest, so it is reported */
} sb;

static void sb_init(sb *s, char *buf, size_t cap)
{
    s->p   = buf;
    s->cap = cap;
    s->len = 0;
    s->cut = false;
    if (cap)
        buf[0] = 0;
}

static void sb_putc(sb *s, char c)
{
    if (s->len + 1u < s->cap) {
        s->p[s->len++] = c;
        s->p[s->len]   = 0;
    } else {
        s->cut = true;
    }
}

static void sb_u16(sb *s, uint16_t v)
{
    char     tmp[6];
    int      n = snprintf(tmp, sizeof tmp, "%u", (unsigned)v);
    int      i;
    for (i = 0; i < n; i++)
        sb_putc(s, tmp[i]);
}

static void sb_hex16(sb *s, uint16_t v)
{
    static const char D[] = "0123456789abcdef";
    sb_putc(s, D[(v >> 12) & 15u]);
    sb_putc(s, D[(v >> 8) & 15u]);
    sb_putc(s, D[(v >> 4) & 15u]);
    sb_putc(s, D[v & 15u]);
}

static void sb_join_dec(sb *s, const uint16_t *v, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (i)
            sb_putc(s, '-');
        sb_u16(s, v[i]);
    }
}

static void hexlify(const uint8_t *in, size_t n, char *out)
{
    static const char D[] = "0123456789abcdef";
    size_t            i;
    for (i = 0; i < n; i++) {
        out[2u * i]      = D[in[i] >> 4];
        out[2u * i + 1u] = D[in[i] & 15u];
    }
    out[2u * n] = 0;
}

bool qn_tls_ja3(const qn_hello_info *info, char *str, size_t strcap, char hash[33])
{
    uint8_t digest[16];
    sb      s;
    size_t  i;

    sb_init(&s, str, strcap);
    sb_u16(&s, 0x0303); /* the legacy_version field of the hello */
    sb_putc(&s, ',');
    sb_join_dec(&s, info->ciphers, info->nciphers);
    sb_putc(&s, ',');
    sb_join_dec(&s, info->exts, info->nexts);
    sb_putc(&s, ',');
    sb_join_dec(&s, info->groups, info->ngroups);
    sb_putc(&s, ',');
    for (i = 0; i < info->necpf; i++) {
        if (i)
            sb_putc(&s, '-');
        sb_u16(&s, info->ecpf[i]);
    }

    if (info->overflow || s.cut) {
        hash[0] = 0;
        return false;
    }
    qn_md5(s.p, s.len, digest);
    hexlify(digest, sizeof digest, hash);
    return true;
}

static void sort_u16(uint16_t *v, size_t n)
{
    size_t i, j;
    for (i = 1; i < n; i++) {
        uint16_t k = v[i];
        for (j = i; j > 0 && v[j - 1u] > k; j--)
            v[j] = v[j - 1u];
        v[j] = k;
    }
}

static void sha256_trunc12(const char *s, size_t n, char out[13])
{
    uint8_t   d[QN_SHA256_LEN];
    char      full[2 * QN_SHA256_LEN + 1];
    qn_sha256 h;

    qn_sha256_init(&h);
    qn_sha256_update(&h, s, n);
    qn_sha256_final(&h, d);
    hexlify(d, sizeof d, full);
    memcpy(out, full, 12);
    out[12] = 0;
}

bool qn_tls_ja4(const qn_hello_info *info, char out[40])
{
    char     buf[512];
    char     a[13], b[13];
    /* One scratch list serves both, so it must hold the longer of the two. */
    uint16_t tmp[JA4_LIST_MAX];
    bool     cut = false;
    size_t   n, i;
    uint16_t maxver = 0x0303;
    const char *vs;
    char     alpn[3];
    sb       s;

    for (i = 0; i < info->nversions; i++)
        if (info->versions[i] > maxver && info->versions[i] <= 0x0304)
            maxver = info->versions[i];
    switch (maxver) {
    case 0x0304: vs = "13"; break;
    case 0x0303: vs = "12"; break;
    case 0x0302: vs = "11"; break;
    default:     vs = "10"; break;
    }

    if (info->alpn_first[0]) {
        size_t l      = strlen(info->alpn_first);
        alpn[0]       = info->alpn_first[0];
        alpn[1]       = info->alpn_first[l - 1u];
    } else {
        alpn[0] = '0';
        alpn[1] = '0';
    }
    alpn[2] = 0;

    /* Sorted cipher list, GREASE already excluded when the hello was written. */
    n = info->nciphers < JA4_LIST_MAX ? info->nciphers : JA4_LIST_MAX;
    memcpy(tmp, info->ciphers, n * sizeof tmp[0]);
    sort_u16(tmp, n);
    sb_init(&s, buf, sizeof buf);
    for (i = 0; i < n; i++) {
        if (i)
            sb_putc(&s, ',');
        sb_hex16(&s, tmp[i]);
    }
    cut = cut || s.cut;
    sha256_trunc12(s.p, s.len, a);

    /* Extensions are sorted with SNI and ALPN removed, then the sigalgs in order. */
    n = 0;
    for (i = 0; i < info->nexts; i++) {
        if (info->exts[i] == JA4_SNI_EXT || info->exts[i] == JA4_ALPN_EXT)
            continue;
        if (n < JA4_LIST_MAX)
            tmp[n++] = info->exts[i];
    }
    sort_u16(tmp, n);
    sb_init(&s, buf, sizeof buf);
    for (i = 0; i < n; i++) {
        if (i)
            sb_putc(&s, ',');
        sb_hex16(&s, tmp[i]);
    }
    if (info->nsigalgs) {
        sb_putc(&s, '_');
        for (i = 0; i < info->nsigalgs; i++) {
            if (i)
                sb_putc(&s, ',');
            sb_hex16(&s, info->sigalgs[i]);
        }
    }
    cut = cut || s.cut;
    sha256_trunc12(s.p, s.len, b);

    if (info->overflow || cut) {
        out[0] = 0;
        return false;
    }
    snprintf(out, 40, "t%s%c%02u%02u%s_%s_%s", vs, info->has_sni ? 'd' : 'i',
             (unsigned)(info->nciphers > 99 ? 99 : info->nciphers),
             (unsigned)(info->nexts > 99 ? 99 : info->nexts), alpn, a, b);
    return true;
}
