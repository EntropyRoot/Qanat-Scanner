/* ClientHello construction, shaped per fingerprint profile. */

#include "qanat/tls_hello.h"
#include "qanat/tls_capability.h"

#include <stdio.h>
#include <string.h>

#define REC_HDR_LEN 5
#define HS_HDR_LEN  4
#define EXT_HDR_LEN 4

typedef struct {
    uint8_t *p;
    size_t   cap, len;
    bool     err;
} bw;

static void w8(bw *w, uint8_t v)
{
    if (w->len + 1 > w->cap) {
        w->err = true;
        return;
    }
    w->p[w->len++] = v;
}

static void w16(bw *w, uint16_t v)
{
    w8(w, (uint8_t)(v >> 8));
    w8(w, (uint8_t)v);
}

static void wbuf(bw *w, const void *src, size_t n)
{
    if (w->len + n > w->cap) {
        w->err = true;
        return;
    }
    memcpy(w->p + w->len, src, n);
    w->len += n;
}

static size_t mark16(bw *w)
{
    size_t at = w->len;
    w16(w, 0);
    return at;
}

static void patch16(bw *w, size_t at)
{
    size_t n;
    if (w->err || at + 2 > w->len)
        return;
    n            = w->len - at - 2;
    w->p[at]     = (uint8_t)(n >> 8);
    w->p[at + 1] = (uint8_t)n;
}

static size_t mark24(bw *w)
{
    size_t at = w->len;
    w8(w, 0);
    w16(w, 0);
    return at;
}

static void patch24(bw *w, size_t at)
{
    size_t n;
    if (w->err || at + 3 > w->len)
        return;
    n            = w->len - at - 3;
    w->p[at]     = (uint8_t)(n >> 16);
    w->p[at + 1] = (uint8_t)(n >> 8);
    w->p[at + 2] = (uint8_t)n;
}

static size_t ext_open(bw *w, uint16_t id)
{
    w16(w, id);
    return mark16(w);
}

static size_t ext_open_grease(bw *w, uint16_t g)
{
    w16(w, g);
    return mark16(w);
}

/* RFC 8701: 0x?a?a with both nibbles equal. */
static uint16_t grease_of(uint8_t nibble)
{
    uint16_t b = (uint16_t)(((nibble & 15u) << 4) | 0x0Au);
    return (uint16_t)(b * 0x0101u);
}

static bool is_grease(uint16_t value)
{
    uint8_t hi = (uint8_t)(value >> 8);
    uint8_t lo = (uint8_t)value;

    return hi == lo && (lo & 0x0Fu) == 0x0Au;
}

static bool is_tls13_suite(uint16_t suite)
{
    return qn_tls_capability_suite(suite, 0x0304u, NULL, NULL, NULL);
}

typedef struct {
    uint16_t cipher, ext_a, ext_b, group, version;
} greases;

static void greases_from(uint64_t seed, greases *g)
{
    uint64_t x = seed;
    uint8_t  n[5] = { 0 };
    unsigned i;

    for (i = 0; i < 5; i++) {
        x += 0x9E3779B97F4A7C15ull;
        {
            uint64_t z = x;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
            n[i] = (uint8_t)((z ^ (z >> 31)) & 15u);
        }
    }
    g->cipher  = grease_of(n[0]);
    g->ext_a   = grease_of(n[1]);
    if (n[2] == n[1])
        n[2] = (uint8_t)((n[2] + 1u) & 15u);
    g->ext_b   = grease_of(n[2]);
    g->group   = grease_of(n[3]);
    g->version = grease_of(n[4]);
}

static const uint16_t SUITES_CHROME[] = { 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F,
                                          0xC02C, 0xC030, 0xCCA9, 0xCCA8 };
static const uint16_t SUITES_FIREFOX[] = { 0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9,
                                           0xCCA8, 0xC02C, 0xC030 };
static const uint16_t SUITES_SAFARI[] = { 0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xCCA9,
                                          0xC030, 0xC02F, 0xCCA8 };

static const uint16_t GROUPS_CHROME[]  = { 0x001D };
static const uint16_t GROUPS_FIREFOX[] = { 0x001D };
static const uint16_t GROUPS_SAFARI[]  = { 0x001D };

static const uint16_t SIGALGS_CHROME[] = { 0x0403, 0x0804, 0x0503, 0x0805, 0x0603, 0x0806 };
static const uint16_t SIGALGS_FIREFOX[] = { 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806 };
static const uint16_t SIGALGS_SAFARI[] = { 0x0403, 0x0804, 0x0503, 0x0805, 0x0603, 0x0806 };

static const uint8_t ALPN_H2[] = { 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1' };

/* Slots, not extension ids: GREASE and padding are positions, not real types. */
typedef enum {
    S_GREASE_A = 1,
    S_GREASE_B,
    S_PAD,
    S_SNI,
    S_EMS,
    S_RENEG,
    S_GROUPS,
    S_ECPF,
    S_TICKET,
    S_ALPN,
    S_STATUS,
    S_SIGALG,
    S_SCT,
    S_KSHARE,
    S_PSKMODE,
    S_VERS,
    S_CCERT,
    S_RECSZ,
    S_DELEG,
    S_ALPS
} slot;

static const uint8_t ORDER_CHROME[] = { S_GREASE_A, S_SNI, S_EMS, S_GROUPS, S_ECPF,
                                        S_ALPN, S_SIGALG, S_KSHARE, S_VERS, S_GREASE_B, S_PAD };
static const uint8_t ORDER_FIREFOX[] = { S_SNI, S_EMS, S_GROUPS, S_ECPF, S_ALPN,
                                         S_KSHARE, S_VERS, S_SIGALG, S_PAD };
static const uint8_t ORDER_SAFARI[] = { S_GREASE_A, S_SNI, S_EMS, S_GROUPS, S_ECPF,
                                        S_ALPN, S_SIGALG, S_KSHARE, S_VERS, S_GREASE_B, S_PAD };

typedef struct {
    const uint16_t *suites;
    uint8_t         nsuites;
    const uint16_t *groups;
    uint8_t         ngroups;
    const uint16_t *sigalgs;
    uint8_t         nsigalgs;
    const uint8_t  *order;
    uint8_t         norder;
    bool            grease;
    uint16_t        pad_to;
} profile;

#define PROF(sfx, gr, pad)                                                                   \
    {                                                                                        \
        SUITES_##sfx, (uint8_t)QN_ARRAY_LEN(SUITES_##sfx), GROUPS_##sfx,                     \
            (uint8_t)QN_ARRAY_LEN(GROUPS_##sfx), SIGALGS_##sfx,                              \
            (uint8_t)QN_ARRAY_LEN(SIGALGS_##sfx), ORDER_##sfx,                               \
            (uint8_t)QN_ARRAY_LEN(ORDER_##sfx), (gr), (pad)                                  \
    }

static const profile PROFILES[] = {
    PROF(CHROME, true, 512),
    PROF(FIREFOX, false, 512),
    PROF(SAFARI, true, 512),
};

static void emit_slot(bw *w, uint8_t s, const profile *pr, const qn_hello_req *req,
                      const greases *g, size_t snilen)
{
    size_t mk, list, i;

    if (s == S_EMS && !req->allow_tls12)
        return;
    switch (s) {
    case S_GREASE_A:
        mk = ext_open_grease(w, g->ext_a);
        patch16(w, mk);
        break;

    case S_GREASE_B:
        mk = ext_open_grease(w, g->ext_b);
        w8(w, 0x00);
        patch16(w, mk);
        break;

    case S_SNI:
        mk   = ext_open(w, 0x0000);
        list = mark16(w);
        w8(w, 0x00);
        w16(w, (uint16_t)snilen);
        wbuf(w, req->sni, snilen);
        patch16(w, list);
        patch16(w, mk);
        break;

    case S_EMS:
        mk = ext_open(w, 0x0017);
        patch16(w, mk);
        break;

    case S_TICKET:
        mk = ext_open(w, 0x0023);
        patch16(w, mk);
        break;

    case S_SCT:
        mk = ext_open(w, 0x0012);
        patch16(w, mk);
        break;

    case S_RENEG:
        mk = ext_open(w, 0xFF01);
        w8(w, 0x00);
        patch16(w, mk);
        break;

    case S_GROUPS:
        mk   = ext_open(w, 0x000A);
        list = mark16(w);
        if (pr->grease)
            w16(w, g->group);
        for (i = 0; i < pr->ngroups; i++)
            w16(w, pr->groups[i]);
        patch16(w, list);
        patch16(w, mk);
        break;

    case S_ECPF:
        mk = ext_open(w, 0x000B);
        w8(w, 0x01);
        w8(w, 0x00);
        patch16(w, mk);
        break;

    case S_ALPN:
        mk   = ext_open(w, 0x0010);
        list = mark16(w);
        wbuf(w, ALPN_H2, sizeof ALPN_H2);
        patch16(w, list);
        patch16(w, mk);
        break;

    case S_STATUS:
        mk = ext_open(w, 0x0005);
        w8(w, 0x01);
        w16(w, 0x0000);
        w16(w, 0x0000);
        patch16(w, mk);
        break;

    case S_SIGALG:
        mk   = ext_open(w, 0x000D);
        list = mark16(w);
        for (i = 0; i < pr->nsigalgs; i++)
            w16(w, pr->sigalgs[i]);
        patch16(w, list);
        patch16(w, mk);
        break;

    case S_KSHARE:
        mk   = ext_open(w, 0x0033);
        list = mark16(w);
        if (pr->grease) {
            w16(w, g->group); /* must match the group GREASE above */
            w16(w, 0x0001);
            w8(w, 0x00);
        }
        w16(w, 0x001D);
        w16(w, QN_X25519_LEN);
        wbuf(w, req->key_share, QN_X25519_LEN);
        patch16(w, list);
        patch16(w, mk);
        break;

    case S_PSKMODE:
        mk = ext_open(w, 0x002D);
        w8(w, 0x01);
        w8(w, 0x01);
        patch16(w, mk);
        break;

    case S_VERS:
        mk = ext_open(w, 0x002B);
        {
            uint8_t n = (uint8_t)(2u + (req->allow_tls12 ? 2u : 0u) + (pr->grease ? 2u : 0u));
            w8(w, n);
            if (pr->grease)
                w16(w, g->version);
            w16(w, 0x0304);
            if (req->allow_tls12)
                w16(w, 0x0303);
        }
        patch16(w, mk);
        break;

    case S_CCERT:
        mk = ext_open(w, 0x001B);
        w8(w, 0x02);
        w16(w, 0x0002);
        patch16(w, mk);
        break;

    case S_RECSZ:
        mk = ext_open(w, 0x001C);
        w16(w, 0x4001);
        patch16(w, mk);
        break;

    case S_DELEG:
        mk   = ext_open(w, 0x0022);
        list = mark16(w);
        w16(w, 0x0403);
        w16(w, 0x0503);
        w16(w, 0x0603);
        w16(w, 0x0203);
        patch16(w, list);
        patch16(w, mk);
        break;

    case S_ALPS: /* application_settings */
        mk   = ext_open(w, 0x4469);
        list = mark16(w);
        w8(w, 0x02);
        w8(w, 'h');
        w8(w, '2');
        patch16(w, list);
        patch16(w, mk);
        break;

    default:
        break;
    }
}

/* Pads the hello body so its length reaches the profile's target. */
static void emit_padding(bw *w, size_t hello_start, uint16_t pad_to)
{
    size_t body, want, need, mk, i;

    if (w->err || !pad_to)
        return;

    body = w->len - hello_start;
    want = (size_t)pad_to - HS_HDR_LEN - REC_HDR_LEN;
    if (body + EXT_HDR_LEN >= want)
        return;

    need = want - body - EXT_HDR_LEN;
    if (w->len + need + EXT_HDR_LEN > w->cap)
        return;

    w16(w, 0x0015);
    mk = mark16(w);
    for (i = 0; i < need; i++)
        w8(w, 0x00);
    patch16(w, mk);
}

static uint16_t wire_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t wire_u24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static bool push_u16(uint16_t *values, size_t cap, size_t *count, uint16_t value)
{
    if (*count >= cap)
        return false;
    values[(*count)++] = value;
    return true;
}

static bool push_u8(uint8_t *values, size_t cap, size_t *count, uint8_t value)
{
    if (*count >= cap)
        return false;
    values[(*count)++] = value;
    return true;
}

static bool ext_unique(uint16_t *seen, size_t *nseen, size_t cap, uint16_t value)
{
    size_t i;

    for (i = 0; i < *nseen; i++)
        if (seen[i] == value)
            return false;
    return push_u16(seen, cap, nseen, value);
}

static bool inspect_sni(const uint8_t *data, size_t len, qn_hello_info *info)
{
    size_t p = 2u;

    if (len < 5u || (size_t)wire_u16(data) != len - 2u)
        return false;
    while (p < len) {
        uint8_t type;
        size_t name_len;

        if (len - p < 3u)
            return false;
        type = data[p++];
        name_len = wire_u16(data + p);
        p += 2u;
        if (!name_len || name_len > len - p)
            return false;
        if (type == 0u)
            info->has_sni = true;
        p += name_len;
    }
    return p == len;
}

static bool inspect_u16_vector(const uint8_t *data, size_t len, uint16_t *values,
                               size_t cap, size_t *count)
{
    size_t p, vector_len;

    if (len < 2u)
        return false;
    vector_len = wire_u16(data);
    if (!vector_len || (vector_len & 1u) != 0u || vector_len != len - 2u)
        return false;
    for (p = 2u; p < len; p += 2u) {
        uint16_t value = wire_u16(data + p);

        if (!is_grease(value) && !push_u16(values, cap, count, value))
            return false;
    }
    return true;
}

static bool inspect_groups(const uint8_t *data, size_t len, qn_hello_info *info)
{
    return inspect_u16_vector(data, len, info->groups, QN_HELLO_MAX_GROUPS,
                              &info->ngroups);
}

static bool inspect_sigalgs(const uint8_t *data, size_t len, qn_hello_info *info)
{
    return inspect_u16_vector(data, len, info->sigalgs, QN_HELLO_MAX_SIGALGS,
                              &info->nsigalgs);
}

static bool inspect_ecpf(const uint8_t *data, size_t len, qn_hello_info *info)
{
    size_t p;

    if (!len || data[0] == 0u || (size_t)data[0] != len - 1u)
        return false;
    for (p = 1u; p < len; p++)
        if (!push_u8(info->ecpf, QN_ARRAY_LEN(info->ecpf), &info->necpf, data[p]))
            return false;
    return true;
}

static bool inspect_versions(const uint8_t *data, size_t len, qn_hello_info *info)
{
    size_t p, vector_len;

    if (!len)
        return false;
    vector_len = data[0];
    if (!vector_len || (vector_len & 1u) != 0u || vector_len != len - 1u)
        return false;
    for (p = 1u; p < len; p += 2u) {
        uint16_t value = wire_u16(data + p);

        if (!is_grease(value) &&
            !push_u16(info->versions, QN_ARRAY_LEN(info->versions),
                      &info->nversions, value))
            return false;
    }
    return true;
}

static bool alpn_known(const uint8_t *value, size_t len)
{
    return (len == 2u && !memcmp(value, "h2", 2u)) ||
           (len == 8u && !memcmp(value, "http/1.1", 8u));
}

static bool inspect_alpn(const uint8_t *data, size_t len, qn_hello_info *info)
{
    size_t p = 2u;
    bool first = true;

    if (len < 3u || (size_t)wire_u16(data) != len - 2u)
        return false;
    info->has_alpn = true;
    info->alpn_capable = true;
    while (p < len) {
        size_t item_len = data[p++];

        if (!item_len || item_len > len - p)
            return false;
        if (!alpn_known(data + p, item_len))
            info->alpn_capable = false;
        if (first) {
            if (item_len >= sizeof info->alpn_first)
                return false;
            memcpy(info->alpn_first, data + p, item_len);
            info->alpn_first[item_len] = '\0';
            first = false;
        }
        p += item_len;
    }
    return p == len && !first;
}

static bool inspect_keyshares(const uint8_t *data, size_t len, qn_hello_info *info)
{
    size_t p = 2u, vector_len;

    if (len < 2u)
        return false;
    vector_len = wire_u16(data);
    if (!vector_len || vector_len != len - 2u)
        return false;
    while (p < len) {
        uint16_t group, share_len;

        if (len - p < 4u)
            return false;
        group = wire_u16(data + p);
        share_len = wire_u16(data + p + 2u);
        p += 4u;
        if (!share_len || share_len > len - p)
            return false;
        if (!is_grease(group)) {
            if (info->nkeyshares >= QN_HELLO_MAX_GROUPS)
                return false;
            info->keyshares[info->nkeyshares] = group;
            info->keyshare_lens[info->nkeyshares] = share_len;
            info->nkeyshares++;
        }
        p += share_len;
    }
    return p == len;
}

static bool all_zero(const uint8_t *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        if (data[i] != 0u)
            return false;
    return true;
}

bool qn_tls_hello_inspect(const uint8_t *wire, size_t len, qn_hello_info *info)
{
    uint16_t seen[QN_HELLO_MAX_EXTS + 8u];
    size_t nseen = 0u, p = 9u, end, suites_len, ext_len;

    if (!wire || !info || len < 45u || wire[0] != 0x16u ||
        wire_u16(wire + 1u) != 0x0301u || (size_t)wire_u16(wire + 3u) != len - 5u ||
        wire[5] != 0x01u || (size_t)wire_u24(wire + 6u) != len - 9u)
        return false;
    memset(info, 0, sizeof *info);
    info->body = wire + REC_HDR_LEN;
    info->body_len = len - REC_HDR_LEN;
    if (wire_u16(wire + p) != 0x0303u)
        return false;
    p += 2u + 32u;
    if (p >= len || wire[p] > 32u || (size_t)wire[p] > len - p - 1u)
        return false;
    p += 1u + wire[p];
    if (len - p < 2u)
        return false;
    suites_len = wire_u16(wire + p);
    p += 2u;
    if (!suites_len || (suites_len & 1u) != 0u || suites_len > len - p)
        return false;
    end = p + suites_len;
    while (p < end) {
        uint16_t suite = wire_u16(wire + p);

        if (!is_grease(suite) &&
            !push_u16(info->ciphers, QN_HELLO_MAX_CIPHERS, &info->nciphers, suite))
            return false;
        p += 2u;
    }
    if (p >= len || wire[p] != 1u || len - p < 2u || wire[p + 1u] != 0u)
        return false;
    p += 2u;
    if (len - p < 2u)
        return false;
    ext_len = wire_u16(wire + p);
    p += 2u;
    if (ext_len != len - p)
        return false;
    end = p + ext_len;
    while (p < end) {
        uint16_t type, item_len;
        const uint8_t *data;
        bool ok = true;

        if (end - p < 4u)
            return false;
        type = wire_u16(wire + p);
        item_len = wire_u16(wire + p + 2u);
        p += 4u;
        if ((size_t)item_len > end - p ||
            !ext_unique(seen, &nseen, QN_ARRAY_LEN(seen), type))
            return false;
        data = wire + p;
        if (!is_grease(type) &&
            !push_u16(info->exts, QN_HELLO_MAX_EXTS, &info->nexts, type))
            return false;
        switch (type) {
        case 0x0000u: ok = inspect_sni(data, item_len, info); break;
        case 0x000Au: ok = inspect_groups(data, item_len, info); break;
        case 0x000Bu: ok = inspect_ecpf(data, item_len, info); break;
        case 0x000Du: ok = inspect_sigalgs(data, item_len, info); break;
        case 0x0010u: ok = inspect_alpn(data, item_len, info); break;
        case 0x0015u: ok = all_zero(data, item_len); break;
        case 0x0017u: ok = item_len == 0u; break;
        case 0x002Bu: ok = inspect_versions(data, item_len, info); break;
        case 0x002Cu:
            ok = item_len >= 3u && wire_u16(data) != 0u &&
                 (size_t)wire_u16(data) == (size_t)item_len - 2u;
            break;
        case 0x0033u: ok = inspect_keyshares(data, item_len, info); break;
        default: break;
        }
        if (!ok)
            return false;
        p += item_len;
    }
    return p == end && !info->overflow;
}

static bool contains_u16(const uint16_t *values, size_t count, uint16_t value)
{
    size_t i;

    for (i = 0; i < count; i++)
        if (values[i] == value)
            return true;
    return false;
}

static bool unique_u16(const uint16_t *values, size_t count)
{
    size_t i, j;

    for (i = 0; i < count; i++)
        for (j = i + 1u; j < count; j++)
            if (values[i] == values[j])
                return false;
    return true;
}

static bool capability_error(char *error, size_t cap, const char *what, uint16_t value)
{
    if (error && cap)
        (void)snprintf(error, cap, "%s 0x%04x is not implemented", what, value);
    return false;
}

bool qn_tls_hello_capability_check(const qn_hello_info *info, bool allow_tls12,
                                   char *error, size_t error_cap)
{
    size_t i;
    bool have_tls13 = false, have_version13 = false;

    if (error && error_cap)
        error[0] = '\0';
    if (!info || info->overflow || !info->has_sni || !info->has_alpn ||
        !info->alpn_capable || strcmp(info->alpn_first, "h2") != 0 ||
        !contains_u16(info->exts, info->nexts, 0x000Au) ||
        !contains_u16(info->exts, info->nexts, 0x000Du) ||
        !contains_u16(info->exts, info->nexts, 0x002Bu) ||
        !contains_u16(info->exts, info->nexts, 0x0033u) ||
        !unique_u16(info->ciphers, info->nciphers) ||
        !unique_u16(info->groups, info->ngroups) ||
        !unique_u16(info->sigalgs, info->nsigalgs) ||
        !unique_u16(info->versions, info->nversions) ||
        info->necpf != 1u || info->ecpf[0] != 0u)
        return capability_error(error, error_cap, "required hello capability", 0u);
    for (i = 0; i < info->nciphers; i++) {
        uint16_t suite = info->ciphers[i];

        if (is_tls13_suite(suite))
            have_tls13 = true;
        else if (!allow_tls12 ||
                 !qn_tls_capability_suite(suite, 0x0303u, NULL, NULL, NULL))
            return capability_error(error, error_cap, "cipher suite", suite);
    }
    if (!have_tls13)
        return capability_error(error, error_cap, "TLS 1.3 cipher suite", 0u);
    for (i = 0; i < info->nexts; i++)
        if (!qn_tls_capability_extension(info->exts[i], allow_tls12))
            return capability_error(error, error_cap, "extension", info->exts[i]);
    for (i = 0; i < info->ngroups; i++)
        if (!qn_tls_capability_group(info->groups[i]))
            return capability_error(error, error_cap, "group", info->groups[i]);
    if (info->ngroups != 1u || info->nkeyshares != 1u ||
        info->keyshares[0] != 0x001Du || info->keyshare_lens[0] != QN_X25519_LEN)
        return capability_error(error, error_cap, "X25519 key share", 0u);
    for (i = 0; i < info->nsigalgs; i++)
        if (!qn_tls_capability_sigalg(info->sigalgs[i], NULL))
            return capability_error(error, error_cap, "signature scheme", info->sigalgs[i]);
    if (!info->nsigalgs)
        return capability_error(error, error_cap, "signature scheme", 0u);
    for (i = 0; i < info->nversions; i++) {
        uint16_t version = info->versions[i];

        if (version == 0x0304u)
            have_version13 = true;
        else if (version != 0x0303u || !allow_tls12)
            return capability_error(error, error_cap, "protocol version", version);
    }
    if (!have_version13)
        return capability_error(error, error_cap, "TLS 1.3 version", 0u);
    return true;
}

int qn_tls_hello_build(const qn_hello_req *req, uint8_t *buf, size_t cap, qn_hello_info *info)
{
    const profile *pr;
    greases        g;
    bw             w = { buf, cap, 0, false };
    size_t         rec_len, hs_len, ext_len, hello_start, snilen, i;
    qn_tls_fp      fp = req->fp;

    if (!req->sni)
        return -1;
    snilen = strlen(req->sni);
    if (snilen > 250)
        return -1;

    if ((size_t)fp < QN_ARRAY_LEN(PROFILES)) {
        pr = &PROFILES[fp];
    } else {
        return -1;
    }

    greases_from(req->grease_seed, &g);

    w8(&w, 0x16);
    w16(&w, 0x0301);
    rec_len = mark16(&w);

    w8(&w, 0x01);
    hs_len      = mark24(&w);
    hello_start = w.len;

    w16(&w, 0x0303);
    wbuf(&w, req->random, 32);

    w8(&w, 32);
    wbuf(&w, req->session_id, 32);

    {
        size_t mk = mark16(&w);
        if (pr->grease)
            w16(&w, g.cipher);
        for (i = 0; i < pr->nsuites; i++) {
            if (!req->allow_tls12 && !is_tls13_suite(pr->suites[i]))
                continue;
            w16(&w, pr->suites[i]);
        }
        patch16(&w, mk);
    }

    w8(&w, 0x01);
    w8(&w, 0x00);

    ext_len = mark16(&w);
    for (i = 0; i < pr->norder; i++) {
        if (pr->order[i] == S_PAD)
            emit_padding(&w, hello_start, pr->pad_to);
        else
            emit_slot(&w, pr->order[i], pr, req, &g, snilen);
    }
    if (req->cookie_len) {
        size_t cookie_ext;

        if (!req->cookie || req->cookie_len > 512u)
            return -1;
        cookie_ext = ext_open(&w, 0x002c);
        w16(&w, req->cookie_len);
        wbuf(&w, req->cookie, req->cookie_len);
        patch16(&w, cookie_ext);
    }
    patch16(&w, ext_len);

    patch24(&w, hs_len);
    patch16(&w, rec_len);

    if (w.err)
        return -1;

    {
        qn_hello_info actual;

        if (!qn_tls_hello_inspect(buf, w.len, &actual) ||
            !qn_tls_hello_capability_check(&actual, req->allow_tls12, NULL, 0u))
            return -1;
        if (info)
            *info = actual;
    }
    return (int)w.len;
}
