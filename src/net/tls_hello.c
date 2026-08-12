/* ClientHello construction, shaped per fingerprint profile. */

#include "qanat/tls_hello.h"
#include "qanat/tls_capability.h"

#include <stdio.h>
#include <string.h>

#define REC_HDR_LEN 5

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

static uint64_t shape_next(uint64_t *state)
{
    uint64_t z;

    *state += UINT64_C(0x9E3779B97F4A7C15);
    z = *state;
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

typedef struct {
    uint16_t cipher, ext_a, ext_b, group, version;
} greases;

static void greases_from(uint64_t seed, greases *g)
{
    uint64_t x = seed;
    uint8_t  n[5] = { 0 };
    unsigned i;

    for (i = 0; i < 5; i++)
        n[i] = (uint8_t)(shape_next(&x) & 15u);
    g->cipher  = grease_of(n[0]);
    g->ext_a   = grease_of(n[1]);
    if (n[2] == n[1])
        n[2] = (uint8_t)((n[2] + 1u) & 15u);
    g->ext_b   = grease_of(n[2]);
    g->group   = grease_of(n[3]);
    g->version = grease_of(n[4]);
}

static const uint16_t SUITES_CHROME[] = {
    0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9,
    0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035
};
static const uint16_t SUITES_FIREFOX[] = {
    0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C,
    0xC030, 0xC00A, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035
};
static const uint16_t SUITES_SAFARI[] = {
    0x1302, 0x1303, 0x1301, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F,
    0xCCA8, 0xC00A, 0xC009, 0xC014, 0xC013, 0x009D, 0x009C, 0x0035,
    0x002F, 0xC008, 0xC012, 0x000A
};

static const uint16_t GROUPS_CHROME[] = { 0x11EC, 0x001D, 0x0017, 0x0018 };
static const uint16_t GROUPS_FIREFOX[] = {
    0x11EC, 0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101
};
static const uint16_t GROUPS_SAFARI[] = { 0x11EC, 0x001D, 0x0017, 0x0018, 0x0019 };

static const uint16_t SHARES_CHROME[] = { 0x11EC, 0x001D };
static const uint16_t SHARES_FIREFOX[] = { 0x11EC, 0x001D, 0x0017 };
static const uint16_t SHARES_SAFARI[] = { 0x11EC, 0x001D };

static const uint16_t SIGALGS_CHROME[] = {
    0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401,
    0x0503, 0x0805, 0x0501, 0x0806, 0x0601
};
static const uint16_t SIGALGS_FIREFOX[] = {
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
    0x0401, 0x0501, 0x0601, 0x0203, 0x0201
};
static const uint16_t SIGALGS_SAFARI[] = {
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
    0x0603, 0x0501, 0x0806, 0x0601, 0x0201
};

static const uint16_t CCERT_CHROME[] = { 0x0002 };
static const uint16_t CCERT_FIREFOX[] = { 0x0001, 0x0002, 0x0003 };
static const uint16_t CCERT_SAFARI[] = { 0x0001 };

static const uint8_t ALPN_H2[] = { 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1' };

/* Slots, not extension ids: GREASE and padding are positions, not real types. */
typedef enum {
    S_SNI = 1,
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
    S_ALPS,
    S_ECH
} slot;

static const uint8_t ORDER_CHROME[] = {
    S_TICKET, S_SNI, S_VERS, S_KSHARE, S_CCERT, S_GROUPS, S_RENEG, S_ECPF,
    S_ECH, S_SCT, S_PSKMODE, S_EMS, S_ALPN, S_ALPS, S_SIGALG, S_STATUS
};
static const uint8_t ORDER_FIREFOX[] = {
    S_SNI, S_EMS, S_RENEG, S_GROUPS, S_ECPF, S_TICKET, S_ALPN, S_STATUS,
    S_DELEG, S_KSHARE, S_VERS, S_SIGALG, S_PSKMODE, S_RECSZ, S_CCERT, S_ECH
};
static const uint8_t ORDER_SAFARI[] = {
    S_SNI, S_EMS, S_RENEG, S_GROUPS, S_ECPF, S_ALPN, S_STATUS, S_SIGALG,
    S_SCT, S_KSHARE, S_PSKMODE, S_VERS, S_CCERT
};

typedef struct {
    const uint16_t *suites;
    uint8_t         nsuites;
    const uint16_t *groups;
    uint8_t         ngroups;
    const uint16_t *sigalgs;
    uint8_t         nsigalgs;
    const uint16_t *shares;
    uint8_t         nshares;
    const uint16_t *ccert;
    uint8_t         nccert;
    const uint8_t  *order;
    uint8_t         norder;
    bool            grease;
    bool            shuffle;
    bool            ech_outer;
} profile;

#define PROF(sfx, gr, shuf, outer)                                                           \
    {                                                                                        \
        SUITES_##sfx, (uint8_t)QN_ARRAY_LEN(SUITES_##sfx), GROUPS_##sfx,                     \
            (uint8_t)QN_ARRAY_LEN(GROUPS_##sfx), SIGALGS_##sfx,                              \
            (uint8_t)QN_ARRAY_LEN(SIGALGS_##sfx), SHARES_##sfx,                              \
            (uint8_t)QN_ARRAY_LEN(SHARES_##sfx), CCERT_##sfx,                                \
            (uint8_t)QN_ARRAY_LEN(CCERT_##sfx), ORDER_##sfx,                                 \
            (uint8_t)QN_ARRAY_LEN(ORDER_##sfx), (gr), (shuf), (outer)                        \
    }

static const profile PROFILES[] = {
    PROF(CHROME, true, true, true),
    PROF(FIREFOX, false, false, true),
    PROF(SAFARI, true, false, false),
};

static const qn_hello_key_share *find_share(const qn_hello_req *req, uint16_t group)
{
    size_t i;

    for (i = 0u; i < req->key_shares_n; i++)
        if (req->key_shares[i].group == group)
            return &req->key_shares[i];
    return NULL;
}

static void emit_grease(bw *w, uint16_t type, bool payload)
{
    size_t mk = ext_open_grease(w, type);

    if (payload)
        w8(w, 0u);
    patch16(w, mk);
}

static void emit_slot(bw *w, uint8_t s, const profile *pr, const qn_hello_req *req,
                      const greases *g, size_t snilen)
{
    size_t mk, list, i;

    if (s == S_EMS && !req->allow_tls12)
        return;
    switch (s) {
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
        if (pr->grease && !req->selected_group) {
            w16(w, g->group);
            w16(w, 0x0001);
            w8(w, 0x00);
        }
        if (req->selected_group) {
            const qn_hello_key_share *share = find_share(req, req->selected_group);

            if (!share || !share->data || !share->len) {
                w->err = true;
            } else {
                w16(w, share->group);
                w16(w, share->len);
                wbuf(w, share->data, share->len);
            }
        } else for (i = 0u; i < pr->nshares; i++) {
            const qn_hello_key_share *share;
            uint16_t group = pr->shares[i];

            share = find_share(req, group);
            if (!share || !share->data || !share->len) {
                w->err = true;
                break;
            }
            w16(w, group);
            w16(w, share->len);
            wbuf(w, share->data, share->len);
        }
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
        w8(w, (uint8_t)(pr->nccert * 2u));
        for (i = 0u; i < pr->nccert; i++)
            w16(w, pr->ccert[i]);
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

    case S_ALPS:
        mk   = ext_open(w, 0x44CD);
        list = mark16(w);
        w8(w, 0x02);
        w8(w, 'h');
        w8(w, '2');
        patch16(w, list);
        patch16(w, mk);
        break;

    case S_ECH:
        if (!req->ech_payload || req->ech_payload_len > QN_ECH_PAYLOAD_MAX ||
            req->ech_payload_len < 16u || !req->ech_aead) {
            w->err = true;
            break;
        }
        mk = ext_open(w, 0xFE0D);
        if (pr->ech_outer)
            w8(w, 0u);
        w16(w, 0x0001u);
        w16(w, req->ech_aead);
        w8(w, req->ech_config_id);
        w16(w, QN_X25519_LEN);
        wbuf(w, req->ech_enc, QN_X25519_LEN);
        w16(w, req->ech_payload_len);
        wbuf(w, req->ech_payload, req->ech_payload_len);
        patch16(w, mk);
        break;

    default:
        break;
    }
}

static void shuffle_order(uint8_t *order, size_t n, uint64_t seed)
{
    while (n > 1u) {
        size_t j = (size_t)(shape_next(&seed) % n);
        uint8_t tmp = order[n - 1u];

        order[n - 1u] = order[j];
        order[j] = tmp;
        n--;
    }
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

static bool inspect_ccert(const uint8_t *data, size_t len)
{
    size_t p, vector_len;

    if (len < 3u)
        return false;
    vector_len = data[0];
    if (!vector_len || (vector_len & 1u) != 0u || vector_len != len - 1u)
        return false;
    for (p = 1u; p < len; p += 2u)
        if (wire_u16(data + p) == 0u)
            return false;
    return true;
}

static bool inspect_delegated(const uint8_t *data, size_t len)
{
    uint16_t values[QN_HELLO_MAX_SIGALGS];
    size_t count = 0u;

    return inspect_u16_vector(data, len, values, QN_ARRAY_LEN(values), &count);
}

static bool inspect_ech(const uint8_t *data, size_t len)
{
    size_t p, enc_len, payload_len;

    if (len >= 42u && data[0] == 0u && wire_u16(data + 1u) == 1u)
        p = 1u;
    else if (len >= 41u && wire_u16(data) == 1u)
        p = 0u;
    else
        return false;
    p += 2u;
    if (wire_u16(data + p) == 0u)
        return false;
    p += 2u + 1u;
    enc_len = wire_u16(data + p);
    p += 2u;
    if (enc_len != QN_X25519_LEN || enc_len > len - p)
        return false;
    p += enc_len;
    if (len - p < 2u)
        return false;
    payload_len = wire_u16(data + p);
    p += 2u;
    return payload_len >= 16u && payload_len <= QN_ECH_PAYLOAD_MAX &&
           payload_len == len - p;
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
        case 0x0005u:
            ok = item_len == 5u && data[0] == 1u && wire_u16(data + 1u) == 0u &&
                 wire_u16(data + 3u) == 0u;
            break;
        case 0x000Au: ok = inspect_groups(data, item_len, info); break;
        case 0x000Bu: ok = inspect_ecpf(data, item_len, info); break;
        case 0x000Du: ok = inspect_sigalgs(data, item_len, info); break;
        case 0x0010u: ok = inspect_alpn(data, item_len, info); break;
        case 0x0012u: ok = item_len == 0u; break;
        case 0x0015u: ok = all_zero(data, item_len); break;
        case 0x0017u: ok = item_len == 0u; break;
        case 0x001Bu: ok = inspect_ccert(data, item_len); break;
        case 0x001Cu:
            ok = item_len == 2u && wire_u16(data) >= 64u &&
                 wire_u16(data) <= 16385u;
            break;
        case 0x0022u: ok = inspect_delegated(data, item_len); break;
        case 0x0023u: ok = item_len == 0u; break;
        case 0x002Bu: ok = inspect_versions(data, item_len, info); break;
        case 0x002Cu:
            ok = item_len >= 3u && wire_u16(data) != 0u &&
                 (size_t)wire_u16(data) == (size_t)item_len - 2u;
            break;
        case 0x002Du:
            ok = item_len == 2u && data[0] == 1u && data[1] == 1u;
            break;
        case 0x0033u: ok = inspect_keyshares(data, item_len, info); break;
        case 0x44CDu:
            ok = item_len == 5u && wire_u16(data) == 3u && data[2] == 2u &&
                 data[3] == 'h' && data[4] == '2';
            break;
        case 0xFE0Du: ok = inspect_ech(data, item_len); break;
        case 0xFF01u: ok = item_len == 1u && data[0] == 0u; break;
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
    bool have_suite = false, have_group = false, have_share = false;
    bool have_sigalg = false, have_version13 = false;

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

        if (is_tls13_suite(suite) ||
            (allow_tls12 && qn_tls_capability_suite(suite, 0x0303u,
                                                    NULL, NULL, NULL)))
            have_suite = true;
    }
    if (!have_suite)
        return capability_error(error, error_cap, "usable cipher suite", 0u);
    for (i = 0; i < info->nexts; i++)
        if (!qn_tls_capability_extension(info->exts[i], allow_tls12))
            return capability_error(error, error_cap, "extension", info->exts[i]);
    for (i = 0; i < info->ngroups; i++)
        if (qn_tls_capability_group(info->groups[i]))
            have_group = true;
    if (!have_group)
        return capability_error(error, error_cap, "usable group", 0u);
    for (i = 0; i < info->nkeyshares; i++) {
        uint16_t group = info->keyshares[i];
        uint16_t len = info->keyshare_lens[i];

        if ((group == QN_GROUP_X25519_MLKEM768 &&
             len == QN_HYBRID_CLIENT_SHARE_LEN) ||
            (group == QN_GROUP_X25519 && len == QN_X25519_LEN) ||
            (group == QN_GROUP_P256 && len == QN_P256_PUBLIC_LEN))
            have_share = true;
    }
    if (!have_share)
        return capability_error(error, error_cap, "usable key share", 0u);
    for (i = 0; i < info->nsigalgs; i++)
        if (qn_tls_capability_sigalg(info->sigalgs[i], NULL))
            have_sigalg = true;
    if (!have_sigalg)
        return capability_error(error, error_cap, "usable signature scheme", 0u);
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
    uint8_t        order[QN_HELLO_MAX_EXTS];
    size_t         rec_len, hs_len, ext_len, snilen, i;
    qn_tls_fp      fp;

    if (!req || !buf || !req->sni || !req->key_shares ||
        !req->key_shares_n || req->key_shares_n > QN_HELLO_MAX_SHARES)
        return -1;
    fp = req->fp;
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
    hs_len = mark24(&w);

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
    memcpy(order, pr->order, pr->norder);
    if (pr->shuffle)
        shuffle_order(order, pr->norder,
                      req->grease_seed ^ UINT64_C(0x4558542D4F524445));
    if (pr->grease)
        emit_grease(&w, g.ext_a, false);
    for (i = 0; i < pr->norder; i++)
        emit_slot(&w, order[i], pr, req, &g, snilen);
    if (pr->grease)
        emit_grease(&w, g.ext_b, true);
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
