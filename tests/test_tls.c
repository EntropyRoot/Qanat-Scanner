#include "qanat/tls_hello.h"
#include "qanat/probe.h"
#include "qanat/http2.h"
#include "qanat/profile.h"
#include "tls_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

static int build(qn_tls_fp fp, const char *sni, qn_hello_info *info, uint8_t *buf, size_t cap)
{
    qn_hello_req req;

    memset(&req, 0, sizeof req);
    req.sni         = sni;
    req.fp          = fp;
    req.grease_seed = 0x0123456789ABCDEFull;
    memset(req.random, 0xA5, sizeof req.random);
    memset(req.session_id, 0x5A, sizeof req.session_id);
    memset(req.key_share, 0x42, sizeof req.key_share);

    return qn_tls_hello_build(&req, buf, cap, info);
}

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static bool unique_extensions(const uint8_t *hello, size_t n)
{
    uint16_t seen[QN_HELLO_MAX_EXTS + 4u];
    size_t   nseen = 0, p = 9u, end;

    if (!hello || n < p + 35u || hello[0] != 0x16u || hello[5] != 0x01u)
        return false;
    p += 2u + 32u; /* legacy version and random */
    if (p >= n || (size_t)hello[p] > n - p - 1u)
        return false;
    p += 1u + hello[p];
    if (p + 2u > n || (size_t)get16(hello + p) > n - p - 2u)
        return false;
    p += 2u + get16(hello + p);
    if (p >= n || (size_t)hello[p] > n - p - 1u)
        return false;
    p += 1u + hello[p];
    if (p + 2u > n || (size_t)get16(hello + p) > n - p - 2u)
        return false;
    end = p + 2u + get16(hello + p);
    p += 2u;

    while (p < end) {
        uint16_t type, len;

        if (end - p < 4u)
            return false;
        type = get16(hello + p);
        len = get16(hello + p + 2u);
        p += 4u;
        if ((size_t)len > end - p || nseen >= QN_ARRAY_LEN(seen))
            return false;
        for (size_t i = 0; i < nseen; i++)
            if (seen[i] == type)
                return false;
        seen[nseen++] = type;
        p += len;
    }
    return p == end;
}

static void test_no_duplicate_extensions(void)
{
    uint8_t       hello[4096];
    qn_hello_info info;

    for (uint64_t seed = 0; seed < 512u; seed++) {
        qn_hello_req req;
        qn_rng       rng;
        int          n;

        memset(&req, 0, sizeof req);
        req.sni = "example.com";
        req.fp = (qn_tls_fp)(seed % QN_TLS_FP_RANDOM);
        req.allow_tls12 = true;
        req.grease_seed = seed;
        memset(req.random, (int)(seed & 0xFFu), sizeof req.random);
        memset(req.session_id, (int)((seed >> 8) & 0xFFu), sizeof req.session_id);
        memset(req.key_share, 0x42, sizeof req.key_share);
        n = qn_tls_hello_build(&req, hello, sizeof hello, &info);
        CHECK(n > 0 && unique_extensions(hello, (size_t)n));

        qn_rng_seed(&rng, seed);
        n = qn_tls_build_hello(hello, sizeof hello, "example.com", &rng,
                               (qn_tls_fp)(seed % QN_TLS_FP_RANDOM));
        CHECK(n > 0 && unique_extensions(hello, (size_t)n));
    }
}

static bool same_facts(const qn_hello_info *left, const qn_hello_info *right)
{
    return left->body_len == right->body_len &&
           left->nciphers == right->nciphers &&
           !memcmp(left->ciphers, right->ciphers,
                   left->nciphers * sizeof left->ciphers[0]) &&
           left->nexts == right->nexts &&
           !memcmp(left->exts, right->exts, left->nexts * sizeof left->exts[0]) &&
           left->ngroups == right->ngroups &&
           !memcmp(left->groups, right->groups,
                   left->ngroups * sizeof left->groups[0]) &&
           left->nkeyshares == right->nkeyshares &&
           !memcmp(left->keyshares, right->keyshares,
                   left->nkeyshares * sizeof left->keyshares[0]) &&
           !memcmp(left->keyshare_lens, right->keyshare_lens,
                   left->nkeyshares * sizeof left->keyshare_lens[0]) &&
           left->nsigalgs == right->nsigalgs &&
           !memcmp(left->sigalgs, right->sigalgs,
                   left->nsigalgs * sizeof left->sigalgs[0]) &&
           left->necpf == right->necpf &&
           !memcmp(left->ecpf, right->ecpf, left->necpf) &&
           left->nversions == right->nversions &&
           !memcmp(left->versions, right->versions,
                   left->nversions * sizeof left->versions[0]) &&
           left->has_sni == right->has_sni &&
           left->has_alpn == right->has_alpn &&
           left->alpn_capable == right->alpn_capable &&
           !strcmp(left->alpn_first, right->alpn_first) &&
           left->overflow == right->overflow;
}

static bool has_u16(const uint16_t *values, size_t count, uint16_t value)
{
    size_t i;

    for (i = 0; i < count; i++)
        if (values[i] == value)
            return true;
    return false;
}

static void test_hello_wire_contract(void)
{
    uint8_t hello[4096];
    char error[96];
    size_t fp, seed;

    for (fp = 0u; fp < QN_TLS_FP_RANDOM; fp++) {
        for (seed = 0u; seed < 64u; seed++) {
            qn_hello_req req;
            qn_hello_info built, parsed;
            int n;

            memset(&req, 0, sizeof req);
            req.sni = "example.com";
            req.fp = (qn_tls_fp)fp;
            req.allow_tls12 = true;
            req.grease_seed = (uint64_t)seed;
            memset(req.random, (int)seed, sizeof req.random);
            memset(req.session_id, (int)(seed ^ 0x5Au), sizeof req.session_id);
            memset(req.key_share, 0x42, sizeof req.key_share);
            n = qn_tls_hello_build(&req, hello, sizeof hello, &built);
            CHECK(n > 0);
            CHECK(n > 0 && qn_tls_hello_inspect(hello, (size_t)n, &parsed));
            CHECK(n > 0 && same_facts(&built, &parsed));
            CHECK(qn_tls_hello_capability_check(&parsed, true, error, sizeof error));
            CHECK(parsed.nciphers == 9u);
            CHECK(parsed.ngroups == 1u && parsed.groups[0] == 0x001Du);
            CHECK(parsed.nkeyshares == 1u && parsed.keyshares[0] == 0x001Du);
            CHECK(parsed.keyshare_lens[0] == QN_X25519_LEN);
            CHECK(parsed.nversions == 2u && parsed.versions[0] == 0x0304u &&
                  parsed.versions[1] == 0x0303u);

            req.allow_tls12 = false;
            n = qn_tls_hello_build(&req, hello, sizeof hello, &parsed);
            CHECK(n > 0);
            CHECK(parsed.nciphers == 3u);
            CHECK(parsed.nversions == 1u && parsed.versions[0] == 0x0304u);
            CHECK(!has_u16(parsed.exts, parsed.nexts, 0x0017u));
            CHECK(qn_tls_hello_capability_check(&parsed, false, error, sizeof error));
        }
    }

    {
        qn_hello_info info;
        int n = build(QN_TLS_FP_CHROME, "example.com", &info, hello, sizeof hello);
        size_t cut;

        CHECK(n > 0);
        for (cut = 0u; cut < (size_t)n; cut++) {
            qn_hello_info partial;
            CHECK(!qn_tls_hello_inspect(hello, cut, &partial));
        }
        CHECK(qn_tls_hello_inspect(hello, (size_t)n, &info));

        info.ciphers[0] = 0x00FFu;
        CHECK(!qn_tls_hello_capability_check(&info, false, error, sizeof error));
        CHECK(strstr(error, "cipher suite") != NULL);
        CHECK(qn_tls_hello_inspect(hello, (size_t)n, &info));
        info.groups[0] = 0x0017u;
        CHECK(!qn_tls_hello_capability_check(&info, false, error, sizeof error));
        CHECK(strstr(error, "group") != NULL);
        CHECK(qn_tls_hello_inspect(hello, (size_t)n, &info));
        info.keyshares[0] = 0x0017u;
        CHECK(!qn_tls_hello_capability_check(&info, false, error, sizeof error));
        CHECK(strstr(error, "key share") != NULL);
        CHECK(qn_tls_hello_inspect(hello, (size_t)n, &info));
        info.sigalgs[0] = 0x0807u;
        CHECK(!qn_tls_hello_capability_check(&info, false, error, sizeof error));
        CHECK(strstr(error, "signature scheme") != NULL);
        CHECK(qn_tls_hello_inspect(hello, (size_t)n, &info));
        info.versions[0] = 0x0305u;
        CHECK(!qn_tls_hello_capability_check(&info, false, error, sizeof error));
        CHECK(strstr(error, "protocol version") != NULL);
    }
}

typedef struct {
    qn_profile_instance instance;
    uint8_t hello[4096], preface[256], headers[2048], http1[2048];
    size_t hello_n, preface_n, headers_n, http1_n;
    char ja3[33], ja4[40];
} persona_snapshot;

static bool persona_build(qn_tls_fp requested, uint64_t run_seed, const char *sni,
                          persona_snapshot *snapshot)
{
    qn_profile_instance before;
    qn_tls_config config;
    qn_tls_session session;
    qn_rng rng;
    int n;
    bool ok = false;

    memset(snapshot, 0, sizeof *snapshot);
    if (!qn_profile_instance_init(&snapshot->instance, requested,
                                  qn_profile_seed_from_run(run_seed), sni, true, false))
        return false;
    before = snapshot->instance;
    memset(&config, 0, sizeof config);
    config.profile = &snapshot->instance;
    qn_rng_seed(&rng, qn_profile_wire_seed(run_seed, 0u));
    config.rng = &rng;
    qn_tls_init(&session, &config);
    n = qn_tls_start(&session, snapshot->hello, sizeof snapshot->hello);
    if (n <= 0)
        goto out;
    snapshot->hello_n = (size_t)n;
    memcpy(snapshot->ja3, session.ja3, sizeof snapshot->ja3);
    memcpy(snapshot->ja4, session.ja4, sizeof snapshot->ja4);
    n = qn_h2_preface_instance(&snapshot->instance, snapshot->preface,
                                sizeof snapshot->preface);
    if (n <= 0)
        goto out;
    snapshot->preface_n = (size_t)n;
    n = qn_h2_get_instance(&snapshot->instance, 1u, sni, "/cdn-cgi/trace",
                           snapshot->headers, sizeof snapshot->headers);
    if (n <= 0)
        goto out;
    snapshot->headers_n = (size_t)n;
    n = qn_profile_instance_http1_get(&snapshot->instance, sni, "/cdn-cgi/trace",
                                      snapshot->http1, sizeof snapshot->http1);
    if (n <= 0)
        goto out;
    snapshot->http1_n = (size_t)n;
    if (memcmp(&before, &snapshot->instance, sizeof before) != 0)
        goto out;
    ok = true;
out:
    qn_tls_free(&session);
    return ok;
}

static bool bytes_differ(const uint8_t *left, size_t left_n,
                         const uint8_t *right, size_t right_n)
{
    return left_n != right_n || memcmp(left, right, left_n) != 0;
}

static void test_profile_instance_wire_identity(void)
{
    static const uint64_t run_seed = UINT64_C(0x514E2D46502D5348);
    persona_snapshot personas[3], repeat, random, resolved, other_sni, other_seed;
    unsigned resolved_mask = 0u;
    size_t i, j;

    for (i = 0u; i < QN_ARRAY_LEN(personas); i++) {
        qn_hello_info parsed;
        char ja3_string[QN_JA3_STR_MAX], ja3[33], ja4[40];

        CHECK(persona_build((qn_tls_fp)i, run_seed, "example.com", &personas[i]));
        CHECK(qn_tls_hello_inspect(personas[i].hello, personas[i].hello_n, &parsed));
        CHECK(qn_tls_hello_capability_check(&parsed, true, NULL, 0u));
        CHECK(qn_tls_ja3(&parsed, ja3_string, sizeof ja3_string, ja3));
        CHECK(qn_tls_ja4(&parsed, ja4));
        CHECK(!strcmp(ja3, personas[i].ja3));
        CHECK(!strcmp(ja4, personas[i].ja4));
        CHECK(personas[i].instance.support == QN_PROFILE_CAPABILITY_CONSTRAINED);
    }
    for (i = 0u; i < QN_ARRAY_LEN(personas); i++)
        for (j = i + 1u; j < QN_ARRAY_LEN(personas); j++)
            CHECK(bytes_differ(personas[i].hello, personas[i].hello_n,
                               personas[j].hello, personas[j].hello_n) ||
                  bytes_differ(personas[i].preface, personas[i].preface_n,
                               personas[j].preface, personas[j].preface_n) ||
                  bytes_differ(personas[i].headers, personas[i].headers_n,
                               personas[j].headers, personas[j].headers_n) ||
                  bytes_differ(personas[i].http1, personas[i].http1_n,
                               personas[j].http1, personas[j].http1_n));

    CHECK(persona_build(QN_TLS_FP_CHROME, run_seed, "example.com", &repeat));
    CHECK(!bytes_differ(personas[0].hello, personas[0].hello_n,
                        repeat.hello, repeat.hello_n));
    CHECK(!bytes_differ(personas[0].preface, personas[0].preface_n,
                        repeat.preface, repeat.preface_n));
    CHECK(!bytes_differ(personas[0].headers, personas[0].headers_n,
                        repeat.headers, repeat.headers_n));
    CHECK(!bytes_differ(personas[0].http1, personas[0].http1_n,
                        repeat.http1, repeat.http1_n));
    CHECK(persona_build(QN_TLS_FP_CHROME, run_seed, "other.example", &other_sni));
    CHECK(bytes_differ(personas[0].hello, personas[0].hello_n,
                       other_sni.hello, other_sni.hello_n));
    CHECK(persona_build(QN_TLS_FP_CHROME, run_seed + 1u, "example.com", &other_seed));
    CHECK(bytes_differ(personas[0].hello, personas[0].hello_n,
                       other_seed.hello, other_seed.hello_n));

    for (i = 0u; i < 256u; i++) {
        qn_profile_instance first, second;

        CHECK(qn_profile_instance_init(&first, QN_TLS_FP_RANDOM,
                                       qn_profile_seed_from_run((uint64_t)i),
                                       "example.com", true, false));
        CHECK(qn_profile_instance_init(&second, QN_TLS_FP_RANDOM,
                                       qn_profile_seed_from_run((uint64_t)i),
                                       "example.com", true, false));
        CHECK(first.resolved < QN_TLS_FP_RANDOM);
        CHECK(first.resolved == second.resolved);
        CHECK(first.profile == second.profile);
        CHECK(first.grease_seed == second.grease_seed);
        resolved_mask |= 1u << (unsigned)first.resolved;
    }
    CHECK(resolved_mask == 0x7u);

    CHECK(persona_build(QN_TLS_FP_RANDOM, run_seed, "example.com", &random));
    CHECK(persona_build(random.instance.resolved, run_seed, "example.com", &resolved));
    CHECK(!bytes_differ(random.hello, random.hello_n, resolved.hello, resolved.hello_n));
    CHECK(!bytes_differ(random.preface, random.preface_n, resolved.preface, resolved.preface_n));
    CHECK(!bytes_differ(random.headers, random.headers_n, resolved.headers, resolved.headers_n));
    CHECK(!bytes_differ(random.http1, random.http1_n, resolved.http1, resolved.http1_n));

    {
        qn_rng cheap_rng;
        qn_hello_info cheap_info, deep_info;
        uint8_t cheap[4096];
        int cheap_n;

        qn_rng_seed(&cheap_rng, qn_profile_wire_seed(run_seed, 0u));
        cheap_n = qn_tls_build_hello_instance(cheap, sizeof cheap, &random.instance,
                                              &cheap_rng);
        CHECK(cheap_n > 0);
        CHECK(qn_tls_hello_inspect(cheap, (size_t)cheap_n, &cheap_info));
        CHECK(qn_tls_hello_inspect(random.hello, random.hello_n, &deep_info));
        CHECK(same_facts(&cheap_info, &deep_info));
    }
}

static void test_hello_shape(void)
{
    uint8_t       buf[4096];
    qn_hello_info info;
    int           n;

    n = build(QN_TLS_FP_CHROME, "example.com", &info, buf, sizeof buf);
    CHECK(n == 512);
    CHECK(buf[0] == 0x16);
    CHECK(buf[1] == 0x03 && buf[2] == 0x01);
    CHECK(((size_t)buf[3] << 8 | buf[4]) == (size_t)n - 5u);
    CHECK(buf[5] == 0x01);
    CHECK(info.has_sni);
    CHECK(info.nciphers == 3u);
    CHECK(strcmp(info.alpn_first, "h2") == 0);

    /* the key share must be the caller's, not invented */
    {
        uint8_t want[QN_X25519_LEN];
        size_t  i;
        bool    found = false;
        memset(want, 0x42, sizeof want);
        for (i = 0; i + sizeof want <= (size_t)n; i++)
            if (memcmp(buf + i, want, sizeof want) == 0)
                found = true;
        CHECK(found);
    }

    /* a hostname longer than the field allows must be refused, not truncated */
    {
        char big[300];
        memset(big, 'a', sizeof big - 1);
        big[sizeof big - 1] = 0;
        CHECK(build(QN_TLS_FP_CHROME, big, &info, buf, sizeof buf) < 0);
    }

    /* and a buffer that cannot hold the hello must fail cleanly */
    CHECK(build(QN_TLS_FP_CHROME, "example.com", &info, buf, 64) < 0);
}

static void test_fp_parse(void)
{
    qn_tls_fp fp;

    CHECK(qn_tls_fp_parse("chrome", &fp) && fp == QN_TLS_FP_CHROME);
    CHECK(qn_tls_fp_parse("firefox", &fp) && fp == QN_TLS_FP_FIREFOX);
    CHECK(qn_tls_fp_parse("safari", &fp) && fp == QN_TLS_FP_SAFARI);
    CHECK(qn_tls_fp_parse("random", &fp) && fp == QN_TLS_FP_RANDOM);
    CHECK(qn_tls_fp_parse("chrome-android-126", &fp) && fp == QN_TLS_FP_CHROME);
    CHECK(qn_tls_fp_parse("firefox-android-127", &fp) && fp == QN_TLS_FP_FIREFOX);
    CHECK(qn_tls_fp_parse("safari-ios-17", &fp) && fp == QN_TLS_FP_SAFARI);
    CHECK(strcmp(qn_tls_fp_str(QN_TLS_FP_CHROME), "chrome-android-126") == 0);
    CHECK(!qn_tls_fp_parse("edge", &fp));
    CHECK(!qn_tls_fp_parse(NULL, &fp));
    CHECK(!qn_tls_fp_parse("chrome", NULL));
    CHECK(strcmp(qn_tls_fp_str((qn_tls_fp)255), "invalid") == 0);
}

static void test_random_requires_instance(void)
{
    qn_hello_req req;
    qn_hello_info info;
    uint8_t hello[4096];

    memset(&req, 0, sizeof req);
    req.sni = "example.com";
    req.allow_tls12 = true;
    req.grease_seed = 1u;
    memset(req.random, 0xA5, sizeof req.random);
    memset(req.session_id, 0x5A, sizeof req.session_id);
    memset(req.key_share, 0x42, sizeof req.key_share);

    req.fp = QN_TLS_FP_RANDOM;
    CHECK(qn_tls_hello_build(&req, hello, sizeof hello, &info) < 0);
    CHECK(qn_tls_build_hello(hello, sizeof hello, "example.com", NULL,
                             QN_TLS_FP_RANDOM) < 0);
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}

enum sh_case {
    SH_VALID = 0,
    SH_BAD_LEGACY_VERSION,
    SH_BAD_COMPRESSION,
    SH_DUP_VERSION,
    SH_TRAILING_BYTE,
    SH_ALPN_WRONG_FLIGHT
};

static size_t server_hello(const qn_tls_session *s, uint8_t *wire, enum sh_case which)
{
    uint8_t  sk[32] = { 7u }, peer[32];
    size_t   p = 9u, compression_at, extlen_at, ext_start;

    qn_x25519_base(peer, sk);
    wire[0] = 22u;
    wire[1] = 3u;
    wire[2] = 3u;
    wire[5] = 2u;

    put16(wire + p, 0x0303u);
    p += 2u;
    memset(wire + p, 0xA6, 32u);
    p += 32u;
    wire[p++] = s->session_id_len;
    memcpy(wire + p, s->session_id, s->session_id_len);
    p += s->session_id_len;
    put16(wire + p, 0x1303u);
    p += 2u;
    compression_at = p;
    wire[p++] = 0u;

    extlen_at = p;
    p += 2u;
    ext_start = p;

    put16(wire + p, 0x002Bu);
    put16(wire + p + 2u, 2u);
    put16(wire + p + 4u, 0x0304u);
    p += 6u;

    put16(wire + p, 0x0033u);
    put16(wire + p + 2u, 36u);
    put16(wire + p + 4u, 0x001Du);
    put16(wire + p + 6u, 32u);
    memcpy(wire + p + 8u, peer, 32u);
    p += 40u;

    if (which == SH_DUP_VERSION) {
        put16(wire + p, 0x002Bu);
        put16(wire + p + 2u, 2u);
        put16(wire + p + 4u, 0x0304u);
        p += 6u;
    } else if (which == SH_ALPN_WRONG_FLIGHT) {
        static const uint8_t alpn[] = { 0, 0x10, 0, 5, 0, 3, 2, 'h', '2' };
        memcpy(wire + p, alpn, sizeof alpn);
        p += sizeof alpn;
    }

    put16(wire + extlen_at, (uint16_t)(p - ext_start));
    if (which == SH_TRAILING_BYTE)
        wire[p++] = 0xA5u;
    if (which == SH_BAD_LEGACY_VERSION)
        wire[10] = 0x02u;
    if (which == SH_BAD_COMPRESSION)
        wire[compression_at] = 1u;

    put24(wire + 6u, (uint32_t)(p - 9u));
    put16(wire + 3u, (uint16_t)(p - 5u));
    return p;
}

enum hrr_case {
    HRR_VALID = 0,
    HRR_NO_COOKIE,
    HRR_X25519_REQUEST,
    HRR_ALTERNATE_GROUP,
    HRR_BAD_COOKIE_LENGTH,
    HRR_UNKNOWN_EXTENSION
};

static size_t hello_retry_request(const qn_tls_session *s, uint8_t *wire,
                                  enum hrr_case which)
{
    static const uint8_t hrr_random[32] = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    };
    static const uint8_t cookie[] = { 0x51u, 0x4Eu, 0x2Du, 0x48u, 0x52u, 0x52u };
    size_t p = 9u, extlen_at, ext_start;

    wire[0] = 22u;
    wire[1] = 3u;
    wire[2] = 3u;
    wire[5] = 2u;
    put16(wire + p, 0x0303u);
    p += 2u;
    memcpy(wire + p, hrr_random, sizeof hrr_random);
    p += sizeof hrr_random;
    wire[p++] = s->session_id_len;
    memcpy(wire + p, s->session_id, s->session_id_len);
    p += s->session_id_len;
    put16(wire + p, 0x1303u);
    p += 2u;
    wire[p++] = 0u;
    extlen_at = p;
    p += 2u;
    ext_start = p;

    put16(wire + p, 0x002Bu);
    put16(wire + p + 2u, 2u);
    put16(wire + p + 4u, 0x0304u);
    p += 6u;

    if (which != HRR_NO_COOKIE) {
        put16(wire + p, 0x002Cu);
        put16(wire + p + 2u, (uint16_t)(sizeof cookie + 2u));
        put16(wire + p + 4u,
              (uint16_t)(sizeof cookie + (which == HRR_BAD_COOKIE_LENGTH ? 1u : 0u)));
        memcpy(wire + p + 6u, cookie, sizeof cookie);
        p += 6u + sizeof cookie;
    }
    if (which == HRR_X25519_REQUEST || which == HRR_ALTERNATE_GROUP) {
        put16(wire + p, 0x0033u);
        put16(wire + p + 2u, 2u);
        put16(wire + p + 4u, which == HRR_X25519_REQUEST ? 0x001Du : 0x0017u);
        p += 6u;
    }
    if (which == HRR_UNKNOWN_EXTENSION) {
        put16(wire + p, 0x1234u);
        put16(wire + p + 2u, 0u);
        p += 4u;
    }
    put16(wire + extlen_at, (uint16_t)(p - ext_start));
    put24(wire + 6u, (uint32_t)(p - 9u));
    put16(wire + 3u, (uint16_t)(p - 5u));
    return p;
}

static bool start_test_session(qn_tls_session *session, qn_rng *rng,
                               uint8_t *hello, size_t hello_cap)
{
    qn_tls_config config;

    qn_rng_seed(rng, UINT64_C(0x514E2D4852520001));
    memset(&config, 0, sizeof config);
    config.sni = "example.com";
    config.fp = QN_TLS_FP_CHROME;
    config.allow_tls12 = true;
    config.rng = rng;
    qn_tls_init(session, &config);
    return qn_tls_start(session, hello, hello_cap) > 0;
}

static qn_tls_rc feed_once(qn_tls_session *session, const uint8_t *wire, size_t len,
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t app[32];
    qn_tls_io io;
    qn_tls_rc rc;

    memset(&io, 0, sizeof io);
    io.in = wire;
    io.inlen = len;
    io.out = out;
    io.outcap = out_cap;
    io.app = app;
    io.appcap = sizeof app;
    rc = qn_tls_recv(session, &io);
    if (out_len)
        *out_len = io.outlen;
    return rc;
}

static void test_hrr_capability_path(void)
{
    uint8_t hello[1024], wire[512], out[1024], final_wire[512];
    size_t split;

    {
        qn_tls_session template_session;
        qn_rng template_rng;
        size_t n;

        CHECK(start_test_session(&template_session, &template_rng, hello, sizeof hello));
        n = hello_retry_request(&template_session, wire, HRR_VALID);
        qn_tls_free(&template_session);

        for (split = 0u; split < n; split++) {
            qn_tls_session session;
            qn_rng rng;
            size_t out_n = 0u;
            qn_hello_info info;

            CHECK(start_test_session(&session, &rng, hello, sizeof hello));
            n = hello_retry_request(&session, wire, HRR_VALID);
            CHECK(feed_once(&session, wire, split, out, sizeof out, &out_n) ==
                  QN_TLS_RC_MORE);
            CHECK(out_n == 0u);
            CHECK(feed_once(&session, wire + split, n - split, out, sizeof out,
                            &out_n) == QN_TLS_RC_MORE);
            CHECK(session.hrr_done && session.st == QN_TLS_ST_WAIT_SH);
            CHECK(out_n > 0u && qn_tls_hello_inspect(out, out_n, &info));
            CHECK(qn_tls_hello_capability_check(&info, true, NULL, 0u));
            CHECK(has_u16(info.exts, info.nexts, 0x002Cu));
            qn_tls_free(&session);
        }
    }

    {
        qn_tls_session session;
        qn_rng rng;
        size_t n, out_n = 0u, final_n;

        CHECK(start_test_session(&session, &rng, hello, sizeof hello));
        n = hello_retry_request(&session, wire, HRR_VALID);
        CHECK(feed_once(&session, wire, n, out, sizeof out, &out_n) == QN_TLS_RC_MORE);
        CHECK(out_n > 0u && session.hrr_done);
        final_n = server_hello(&session, final_wire, SH_VALID);
        CHECK(feed_once(&session, final_wire, final_n, out, sizeof out, &out_n) ==
              QN_TLS_RC_MORE);
        CHECK(session.st == QN_TLS_ST_WAIT_EE);
        qn_tls_free(&session);
    }

    {
        static const struct {
            enum hrr_case which;
            qn_tls_rc expected;
        } cases[] = {
            { HRR_NO_COOKIE, QN_TLS_RC_PROTO },
            { HRR_X25519_REQUEST, QN_TLS_RC_PROTO },
            { HRR_ALTERNATE_GROUP, QN_TLS_RC_UNSUPPORTED },
            { HRR_BAD_COOKIE_LENGTH, QN_TLS_RC_PROTO },
            { HRR_UNKNOWN_EXTENSION, QN_TLS_RC_PROTO }
        };
        size_t i;

        for (i = 0u; i < QN_ARRAY_LEN(cases); i++) {
            qn_tls_session session;
            qn_rng rng;
            size_t n, out_n = 0u;

            CHECK(start_test_session(&session, &rng, hello, sizeof hello));
            n = hello_retry_request(&session, wire, cases[i].which);
            CHECK(feed_once(&session, wire, n, out, sizeof out, &out_n) ==
                  cases[i].expected);
            CHECK(out_n == 0u && !session.hrr_done);
            qn_tls_free(&session);
        }
    }

    {
        qn_tls_session session;
        qn_rng rng;
        size_t n, out_n = 0u;

        CHECK(start_test_session(&session, &rng, hello, sizeof hello));
        n = hello_retry_request(&session, wire, HRR_VALID);
        CHECK(feed_once(&session, wire, n, out, 64u, &out_n) == QN_TLS_RC_SPACE);
        CHECK(out_n == 0u && !session.hrr_done);
        qn_tls_free(&session);
    }
}

static qn_tls_rc feed_server_hello(enum sh_case which, uint8_t *state)
{
    uint8_t         hello[1024], wire[512], out[512], app[32];
    qn_rng          rng;
    qn_tls_config   cfg;
    qn_tls_session  s;
    qn_tls_io       io;
    qn_tls_rc       rc;
    size_t          n;

    qn_rng_seed(&rng, 0xC0FFEEu);
    memset(&cfg, 0, sizeof cfg);
    cfg.sni = "example.com";
    cfg.fp = QN_TLS_FP_CHROME;
    cfg.rng = &rng;
    qn_tls_init(&s, &cfg);
    CHECK(qn_tls_start(&s, hello, sizeof hello) > 0);

    n = server_hello(&s, wire, which);
    memset(&io, 0, sizeof io);
    io.in = wire;
    io.inlen = n;
    io.out = out;
    io.outcap = sizeof out;
    io.app = app;
    io.appcap = sizeof app;
    rc = qn_tls_recv(&s, &io);
    *state = s.st;
    qn_tls_free(&s);
    return rc;
}

static void test_server_hello_validation(void)
{
    uint8_t st = 0;

    CHECK(feed_server_hello(SH_VALID, &st) == QN_TLS_RC_MORE);
    CHECK(st == QN_TLS_ST_WAIT_EE);
    CHECK(feed_server_hello(SH_BAD_LEGACY_VERSION, &st) == QN_TLS_RC_PROTO);
    CHECK(feed_server_hello(SH_BAD_COMPRESSION, &st) == QN_TLS_RC_PROTO);
    CHECK(feed_server_hello(SH_DUP_VERSION, &st) == QN_TLS_RC_PROTO);
    CHECK(feed_server_hello(SH_TRAILING_BYTE, &st) == QN_TLS_RC_PROTO);
    CHECK(feed_server_hello(SH_ALPN_WRONG_FLIGHT, &st) == QN_TLS_RC_PROTO);
}

static void test_server_hello_split_points(void)
{
    uint8_t hello[1024], wire[512], out[512];
    qn_tls_session template_session;
    qn_rng template_rng;
    size_t n, split;

    CHECK(start_test_session(&template_session, &template_rng, hello, sizeof hello));
    n = server_hello(&template_session, wire, SH_VALID);
    qn_tls_free(&template_session);

    for (split = 0u; split < n; split++) {
        qn_tls_session session;
        qn_rng rng;
        size_t out_n = 0u;

        CHECK(start_test_session(&session, &rng, hello, sizeof hello));
        n = server_hello(&session, wire, SH_VALID);
        CHECK(feed_once(&session, wire, split, out, sizeof out, &out_n) ==
              QN_TLS_RC_MORE);
        CHECK(out_n == 0u);
        CHECK(feed_once(&session, wire + split, n - split, out, sizeof out,
                        &out_n) == QN_TLS_RC_MORE);
        CHECK(out_n == 0u && session.st == QN_TLS_ST_WAIT_EE);
        qn_tls_free(&session);
    }

    {
        qn_tls_session session;
        qn_rng rng;

        CHECK(start_test_session(&session, &rng, hello, sizeof hello));
        n = server_hello(&session, wire, SH_VALID);
        for (split = 0u; split < n; split++) {
            size_t out_n = 0u;

            CHECK(feed_once(&session, wire + split, 1u, out, sizeof out, &out_n) ==
                  QN_TLS_RC_MORE);
            CHECK(out_n == 0u);
        }
        CHECK(session.st == QN_TLS_ST_WAIT_EE);
        qn_tls_free(&session);
    }
}

/* QN2-029: the TLS 1.2 AEAD sequence number must never wrap to a reused nonce. */
static void test_tls12_sequence_wrap(void)
{
    static const uint64_t seqs[] = { UINT64_MAX - 1u, UINT64_MAX };
    uint8_t               key[32];
    size_t                i;

    memset(key, 0x3C, sizeof key);

    for (i = 0; i < sizeof seqs / sizeof seqs[0]; i++) {
        qn_tls_session *s = (qn_tls_session *)calloc(1, sizeof *s);
        uint8_t         out[256];
        int             n;
        size_t          plen = 0;

        CHECK(s != NULL);
        if (!s)
            return;

        s->aead_id = QN_AEAD_AES128GCM;
        CHECK(qn_aead_init(&s->wr.aead, QN_AEAD_AES128GCM, key));
        CHECK(qn_aead_init(&s->rd.aead, QN_AEAD_AES128GCM, key));
        s->wr.on = s->rd.on = true;
        s->wr.seq = s->rd.seq = seqs[i];

        n = qn_tls12_seal(s, 23u, key, 16u, out, sizeof out);
        if (seqs[i] == UINT64_MAX) {
            CHECK(n < 0); /* the record that would wrap is refused */
            s->rec_len = 5u + 8u + 16u + QN_AEAD_TAG_LEN;
            CHECK(qn_tls12_open(s, 23u, &plen) == QN_TLS_RC_PROTO);
        } else {
            CHECK(n > 0);
            CHECK(s->wr.seq == UINT64_MAX);
            /* The next one has nowhere to go. */
            CHECK(qn_tls12_seal(s, 23u, key, 16u, out, sizeof out) < 0);
        }
        free(s);
    }
}

/* Builds a handshake message body straight into the session's parse buffer. */
/* The state a 1.2 server flight starts from: suite chosen, offered list known. */
static void tls12_begin(qn_tls_session *s)
{
    static const uint16_t offered[] = { 0x0403u, 0x0503u, 0x0603u,
                                        0x0804u, 0x0805u, 0x0806u };

    qn_tls12_setup(s);
    s->suite    = 0xC02Fu; /* ECDHE-RSA-AES128-GCM-SHA256 */
    s->nsigalgs = (uint8_t)(sizeof offered / sizeof offered[0]);
    memcpy(s->sigalgs, offered, sizeof offered);
}

static void stage_hs(qn_tls_session *s, uint32_t type, const uint8_t *body, size_t n)
{
    s->hs_type = type;
    s->hs_len  = (uint32_t)n;
    s->hs_kept = (uint32_t)n;
    if (n)
        memcpy(s->hs, body, n);
}

/* QN2-025: ServerKeyExchange must carry complete signature framing. */
static void test_tls12_server_kx_signature_framing(void)
{
    uint8_t        base[4 + QN_X25519_LEN + 2 + 2 + 8];
    qn_tls_session s;
    size_t         params = 4u + QN_X25519_LEN;
    size_t         i;

    memset(base, 0, sizeof base);
    base[0] = 0x03;                  /* named_curve */
    base[1] = 0x00; base[2] = 0x1D;  /* x25519 */
    base[3] = QN_X25519_LEN;
    memset(base + 4, 0xAB, QN_X25519_LEN);
    base[params]      = 0x08;
    base[params + 1u] = 0x04;
    base[params + 2u] = 0x00;
    base[params + 3u] = 0x08;        /* signature length 8 */
    memset(base + params + 4u, 0x5A, 8u);

    /* Complete framing is accepted. */
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    stage_hs(&s, HS_SERVER_KX, base, sizeof base);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO); /* certificate first */

    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    s.tls12_step = T12_EXPECT_SERVER_KX;
    stage_hs(&s, HS_SERVER_KX, base, sizeof base);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_OK);
    CHECK(s.have_peer);

    /* Params only: the signature is structurally absent. */
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    s.tls12_step = T12_EXPECT_SERVER_KX;
    stage_hs(&s, HS_SERVER_KX, base, params);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

    /* Signature algorithm present, length missing. */
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    s.tls12_step = T12_EXPECT_SERVER_KX;
    stage_hs(&s, HS_SERVER_KX, base, params + 2u);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

    /* Length present, signature bytes truncated. */
    for (i = 0; i < 8u; i++) {
        memset(&s, 0, sizeof s);
        tls12_begin(&s);
        s.tls12_step = T12_EXPECT_SERVER_KX;
        stage_hs(&s, HS_SERVER_KX, base, params + 4u + i);
        CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    }

    /* A zero-length signature is illegal. */
    {
        uint8_t zero[4 + QN_X25519_LEN + 2 + 2];

        memcpy(zero, base, sizeof zero);
        zero[params + 2u] = 0;
        zero[params + 3u] = 0;
        memset(&s, 0, sizeof s);
        tls12_begin(&s);
        s.tls12_step = T12_EXPECT_SERVER_KX;
        stage_hs(&s, HS_SERVER_KX, zero, sizeof zero);
        CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    }

    /* Trailing bytes after a complete signature are malformed framing. */
    {
        uint8_t extra[sizeof base + 3];

        memcpy(extra, base, sizeof base);
        memset(extra + sizeof base, 0x11, 3);
        memset(&s, 0, sizeof s);
        tls12_begin(&s);
        s.tls12_step = T12_EXPECT_SERVER_KX;
        stage_hs(&s, HS_SERVER_KX, extra, sizeof extra);
        CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    }
}

/* QN2-026: the 1.2 server flight is an ordered sequence, not a set. */
static void test_tls12_flight_order(void)
{
    qn_tls_session s;
    uint8_t        body[1] = { 0 };

    /* ServerHelloDone before anything else. */
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    stage_hs(&s, HS_HELLO_DONE, NULL, 0);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

    /* ServerKeyExchange before Certificate. */
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    stage_hs(&s, HS_SERVER_KX, body, 1u);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

    /* A CertificateRequest out of position. */
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    stage_hs(&s, HS_CERT_REQ, NULL, 0);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

    /* A repeated CertificateRequest. */
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    s.tls12_step = T12_EXPECT_REQ_OR_DONE;
    stage_hs(&s, HS_CERT_REQ, NULL, 0);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_UNSUPPORTED);
    stage_hs(&s, HS_CERT_REQ, NULL, 0);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

    /* ServerHelloDone with a body. */
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    s.tls12_step = T12_EXPECT_REQ_OR_DONE;
    stage_hs(&s, HS_HELLO_DONE, body, 1u);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

    /* A Certificate whose framing never completed is not a Certificate. */
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    stage_hs(&s, HS_CERT, body, 1u);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    CHECK(!s.saw_certificate);
}

/* The chosen signature algorithm must be offered and match the suite's key type. */
static void test_tls12_sigalg_semantics(void)
{
    static const struct {
        uint16_t  suite;
        uint16_t  alg;
        qn_tls_rc want;
        const char *what;
    } cases[] = {
        { 0xC02Fu, 0x0804u, QN_TLS_RC_OK,    "rsa_pss_rsae_sha256 on an RSA suite" },
        { 0xC02Bu, 0x0403u, QN_TLS_RC_OK,    "ecdsa_secp256r1 on an ECDSA suite" },
        { 0xC02Fu, 0x0403u, QN_TLS_RC_PROTO, "ecdsa algorithm on an RSA suite" },
        { 0xC02Bu, 0x0804u, QN_TLS_RC_PROTO, "rsa algorithm on an ECDSA suite" },
        { 0xC02Fu, 0xFFFFu, QN_TLS_RC_PROTO, "undefined codepoint" },
        { 0xC02Fu, 0x0000u, QN_TLS_RC_PROTO, "both components none" },
        { 0xC02Fu, 0x0400u, QN_TLS_RC_PROTO, "signature none" },
        { 0xC02Fu, 0x0001u, QN_TLS_RC_PROTO, "hash none" },
        { 0xC02Fu, 0x0803u, QN_TLS_RC_PROTO, "undefined 0x08 scheme" },
        { 0xC02Fu, 0x0401u, QN_TLS_RC_PROTO, "rsa_pkcs1 is not implemented" },
        { 0xC02Bu, 0x0603u, QN_TLS_RC_OK,    "ecdsa_sha512 on an ECDSA suite" },
        { 0xC02Fu, 0x0603u, QN_TLS_RC_PROTO, "ecdsa_sha512 on an RSA suite" },
        { 0xC02Fu, 0x0807u, QN_TLS_RC_PROTO, "ed25519 is not implemented" }
    };
    uint8_t        base[4 + QN_X25519_LEN + 2 + 2 + 8];
    qn_tls_session s;
    size_t         params = 4u + QN_X25519_LEN;
    size_t         i;

    memset(base, 0, sizeof base);
    base[0] = 0x03;
    base[1] = 0x00; base[2] = 0x1D;
    base[3] = QN_X25519_LEN;
    memset(base + 4, 0xAB, QN_X25519_LEN);
    base[params + 2u] = 0x00;
    base[params + 3u] = 0x08;
    memset(base + params + 4u, 0x5A, 8u);

    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        base[params]      = (uint8_t)(cases[i].alg >> 8);
        base[params + 1u] = (uint8_t)cases[i].alg;

        memset(&s, 0, sizeof s);
        tls12_begin(&s);
        s.suite      = cases[i].suite;
        s.tls12_step = T12_EXPECT_SERVER_KX;
        stage_hs(&s, HS_SERVER_KX, base, sizeof base);
        if (qn_tls12_dispatch(&s, NULL) != cases[i].want) {
            printf("FAIL sigalg case: %s\n", cases[i].what);
            failures++;
        }
    }

    /* Offering nothing means nothing can be checked against, so nothing passes. */
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    s.nsigalgs   = 0;
    s.tls12_step = T12_EXPECT_SERVER_KX;
    base[params] = 0x08; base[params + 1u] = 0x04;
    stage_hs(&s, HS_SERVER_KX, base, sizeof base);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
}

/* Builds a 1.2 Certificate body from the given certificate sizes. */
static size_t build_cert_body(uint8_t *out, size_t cap, const uint32_t *sizes,
                              size_t n)
{
    size_t off = 3u, i;
    uint32_t list;

    for (i = 0; i < n; i++) {
        uint32_t j;

        if (off + 3u + sizes[i] > cap)
            return 0;
        out[off++] = (uint8_t)(sizes[i] >> 16);
        out[off++] = (uint8_t)(sizes[i] >> 8);
        out[off++] = (uint8_t)sizes[i];
        for (j = 0; j < sizes[i]; j++)
            out[off + j] = (uint8_t)(j + i);
        off += sizes[i];
    }
    list   = (uint32_t)(off - 3u);
    out[0] = (uint8_t)(list >> 16);
    out[1] = (uint8_t)(list >> 8);
    out[2] = (uint8_t)list;
    return off;
}

/* Mirrors hs_feed: the scanner sees every byte, hs[] keeps only a prefix. */
static void stage_cert(qn_tls_session *s, const uint8_t *body, size_t n,
                       size_t chunk)
{
    size_t off = 0;

    s->hs_type = HS_CERT;
    s->hs_len  = (uint32_t)n;
    s->hs_kept = (uint32_t)(n < QN_TLS_HS_BUF ? n : QN_TLS_HS_BUF);
    if (s->hs_kept)
        memcpy(s->hs, body, s->hs_kept);
    qn_cert_scan_init(&s->cert_scan, (uint32_t)n, QN_TLS_CERT_MAX);
    while (off < n) {
        size_t take = n - off < chunk ? n - off : chunk;

        if (!qn_cert_scan_push(&s->cert_scan, body + off, take))
            return;
        off += take;
    }
}

/* A chain is validated by framing over every byte, at any size. */
static void test_tls12_certificate_framing(void)
{
    enum { CAP = 8192 };
    static const uint32_t one_small[]  = { 900u };
    static const uint32_t one_large[]  = { 6000u };
    static const uint32_t chain[]      = { 2500u, 2400u, 1200u };
    uint8_t       *body = (uint8_t *)malloc(CAP);
    qn_tls_session s;
    size_t         n;

    CHECK(body != NULL);
    if (!body)
        return;

    /* Under the parse buffer, over it, and a multi-certificate chain. */
    n = build_cert_body(body, CAP, one_small, 1u);
    CHECK(n == 906u);
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    stage_cert(&s, body, n, n);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_OK && s.saw_certificate);

    n = build_cert_body(body, CAP, one_large, 1u);
    CHECK(n > QN_TLS_HS_BUF);
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    stage_cert(&s, body, n, n);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_OK && s.saw_certificate);
    CHECK(s.cert_scan.count == 1u);

    n = build_cert_body(body, CAP, chain, 3u);
    CHECK(n > QN_TLS_HS_BUF);
    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    stage_cert(&s, body, n, n);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_OK && s.saw_certificate);
    CHECK(s.cert_scan.count == 3u);

    /* Every chunking of the same bytes must reach the same verdict. */
    {
        size_t chunk;

        for (chunk = 1u; chunk <= 8u; chunk++) {
            memset(&s, 0, sizeof s);
            tls12_begin(&s);
            stage_cert(&s, body, n, chunk);
            CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_OK);
        }
        memset(&s, 0, sizeof s);
        tls12_begin(&s);
        stage_cert(&s, body, n, 4095u);
        CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_OK);
    }

    /* A large chain whose framing lies must not pass merely for being large. */
    {
        static const struct {
            uint32_t at;
            uint8_t  to;
        } bad[] = {
            { 2u, 0x00u },  /* list length disagrees with the message length */
            { 5u, 0xFFu },  /* leaf length overruns the list */
            { 5u, 0x71u },  /* leaf length one byte too long */
            { 4u, 0x00u }   /* leaf length far short of the bytes that follow */
        };
        size_t i;

        for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            size_t  m = build_cert_body(body, CAP, one_large, 1u);
            uint8_t save;

            CHECK(m > QN_TLS_HS_BUF);
            save            = body[bad[i].at];
            body[bad[i].at] = bad[i].to;
            memset(&s, 0, sizeof s);
            tls12_begin(&s);
            stage_cert(&s, body, m, m);
            CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
            CHECK(!s.saw_certificate);
            body[bad[i].at] = save;
        }
    }

    /* A zero-length certificate inside a well-formed list is still malformed. */
    {
        static const uint32_t zero_leaf[] = { 0u };
        size_t m = build_cert_body(body, CAP, zero_leaf, 1u);

        CHECK(m == 6u);
        memset(&s, 0, sizeof s);
        tls12_begin(&s);
        stage_cert(&s, body, m, m);
        CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
        CHECK(!s.saw_certificate);
    }

    /* Trailing bytes after the list, and truncation at each length field. */
    {
        size_t m = build_cert_body(body, CAP, one_large, 1u);
        size_t cut;

        memset(&s, 0, sizeof s);
        tls12_begin(&s);
        stage_cert(&s, body, m + 1u, m + 1u); /* declares one byte too many */
        CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

        for (cut = 1u; cut <= 8u; cut++) {
            memset(&s, 0, sizeof s);
            tls12_begin(&s);
            stage_cert(&s, body, m - cut, m - cut);
            CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
            CHECK(!s.saw_certificate);
        }
        /* Stopping one byte inside the final certificate is still incomplete. */
        memset(&s, 0, sizeof s);
        tls12_begin(&s);
        s.hs_len = (uint32_t)m;
        qn_cert_scan_init(&s.cert_scan, (uint32_t)m, QN_TLS_CERT_MAX);
        CHECK(qn_cert_scan_push(&s.cert_scan, body, m - 1u));
        s.hs_type = HS_CERT;
        CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    }

    /* An empty list and a message too short to frame are both rejected. */
    {
        uint8_t empty[3] = { 0, 0, 0 };

        memset(&s, 0, sizeof s);
        tls12_begin(&s);
        stage_cert(&s, empty, sizeof empty, sizeof empty);
        CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

        memset(&s, 0, sizeof s);
        tls12_begin(&s);
        stage_cert(&s, empty, 2u, 2u);
        CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    }

    /* The bound is a refusal, not a truncation. */
    {
        memset(&s, 0, sizeof s);
        tls12_begin(&s);
        qn_cert_scan_init(&s.cert_scan, QN_TLS_CERT_MAX + 1u, QN_TLS_CERT_MAX);
        s.hs_type = HS_CERT;
        s.hs_len  = QN_TLS_CERT_MAX + 1u;
        CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    }

    free(body);
}

/* QN2-027: unsupported KeyUpdate is typed instead of causing later decrypt failures. */
static void test_tls13_key_update_is_typed(void)
{
    qn_tls_session s;
    uint8_t        req[1];

    for (req[0] = 0; req[0] <= 1u; req[0]++) {
        memset(&s, 0, sizeof s);
        s.st = QN_TLS_ST_READY;
        stage_hs(&s, HS_KEY_UPDATE, req, 1u);
        CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_UNSUPPORTED);
    }

    /* An invalid request byte, a wrong length, and the wrong state. */
    memset(&s, 0, sizeof s);
    s.st   = QN_TLS_ST_READY;
    req[0] = 2u;
    stage_hs(&s, HS_KEY_UPDATE, req, 1u);
    CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

    memset(&s, 0, sizeof s);
    s.st = QN_TLS_ST_READY;
    stage_hs(&s, HS_KEY_UPDATE, NULL, 0);
    CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

    memset(&s, 0, sizeof s);
    s.st   = QN_TLS_ST_WAIT_FIN;
    req[0] = 0u;
    stage_hs(&s, HS_KEY_UPDATE, req, 1u);
    CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
}

static void test_tls13_cert_verify_capability(void)
{
    uint8_t message[] = { 0x04u, 0x03u, 0x00u, 0x01u, 0xA5u };
    qn_tls_session session;

    memset(&session, 0, sizeof session);
    session.st = QN_TLS_ST_WAIT_FIN;
    session.saw_certificate = true;
    session.sigalgs[0] = 0x0403u;
    session.nsigalgs = 1u;
    stage_hs(&session, HS_CERT_VERIFY, message, sizeof message);
    CHECK(qn_tls13_dispatch(&session, NULL) == QN_TLS_RC_OK);
    CHECK(session.saw_cert_verify);

    memset(&session, 0, sizeof session);
    session.st = QN_TLS_ST_WAIT_FIN;
    session.saw_certificate = true;
    session.sigalgs[0] = 0x0503u;
    session.nsigalgs = 1u;
    stage_hs(&session, HS_CERT_VERIFY, message, sizeof message);
    CHECK(qn_tls13_dispatch(&session, NULL) == QN_TLS_RC_UNSUPPORTED);
    CHECK(!session.saw_cert_verify);

    memset(&session, 0, sizeof session);
    session.st = QN_TLS_ST_WAIT_FIN;
    session.saw_certificate = true;
    session.sigalgs[0] = 0x0807u;
    session.nsigalgs = 1u;
    message[0] = 0x08u;
    message[1] = 0x07u;
    stage_hs(&session, HS_CERT_VERIFY, message, sizeof message);
    CHECK(qn_tls13_dispatch(&session, NULL) == QN_TLS_RC_UNSUPPORTED);
    CHECK(!session.saw_cert_verify);

    memset(&session, 0, sizeof session);
    session.st = QN_TLS_ST_WAIT_FIN;
    session.saw_certificate = true;
    session.sigalgs[0] = 0x0403u;
    session.nsigalgs = 1u;
    message[0] = 0x04u;
    message[1] = 0x03u;
    message[3] = 0x02u;
    stage_hs(&session, HS_CERT_VERIFY, message, sizeof message);
    CHECK(qn_tls13_dispatch(&session, NULL) == QN_TLS_RC_PROTO);
}

/* QN2-028: five plausible bytes are not a certificate. */
static void test_tls13_compressed_certificate_framing(void)
{
    qn_tls_session s;
    uint8_t        msg[8 + 16];
    size_t         i;

    memset(msg, 0, sizeof msg);
    msg[0] = 0; msg[1] = 2;          /* brotli */
    msg[2] = 0; msg[3] = 0; msg[4] = 64; /* uncompressed_length */
    msg[5] = 0; msg[6] = 0; msg[7] = 16; /* compressed_length */
    memset(msg + 8, 0xC3, 16);

    /* Opaque mode: framing accepted, and the state says nothing was parsed. */
    memset(&s, 0, sizeof s);
    s.st = QN_TLS_ST_WAIT_FIN;
    stage_hs(&s, 25u, msg, sizeof msg);
    CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_OK);
    CHECK(!s.saw_certificate);
    CHECK(s.cert_compressed);
    CHECK(s.peer_cn[0] == '\0');
    CHECK(qn_tls_cert_status(&s) == QN_TLS_CERT_OPAQUE);

    /* Strict mode: the same framing is validated and then refused. */
    memset(&s, 0, sizeof s);
    s.st             = QN_TLS_ST_WAIT_FIN;
    s.cfg.cert_strict = true;
    stage_hs(&s, 25u, msg, sizeof msg);
    CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_UNSUPPORTED);
    CHECK(!s.saw_certificate);
    CHECK(qn_tls_cert_status(&s) == QN_TLS_CERT_OPAQUE);

    /* Strict mode rejects bad framing as malformed, not as unsupported. */
    memset(&s, 0, sizeof s);
    s.st              = QN_TLS_ST_WAIT_FIN;
    s.cfg.cert_strict = true;
    stage_hs(&s, 25u, msg, sizeof msg);
    s.hs[7] = 15u; /* compressed_length disagrees with the message */
    CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

    /* A parsed certificate is a different state from an opaque one. */
    memset(&s, 0, sizeof s);
    CHECK(qn_tls_cert_status(&s) == QN_TLS_CERT_NONE);
    s.saw_certificate = true;
    CHECK(qn_tls_cert_status(&s) == QN_TLS_CERT_PARSED);

    /* Truncated chain storage still validates lengths against the complete message. */
    memset(&s, 0, sizeof s);
    s.st = QN_TLS_ST_WAIT_FIN;
    stage_hs(&s, 25u, msg, sizeof msg);
    s.hs[5] = 0x00; s.hs[6] = 0x40; s.hs[7] = 0x00; /* compressed_length 16384 */
    s.hs_len = 16384u + 8u;
    CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_OK);
    CHECK(s.cert_compressed);

    /* The declared length still has to match, truncation or not. */
    memset(&s, 0, sizeof s);
    s.st = QN_TLS_ST_WAIT_FIN;
    stage_hs(&s, 25u, msg, sizeof msg);
    s.hs[5] = 0x00; s.hs[6] = 0x40; s.hs[7] = 0x00;
    s.hs_len = 16384u + 9u;
    CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

    /* Truncated header. */
    for (i = 0; i < 8u; i++) {
        memset(&s, 0, sizeof s);
        s.st = QN_TLS_ST_WAIT_FIN;
        stage_hs(&s, 25u, msg, i);
        CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    }

    /* compressed_length disagrees with the message. */
    {
        uint8_t bad[sizeof msg];

        memcpy(bad, msg, sizeof bad);
        bad[7] = 15u;
        memset(&s, 0, sizeof s);
        s.st = QN_TLS_ST_WAIT_FIN;
        stage_hs(&s, 25u, bad, sizeof bad);
        CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

        bad[7] = 17u;
        memset(&s, 0, sizeof s);
        s.st = QN_TLS_ST_WAIT_FIN;
        stage_hs(&s, 25u, bad, sizeof bad);
        CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    }

    /* Zero uncompressed length, and one beyond the parse buffer. */
    {
        uint8_t bad[sizeof msg];

        memcpy(bad, msg, sizeof bad);
        bad[2] = bad[3] = bad[4] = 0;
        memset(&s, 0, sizeof s);
        s.st = QN_TLS_ST_WAIT_FIN;
        stage_hs(&s, 25u, bad, sizeof bad);
        CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

        bad[2] = 0xFF; bad[3] = 0xFF; bad[4] = 0xFF;
        memset(&s, 0, sizeof s);
        s.st = QN_TLS_ST_WAIT_FIN;
        stage_hs(&s, 25u, bad, sizeof bad);
        CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    }

    /* An algorithm we never offered is unsupported, not a certificate. */
    {
        uint8_t bad[sizeof msg];

        memcpy(bad, msg, sizeof bad);
        bad[1] = 1u; /* zlib */
        memset(&s, 0, sizeof s);
        s.st = QN_TLS_ST_WAIT_FIN;
        stage_hs(&s, 25u, bad, sizeof bad);
        CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_UNSUPPORTED);
        CHECK(!s.saw_certificate && !s.cert_compressed);
    }
}

static void test_tls13_certificate_framing(void)
{
    static const uint8_t one_zero[] = { 0u };
    static const uint8_t empty_list[] = { 0u, 0u, 0u, 0u };
    static const uint8_t zero_entry[] = { 0u, 0u, 0u, 5u, 0u, 0u, 0u, 0u };
    qn_tls_session s;

    memset(&s, 0, sizeof s);
    s.st = QN_TLS_ST_WAIT_FIN;
    stage_hs(&s, HS_CERT, one_zero, sizeof one_zero);
    CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    CHECK(!s.saw_certificate);

    memset(&s, 0, sizeof s);
    s.st = QN_TLS_ST_WAIT_FIN;
    stage_hs(&s, HS_CERT, empty_list, sizeof empty_list);
    CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    CHECK(!s.saw_certificate);

    memset(&s, 0, sizeof s);
    s.st = QN_TLS_ST_WAIT_FIN;
    stage_hs(&s, HS_CERT, zero_entry, sizeof zero_entry);
    CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    CHECK(!s.saw_certificate);

    memset(&s, 0, sizeof s);
    s.st = QN_TLS_ST_WAIT_FIN;
    s.hs_type = HS_CERT;
    s.hs_len = QN_TLS_CERT_MAX + 1u;
    s.hs_kept = 1u;
    s.hs[0] = 0u;
    CHECK(qn_tls13_dispatch(&s, NULL) == QN_TLS_RC_PROTO);
    CHECK(!s.saw_certificate);
}

static void test_tls13_rejects_plaintext_alert_after_keys(void)
{
    static const uint8_t alert[] = { RT_ALERT, 0x03u, 0x03u, 0u, 2u, 2u, 40u };
    uint8_t app[16], out[64];
    qn_tls_session s;
    qn_tls_io io;

    memset(&s, 0, sizeof s);
    s.version = 0x0304u;
    s.st = QN_TLS_ST_READY;
    s.rd.on = true;
    memset(&io, 0, sizeof io);
    io.in = alert;
    io.inlen = sizeof alert;
    io.out = out;
    io.outcap = sizeof out;
    io.app = app;
    io.appcap = sizeof app;
    CHECK(qn_tls_recv(&s, &io) == QN_TLS_RC_PROTO);
}

static void test_tls12_new_ticket_sequence(void)
{
    static const uint8_t ticket[] = { 0u, 0u, 0u, 1u, 0u, 0u };
    qn_tls_session s;

    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    stage_hs(&s, HS_NEW_TICKET, NULL, 0u);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_PROTO);

    memset(&s, 0, sizeof s);
    tls12_begin(&s);
    s.st = QN_TLS_ST_WAIT_CCS;
    stage_hs(&s, HS_NEW_TICKET, ticket, sizeof ticket);
    CHECK(qn_tls12_dispatch(&s, NULL) == QN_TLS_RC_OK);
}

int main(void)
{
    test_tls12_sequence_wrap();
    test_tls12_server_kx_signature_framing();
    test_tls12_flight_order();
    test_tls12_sigalg_semantics();
    test_tls12_certificate_framing();
    test_tls13_key_update_is_typed();
    test_tls13_cert_verify_capability();
    test_tls13_compressed_certificate_framing();
    test_tls13_certificate_framing();
    test_tls13_rejects_plaintext_alert_after_keys();
    test_tls12_new_ticket_sequence();
    test_no_duplicate_extensions();
    test_hello_wire_contract();
    test_profile_instance_wire_identity();
    test_hello_shape();
    test_fp_parse();
    test_random_requires_instance();
    test_server_hello_validation();
    test_server_hello_split_points();
    test_hrr_capability_path();

    if (failures) {
        fprintf(stderr, "tls tests: %d failure(s)\n", failures);
        return 1;
    }
    printf("tls tests: ok\n");
    return 0;
}
