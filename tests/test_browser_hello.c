#include "qanat/tls_hello.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); failures++; \
} } while (0)

static bool has_u16(const uint16_t *values, size_t count, uint16_t value)
{
    size_t i;

    for (i = 0u; i < count; i++)
        if (values[i] == value)
            return true;
    return false;
}

static bool same_u16(const uint16_t *actual, size_t actual_count,
                     const uint16_t *expected, size_t expected_count)
{
    return actual_count == expected_count &&
           !memcmp(actual, expected, expected_count * sizeof expected[0]);
}

static int build(qn_tls_fp fp, uint64_t seed, uint8_t *wire, size_t capacity,
                 qn_hello_info *info)
{
    qn_hello_req request;
    uint8_t hybrid[QN_HYBRID_CLIENT_SHARE_LEN];
    uint8_t x25519[QN_X25519_LEN];
    uint8_t p256[QN_P256_PUBLIC_LEN];
    uint8_t ech_payload[QN_ECH_PAYLOAD_MAX];
    qn_hello_key_share shares[3];
    size_t i;

    memset(&request, 0, sizeof request);
    request.sni = "localhost";
    request.fp = fp;
    request.allow_tls12 = true;
    request.grease_seed = seed;
    for (i = 0u; i < sizeof request.random; i++)
        request.random[i] = (uint8_t)i;
    for (i = 0u; i < sizeof request.session_id; i++)
        request.session_id[i] = (uint8_t)(0x80u + i);
    memset(hybrid, 0x41, sizeof hybrid);
    memset(x25519, 0x42, sizeof x25519);
    memset(p256, 0x43, sizeof p256);
    p256[0] = 0x04u;
    memset(request.ech_enc, 0x44, sizeof request.ech_enc);
    memset(ech_payload, 0x45, sizeof ech_payload);
    shares[0] = (qn_hello_key_share){ QN_GROUP_X25519_MLKEM768, hybrid,
                                      sizeof hybrid };
    shares[1] = (qn_hello_key_share){ QN_GROUP_X25519, x25519, sizeof x25519 };
    shares[2] = (qn_hello_key_share){ QN_GROUP_P256, p256, sizeof p256 };
    request.key_shares = shares;
    request.key_shares_n = 3u;
    request.ech_aead = fp == QN_TLS_FP_FIREFOX ? 0x0003u : 0x0001u;
    request.ech_config_id = 0x46u;
    request.ech_payload = ech_payload;
    request.ech_payload_len = fp == QN_TLS_FP_FIREFOX
                                  ? (uint16_t)(sizeof ech_payload - 1u)
                                  : (uint16_t)sizeof ech_payload;
    return qn_tls_hello_build(&request, wire, capacity, info);
}

static void test_chrome_android_151_shape(void)
{
    static const uint16_t ciphers[] = {
        0x1301u, 0x1302u, 0x1303u, 0xC02Bu, 0xC02Fu, 0xC02Cu, 0xC030u,
        0xCCA9u, 0xCCA8u, 0xC013u, 0xC014u, 0x009Cu, 0x009Du, 0x002Fu,
        0x0035u
    };
    static const uint16_t extensions[] = {
        0x0023u, 0x0000u, 0x002Bu, 0x0033u, 0x001Bu, 0x000Au,
        0xFF01u, 0x000Bu, 0xFE0Du, 0x0012u, 0x002Du, 0x0017u,
        0x0010u, 0x44CDu, 0x000Du, 0x0005u
    };
    static const uint16_t groups[] = { 0x11ECu, 0x001Du, 0x0017u, 0x0018u };
    static const uint16_t sigalgs[] = {
        0x0904u, 0x0905u, 0x0906u, 0x0403u, 0x0804u, 0x0401u,
        0x0503u, 0x0805u, 0x0501u, 0x0806u, 0x0601u
    };
    static const uint16_t versions[] = { 0x0304u, 0x0303u };
    uint8_t wire[4096];
    qn_hello_info info;
    int length = build(QN_TLS_FP_CHROME, UINT64_C(0x151151151), wire,
                       sizeof wire, &info);
    size_t i;

    CHECK(length > 0);
    if (length <= 0)
        return;
    CHECK(qn_tls_hello_inspect(wire, (size_t)length, &info));
    CHECK(length == 1821);
    CHECK(same_u16(info.ciphers, info.nciphers, ciphers,
                   sizeof ciphers / sizeof ciphers[0]));
    CHECK(info.nexts == sizeof extensions / sizeof extensions[0]);
    for (i = 0u; i < sizeof extensions / sizeof extensions[0]; i++)
        CHECK(has_u16(info.exts, info.nexts, extensions[i]));
    CHECK(same_u16(info.groups, info.ngroups, groups,
                   sizeof groups / sizeof groups[0]));
    CHECK(info.nkeyshares == 2u);
    CHECK(info.keyshares[0] == 0x11ECu);
    CHECK(info.keyshare_lens[0] == 1216u);
    CHECK(info.keyshares[1] == 0x001Du);
    CHECK(info.keyshare_lens[1] == 32u);
    CHECK(same_u16(info.sigalgs, info.nsigalgs, sigalgs,
                   sizeof sigalgs / sizeof sigalgs[0]));
    CHECK(same_u16(info.versions, info.nversions, versions,
                   sizeof versions / sizeof versions[0]));
}

static void test_firefox_android_153_shape(void)
{
    static const uint16_t ciphers[] = {
        0x1301u, 0x1303u, 0x1302u, 0xC02Bu, 0xC02Fu, 0xCCA9u, 0xCCA8u,
        0xC02Cu, 0xC030u, 0xC00Au, 0xC013u, 0xC014u, 0x009Cu, 0x009Du,
        0x002Fu, 0x0035u
    };
    static const uint16_t order[] = {
        0x0000u, 0x0017u, 0xFF01u, 0x000Au, 0x000Bu, 0x0023u,
        0x0010u, 0x0005u, 0x0022u, 0x0033u, 0x002Bu, 0x000Du,
        0x002Du, 0x001Cu, 0x001Bu, 0xFE0Du
    };
    static const uint16_t groups[] = {
        0x11ECu, 0x001Du, 0x0017u, 0x0018u, 0x0019u, 0x0100u, 0x0101u
    };
    static const uint16_t sigalgs[] = {
        0x0403u, 0x0503u, 0x0603u, 0x0804u, 0x0805u, 0x0806u,
        0x0401u, 0x0501u, 0x0601u, 0x0203u, 0x0201u
    };
    static const uint16_t versions[] = { 0x0304u, 0x0303u };
    uint8_t wire[4096];
    qn_hello_info info;
    int length = build(QN_TLS_FP_FIREFOX, UINT64_C(0x153153153), wire,
                       sizeof wire, &info);

    CHECK(length > 0);
    if (length <= 0)
        return;
    CHECK(qn_tls_hello_inspect(wire, (size_t)length, &info));
    CHECK(length == 1888);
    CHECK(same_u16(info.ciphers, info.nciphers, ciphers,
                   sizeof ciphers / sizeof ciphers[0]));
    CHECK(info.nexts == sizeof order / sizeof order[0]);
    CHECK(!memcmp(info.exts, order, sizeof order));
    CHECK(same_u16(info.groups, info.ngroups, groups,
                   sizeof groups / sizeof groups[0]));
    CHECK(info.nkeyshares == 3u);
    CHECK(info.keyshares[0] == 0x11ECu);
    CHECK(info.keyshare_lens[0] == 1216u);
    CHECK(info.keyshares[1] == 0x001Du);
    CHECK(info.keyshare_lens[1] == 32u);
    CHECK(info.keyshares[2] == 0x0017u);
    CHECK(info.keyshare_lens[2] == 65u);
    CHECK(same_u16(info.sigalgs, info.nsigalgs, sigalgs,
                   sizeof sigalgs / sizeof sigalgs[0]));
    CHECK(same_u16(info.versions, info.nversions, versions,
                   sizeof versions / sizeof versions[0]));
}

static void test_safari_ios_26_shape(void)
{
    static const uint16_t ciphers[] = {
        0x1302u, 0x1303u, 0x1301u, 0xC02Cu, 0xC02Bu, 0xCCA9u, 0xC030u,
        0xC02Fu, 0xCCA8u, 0xC00Au, 0xC009u, 0xC014u, 0xC013u, 0x009Du,
        0x009Cu, 0x0035u, 0x002Fu, 0xC008u, 0xC012u, 0x000Au
    };
    static const uint16_t order[] = {
        0x0000u, 0x0017u, 0xFF01u, 0x000Au, 0x000Bu, 0x0010u,
        0x0005u, 0x000Du, 0x0012u, 0x0033u, 0x002Du, 0x002Bu, 0x001Bu
    };
    static const uint16_t groups[] = {
        0x11ECu, 0x001Du, 0x0017u, 0x0018u, 0x0019u
    };
    static const uint16_t sigalgs[] = {
        0x0403u, 0x0804u, 0x0401u, 0x0503u, 0x0805u,
        0x0603u, 0x0501u, 0x0806u, 0x0601u, 0x0201u
    };
    static const uint16_t versions[] = { 0x0304u, 0x0303u };
    uint8_t wire[4096];
    qn_hello_info info;
    int length = build(QN_TLS_FP_SAFARI, UINT64_C(0x263263263), wire,
                       sizeof wire, &info);

    CHECK(length > 0);
    if (length <= 0)
        return;
    CHECK(qn_tls_hello_inspect(wire, (size_t)length, &info));
    CHECK(length == 1532);
    CHECK(same_u16(info.ciphers, info.nciphers, ciphers,
                   sizeof ciphers / sizeof ciphers[0]));
    CHECK(info.nexts == sizeof order / sizeof order[0]);
    CHECK(!memcmp(info.exts, order, sizeof order));
    CHECK(same_u16(info.groups, info.ngroups, groups,
                   sizeof groups / sizeof groups[0]));
    CHECK(info.nkeyshares == 2u);
    CHECK(info.keyshares[0] == 0x11ECu);
    CHECK(info.keyshare_lens[0] == 1216u);
    CHECK(info.keyshares[1] == 0x001Du);
    CHECK(info.keyshare_lens[1] == 32u);
    CHECK(same_u16(info.sigalgs, info.nsigalgs, sigalgs,
                   sizeof sigalgs / sizeof sigalgs[0]));
    CHECK(same_u16(info.versions, info.nversions, versions,
                   sizeof versions / sizeof versions[0]));
}

int main(void)
{
    test_chrome_android_151_shape();
    test_firefox_android_153_shape();
    test_safari_ios_26_shape();
    if (failures) {
        fprintf(stderr, "browser hello tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("browser hello tests: ok");
    return 0;
}
