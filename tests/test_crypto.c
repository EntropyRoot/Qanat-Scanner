#include "qanat/crypto.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
    size_t n = 0;
    while (h[0] && h[1] && n < cap) {
        unsigned v;
        if (sscanf(h, "%2x", &v) != 1)
            break;
        out[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

static bool eqhex(const uint8_t *got, size_t n, const char *want)
{
    uint8_t w[256];
    size_t  wn = unhex(want, w, sizeof w);
    return wn == n && memcmp(got, w, n) == 0;
}

typedef struct {
    _Atomic unsigned *ready;
    _Atomic bool     *go;
    const uint8_t    *sha_want;
    const uint8_t    *aead_want;
    bool              ok;
} dispatch_arg;

static void *dispatch_worker(void *opaque)
{
    dispatch_arg *arg = (dispatch_arg *)opaque;
    static const uint8_t zeros[32] = { 0 };

    arg->ok = true;
    atomic_fetch_add_explicit(arg->ready, 1u, memory_order_release);
    while (!atomic_load_explicit(arg->go, memory_order_acquire))
        sched_yield();

    for (unsigned round = 0; round < 32u && arg->ok; round++) {
        static const uint8_t xsk[32] = {
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        };
        static const uint8_t xwant[32] = {
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
            0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
            0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
            0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
        };
        static const uint8_t basepoint[32] = { 9 };
        uint8_t   digest[QN_SHA256_LEN], xout[32];
        uint8_t   sealed[16u + QN_AEAD_TAG_LEN], chacha_sealed[16u + QN_AEAD_TAG_LEN];
        uint8_t   opened[16];
        qn_sha256 sha;
        qn_aead   aead, chacha;

        qn_sha256_init(&sha);
        qn_sha256_update(&sha, "abc", 3u);
        qn_sha256_final(&sha, digest);
        if (memcmp(digest, arg->sha_want, sizeof digest) != 0 ||
            !qn_aead_init(&aead, QN_AEAD_AES128GCM, zeros) ||
            !qn_aead_seal(&aead, zeros, NULL, 0, zeros, sizeof opened, sealed) ||
            memcmp(sealed, arg->aead_want, sizeof sealed) != 0 ||
            !qn_aead_open(&aead, zeros, NULL, 0, sealed, sizeof sealed, opened) ||
            memcmp(opened, zeros, sizeof opened) != 0 ||
            !qn_aead_init(&chacha, QN_AEAD_CHACHA20POLY1305, zeros) ||
            !qn_aead_seal(&chacha, zeros, NULL, 0, zeros, sizeof opened, chacha_sealed) ||
            !qn_aead_open(&chacha, zeros, NULL, 0, chacha_sealed, sizeof chacha_sealed,
                          opened) ||
            memcmp(opened, zeros, sizeof opened) != 0 || !qn_x25519(xout, xsk, basepoint) ||
            memcmp(xout, xwant, sizeof xout) != 0)
            arg->ok = false;
    }
    return NULL;
}

/* Run first to race initial CPU-capability and accelerated dispatch publication. */
static void test_parallel_first_use(void)
{
    enum { THREADS = 16 };
    pthread_t       thread[THREADS];
    dispatch_arg    arg[THREADS];
    uint8_t         sha_want[QN_SHA256_LEN];
    uint8_t         aead_want[16u + QN_AEAD_TAG_LEN];
    _Atomic unsigned ready;
    _Atomic bool     go;
    unsigned         created = 0;

    CHECK(unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                sha_want, sizeof sha_want) == sizeof sha_want);
    CHECK(unhex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf",
                aead_want, sizeof aead_want) == sizeof aead_want);
    atomic_init(&ready, 0u);
    atomic_init(&go, false);
    memset(arg, 0, sizeof arg);

    for (; created < THREADS; created++) {
        arg[created].ready = &ready;
        arg[created].go = &go;
        arg[created].sha_want = sha_want;
        arg[created].aead_want = aead_want;
        if (pthread_create(&thread[created], NULL, dispatch_worker, &arg[created]) != 0)
            break;
    }
    while (atomic_load_explicit(&ready, memory_order_acquire) < created)
        sched_yield();
    atomic_store_explicit(&go, true, memory_order_release);
    for (unsigned i = 0; i < created; i++) {
        CHECK(pthread_join(thread[i], NULL) == 0);
        CHECK(arg[i].ok);
    }
    CHECK(created == THREADS);
}

static void test_sha256(void)
{
    static const char abcdbcde[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t           d[QN_SHA256_LEN];
    qn_sha256         s;

    qn_sha256_init(&s);
    qn_sha256_update(&s, "abc", 3);
    qn_sha256_final(&s, d);
    CHECK(eqhex(d, sizeof d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    qn_sha256_init(&s);
    qn_sha256_final(&s, d);
    CHECK(eqhex(d, sizeof d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

    qn_sha256_init(&s);
    qn_sha256_update(&s, abcdbcde, sizeof abcdbcde - 1);
    qn_sha256_final(&s, d);
    CHECK(eqhex(d, sizeof d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

    /* one byte at a time must match the bulk path */
    {
        size_t i;
        qn_sha256_init(&s);
        for (i = 0; i < sizeof abcdbcde - 1; i++)
            qn_sha256_update(&s, abcdbcde + i, 1);
        qn_sha256_final(&s, d);
        CHECK(eqhex(d, sizeof d,
                    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    }

    /* final() must not disturb the running context */
    {
        uint8_t d2[QN_SHA256_LEN];
        qn_sha256_init(&s);
        qn_sha256_update(&s, "ab", 2);
        qn_sha256_final(&s, d);
        qn_sha256_update(&s, "c", 1);
        qn_sha256_final(&s, d2);
        CHECK(eqhex(d2, sizeof d2,
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    }
}

static void test_sha512(void)
{
    static const char long2[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                                "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t           d[QN_SHA512_LEN];
    qn_sha512         s;

    qn_sha512_init(&s, QN_SHA512_LEN);
    qn_sha512_update(&s, "abc", 3);
    qn_sha512_final(&s, d);
    CHECK(eqhex(d, QN_SHA512_LEN,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));

    qn_sha512_init(&s, QN_SHA384_LEN);
    qn_sha512_update(&s, "abc", 3);
    qn_sha512_final(&s, d);
    CHECK(eqhex(d, QN_SHA384_LEN,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                "8086072ba1e7cc2358baeca134c825a7"));

    qn_sha512_init(&s, QN_SHA384_LEN);
    qn_sha512_update(&s, long2, sizeof long2 - 1);
    qn_sha512_final(&s, d);
    CHECK(eqhex(d, QN_SHA384_LEN,
                "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
                "fcc7c71a557e2db966c3e9fa91746039"));
}

static void test_hmac(void)
{
    uint8_t key[20], d[QN_HASH_MAX];

    memset(key, 0x0b, sizeof key);
    qn_hmac_once(QN_HASH_SHA256, key, sizeof key, "Hi There", 8, d);
    CHECK(eqhex(d, QN_SHA256_LEN, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));

    qn_hmac_once(QN_HASH_SHA384, key, sizeof key, "Hi There", 8, d);
    CHECK(eqhex(d, QN_SHA384_LEN,
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
                "faea9ea9076ede7f4af152e8b2fa9cb6"));

    /* key longer than the block must be hashed first */
    {
        uint8_t big[131];
        memset(big, 0xaa, sizeof big);
        qn_hmac_once(QN_HASH_SHA256, big, sizeof big, "Test Using Larger Than Block-Size Key - Hash Key First", 54, d);
        CHECK(eqhex(d, QN_SHA256_LEN,
                    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    }
}

static void test_hkdf(void)
{
    uint8_t ikm[22], salt[13], info[10];
    uint8_t prk[QN_HASH_MAX], okm[42];

    memset(ikm, 0x0b, sizeof ikm);
    unhex("000102030405060708090a0b0c", salt, sizeof salt);
    unhex("f0f1f2f3f4f5f6f7f8f9", info, sizeof info);

    qn_hkdf_extract(QN_HASH_SHA256, salt, sizeof salt, ikm, sizeof ikm, prk);
    CHECK(eqhex(prk, QN_SHA256_LEN,
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));

    CHECK(qn_hkdf_expand(QN_HASH_SHA256, prk, info, sizeof info, okm, sizeof okm));
    CHECK(eqhex(okm, sizeof okm,
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865"));
}

static void test_tls13_schedule(void)
{
    uint8_t zeros[QN_SHA256_LEN] = { 0 };
    uint8_t early[QN_SHA256_LEN], derived[QN_SHA256_LEN];
    qn_hash empty;

    /* RFC 8448: early secret and the "derived" secret over an empty transcript. */
    qn_hkdf_extract(QN_HASH_SHA256, NULL, 0, zeros, sizeof zeros, early);
    CHECK(eqhex(early, sizeof early,
                "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"));

    qn_hash_init(&empty, QN_HASH_SHA256);
    CHECK(qn_derive_secret(QN_HASH_SHA256, early, "derived", &empty, derived));
    CHECK(eqhex(derived, sizeof derived,
                "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"));
}

static void test_tls12_prf(void)
{
    uint8_t secret[16], seed[16], out[100];

    unhex("9bbe436ba940f017b17652849a71db35", secret, sizeof secret);
    unhex("a0ba9f936cda311827a6f796ffd5198c", seed, sizeof seed);

    CHECK(qn_tls12_prf(QN_HASH_SHA256, secret, sizeof secret, "test label", seed, sizeof seed,
                       out, sizeof out));
    CHECK(eqhex(out, sizeof out,
                "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a"
                "6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab"
                "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701"
                "87347b66"));
}

static void aead_case(qn_aead_id id, const char *khex, const char *ivhex, const char *aadhex,
                      const char *pthex, const char *cthex, const char *taghex)
{
    uint8_t key[32], iv[QN_AEAD_IV_LEN], aad[64], pt[256], out[256 + QN_AEAD_TAG_LEN];
    uint8_t back[256], want[256];
    size_t  klen, ivlen, aadlen, ptlen, wantlen;
    qn_aead a;

    klen   = unhex(khex, key, sizeof key);
    ivlen  = unhex(ivhex, iv, sizeof iv);
    aadlen = unhex(aadhex, aad, sizeof aad);
    ptlen  = unhex(pthex, pt, sizeof pt);

    CHECK(klen == qn_aead_key_len(id));
    CHECK(ivlen == QN_AEAD_IV_LEN);
    CHECK(qn_aead_init(&a, id, key));

    CHECK(qn_aead_seal(&a, iv, aad, aadlen, pt, ptlen, out));

    wantlen = unhex(cthex, want, sizeof want);
    CHECK(wantlen == ptlen);
    CHECK(memcmp(out, want, ptlen) == 0);
    CHECK(eqhex(out + ptlen, QN_AEAD_TAG_LEN, taghex));

    CHECK(qn_aead_open(&a, iv, aad, aadlen, out, ptlen + QN_AEAD_TAG_LEN, back));
    CHECK(memcmp(back, pt, ptlen) == 0);

    /* a flipped bit anywhere must be rejected */
    memset(back, 0x5c, sizeof back);
    out[0] ^= 0x01u;
    CHECK(!qn_aead_open(&a, iv, aad, aadlen, out, ptlen + QN_AEAD_TAG_LEN, back));
    for (size_t i = 0; i < sizeof back; i++)
        CHECK(back[i] == 0x5cu);
    out[0] ^= 0x01u;
    out[ptlen + 3] ^= 0x80u;
    CHECK(!qn_aead_open(&a, iv, aad, aadlen, out, ptlen + QN_AEAD_TAG_LEN, back));
    for (size_t i = 0; i < sizeof back; i++)
        CHECK(back[i] == 0x5cu);
    out[ptlen + 3] ^= 0x80u;
    if (aadlen) {
        aad[0] ^= 0x01u;
        CHECK(!qn_aead_open(&a, iv, aad, aadlen, out, ptlen + QN_AEAD_TAG_LEN, back));
        for (size_t i = 0; i < sizeof back; i++)
            CHECK(back[i] == 0x5cu);
        aad[0] ^= 0x01u;
    }
    CHECK(!qn_aead_open(&a, iv, aad, aadlen, out, QN_AEAD_TAG_LEN - 1u, back));
    for (size_t i = 0; i < sizeof back; i++)
        CHECK(back[i] == 0x5cu);
}

static void test_chacha20poly1305(void)
{
    aead_case(QN_AEAD_CHACHA20POLY1305,
              "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
              "070000004041424344454647", "50515253c0c1c2c3c4c5c6c7",
              "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
              "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
              "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
              "637265656e20776f756c642062652069742e",
              "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
              "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
              "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
              "3ff4def08e4b7a9de576d26586cec64b6116",
              "1ae10b594f09e26a7e902ecbd0600691");
}

static void test_aes_gcm(void)
{
    aead_case(QN_AEAD_AES128GCM, "00000000000000000000000000000000", "000000000000000000000000",
              "", "00000000000000000000000000000000", "0388dace60b6a392f328c2b971b2fe78",
              "ab6e47d42cec13bdf53a67b21257bddf");

    aead_case(QN_AEAD_AES128GCM, "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
              "feedfacedeadbeeffeedfacedeadbeefabaddad2",
              "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
              "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
              "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
              "5bc94fbc3221a5db94fae95ae7121a47");

    aead_case(QN_AEAD_AES256GCM,
              "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
              "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
              "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
              "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
              "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
              "76fc6ece0f4e1768cddf8853bb2d551b");
}

static void test_x25519(void)
{
    uint8_t sk[32], u[32], out[32];
    uint8_t apriv[32], apub[32], bpriv[32], bpub[32], s1[32], s2[32];

    /* RFC 7748 5.2 */
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", sk, sizeof sk);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u, sizeof u);
    CHECK(qn_x25519(out, sk, u));
    CHECK(eqhex(out, sizeof out,
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));

    unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", sk, sizeof sk);
    unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u, sizeof u);
    CHECK(qn_x25519(out, sk, u));
    CHECK(eqhex(out, sizeof out,
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));

    /* RFC 7748 6.1 */
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", apriv, sizeof apriv);
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bpriv, sizeof bpriv);

    qn_x25519_base(apub, apriv);
    CHECK(eqhex(apub, sizeof apub,
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    qn_x25519_base(bpub, bpriv);
    CHECK(eqhex(bpub, sizeof bpub,
                "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));

    CHECK(qn_x25519(s1, apriv, bpub));
    CHECK(qn_x25519(s2, bpriv, apub));
    CHECK(memcmp(s1, s2, 32) == 0);
    CHECK(eqhex(s1, sizeof s1,
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));

    /* generated pairs must agree both ways */
    {
        uint8_t g1[32], p1[32], g2[32], p2[32];
        CHECK(qn_x25519_keypair(g1, p1, NULL));
        CHECK(qn_x25519_keypair(g2, p2, NULL));
        CHECK(qn_x25519(s1, g1, p2));
        CHECK(qn_x25519(s2, g2, p1));
        CHECK(memcmp(s1, s2, 32) == 0);
    }

    /* all-zero output from a small-order point must be rejected */
    {
        uint8_t small[32] = { 0 };
        CHECK(qn_x25519_keypair(sk, out, NULL));
        CHECK(!qn_x25519(out, sk, small));
    }
}

/* QN2-030: unknown IDs must not publish a usable context. */
static void test_aead_invalid_id(void)
{
    static const int bad[] = { -1, 3, 4, 99, 0x7FFFFFFF };
    uint8_t          key[32], iv[QN_AEAD_IV_LEN], out[64];
    qn_aead          a;
    size_t           i;

    memset(key, 0x5A, sizeof key);
    memset(iv, 0x11, sizeof iv);

    CHECK(qn_aead_key_len(QN_AEAD_AES128GCM) == 16u);
    CHECK(qn_aead_key_len(QN_AEAD_AES256GCM) == 32u);
    CHECK(qn_aead_key_len(QN_AEAD_CHACHA20POLY1305) == 32u);

    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        qn_aead_id id = (qn_aead_id)bad[i];

        CHECK(qn_aead_key_len(id) == 0u);
        memset(&a, 0xCC, sizeof a);
        CHECK(!qn_aead_init(&a, id, key));
        CHECK(!a.ready);
        /* A rejected context must not encrypt or decrypt anything. */
        CHECK(!qn_aead_seal(&a, iv, NULL, 0, key, 16u, out));
        CHECK(!qn_aead_open(&a, iv, NULL, 0, key, 32u, out));
    }

    /* A zeroed context is id 0, which is a real algorithm: still not usable. */
    memset(&a, 0, sizeof a);
    CHECK(!qn_aead_seal(&a, iv, NULL, 0, key, 16u, out));
    CHECK(!qn_aead_open(&a, iv, NULL, 0, key, 32u, out));

    for (i = 0; i < 3u; i++) {
        CHECK(qn_aead_init(&a, (qn_aead_id)i, key));
        CHECK(a.ready);
        CHECK(a.id == (qn_aead_id)i);
    }
}

int main(void)
{
    test_parallel_first_use();
    test_aead_invalid_id();
    test_sha256();
    test_sha512();
    test_hmac();
    test_hkdf();
    test_tls13_schedule();
    test_tls12_prf();
    test_chacha20poly1305();
    test_aes_gcm();
    test_x25519();

    if (failures) {
        fprintf(stderr, "crypto tests: %d failure(s)\n", failures);
        return 1;
    }
    printf("crypto tests: ok\n");
    return 0;
}
