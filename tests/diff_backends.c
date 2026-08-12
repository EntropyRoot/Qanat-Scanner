/* One checksum over a wide AEAD and hash matrix, to compare asm against C. */
/* The fold is FNV-1a, not a library hash, so a broken hash cannot hide. */

#include "qanat/crypto.h"
#include "arm64/backend.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t fnv = 1469598103934665603ull;

static void fold(const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t         i;

    for (i = 0; i < n; i++) {
        fnv ^= b[i];
        fnv *= 1099511628211ull;
    }
}

/* Deterministic filler; the values only have to be identical across runs. */
static uint32_t lcg_state = 0x12345678u;

static uint32_t lcg(void)
{
    lcg_state = lcg_state * 1664525u + 1013904223u;
    return lcg_state;
}

static void fill(uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        p[i] = (uint8_t)(lcg() >> 24);
}

static const size_t LENS[] = {
    0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 95, 96, 97,
    127, 128, 129, 191, 192, 193, 255, 256, 257, 511, 512, 513, 1023, 1024,
    1025, 4095, 4096, 4097, 8191, 8192
};
static const size_t AADS[] = { 0, 1, 15, 16, 17, 63, 64, 65, 255, 256 };

#define MAXLEN 8192u

static int run_aead(qn_aead_id id, const char *label)
{
    uint8_t *pt  = (uint8_t *)malloc(MAXLEN);
    uint8_t *ct  = (uint8_t *)malloc(MAXLEN + 16u);
    uint8_t *rt  = (uint8_t *)malloc(MAXLEN + 16u);
    uint8_t *aad = (uint8_t *)malloc(512u);
    uint8_t  key[32], iv[QN_AEAD_IV_LEN];
    qn_aead  a;
    size_t   li, ai;
    int      bad = 0;

    if (!pt || !ct || !rt || !aad) {
        free(pt); free(ct); free(rt); free(aad);
        return 1;
    }

    for (li = 0; li < sizeof LENS / sizeof LENS[0]; li++) {
        for (ai = 0; ai < sizeof AADS / sizeof AADS[0]; ai++) {
            size_t n = LENS[li], m = AADS[ai];

            fill(key, sizeof key);
            fill(iv, sizeof iv);
            fill(pt, n);
            fill(aad, m);

            if (!qn_aead_init(&a, id, key)) {
                printf("%s: init failed\n", label);
                bad = 1;
                goto done;
            }
            if (!qn_aead_seal(&a, iv, aad, m, pt, n, ct)) {
                printf("%s: seal failed at pt=%zu aad=%zu\n", label, n, m);
                bad = 1;
                goto done;
            }
            fold(ct, n + 16u);

            /* A round trip must return the plaintext, in either backend. */
            if (!qn_aead_open(&a, iv, aad, m, ct, n + 16u, rt)) {
                printf("%s: open failed at pt=%zu aad=%zu\n", label, n, m);
                bad = 1;
                goto done;
            }
            if (n && memcmp(rt, pt, n) != 0) {
                printf("%s: round trip differs at pt=%zu aad=%zu\n", label, n, m);
                bad = 1;
                goto done;
            }

            /* A flipped tag bit must not open. */
            ct[n + 3u] ^= 0x40u;
            if (qn_aead_open(&a, iv, aad, m, ct, n + 16u, rt)) {
                printf("%s: forged tag opened at pt=%zu aad=%zu\n", label, n, m);
                bad = 1;
                goto done;
            }
            ct[n + 3u] ^= 0x40u;

            /* So must a flipped ciphertext bit, when there is ciphertext. */
            if (n) {
                ct[n / 2u] ^= 0x01u;
                if (qn_aead_open(&a, iv, aad, m, ct, n + 16u, rt)) {
                    printf("%s: forged ciphertext opened at pt=%zu\n", label, n);
                    bad = 1;
                    goto done;
                }
                ct[n / 2u] ^= 0x01u;
            }

            /* And a flipped AAD bit, when there is AAD. */
            if (m) {
                aad[m / 2u] ^= 0x01u;
                if (qn_aead_open(&a, iv, aad, m, ct, n + 16u, rt)) {
                    printf("%s: forged aad opened at pt=%zu aad=%zu\n", label, n, m);
                    bad = 1;
                    goto done;
                }
                aad[m / 2u] ^= 0x01u;
            }
        }
    }

done:
    free(pt); free(ct); free(rt); free(aad);
    return bad;
}

static int run_sha256(void)
{
    uint8_t *buf = (uint8_t *)malloc(MAXLEN);
    uint8_t  out[QN_SHA256_LEN];
    size_t   li;

    if (!buf)
        return 1;
    for (li = 0; li < sizeof LENS / sizeof LENS[0]; li++) {
        qn_sha256 s;
        size_t    n = LENS[li], split;

        fill(buf, n);
        qn_sha256_init(&s);
        qn_sha256_update(&s, buf, n);
        qn_sha256_final(&s, out);
        fold(out, sizeof out);

        /* Every split must hash the same, which exercises the block carry. */
        for (split = 0; split <= n && split <= 200u; split += 37u) {
            uint8_t alt[QN_SHA256_LEN];

            qn_sha256_init(&s);
            qn_sha256_update(&s, buf, split);
            qn_sha256_update(&s, buf + split, n - split);
            qn_sha256_final(&s, alt);
            if (memcmp(alt, out, sizeof out) != 0) {
                printf("sha256: split %zu of %zu differs\n", split, n);
                free(buf);
                return 1;
            }
        }
    }
    free(buf);
    return 0;
}

/* Same shape for the 128-byte-block hashes, which have their own kernel. */
static int run_sha512(uint32_t outlen, const char *label)
{
    uint8_t *buf = (uint8_t *)malloc(MAXLEN);
    uint8_t  out[64];
    size_t   li;

    if (!buf)
        return 1;
    for (li = 0; li < sizeof LENS / sizeof LENS[0]; li++) {
        qn_sha512 s;
        size_t    n = LENS[li], split;

        fill(buf, n);
        qn_sha512_init(&s, outlen);
        qn_sha512_update(&s, buf, n);
        qn_sha512_final(&s, out);
        fold(out, outlen);

        for (split = 0; split <= n && split <= 400u; split += 53u) {
            uint8_t alt[64];

            qn_sha512_init(&s, outlen);
            qn_sha512_update(&s, buf, split);
            qn_sha512_update(&s, buf + split, n - split);
            qn_sha512_final(&s, alt);
            if (memcmp(alt, out, outlen) != 0) {
                printf("%s: split %zu of %zu differs\n", label, split, n);
                free(buf);
                return 1;
            }
        }
    }
    free(buf);
    return 0;
}

int main(void)
{
    int bad = 0;
    unsigned i;

    bad |= run_sha512(48u, "sha384");
    bad |= run_sha512(64u, "sha512");
    bad |= run_aead(QN_AEAD_AES128GCM, "aes128gcm");
    bad |= run_aead(QN_AEAD_AES256GCM, "aes256gcm");
    bad |= run_aead(QN_AEAD_CHACHA20POLY1305, "chacha20poly1305");
    bad |= run_sha256();

    printf("backends:");
    for (i = 0; i < QN_BACKEND_COUNT; i++)
        printf(" %s=%d", qn_crypto_backend_name((qn_crypto_backend)i),
               qn_crypto_backend_enabled((qn_crypto_backend)i) ? 1 : 0);
    printf("\n");
    printf("fold=%016llx\n", (unsigned long long)fnv);
    return bad;
}
