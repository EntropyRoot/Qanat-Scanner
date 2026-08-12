/* MD5, RFC 1321. Present only because JA3 is defined in terms of it. */

#include "qanat/crypto.h"

#include <string.h>

#define ROL(x, n) (((x) << (n)) | ((x) >> (32u - (n))))

static const uint32_t K[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u,
    0xfd469501u, 0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u,
    0xa679438eu, 0x49b40821u, 0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du,
    0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u, 0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au, 0xfffa3942u, 0x8771f681u, 0x6d9d6122u,
    0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u, 0x289b7ec6u, 0xeaa127fau,
    0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u, 0xf4292244u,
    0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu,
    0xeb86d391u
};

static const uint8_t R[64] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                               5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                               4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                               6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

static uint32_t ld32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void md5_block(uint32_t h[4], const uint8_t *b)
{
    uint32_t m[16], a = h[0], bb = h[1], c = h[2], d = h[3];
    unsigned i;

    for (i = 0; i < 16; i++)
        m[i] = ld32le(b + 4u * i);

    for (i = 0; i < 64; i++) {
        uint32_t f;
        unsigned g;

        if (i < 16) {
            f = (bb & c) | (~bb & d);
            g = i;
        } else if (i < 32) {
            f = (d & bb) | (~d & c);
            g = (5u * i + 1u) & 15u;
        } else if (i < 48) {
            f = bb ^ c ^ d;
            g = (3u * i + 5u) & 15u;
        } else {
            f = c ^ (bb | ~d);
            g = (7u * i) & 15u;
        }

        f  = f + a + K[i] + m[g];
        a  = d;
        d  = c;
        c  = bb;
        bb = bb + ROL(f, R[i]);
    }

    h[0] += a;
    h[1] += bb;
    h[2] += c;
    h[3] += d;
}

void qn_md5(const void *data, size_t len, uint8_t out[16])
{
    uint32_t       h[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };
    const uint8_t *p    = (const uint8_t *)data;
    uint8_t        tail[128];
    size_t         n = len, off = 0, tlen;
    uint64_t       bits = (uint64_t)len << 3;
    unsigned       i;

    while (n >= 64u) {
        md5_block(h, p + off);
        off += 64u;
        n -= 64u;
    }

    memcpy(tail, p + off, n);
    tail[n++] = 0x80u;
    tlen      = (n <= 56u) ? 64u : 128u;
    memset(tail + n, 0, tlen - n - 8u);
    for (i = 0; i < 8; i++)
        tail[tlen - 8u + i] = (uint8_t)(bits >> (8u * i));

    md5_block(h, tail);
    if (tlen == 128u)
        md5_block(h, tail + 64);

    for (i = 0; i < 4; i++) {
        out[4u * i]      = (uint8_t)h[i];
        out[4u * i + 1u] = (uint8_t)(h[i] >> 8);
        out[4u * i + 2u] = (uint8_t)(h[i] >> 16);
        out[4u * i + 3u] = (uint8_t)(h[i] >> 24);
    }
}
