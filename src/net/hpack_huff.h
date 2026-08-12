#ifndef QANAT_HPACK_HUFF_H
#define QANAT_HPACK_HUFF_H

/* RFC 7541 Appendix B Huffman code, decoded bit-serially; tables from the RFC. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define QN_HUFF_MAXLEN 30
#define QN_HUFF_NSYM   257
#define QN_HUFF_EOS    256

/* The shortest code is 5 bits, so output never exceeds 8/5 of the input. */
#define QN_HUFF_MAX_OUT 65536u

static const uint8_t huff_count[QN_HUFF_MAXLEN + 1] = {
    0, 0, 0, 0, 0, 10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3,
    0, 0, 0, 3, 8, 13, 26, 29, 12, 4, 15, 19, 29, 0, 4
};

static const uint32_t huff_first_code[QN_HUFF_MAXLEN + 1] = {
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000014u, 0x0000005cu, 0x000000f8u, 0x000001fcu,
    0x000003f8u, 0x000007fau, 0x00000ffau, 0x00001ff8u, 0x00003ffcu,
    0x00007ffcu, 0x0000fffeu, 0x0001fffcu, 0x0003fff8u, 0x0007fff0u,
    0x000fffe6u, 0x001fffdcu, 0x003fffd2u, 0x007fffd8u, 0x00ffffeau,
    0x01ffffecu, 0x03ffffe0u, 0x07ffffdeu, 0x0fffffe2u, 0x1ffffffeu,
    0x3ffffffcu
};

static const uint16_t huff_first_index[QN_HUFF_MAXLEN + 1] = {
    0u, 0u, 0u, 0u, 0u, 0u, 10u, 36u, 68u, 74u, 74u, 79u, 82u, 84u, 90u,
    92u, 95u, 95u, 95u, 95u, 98u, 106u, 119u, 145u, 174u, 186u, 190u, 205u,
    224u, 253u, 253u
};

static const uint16_t huff_sym[QN_HUFF_NSYM] = {
    48u, 49u, 50u, 97u, 99u, 101u, 105u, 111u, 115u, 116u, 32u, 37u, 45u,
    46u, 47u, 51u, 52u, 53u, 54u, 55u, 56u, 57u, 61u, 65u, 95u, 98u, 100u,
    102u, 103u, 104u, 108u, 109u, 110u, 112u, 114u, 117u, 58u, 66u, 67u,
    68u, 69u, 70u, 71u, 72u, 73u, 74u, 75u, 76u, 77u, 78u, 79u, 80u, 81u,
    82u, 83u, 84u, 85u, 86u, 87u, 89u, 106u, 107u, 113u, 118u, 119u, 120u,
    121u, 122u, 38u, 42u, 44u, 59u, 88u, 90u, 33u, 34u, 40u, 41u, 63u, 39u,
    43u, 124u, 35u, 62u, 0u, 36u, 64u, 91u, 93u, 126u, 94u, 125u, 60u, 96u,
    123u, 92u, 195u, 208u, 128u, 130u, 131u, 162u, 184u, 194u, 224u, 226u,
    153u, 161u, 167u, 172u, 176u, 177u, 179u, 209u, 216u, 217u, 227u, 229u,
    230u, 129u, 132u, 133u, 134u, 136u, 146u, 154u, 156u, 160u, 163u, 164u,
    169u, 170u, 173u, 178u, 181u, 185u, 186u, 187u, 189u, 190u, 196u, 198u,
    228u, 232u, 233u, 1u, 135u, 137u, 138u, 139u, 140u, 141u, 143u, 147u,
    149u, 150u, 151u, 152u, 155u, 157u, 158u, 165u, 166u, 168u, 174u, 175u,
    180u, 182u, 183u, 188u, 191u, 197u, 231u, 239u, 9u, 142u, 144u, 145u,
    148u, 159u, 171u, 206u, 215u, 225u, 236u, 237u, 199u, 207u, 234u, 235u,
    192u, 193u, 200u, 201u, 202u, 205u, 210u, 213u, 218u, 219u, 238u, 240u,
    242u, 243u, 255u, 203u, 204u, 211u, 212u, 214u, 221u, 222u, 223u, 241u,
    244u, 245u, 246u, 247u, 248u, 250u, 251u, 252u, 253u, 254u, 2u, 3u, 4u,
    5u, 6u, 7u, 8u, 11u, 12u, 14u, 15u, 16u, 17u, 18u, 19u, 20u, 21u, 23u,
    24u, 25u, 26u, 27u, 28u, 29u, 30u, 31u, 127u, 220u, 249u, 10u, 13u, 22u,
    256u
};

typedef struct {
    size_t len;       /* complete decoded length, even when out held less */
    bool   truncated; /* out held only a prefix */
    bool   has_upper; /* any decoded byte in 'A'..'Z', over the whole string */
} qn_huff_info;

/* Validates all of src; a cap below the decoded length still measures it. */
static inline bool qn_huff_decode(const uint8_t *src, size_t n, uint8_t *out,
                                  size_t cap, qn_huff_info *info)
{
    uint32_t code  = 0;
    unsigned nbits = 0;
    size_t   i, produced = 0;

    info->len       = 0;
    info->truncated = false;
    info->has_upper = false;

    for (i = 0; i < n; i++) {
        unsigned bit = 8;

        while (bit-- > 0) {
            uint32_t off;
            uint16_t sym;

            code = (code << 1) | ((uint32_t)(src[i] >> bit) & 1u);
            nbits++;
            if (nbits > QN_HUFF_MAXLEN)
                return false;
            if (!huff_count[nbits] || code < huff_first_code[nbits])
                continue;
            off = code - huff_first_code[nbits];
            if (off >= huff_count[nbits])
                continue;

            sym = huff_sym[huff_first_index[nbits] + off];
            if (sym == QN_HUFF_EOS)
                return false; /* RFC 7541 5.2 forbids EOS inside a string */
            if (info->len >= QN_HUFF_MAX_OUT)
                return false;
            info->len++;
            if (sym >= 'A' && sym <= 'Z')
                info->has_upper = true;
            if (out && produced < cap)
                out[produced++] = (uint8_t)sym;
            else
                info->truncated = true;
            code  = 0;
            nbits = 0;
        }
    }

    /* Padding must be an EOS prefix, so all ones and shorter than one code. */
    if (nbits >= 8u)
        return false;
    if (nbits && code != ((1u << nbits) - 1u))
        return false;
    return true;
}

#endif /* QANAT_HPACK_HUFF_H */
