/* OS randomness and the two constant-shape helpers the rest of the crypto uses. */

#include "qanat/crypto.h"
#include "qanat/util.h"

#include <string.h>

void qn_wipe(void *p, size_t n)
{
#if defined(__GNUC__) || defined(__clang__)
    /* The barrier keeps vectorized memset from being deleted. */
    memset(p, 0, n);
    __asm__ __volatile__("" : : "r"(p) : "memory");
#else
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
        *v++ = 0;
#endif
}

bool qn_ct_eq(const void *a, const void *b, size_t n)
{
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t        d = 0;

    while (n--)
        d = (uint8_t)(d | (*x++ ^ *y++));
    return d == 0;
}

bool qn_random_secure(void *dst, size_t n)
{
    return qn_os_entropy(dst, n);
}
