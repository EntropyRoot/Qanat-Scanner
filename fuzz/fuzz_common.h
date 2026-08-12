#ifndef QANAT_FUZZ_COMMON_H
#define QANAT_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Standalone driver so the harnesses also run under gcc, which has no
   libFuzzer: each argument is replayed as one input. */
#ifdef QN_FUZZ_STANDALONE
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    static uint8_t buf[1 << 20];
    int            i;

    for (i = 1; i < argc; i++) {
        FILE  *f = fopen(argv[i], "rb");
        size_t n;
        if (!f) {
            perror(argv[i]);
            return 1;
        }
        n = fread(buf, 1, sizeof buf, f);
        fclose(f);
        LLVMFuzzerTestOneInput(buf, n);
    }

    /* No corpus: exhaustive short inputs, then seeded random ones. */
    if (argc == 1) {
        const char *env  = getenv("QN_FUZZ_ITERS");
        unsigned long iters = env ? strtoul(env, NULL, 10) : 20000ul;
        uint64_t      st    = 0x9E3779B97F4A7C15ull;
        unsigned long it;
        unsigned      v;

        for (v = 0; v < 65536u; v++) {
            uint8_t two[2] = { (uint8_t)(v >> 8), (uint8_t)v };
            LLVMFuzzerTestOneInput(two, 1);
            LLVMFuzzerTestOneInput(two, 2);
        }

        for (it = 0; it < iters; it++) {
            size_t n, j;
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            n = (size_t)(st % 4096u);
            for (j = 0; j < n; j++) {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                /* Bias toward structured bytes so parsers get past their headers. */
                buf[j] = (uint8_t)((st & 0xFFu) ^ (((st >> 8) & 3u) ? 0u : 0x16u));
            }
            LLVMFuzzerTestOneInput(buf, n);
        }
        printf("%s: %lu random inputs ok\n", argv[0], iters);
    }
    return 0;
}
#endif

#endif /* QANAT_FUZZ_COMMON_H */
