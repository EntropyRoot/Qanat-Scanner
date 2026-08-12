/* Feeds hostile bytes to the record layer and handshake parser. */

#include "qanat/tls.h"

#include <string.h>

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static qn_tls_session s;
    static uint8_t        out[8192], app[16384], hello[4096];
    qn_tls_config         cfg;
    qn_rng                rng;
    size_t                off = 0;

    qn_rng_seed(&rng, 0x51A7E5u);
    memset(&cfg, 0, sizeof cfg);
    cfg.sni         = "example.com";
    cfg.fp          = QN_TLS_FP_CHROME;
    cfg.allow_tls12 = true;
    cfg.rng         = &rng;

    qn_tls_init(&s, &cfg);
    if (qn_tls_start(&s, hello, sizeof hello) <= 0)
        return 0;

    /* Chunk boundaries come from the input too, so record splits get explored. */
    while (off < size) {
        qn_tls_io io;
        qn_tls_rc rc;
        size_t    take = (size_t)(data[off] | 1u) * 7u;

        if (take > size - off)
            take = size - off;

        memset(&io, 0, sizeof io);
        io.in     = data + off;
        io.inlen  = take;
        io.out    = out;
        io.outcap = sizeof out;
        io.app    = app;
        io.appcap = sizeof app;

        rc = qn_tls_recv(&s, &io);
        if (io.consumed > io.inlen || io.outlen > io.outcap || io.applen > io.appcap)
            __builtin_trap();
        if (rc != QN_TLS_RC_MORE && rc != QN_TLS_RC_OK && rc != QN_TLS_RC_DONE)
            break;

        off += take ? take : 1u;
    }

    qn_tls_free(&s);
    return 0;
}
