#include "qanat/http2.h"

#include <string.h>

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    qn_h2       h;
    qn_h2_event ev;
    uint8_t     control[256];
    size_t      off = 0;

    qn_h2_init(&h);

    while (off < size) {
        size_t   take = (size_t)(data[off] | 1u) * 5u;
        size_t   clen = 0xDEAD;
        qn_h2_rc rc;

        if (take > size - off)
            take = size - off;

        memset(&ev, 0xA5, sizeof ev);
        memset(control, 0xA5, sizeof control);
        rc = qn_h2_feed(&h, data + off, take, control, sizeof control, &clen, &ev);
        if (rc == QN_H2_OK && clen > sizeof control)
            __builtin_trap();
        if (h.control_n > sizeof h.control || h.hblock_n > QN_H2_HEADER_BLOCK_MAX)
            __builtin_trap();
        if (rc != QN_H2_OK)
            break;
        off += take;
    }
    return 0;
}
