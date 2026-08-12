#include "qanat/http1.h"

#include <string.h>

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    qn_http1       h;
    qn_http1_event ev;
    size_t         off = 0;

    qn_http1_init(&h);

    /* Chunk boundaries come from the input, so split responses get explored. */
    while (off < size) {
        size_t      take = (size_t)(data[off] | 1u) * 3u;
        qn_http1_rc rc;

        if (take > size - off)
            take = size - off;

        memset(&ev, 0xA5, sizeof ev);
        rc = qn_http1_feed(&h, data + off, take, &ev);
        if (h.head_n > QN_HTTP1_HEAD_MAX || h.line_n > sizeof h.line)
            __builtin_trap();
        if (rc != QN_HTTP1_OK)
            break;
        off += take;
    }

    memset(&ev, 0xA5, sizeof ev);
    qn_http1_eof(&h, &ev);
    return 0;
}
