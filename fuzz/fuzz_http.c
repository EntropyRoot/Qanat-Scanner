#include "qanat/probe.h"

#include <string.h>

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    qn_http_reply rep;

    memset(&rep, 0xA5, sizeof rep);
    if (qn_http_parse(data, size, &rep)) {
        /* colo must always come back NUL-terminated within its field */
        volatile size_t n = strnlen(rep.colo, sizeof rep.colo);
        (void)n;
    }
    return 0;
}
