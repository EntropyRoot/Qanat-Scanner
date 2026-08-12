#include "qanat/cidr.h"

#include <string.h>
#include <sys/socket.h>

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char      s[256];
    qn_prefix p;

    if (size >= sizeof s)
        size = sizeof s - 1u;
    memcpy(s, data, size);
    s[size] = 0;

    memset(&p, 0xA5, sizeof p);
    if (qn_cidr_parse(s, &p)) {
        /* a parsed prefix must describe a non-empty, bounded host count */
        uint64_t hosts = qn_prefix_hosts(&p);
        if (hosts == 0 || p.bits > (p.af == AF_INET6 ? 128u : 32u))
            __builtin_trap();
    }
    return 0;
}
