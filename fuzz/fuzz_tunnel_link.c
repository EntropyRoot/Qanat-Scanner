#include "qanat/tunnel.h"

#include <stddef.h>
#include <stdint.h>

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    qn_tunnel_link link;

    if (qn_tunnel_link_parse(data, size, &link) == QN_TUNNEL_PARSE_OK)
        qn_tunnel_link_clear(&link);
    return 0;
}
