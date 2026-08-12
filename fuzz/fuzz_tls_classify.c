#include "qanat/probe.h"

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)qn_tls_outcome_str(qn_tls_classify(data, size));
    return 0;
}
