#include "qanat/request_gate.h"

#include <limits.h>
#include <string.h>

void qn_request_gate_begin(qn_request_gate *gate, uint8_t index)
{
    if (!gate)
        return;
    memset(gate, 0, sizeof *gate);
    gate->queued = true;
    gate->index = index;
}

bool qn_request_gate_mark_flushed(qn_request_gate *gate,
                                  size_t pending_bytes, uint64_t wire_ns)
{
    if (!gate || !gate->queued || gate->fully_flushed || pending_bytes)
        return false;
    gate->fully_flushed = true;
    gate->wire_ns = wire_ns;
    return true;
}

qn_request_app_action qn_request_gate_app(const qn_request_gate *gate,
                                          size_t app_bytes)
{
    if (!app_bytes)
        return QN_REQUEST_APP_NONE;
    if (!gate || !gate->queued)
        return QN_REQUEST_APP_REJECT;
    return gate->fully_flushed ? QN_REQUEST_APP_PARSE
                               : QN_REQUEST_APP_QUARANTINE;
}

uint32_t qn_request_gate_elapsed_us(const qn_request_gate *gate,
                                    uint64_t observed_ns)
{
    uint64_t elapsed;

    if (!gate || !gate->fully_flushed || !gate->wire_ns ||
        observed_ns <= gate->wire_ns)
        return 0u;
    elapsed = (observed_ns - gate->wire_ns) / 1000u;
    return elapsed > UINT32_MAX ? UINT32_MAX : (uint32_t)elapsed;
}
