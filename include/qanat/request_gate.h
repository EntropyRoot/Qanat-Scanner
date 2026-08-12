#ifndef QANAT_REQUEST_GATE_H
#define QANAT_REQUEST_GATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    QN_REQUEST_APP_NONE = 0,
    QN_REQUEST_APP_REJECT,
    QN_REQUEST_APP_QUARANTINE,
    QN_REQUEST_APP_PARSE
} qn_request_app_action;

typedef struct {
    uint64_t wire_ns;
    uint8_t  index;
    bool     queued;
    bool     fully_flushed;
} qn_request_gate;

void qn_request_gate_begin(qn_request_gate *gate, uint8_t index);
bool qn_request_gate_mark_flushed(qn_request_gate *gate,
                                  size_t pending_bytes, uint64_t wire_ns);
qn_request_app_action qn_request_gate_app(const qn_request_gate *gate,
                                          size_t app_bytes);
uint32_t qn_request_gate_elapsed_us(const qn_request_gate *gate,
                                    uint64_t observed_ns);

#endif /* QANAT_REQUEST_GATE_H */
