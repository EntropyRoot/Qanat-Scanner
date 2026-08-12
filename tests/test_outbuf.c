/* Pure tests for the verifier's send staging buffer and flow meter. */

#include "outbuf.h"
#include "flowmeter.h"
#include "qanat/request_gate.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

#define CAP 16u

static void fill(uint8_t *p, size_t n, uint8_t base)
{
    size_t i;

    for (i = 0; i < n; i++)
        p[i] = (uint8_t)(base + i);
}

/* QN2-010: partial writes must make the consumed prefix reusable. */
static void test_prefix_becomes_reusable(void)
{
    uint8_t   store[CAP];
    qn_outbuf b;
    uint8_t   a[12], c[8];

    qn_outbuf_init(&b, store, sizeof store);
    fill(a, sizeof a, 0x10);
    fill(c, sizeof c, 0xA0);

    CHECK(qn_outbuf_queue(&b, a, sizeof a));
    CHECK(qn_outbuf_pending(&b) == 12u);

    /* The socket took 10 of 12; 10 bytes of capacity are now free. */
    qn_outbuf_consume(&b, 10u);
    CHECK(qn_outbuf_pending(&b) == 2u);

    CHECK(qn_outbuf_queue(&b, c, sizeof c));
    CHECK(qn_outbuf_pending(&b) == 10u);

    /* Order is preserved across the compaction. */
    CHECK(qn_outbuf_head(&b)[0] == 0x1Au);
    CHECK(qn_outbuf_head(&b)[1] == 0x1Bu);
    CHECK(memcmp(qn_outbuf_head(&b) + 2, c, sizeof c) == 0);
}

/* One byte at a time must not lose or reorder anything. */
static void test_single_byte_writes(void)
{
    uint8_t   store[CAP];
    qn_outbuf b;
    uint8_t   src[CAP];
    uint8_t   got[CAP];
    size_t    i, n = 0;

    qn_outbuf_init(&b, store, sizeof store);
    fill(src, sizeof src, 1u);
    CHECK(qn_outbuf_queue(&b, src, sizeof src));

    for (i = 0; i < sizeof src; i++) {
        CHECK(qn_outbuf_pending(&b) == sizeof src - i);
        got[n++] = qn_outbuf_head(&b)[0];
        qn_outbuf_consume(&b, 1u);
    }
    CHECK(qn_outbuf_pending(&b) == 0u);
    CHECK(memcmp(got, src, sizeof src) == 0);

    /* A fully drained buffer is back to full capacity. */
    CHECK(qn_outbuf_queue(&b, src, sizeof src));
    CHECK(qn_outbuf_pending(&b) == sizeof src);
}

/* Repeated partial writes interleaved with appends keep byte order. */
static void test_interleaved_partial_writes(void)
{
    uint8_t   store[CAP];
    qn_outbuf b;
    uint8_t   expect[256];
    uint8_t   got[256];
    size_t    produced = 0, consumed = 0, round;
    uint8_t   next_val = 0;

    qn_outbuf_init(&b, store, sizeof store);
    for (round = 0; round < 64u; round++) {
        uint8_t chunk[5];
        size_t  take;

        fill(chunk, sizeof chunk, next_val);
        if (produced + sizeof chunk <= sizeof expect &&
            qn_outbuf_queue(&b, chunk, sizeof chunk)) {
            memcpy(expect + produced, chunk, sizeof chunk);
            produced += sizeof chunk;
            next_val = (uint8_t)(next_val + sizeof chunk);
        }

        /* Drain a partial, deliberately awkward amount. */
        take = qn_outbuf_pending(&b);
        if (take > 3u)
            take = 3u;
        if (take) {
            memcpy(got + consumed, qn_outbuf_head(&b), take);
            consumed += take;
            qn_outbuf_consume(&b, take);
        }
    }
    while (qn_outbuf_pending(&b)) {
        got[consumed] = qn_outbuf_head(&b)[0];
        consumed++;
        qn_outbuf_consume(&b, 1u);
    }

    CHECK(consumed == produced);
    CHECK(memcmp(got, expect, produced) == 0);
}

/* Exact capacity fits; one more byte is rejected without corrupting state. */
static void test_exact_capacity_and_overflow(void)
{
    uint8_t   store[CAP];
    qn_outbuf b;
    uint8_t   full[CAP];
    uint8_t   one = 0xEE;
    uint8_t   toobig[CAP + 1u];

    qn_outbuf_init(&b, store, sizeof store);
    fill(full, sizeof full, 0x40);

    CHECK(qn_outbuf_queue(&b, full, sizeof full));
    CHECK(qn_outbuf_pending(&b) == CAP);

    CHECK(!qn_outbuf_queue(&b, &one, 1u));
    CHECK(qn_outbuf_pending(&b) == CAP);
    CHECK(memcmp(qn_outbuf_head(&b), full, sizeof full) == 0);

    /* Larger than the whole buffer is rejected even when it is empty. */
    qn_outbuf_reset(&b);
    fill(toobig, sizeof toobig, 0x70);
    CHECK(!qn_outbuf_queue(&b, toobig, sizeof toobig));
    CHECK(qn_outbuf_pending(&b) == 0u);
    CHECK(qn_outbuf_queue(&b, full, sizeof full));
}

/* Consuming more than is pending must clamp, never wrap. */
static void test_overconsume_clamps(void)
{
    uint8_t   store[CAP];
    qn_outbuf b;
    uint8_t   src[4];

    qn_outbuf_init(&b, store, sizeof store);
    fill(src, sizeof src, 9u);
    CHECK(qn_outbuf_queue(&b, src, sizeof src));

    qn_outbuf_consume(&b, 1000u);
    CHECK(qn_outbuf_pending(&b) == 0u);
    CHECK(b.len == 0u && b.off == 0u);
    CHECK(qn_outbuf_queue(&b, src, sizeof src));
}

/* The in-place producer path must see only genuinely free room. */
static void test_tail_room(void)
{
    uint8_t   store[CAP];
    qn_outbuf b;
    uint8_t   src[10];
    size_t    room = 0;
    uint8_t  *tail;

    qn_outbuf_init(&b, store, sizeof store);
    fill(src, sizeof src, 0x21);
    CHECK(qn_outbuf_queue(&b, src, sizeof src));
    qn_outbuf_consume(&b, 6u);

    tail = qn_outbuf_tail(&b, &room);
    /* Compaction happened, so the room is CAP minus the 4 unsent bytes. */
    CHECK(room == CAP - 4u);
    CHECK(qn_outbuf_pending(&b) == 4u);
    memset(tail, 0x5A, room);
    qn_outbuf_commit(&b, room);
    CHECK(qn_outbuf_pending(&b) == CAP);
    CHECK(qn_outbuf_head(&b)[0] == 0x27u);

    /* Committing past capacity clamps instead of overflowing. */
    qn_outbuf_commit(&b, 999u);
    CHECK(b.len == CAP);
}

static void test_request_gate_quarantines_until_wire_complete(void)
{
    qn_request_gate gate;

    memset(&gate, 0, sizeof gate);
    CHECK(qn_request_gate_app(&gate, 5u) == QN_REQUEST_APP_REJECT);
    qn_request_gate_begin(&gate, 1u);
    CHECK(qn_request_gate_app(&gate, 5u) == QN_REQUEST_APP_QUARANTINE);
    CHECK(!qn_request_gate_mark_flushed(&gate, 1u, 1000000u));
    CHECK(qn_request_gate_app(&gate, 5u) == QN_REQUEST_APP_QUARANTINE);
    CHECK(qn_request_gate_mark_flushed(&gate, 0u, 2000000u));
    CHECK(qn_request_gate_app(&gate, 5u) == QN_REQUEST_APP_PARSE);
    CHECK(qn_request_gate_elapsed_us(&gate, 1999000u) == 0u);
    CHECK(qn_request_gate_elapsed_us(&gate, 2500000u) == 500u);
    CHECK(!qn_request_gate_mark_flushed(&gate, 0u, 3000000u));
    CHECK(gate.wire_ns == 2000000u);
}

#define SEC 1000000000ull

/* QN2-039: incomplete or stalled transfers cannot publish ordinary throughput. */
static void test_flow_report(void)
{
    qn_flow_sample s;
    qn_flow_report r;

    /* No flow requested at all. */
    memset(&s, 0, sizeof s);
    qn_flow_report_of(&s, &r);
    CHECK(!r.attempted && !r.completed && r.kbps == 0u && r.partial_kbps == 0u);

    /* Complete transfer: 1 MiB in 1 s is 8388 kbit/s. */
    memset(&s, 0, sizeof s);
    s.requested = 1024u * 1024u;
    s.received  = 1024u * 1024u;
    s.span_ns   = SEC;
    qn_flow_report_of(&s, &r);
    CHECK(r.attempted && r.completed);
    CHECK(r.kbps == 8388u && r.partial_kbps == 0u && r.stall_us == 0u);

    /* Requested size reached exactly, and overshoot, both count as complete. */
    memset(&s, 0, sizeof s);
    s.requested = 65536u;
    s.received  = 65536u;
    s.span_ns   = SEC;
    qn_flow_report_of(&s, &r);
    CHECK(r.completed);
    s.received = 65537u;
    qn_flow_report_of(&s, &r);
    CHECK(r.completed);

    /* A fast start followed by a long stall must remain partial and visibly stalled. */
    memset(&s, 0, sizeof s);
    s.requested         = 1024u * 1024u;
    s.received          = 512u * 1024u;
    s.span_ns           = 10ull * SEC;
    s.since_progress_ns = 9ull * SEC;
    qn_flow_report_of(&s, &r);
    CHECK(r.attempted && !r.completed);
    CHECK(r.kbps == 0u);
    CHECK(r.partial_kbps == 419u);
    CHECK(r.stall_us == 9000000u);

    /* Partial then reset, with progress right up to the end. */
    memset(&s, 0, sizeof s);
    s.requested         = 1024u * 1024u;
    s.received          = 700u * 1024u;
    s.span_ns           = 2ull * SEC;
    s.since_progress_ns = 1000ull;
    qn_flow_report_of(&s, &r);
    CHECK(!r.completed && r.kbps == 0u && r.partial_kbps > 0u);
    CHECK(r.stall_us == 1u);

    /* Immediate timeout: nothing ever arrived, so the whole span is stall. */
    memset(&s, 0, sizeof s);
    s.requested = 1024u * 1024u;
    s.received  = 0u;
    s.span_ns   = 5ull * SEC;
    qn_flow_report_of(&s, &r);
    CHECK(!r.completed && r.kbps == 0u && r.partial_kbps == 0u);
    CHECK(r.stall_us == 5000000u);

    /* A span too short to divide by must not produce a fabricated rate. */
    memset(&s, 0, sizeof s);
    s.requested = 100u;
    s.received  = 100u;
    s.span_ns   = 1000ull;
    qn_flow_report_of(&s, &r);
    CHECK(r.completed && r.kbps == 0u);
}

int main(void)
{
    test_flow_report();
    test_prefix_becomes_reusable();
    test_single_byte_writes();
    test_interleaved_partial_writes();
    test_exact_capacity_and_overflow();
    test_overconsume_clamps();
    test_tail_room();
    test_request_gate_quarantines_until_wire_complete();

    if (failures) {
        fprintf(stderr, "outbuf tests: %d failure(s)\n", failures);
        return 1;
    }
    printf("outbuf tests: ok\n");
    return 0;
}
