/* Invariants the engine assumes but never checked. */

#include "qanat/bandit.h"
#include "qanat/stats.h"
#include "qanat/store.h"
#include "qanat/perm.h"
#include "qanat/sprt.h"
#include "qanat/topk.h"
#include "qanat/ring.h"
#include "qanat/timewheel.h"

#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int failures;

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

static int open_fd_count(void)
{
    DIR           *dir = opendir("/proc/self/fd");
    struct dirent *entry;
    int            count = 0;

    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
            count++;
    }
    if (closedir(dir) != 0)
        return -1;
    return count;
}

/* Every permuted index must remain distinct and inside its domain. */
static void test_perm_bijective(void)
{
    static const uint64_t domains[] = { 1, 2, 3, 7, 16, 17, 255, 256, 1000, 4096, 65537, 100003 };
    size_t                d;

    for (d = 0; d < sizeof domains / sizeof domains[0]; d++) {
        uint64_t  n    = domains[d];
        uint8_t  *seen = (uint8_t *)calloc((size_t)n, 1);
        qn_perm   p;
        uint64_t  i;
        uint64_t  dup = 0, oor = 0;

        if (!seen) {
            failures++;
            return;
        }
        qn_perm_init(&p, n, 0xD1CE5EEDull ^ n);

        for (i = 0; i < n; i++) {
            uint64_t v = qn_perm_apply(&p, i);
            if (v >= n) {
                oor++;
                continue;
            }
            if (seen[v])
                dup++;
            seen[v] = 1;
        }
        if (oor || dup)
            fprintf(stderr, "  domain %llu: %llu out-of-range, %llu duplicate\n",
                    (unsigned long long)n, (unsigned long long)oor, (unsigned long long)dup);
        CHECK(oor == 0);
        CHECK(dup == 0);

        for (i = 0; i < n; i++)
            CHECK(seen[i] == 1);

        free(seen);
    }
}

static void test_perm_seed_varies(void)
{
    qn_perm  a, b;
    uint64_t i, same = 0;

    qn_perm_init(&a, 4096, 1);
    qn_perm_init(&b, 4096, 2);
    for (i = 0; i < 4096; i++)
        if (qn_perm_apply(&a, i) == qn_perm_apply(&b, i))
            same++;
    /* A different seed must not reproduce the same walk. */
    CHECK(same < 4096 / 4);
}

#define TW_N 4096

static void test_timewheel_conserves(void)
{
    qn_timewheel w;
    qn_tw_node  *n = (qn_tw_node *)calloc(TW_N, sizeof *n);
    uint64_t     now = 1000;
    uint32_t     i, popped = 0;
    uint8_t     *seen = (uint8_t *)calloc(TW_N, 1);

    if (!n || !seen) {
        failures++;
        free(n);
        free(seen);
        return;
    }

    qn_tw_init(&w, now);
    for (i = 0; i < TW_N; i++)
        qn_tw_arm(&w, &n[i], now, (i % 900u) + 1u);
    CHECK(w.armed == TW_N);

    /* Disarming a quarter of them must not disturb the rest. */
    for (i = 0; i < TW_N; i += 4)
        qn_tw_disarm(&w, &n[i]);
    CHECK(w.armed == TW_N - (TW_N + 3) / 4);

    for (now = 1000; now <= 1000 + 1000; now += 4) {
        qn_tw_node *e;
        while ((e = qn_tw_expire(&w, now)) != NULL) {
            size_t idx = (size_t)(e - n);
            CHECK(idx < TW_N);
            CHECK(idx % 4 != 0);
            CHECK(!seen[idx]);
            seen[idx] = 1;
            popped++;
        }
    }

    CHECK(popped == TW_N - (TW_N + 3) / 4);
    CHECK(w.armed == 0);

    free(n);
    free(seen);
}

static void test_timewheel_next_timeout(void)
{
    qn_timewheel w;
    qn_tw_node   a;

    memset(&a, 0, sizeof a);
    qn_tw_init(&w, 5000);
    CHECK(qn_tw_next_timeout(&w, 5000, 250) == 250); /* empty wheel clamps to cap */

    qn_tw_arm(&w, &a, 5000, 40);
    CHECK(qn_tw_next_timeout(&w, 5000, 250) <= 40);
    CHECK(qn_tw_next_timeout(&w, 6000, 250) == 0); /* already overdue */
}

static void test_timewheel_exact_boundary(void)
{
    qn_timewheel w;
    qn_tw_node   a;

    memset(&a, 0, sizeof a);
    qn_tw_init(&w, 1000u); /* 1000 is exactly tick 125. */
    qn_tw_arm(&w, &a, 1000u, 24u);
    CHECK(a.deadline_ms == 1024u);
    CHECK(qn_tw_expire(&w, 1023u) == NULL);
    CHECK(qn_tw_expire(&w, 1024u) == &a);
}

/* Arming after a blocking syscall must use the caller's fresh clock. */
static void test_timewheel_arm_uses_caller_clock(void)
{
    qn_timewheel w;
    qn_tw_node   a;

    memset(&a, 0, sizeof a);
    qn_tw_init(&w, 1000);

    qn_tw_arm(&w, &a, 1200, 250);
    CHECK(a.deadline_ms == 1450);
    CHECK(w.now_ms == 1200); /* arming advances the wheel with it */
    CHECK(qn_tw_expire(&w, 1449) == NULL);
    CHECK(qn_tw_expire(&w, 1450 + QN_TW_TICK_MS) == &a);

    /* A clock that goes backwards must not shorten anything either. */
    qn_tw_arm(&w, &a, 1000, 250);
    CHECK(a.deadline_ms >= 1450 + QN_TW_TICK_MS);
}

#define TW_SPAN_MS ((uint64_t)QN_TW_SLOTS * QN_TW_TICK_MS)

/* QN2-002: whole-revolution jumps must drain every overdue node. */
static void test_timewheel_revolution_jump(void)
{
    static const uint64_t jumps[] = { 8191, 8192, 8193, 16384, 60000, 1000000 };
    size_t                j;

    for (j = 0; j < sizeof jumps / sizeof jumps[0]; j++) {
        qn_timewheel w;
        qn_tw_node   a;

        memset(&a, 0, sizeof a);
        qn_tw_init(&w, 0);
        qn_tw_arm(&w, &a, 0, 100);
        CHECK(a.deadline_ms == 100);

        if (qn_tw_expire(&w, jumps[j]) != &a)
            fprintf(stderr, "  jump %llu ms hid an overdue deadline\n",
                    (unsigned long long)jumps[j]);
        CHECK(w.armed == 0);
    }
}

/* Nodes spread over several revolutions must all come back, once each. */
static void test_timewheel_multiple_revolutions(void)
{
    enum { N = 64 };
    qn_timewheel w;
    qn_tw_node   n[N];
    uint8_t      seen[N] = { 0 };
    uint32_t     i, popped = 0;
    qn_tw_node  *e;

    memset(n, 0, sizeof n);
    qn_tw_init(&w, 0);
    for (i = 0; i < N; i++)
        qn_tw_arm(&w, &n[i], 0, (uint32_t)((uint64_t)(i + 1u) * TW_SPAN_MS / 8u));

    while ((e = qn_tw_expire(&w, (uint64_t)N * TW_SPAN_MS)) != NULL) {
        size_t idx = (size_t)(e - n);
        CHECK(idx < N);
        CHECK(!seen[idx]);
        seen[idx] = 1;
        popped++;
    }
    CHECK(popped == N);
    CHECK(w.armed == 0);
}

/* No clock progress and a clock that runs backwards must both be inert. */
static void test_timewheel_clock_edges(void)
{
    qn_timewheel w;
    qn_tw_node   a;

    memset(&a, 0, sizeof a);
    qn_tw_init(&w, 10000);
    qn_tw_arm(&w, &a, 10000, 200);

    CHECK(qn_tw_expire(&w, 10000) == NULL);
    CHECK(qn_tw_expire(&w, 10000) == NULL);
    CHECK(qn_tw_expire(&w, 5000) == NULL);
    CHECK(w.now_ms == 10000);
    CHECK(w.armed == 1);
    CHECK(qn_tw_expire(&w, 10200 + QN_TW_TICK_MS) == &a);
}

/* Re-arming from inside the drain loop must not lose or duplicate a node. */
static void test_timewheel_rearm_during_expiry(void)
{
    qn_timewheel w;
    qn_tw_node   a, b;
    qn_tw_node  *e;
    uint32_t     a_seen = 0, b_seen = 0;
    uint64_t     now = 0;

    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    qn_tw_init(&w, 0);
    qn_tw_arm(&w, &a, 0, 40);
    qn_tw_arm(&w, &b, 0, 40);

    for (now = 0; now <= 400; now += 8) {
        while ((e = qn_tw_expire(&w, now)) != NULL) {
            if (e == &a) {
                a_seen++;
                if (a_seen == 1u)
                    qn_tw_arm(&w, &a, now, 100); /* re-arm from the callback */
            } else {
                b_seen++;
            }
        }
    }
    CHECK(a_seen == 2);
    CHECK(b_seen == 1);
    CHECK(w.armed == 0);
}

/* QN2-003: pseudo-random schedules compare sleep hints against a reference model. */
static void test_timewheel_next_timeout_model(void)
{
    enum { N = 48 };
    qn_timewheel w;
    qn_tw_node   n[N];
    uint64_t     deadline[N];
    uint64_t     st = 0x9E3779B97F4A7C15ull;
    uint32_t     i, round;
    uint64_t     now = 100000;

    memset(n, 0, sizeof n);
    qn_tw_init(&w, now);
    for (i = 0; i < N; i++) {
        st ^= st << 13;
        st ^= st >> 7;
        st ^= st << 17;
        {
            uint32_t after = (uint32_t)(st % 6000u) + 1u;
            qn_tw_arm(&w, &n[i], now, after);
            deadline[i] = n[i].deadline_ms;
        }
    }

    for (round = 0; round < 400u; round++) {
        uint32_t cap  = 50u;
        uint32_t hint = qn_tw_next_timeout(&w, now, cap);
        uint64_t soonest = UINT64_MAX;

        for (i = 0; i < N; i++)
            if (n[i].armed && deadline[i] < soonest)
                soonest = deadline[i];

        if (soonest == UINT64_MAX) {
            CHECK(hint == cap);
            break;
        }
        /* Never sleep past a deadline, and never past the caller's cap. */
        CHECK(hint <= cap);
        if (soonest > now)
            CHECK((uint64_t)hint <= soonest - now);

        now += hint ? hint : 1u;
        while (qn_tw_expire(&w, now) != NULL)
            ;
    }
    CHECK(w.armed == 0);
}

/* The measurement behind QN2-003: one silent 8 s deadline, 50 ms cap. */
static void test_timewheel_wakeup_budget(void)
{
    qn_timewheel w;
    qn_tw_node   a;
    uint64_t     now    = 0;
    uint32_t     wakes  = 0;

    memset(&a, 0, sizeof a);
    qn_tw_init(&w, 0);
    qn_tw_arm(&w, &a, 0, 8000);

    while (now < 8000 && wakes < 20000u) {
        uint32_t hint = qn_tw_next_timeout(&w, now, 50u);
        now += hint ? hint : 1u;
        wakes++;
        while (qn_tw_expire(&w, now) != NULL)
            ;
    }
    fprintf(stderr, "  timewheel: %u wakeups for an 8 s deadline at a 50 ms cap\n", wakes);
    /* One tick per wakeup would be 1000; the cap must dominate instead. */
    CHECK(wakes <= 200u);
    CHECK(a.armed == 0);
}

#define RING_CAP   1024u
#define RING_ITEMS 200000u

typedef struct {
    qn_ring *r;
    uint32_t produced;
    uint32_t dropped;
} prod_arg;

static void *producer(void *v)
{
    prod_arg *a = (prod_arg *)v;
    uint32_t  i;

    for (i = 0; i < RING_ITEMS; i++) {
        while (!qn_ring_push(a->r, &i)) {
            a->dropped++;
            sched_yield();
            if (a->dropped > RING_ITEMS * 8u)
                return NULL; /* consumer wedged; fail in the checker */
        }
        a->produced++;
    }
    return NULL;
}

/* The hot-path SPSC ring must preserve order and conservation under contention. */
static void test_ring_spsc(void)
{
    qn_arena  arena;
    qn_ring   r;
    pthread_t tid;
    prod_arg  pa;
    uint32_t  batch[64];
    uint32_t  got = 0, expect = 0;
    bool      order_ok = true;

    CHECK(qn_arena_init(&arena, 1u << 20));
    CHECK(qn_ring_init(&r, &arena, RING_CAP, sizeof(uint32_t)));

    memset(&pa, 0, sizeof pa);
    pa.r = &r;
    CHECK(pthread_create(&tid, NULL, producer, &pa) == 0);

    while (got < RING_ITEMS) {
        uint32_t n = qn_ring_pop_batch(&r, batch, (uint32_t)(sizeof batch / sizeof batch[0]));
        uint32_t k;
        if (!n) {
            sched_yield();
            continue;
        }
        for (k = 0; k < n; k++) {
            if (batch[k] != expect)
                order_ok = false;
            expect++;
        }
        got += n;
    }

    pthread_join(tid, NULL);
    CHECK(order_ok);
    CHECK(got == RING_ITEMS);
    CHECK(pa.produced == RING_ITEMS);
    CHECK(qn_ring_len(&r) == 0);

    qn_arena_free(&arena);
}

/* Reset must prevent cross-run event delivery. */
static void test_ring_reset(void)
{
    qn_arena arena;
    qn_ring  r;
    uint32_t v, out[8];

    CHECK(qn_arena_init(&arena, 1u << 16));
    CHECK(qn_ring_init(&r, &arena, 64u, sizeof(uint32_t)));

    for (v = 0; v < 8u; v++)
        CHECK(qn_ring_push(&r, &v));
    CHECK(qn_ring_len(&r) == 8u);

    qn_ring_reset(&r);
    CHECK(qn_ring_len(&r) == 0u);
    CHECK(qn_ring_pop_batch(&r, out, 8u) == 0u);

    v = 99u;
    CHECK(qn_ring_push(&r, &v));
    CHECK(qn_ring_pop_batch(&r, out, 8u) == 1u);
    CHECK(out[0] == 99u);

    qn_arena_free(&arena);
}

static int int_better(const void *a, const void *b)
{
    int x = *(const int *)a, y = *(const int *)b;
    return x > y ? 1 : (x < y ? -1 : 0);
}

#define TOPK_CAP 64
#define TOPK_N   20000

static void test_topk(void)
{
    qn_arena arena;
    qn_topk  h;
    int      out[TOPK_CAP];
    uint64_t st = 0x243F6A8885A308D3ull;
    int      i, best[TOPK_N];

    CHECK(qn_arena_init(&arena, 1u << 16));
    CHECK(qn_topk_init(&h, &arena, TOPK_CAP, sizeof(int), int_better));

    for (i = 0; i < TOPK_N; i++) {
        st ^= st << 13;
        st ^= st >> 7;
        st ^= st << 17;
        best[i] = (int)(st % 1000000u);
        qn_topk_offer(&h, &best[i]);
    }
    CHECK(h.offered == TOPK_N);
    CHECK(h.n == TOPK_CAP);

    CHECK(qn_topk_drain(&h, out) == TOPK_CAP);
    CHECK(h.n == 0);

    /* best-first, and every kept value must beat everything discarded */
    for (i = 1; i < TOPK_CAP; i++)
        CHECK(out[i - 1] >= out[i]);
    {
        int cutoff = out[TOPK_CAP - 1];
        int above  = 0;
        for (i = 0; i < TOPK_N; i++)
            if (best[i] > cutoff)
                above++;
        CHECK(above <= TOPK_CAP - 1);
    }

    /* fewer items than capacity must all survive */
    {
        int few[3] = { 5, 9, 1 }, got[3];
        CHECK(qn_topk_init(&h, &arena, TOPK_CAP, sizeof(int), int_better));
        for (i = 0; i < 3; i++)
            CHECK(qn_topk_offer(&h, &few[i]));
        CHECK(qn_topk_drain(&h, got) == 3);
        CHECK(got[0] == 9 && got[1] == 5 && got[2] == 1);
    }

    qn_arena_free(&arena);
}

static void test_sprt(void)
{
    qn_sprt s;
    int     i;

    /* a clean run should decide well before the fixed sample budget */
    qn_sprt_init(&s, 500, 900, 50, 50, 3, 15);
    for (i = 0; i < 15; i++)
        if (qn_sprt_push(&s, true) == QN_SPRT_ACCEPT)
            break;
    CHECK(qn_sprt_status(&s) == QN_SPRT_ACCEPT);
    CHECK(s.n < 15);

    qn_sprt_init(&s, 500, 900, 50, 50, 3, 15);
    for (i = 0; i < 15; i++)
        if (qn_sprt_push(&s, false) == QN_SPRT_REJECT)
            break;
    CHECK(qn_sprt_status(&s) == QN_SPRT_REJECT);
    CHECK(s.n < 15);

    /* nmin is honoured even when the evidence is one-sided */
    qn_sprt_init(&s, 500, 900, 50, 50, 6, 15);
    CHECK(qn_sprt_push(&s, true) == QN_SPRT_CONTINUE);
    CHECK(qn_sprt_push(&s, true) == QN_SPRT_CONTINUE);
    CHECK(s.n == 2);

    /* an ambiguous stream must still terminate at nmax */
    qn_sprt_init(&s, 500, 900, 50, 50, 2, 12);
    for (i = 0; i < 12; i++)
        qn_sprt_push(&s, (i & 1) != 0);
    CHECK(qn_sprt_status(&s) != QN_SPRT_CONTINUE);
    CHECK(s.n == 12);

    /* boundary constants: ln(1.8), ln(0.2), ln(19) in milli-nats */
    qn_sprt_init(&s, 500, 900, 50, 50, 1, 20);
    CHECK(s.up > 570 && s.up < 605);
    CHECK(s.down < -1590 && s.down > -1630);
    CHECK(s.accept > 2920 && s.accept < 2970);
    CHECK(s.reject < -2920 && s.reject > -2970);
}

#define BND_BLOCKS 64u
#define BND_SPAN   256u

static void test_bandit_block_plan_is_bounded(void)
{
    CHECK(qn_bandit_block_count(BND_BLOCKS * BND_SPAN, BND_SPAN) == BND_BLOCKS);
    CHECK(qn_bandit_block_count(BND_SPAN + 1u, BND_SPAN) == 2u);
    CHECK(qn_bandit_block_count(UINT32_MAX, BND_SPAN) == 65536u);
    CHECK(qn_bandit_block_count(UINT64_MAX, BND_SPAN) == 0u);
    CHECK(qn_bandit_block_count(1u, 0u) == 0u);
}

/* Coverage must stay exact: adaptive does not get to mean "repeats". */
static void test_bandit_covers_once(void)
{
    qn_arena  arena;
    qn_bandit t;
    uint8_t  *seen;
    bool      blocks[BND_BLOCKS] = { false };
    uint64_t  total = BND_BLOCKS * BND_SPAN, i, idx, got = 0;

    CHECK(qn_arena_init(&arena, 1u << 20));
    CHECK(qn_bandit_init(&t, &arena, total, BND_SPAN, 2, 0xBEEFu));
    seen = (uint8_t *)calloc((size_t)total, 1);
    CHECK(seen != NULL);
    if (!seen)
        return;

    for (i = 0; i < total; i++) {
        CHECK(qn_bandit_next(&t, i, &idx));
        CHECK(idx < total);
        if (idx < total) {
            if (i < BND_BLOCKS) {
                uint32_t blk = (uint32_t)(idx / BND_SPAN);

                CHECK(!blocks[blk]);
                blocks[blk] = true;
            }
            CHECK(!seen[idx]);
            seen[idx] = 1;
            got++;
        }
    }
    CHECK(got == total);
    CHECK(!qn_bandit_next(&t, total, &idx));

    for (i = 0; i < total; i++)
        CHECK(seen[i] == 1);

    free(seen);
    qn_arena_free(&arena);
}

/* Every short final block must remain a complete permutation. */
static void test_bandit_partial_blocks(void)
{
    for (uint32_t rem = 1u; rem < BND_SPAN; rem++) {
        for (uint64_t seed = 1u; seed <= 8u; seed++) {
            qn_arena  arena;
            qn_bandit t;
            uint64_t  total = BND_SPAN + rem;
            uint8_t   seen[BND_SPAN * 2u] = { 0 };

            CHECK(qn_arena_init(&arena, 1u << 16));
            CHECK(qn_bandit_init(&t, &arena, total, BND_SPAN, 2u, seed));
            for (uint64_t i = 0; i < total; i++) {
                uint64_t idx = UINT64_MAX;

                CHECK(qn_bandit_next(&t, i, &idx));
                CHECK(idx < total);
                if (idx < total) {
                    CHECK(!seen[idx]);
                    seen[idx] = 1u;
                }
            }
            for (uint64_t i = 0; i < total; i++)
                CHECK(seen[i] == 1u);
            qn_arena_free(&arena);
        }
    }
}

/* Reusing a bandit step consumes another address, so retries must retain jobs. */
static void test_bandit_draw_is_not_replayable(void)
{
    qn_arena  arena;
    qn_bandit t;
    uint64_t  a = 0, b = 0;

    CHECK(qn_arena_init(&arena, 1u << 20));
    CHECK(qn_bandit_init(&t, &arena, BND_BLOCKS * BND_SPAN, BND_SPAN, 2, 0x5EEDu));

    CHECK(qn_bandit_next(&t, 5u, &a));
    CHECK(qn_bandit_next(&t, 5u, &b));
    CHECK(a != b);
    CHECK(atomic_load_explicit(&t.issued, memory_order_relaxed) == 2u);

    qn_arena_free(&arena);
}

/* And the point of the thing: budget should follow the block that answers. */
static void test_bandit_finds_the_live_block(void)
{
    qn_arena  arena;
    qn_bandit t;
    uint64_t  idx, i;
    uint32_t  hits = 0;
    const uint32_t lucky = 7u;
    const uint64_t draws = 4000u;

    CHECK(qn_arena_init(&arena, 1u << 20));
    CHECK(qn_bandit_init(&t, &arena, BND_BLOCKS * BND_SPAN, BND_SPAN, 2, 0x1234u));

    for (i = 0; i < draws; i++) {
        if (!qn_bandit_next(&t, i, &idx))
            break;
        {
            bool good = (idx / BND_SPAN) == lucky;
            qn_bandit_report(&t, idx, good);
            if (good)
                hits++;
        }
    }

    /* Uniform allocation would spend about 1/64 of the budget there. */
    CHECK(hits > draws / BND_BLOCKS * 4u);
    CHECK(qn_bandit_live_blocks(&t) >= 1u);
    fprintf(stderr, "  bandit: %u of %llu draws landed in the live block\n", hits,
            (unsigned long long)draws);

    qn_arena_free(&arena);
}

/* A bounded two-sided 90% median interval is unavailable before n=5. */
static void test_samples_ci(void)
{
    qn_samples s;
    uint32_t   lo, hi, i;

    memset(&s, 0, sizeof s);
    CHECK(!qn_samples_median_ci90(&s, &lo, &hi));
    CHECK(lo == 0 && hi == 0);

    qn_samples_add(&s, 900);
    CHECK(!qn_samples_median_ci90(&s, &lo, &hi));
    CHECK(lo == 0 && hi == 0);

    for (i = 1; i < 5; i++) {
        qn_samples_add(&s, (uint32_t)(900 + i * 10));
        CHECK(qn_samples_median_ci90(&s, &lo, &hi) == (i == 4u));
    }
    CHECK(lo == 900 && hi == 940);

    memset(&s, 0, sizeof s);
    for (i = 0; i < 9; i++)
        qn_samples_add(&s, (uint32_t)(100 + i * 10));
    CHECK(qn_samples_median_ci90(&s, &lo, &hi));
    /* nine samples use rank two, so the ends are trimmed by one each */
    CHECK(lo == 110 && hi == 170);
    CHECK(lo <= qn_samples_median(&s) && qn_samples_median(&s) <= hi);

    /* the interval must bracket the median whatever the sample count */
    for (i = 5; i <= QN_MAX_SAMPLES; i++) {
        uint32_t j;
        memset(&s, 0, sizeof s);
        for (j = 0; j < i; j++)
            qn_samples_add(&s, (uint32_t)(1000 - j * 7));
        CHECK(qn_samples_median_ci90(&s, &lo, &hi));
        CHECK(lo <= hi);
        CHECK(lo <= qn_samples_median(&s));
        CHECK(qn_samples_median(&s) <= hi);
    }
}

static qn_addr ip4(uint32_t v)
{
    qn_addr a;
    memset(&a, 0, sizeof a);
    a.af   = 2; /* AF_INET */
    a.u.v4 = v;
    return a;
}

#define DAY 86400ull

/* Recent repeated multi-path history must outrank one stale lucky observation. */
static void test_store_decay(void)
{
    qn_arena arena;
    qn_store st;
    qn_addr  once = ip4(0x01020304u);
    qn_addr  many = ip4(0x01020305u);
    qn_addr  both = ip4(0x01020306u);
    qn_addr  bad  = ip4(0x01020307u);
    uint64_t t0   = 1700000000ull;
    uint32_t i;

    CHECK(qn_arena_init(&arena, 1u << 18));
    CHECK(qn_store_init(&st, &arena, 256));

    CHECK(qn_store_confidence(&st, &once, t0) == 0);

    qn_store_observe(&st, &once, "cell/1.2", true, 100000, t0);
    for (i = 0; i < 5; i++)
        qn_store_observe(&st, &many, "cell/1.2", true, 100000, t0 + i * DAY / 4u);
    for (i = 0; i < 5; i++)
        qn_store_observe(&st, &both, i & 1 ? "wifi/9.9" : "cell/1.2", true, 100000,
                         t0 + i * DAY / 4u);
    for (i = 0; i < 5; i++)
        qn_store_observe(&st, &bad, "cell/1.2", false, 0, t0 + i * DAY / 4u);

    {
        uint32_t c_once = qn_store_confidence(&st, &once, t0 + DAY);
        uint32_t c_many = qn_store_confidence(&st, &many, t0 + DAY);
        uint32_t c_both = qn_store_confidence(&st, &both, t0 + DAY);
        uint32_t c_bad  = qn_store_confidence(&st, &bad, t0 + DAY);

        CHECK(c_bad < 100);
        CHECK(c_many > c_once);
        CHECK(c_both > c_many);
        CHECK(c_both <= 1000);

        /* the same evidence, read much later, must count for less */
        CHECK(qn_store_confidence(&st, &both, t0 + 30 * DAY) < c_both / 2u);
    }

    qn_arena_free(&arena);
}

static bool write_history(const char *path, const char *body)
{
    FILE *f = fopen(path, "w");

    if (!f)
        return false;
    if (fputs(body, f) < 0) {
        fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

/* Evidence is dated with a clock that is checked, never with a cast of -1. */
static void test_wall_clock_is_validated(void)
{
    uint64_t now = 0;
    time_t   raw = time(NULL);

    CHECK(qn_wall_now(&now));
    CHECK(now >= 1577836800ull && now <= 4102444800ull);
    if (raw != (time_t)-1)
        CHECK(now + 5u >= (uint64_t)raw && (uint64_t)raw + 5u >= now);
    /* A refused clock leaves the caller's instant untouched. */
    CHECK(!qn_wall_now(NULL));
}

/* Store schema is mandatory, unreadable files fail, and v1 remains migratable. */
static void test_store_schema(void)
{
    /* a version beyond what this build understands */
    static const char future[] =
        "# qanat history v3: address last_seen runs score weight paths x\n"
        "10.11.12.13 1700000000 1 1024 1024 1 90000\n";
    /* data before any version line */
    static const char headerless[] = "10.11.12.13 1700000000 1 1024 1024 1 90000\n";
    /* version zero is not a version */
    static const char zero[] =
        "# qanat history v0\n"
        "10.11.12.13 1700000000 1 1024 1024 1 90000\n";
    static const char *refused[] = { future, headerless, zero };
    const char *path = "qanat-test-schema.tsv";
    qn_arena    arena;
    qn_store    s;
    size_t      i;

    CHECK(qn_arena_init(&arena, 1u << 16));
    CHECK(qn_store_init(&s, &arena, 16));

    for (i = 0; i < sizeof refused / sizeof refused[0]; i++) {
        CHECK(write_history(path, refused[i]));
        CHECK(!qn_store_load(&s, path));
    }

    /* v1 migrates: its rtt_us column always held a handshake duration. */
    CHECK(write_history(path,
                        "# qanat history v1: address last_seen runs score weight"
                        " paths rtt_us\n"
                        "10.11.12.13 1700000000 3 2048 3072 5 91000\n"));
    CHECK(qn_store_load(&s, path));
    CHECK(s.n == 1u);
    if (s.n == 1u) {
        CHECK(s.e[0].handshake_us == 91000u);
        CHECK(s.e[0].runs == 3u && s.e[0].weight_q10 == 3072u);
    }

    /* A store we write must be a store we read. */
    CHECK(qn_store_save(&s, path));
    CHECK(qn_store_load(&s, path));
    CHECK(s.n == 1u && s.e[0].handshake_us == 91000u);

    remove(path);
    remove("qanat-test-schema.tsv.lock");
    qn_arena_free(&arena);
}

/* A second writer must not lose the first writer's addresses. */
static void test_store_concurrent_merge(void)
{
    const char *path = "qanat-test-merge.tsv";
    qn_arena    arena;
    qn_store    a, b;
    qn_addr     ip_a = ip4(0x0A000001u), ip_b = ip4(0x0A000002u);
    uint64_t    t0 = 1700000000ull;

    CHECK(qn_arena_init(&arena, 1u << 18));
    CHECK(qn_store_init(&a, &arena, 64));
    CHECK(qn_store_init(&b, &arena, 64));

    /* Both processes start from an empty history and see different addresses. */
    qn_store_observe(&a, &ip_a, "cell/1", true, 90000u, t0);
    qn_store_observe(&b, &ip_b, "wifi/1", true, 40000u, t0);

    CHECK(qn_store_save(&a, path));
    CHECK(qn_store_save(&b, path)); /* would clobber a without the merge */

    {
        qn_store c;

        CHECK(qn_store_init(&c, &arena, 64));
        CHECK(qn_store_load(&c, path));
        CHECK(c.n == 2u);
        CHECK(qn_store_find(&c, &ip_a) != NULL);
        CHECK(qn_store_find(&c, &ip_b) != NULL);
    }

    /* Fresher shared-address evidence wins while both path tags survive. */
    qn_store_observe(&a, &ip_b, "cell/1", true, 95000u, t0 + 10u);
    CHECK(qn_store_save(&a, path));
    {
        qn_store c;
        const qn_store_entry *e;

        CHECK(qn_store_init(&c, &arena, 64));
        CHECK(qn_store_load(&c, path));
        e = qn_store_find(&c, &ip_b);
        CHECK(e != NULL);
        if (e) {
            CHECK(e->last_seen == t0 + 10u);
            /* two distinct path tags, so at least two bits are set */
            CHECK(e->oper_mask != 0u && (e->oper_mask & (e->oper_mask - 1u)) != 0u);
        }
    }

    remove(path);
    remove("qanat-test-merge.tsv.lock");
    qn_arena_free(&arena);
}

/* Eviction must weigh evidence as of now, not as of whenever it was recorded. */
static void test_store_eviction_is_stale_aware(void)
{
    qn_arena arena;
    qn_store s;
    qn_addr  old_perfect = ip4(0x0A010001u);
    qn_addr  recent_good = ip4(0x0A010002u);
    qn_addr  newcomer    = ip4(0x0A010003u);
    uint64_t t0 = 1700000000ull;
    uint64_t now = t0 + 30u * DAY;

    CHECK(qn_arena_init(&arena, 1u << 16));
    CHECK(qn_store_init(&s, &arena, 2));

    /* One perfect observation a month ago. */
    qn_store_observe(&s, &old_perfect, "cell/1", true, 90000u, t0);
    /* Many recent observations, most of them good. */
    for (uint32_t i = 0; i < 40u; i++)
        qn_store_observe(&s, &recent_good, "cell/1", i % 5u != 0u, 90000u, now - 60u);

    CHECK(s.n == 2u);
    qn_store_observe(&s, &newcomer, "cell/1", true, 90000u, now);

    /* The stale single sample is the one that must go. */
    CHECK(qn_store_find(&s, &old_perfect) == NULL);
    CHECK(qn_store_find(&s, &recent_good) != NULL);
    CHECK(qn_store_find(&s, &newcomer) != NULL);
    qn_arena_free(&arena);
}

static void test_store_roundtrip(void)
{
    qn_arena arena;
    qn_store a, b;
    qn_addr  ip = ip4(0x0A0B0C0Du);
    uint64_t t0 = 1700000000ull;
    uint32_t i, before, after;

    CHECK(qn_arena_init(&arena, 1u << 18));
    CHECK(qn_store_init(&a, &arena, 64));
    for (i = 0; i < 4; i++)
        qn_store_observe(&a, &ip, "cell/1.2", true, 90000, t0 + i * DAY / 8u);
    before = qn_store_confidence(&a, &ip, t0 + DAY);

    CHECK(qn_store_save(&a, "qanat-test-history.tsv"));
    CHECK(qn_store_init(&b, &arena, 64));
    CHECK(qn_store_load(&b, "qanat-test-history.tsv"));
    after = qn_store_confidence(&b, &ip, t0 + DAY);

    CHECK(b.n == 1);
    CHECK(before == after);

    /* Invalid persisted evidence cannot partially replace the in-memory store. */
    {
        qn_store_entry snapshot = b.e[0];
        FILE          *f = fopen("qanat-test-history.tsv", "w");
        CHECK(f != NULL);
        if (f) {
            CHECK(fputs("# qanat history v2: address last_seen runs score weight"
                        " paths handshake_us\n"
                        "10.11.12.13 1700000000 1 2048 1024 1 90000 trailing\n", f) >= 0);
            CHECK(fclose(f) == 0);
        }
        CHECK(!qn_store_load(&b, "qanat-test-history.tsv"));
        CHECK(b.n == 1u && memcmp(&b.e[0], &snapshot, sizeof snapshot) == 0);

        f = fopen("qanat-test-history.tsv", "w");
        CHECK(f != NULL);
        if (f) {
            CHECK(fputs("# qanat history v2: address last_seen runs score weight"
                        " paths handshake_us\n"
                        "10.11.12.13 1700000000 1 1024 1024 1 90000\n"
                        "10.11.12.13 1700000001 2 2048 2048 1 90000\n", f) >= 0);
            CHECK(fclose(f) == 0);
        }
        CHECK(!qn_store_load(&b, "qanat-test-history.tsv"));
        CHECK(b.n == 1u && memcmp(&b.e[0], &snapshot, sizeof snapshot) == 0);
    }

    /* Saturation rescales evidence; neither counters nor RTT averaging wrap. */
    b.e[0].score_q10 = UINT32_MAX - 512u;
    b.e[0].weight_q10 = UINT32_MAX - 512u;
    b.e[0].runs = UINT32_MAX;
    b.e[0].handshake_us = UINT32_MAX;
    b.e[0].last_seen = t0 + 2u * DAY;
    qn_store_observe(&b, &ip, "cell/1.2", true, UINT32_MAX, t0 + 2u * DAY);
    CHECK(b.e[0].score_q10 <= b.e[0].weight_q10);
    CHECK(b.e[0].weight_q10 > 1024u);
    CHECK(b.e[0].runs == UINT32_MAX);
    CHECK(b.e[0].handshake_us == UINT32_MAX);

    /* A wall-clock rollback cannot make last_seen move backwards. */
    {
        uint64_t last_seen = b.e[0].last_seen;
        qn_store_observe(&b, &ip, "cell/1.2", true, 1000u, last_seen - DAY);
        CHECK(b.e[0].last_seen == last_seen);
    }

    remove("qanat-test-history.tsv");
    remove("qanat-test-history.tsv.lock");

    /* a missing file is a fresh start, not a failure */
    CHECK(qn_store_init(&b, &arena, 64));
    CHECK(qn_store_load(&b, "qanat-no-such-history.tsv"));
    CHECK(b.n == 0);

    /* Repeated directory read failures must close every FILE and descriptor. */
    {
        char dir_template[] = "qanat-test-history-dir-XXXXXX";
        char *dir = mkdtemp(dir_template);
        int   fd_before = open_fd_count();

        CHECK(dir != NULL);
        if (dir) {
            for (i = 0; i < 64u; i++)
                CHECK(!qn_store_load(&b, dir));
            if (fd_before >= 0)
                CHECK(open_fd_count() == fd_before);
            CHECK(rmdir(dir) == 0);
        }
    }

    qn_arena_free(&arena);
}

int main(void)
{
    test_store_decay();
    test_store_roundtrip();
    test_wall_clock_is_validated();
    test_store_schema();
    test_store_concurrent_merge();
    test_store_eviction_is_stale_aware();
    test_samples_ci();
    test_bandit_covers_once();
    test_bandit_partial_blocks();
    test_bandit_draw_is_not_replayable();
    test_bandit_finds_the_live_block();
    test_topk();
    test_sprt();
    test_perm_bijective();
    test_perm_seed_varies();
    test_bandit_block_plan_is_bounded();
    test_timewheel_conserves();
    test_timewheel_next_timeout();
    test_timewheel_exact_boundary();
    test_timewheel_arm_uses_caller_clock();
    test_timewheel_revolution_jump();
    test_timewheel_multiple_revolutions();
    test_timewheel_clock_edges();
    test_timewheel_rearm_during_expiry();
    test_timewheel_next_timeout_model();
    test_timewheel_wakeup_budget();
    test_ring_spsc();
    test_ring_reset();

    if (failures) {
        fprintf(stderr, "property tests: %d failure(s)\n", failures);
        return 1;
    }
    printf("property tests: ok\n");
    return 0;
}
