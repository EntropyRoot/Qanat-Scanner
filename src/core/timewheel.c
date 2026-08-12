#include "qanat/timewheel.h"

#include <string.h>

#define TW_SPAN_MS (QN_TW_SLOTS * QN_TW_TICK_MS)

void qn_tw_init(qn_timewheel *w, uint64_t now_ms)
{
    memset(w, 0, sizeof *w);
    w->now_ms      = now_ms;
    w->cursor_tick = now_ms / QN_TW_TICK_MS;
}

void qn_tw_disarm(qn_timewheel *w, qn_tw_node *n)
{
    if (!n->armed)
        return;
    if (n->prev)
        n->prev->next = n->next;
    else
        w->slot[n->slot] = n->next;
    if (n->next)
        n->next->prev = n->prev;

    n->prev = n->next = NULL;
    n->armed = 0;
    w->armed--;
}

void qn_tw_arm(qn_timewheel *w, qn_tw_node *n, uint64_t now_ms, uint32_t after_ms)
{
    uint64_t deadline, wheel_deadline, tick;
    uint32_t slot;

    if (n->armed)
        qn_tw_disarm(w, n);

    if (now_ms > w->now_ms)
        w->now_ms = now_ms;
    deadline = UINT64_MAX - w->now_ms < after_ms ? UINT64_MAX : w->now_ms + after_ms;

    /* Long deadlines clamp one revolution short and expire() re-arms the remainder. */
    if (after_ms > TW_SPAN_MS - 2u * QN_TW_TICK_MS)
        after_ms = TW_SPAN_MS - 2u * QN_TW_TICK_MS;

    /* Exact boundaries belong to their current tick; only a remainder rounds up. */
    wheel_deadline = UINT64_MAX - w->now_ms < after_ms ? UINT64_MAX : w->now_ms + after_ms;
    tick = wheel_deadline / QN_TW_TICK_MS;
    if (wheel_deadline % QN_TW_TICK_MS)
        tick++;
    slot = (uint32_t)(tick & (QN_TW_SLOTS - 1u));

    n->deadline_ms = deadline;
    n->slot        = slot;
    n->armed       = 1;
    n->prev        = NULL;
    n->next        = w->slot[slot];
    if (n->next)
        n->next->prev = n;
    w->slot[slot] = n;
    w->armed++;
}

qn_tw_node *qn_tw_expire(qn_timewheel *w, uint64_t now_ms)
{
    uint64_t now_tick;

    /* A monotonic clock that went backwards keeps the wheel's high-water mark. */
    if (now_ms > w->now_ms)
        w->now_ms = now_ms;
    now_tick = w->now_ms / QN_TW_TICK_MS;

    /* One revolution already visits every slot, so a longer jump costs no more. */
    if (now_tick >= w->cursor_tick + QN_TW_SLOTS)
        w->cursor_tick = now_tick - (QN_TW_SLOTS - 1u);

    for (;;) {
        qn_tw_node *n = w->slot[w->cursor_tick & (QN_TW_SLOTS - 1u)];

        if (n) {
            qn_tw_disarm(w, n);
            if (n->deadline_ms > w->now_ms) {
                /* Re-arm lands strictly past now_tick, so the sweep terminates. */
                qn_tw_arm(w, n, w->now_ms, (uint32_t)(n->deadline_ms - w->now_ms));
                continue;
            }
            return n;
        }
        if (w->cursor_tick >= now_tick)
            return NULL;
        w->cursor_tick++;
    }
}

uint32_t qn_tw_next_timeout(const qn_timewheel *w, uint64_t now_ms, uint32_t cap)
{
    uint64_t now_tick, tick, ahead, soonest = UINT64_MAX;

    if (!w->armed)
        return cap;
    if (now_ms < w->now_ms)
        now_ms = w->now_ms;
    now_tick = now_ms / QN_TW_TICK_MS;

    /* Ticks the sweep has not reached yet may already hold due work. */
    if (w->cursor_tick < now_tick)
        return 0;

    /* A deadline within cap rounds up into this window and no further. */
    ahead = (uint64_t)cap / QN_TW_TICK_MS + 2u;
    if (ahead > QN_TW_SLOTS)
        ahead = QN_TW_SLOTS;

    /* Slots hold nodes from later revolutions too, so read the deadlines. */
    for (tick = now_tick; tick < now_tick + ahead; tick++) {
        const qn_tw_node *n = w->slot[tick & (QN_TW_SLOTS - 1u)];

        for (; n; n = n->next)
            if (n->deadline_ms < soonest)
                soonest = n->deadline_ms;
    }

    if (soonest == UINT64_MAX)
        return cap;
    if (soonest <= now_ms)
        return 0;
    soonest -= now_ms;
    return soonest < cap ? (uint32_t)soonest : cap;
}
