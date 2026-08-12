#define QN_DISCOVER_TESTING 1

/* A reply is evidence only if it quotes a probe we sent; statics compiled in. */

#include "task_discover.c"
#include "cpuinfo.c"

#include <stdio.h>

static int failures;

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

#define SPAN 256u
#define BASE 0xC0A80000u /* 192.168.0.0 */

static uint64_t sent_ns[SPAN];

typedef enum {
    FAKE_ICMP_OK = 0,
    FAKE_ICMP_SOCKET_FAIL,
    FAKE_ICMP_SEND_FAIL,
    FAKE_ICMP_RECV_FAIL,
    FAKE_ICMP_POLL_FAIL,
    FAKE_ICMP_STALL,
    FAKE_ICMP_CLOSE_FAIL
} fake_icmp_mode;

typedef struct {
    fake_icmp_mode mode;
    uint32_t       opens;
    uint32_t       sends;
    uint32_t       receives;
    uint32_t       waits;
    uint32_t       closes;
} fake_icmp;

static void setup(host_discover *s)
{
    memset(s, 0, sizeof *s);
    s->prefix.af     = AF_INET;
    s->prefix.bits   = 24;
    s->prefix.net.af = AF_INET;
    s->prefix.net.u.v4 = BASE;
    s->span        = SPAN;
    s->first_host  = 1;
    s->host_count  = SPAN - 2u;
    s->icmp_sent_ns = sent_ns;
    s->icmp_nonce  = 0x0123456789ABCDEFull;
    memset(sent_ns, 0, sizeof sent_ns);
}

static int fake_icmp_open(void *opaque)
{
    fake_icmp *fake = (fake_icmp *)opaque;

    fake->opens++;
    if (fake->mode == FAKE_ICMP_SOCKET_FAIL) {
        errno = EACCES;
        return -1;
    }
    return 7;
}

static int fake_icmp_set_recvbuf(void *opaque, int fd, int bytes)
{
    (void)opaque;
    (void)fd;
    (void)bytes;
    return 0;
}

static int fake_icmp_send(void *opaque, int fd, struct mmsghdr *messages,
                          unsigned count)
{
    fake_icmp *fake = (fake_icmp *)opaque;

    (void)fd;
    (void)messages;
    fake->sends++;
    if (fake->mode == FAKE_ICMP_SEND_FAIL) {
        errno = EIO;
        return -1;
    }
    if (fake->mode == FAKE_ICMP_STALL) {
        errno = EAGAIN;
        return -1;
    }
    return (int)count;
}

static ssize_t fake_icmp_recv(void *opaque, int fd, uint8_t *buffer, size_t capacity,
                              struct sockaddr_in *from, socklen_t *from_length)
{
    fake_icmp *fake = (fake_icmp *)opaque;

    (void)fd;
    (void)buffer;
    (void)capacity;
    (void)from;
    (void)from_length;
    fake->receives++;
    errno = fake->mode == FAKE_ICMP_RECV_FAIL ? EIO : EAGAIN;
    return -1;
}

static int fake_icmp_wait(void *opaque, struct pollfd *fd, int timeout_ms)
{
    fake_icmp *fake = (fake_icmp *)opaque;

    (void)fd;
    (void)timeout_ms;
    fake->waits++;
    if (fake->mode == FAKE_ICMP_POLL_FAIL) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int fake_icmp_close(void *opaque, int fd)
{
    fake_icmp *fake = (fake_icmp *)opaque;

    (void)fd;
    fake->closes++;
    if (fake->mode == FAKE_ICMP_CLOSE_FAIL) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static uint64_t fake_icmp_now_ns(void *opaque)
{
    (void)opaque;
    return UINT64_C(1000000000);
}

static uint64_t fake_icmp_now_ms(void *opaque)
{
    (void)opaque;
    return 100u;
}

static qn_run_outcome run_fake_icmp(host_discover *s, fake_icmp *fake,
                                    fake_icmp_mode mode, uint32_t timeout_ms)
{
    qn_icmp_io io = {
        fake, fake_icmp_open, fake_icmp_set_recvbuf, fake_icmp_send,
        fake_icmp_recv, fake_icmp_wait, fake_icmp_close,
        fake_icmp_now_ns, fake_icmp_now_ms
    };
    qn_run_outcome outcome;

    memset(fake, 0, sizeof *fake);
    fake->mode = mode;
    icmp_test_set_io(&io);
    outcome = host_discover_icmp(s, timeout_ms);
    icmp_test_set_io(NULL);
    return outcome;
}

static void test_icmp_failures_are_typed(void)
{
    host_discover s;
    fake_icmp     fake;
    _Atomic bool  cancel = false;

    setup(&s);
    CHECK(run_fake_icmp(&s, &fake, FAKE_ICMP_OK, 0u) == QN_RUN_SUCCESS);
    CHECK(s.icmp_outcome == QN_RUN_SUCCESS && s.icmp_errno == 0);
    CHECK(s.icmp_attempted == s.host_count && s.icmp_unsent == 0u);
    CHECK(fake.opens == 1u && fake.closes == 1u);

    setup(&s);
    CHECK(run_fake_icmp(&s, &fake, FAKE_ICMP_SOCKET_FAIL, 0u) == QN_RUN_FAILED);
    CHECK(s.icmp_outcome == QN_RUN_FAILED && s.icmp_errno == EACCES);
    CHECK(s.icmp_attempted == 0u && s.icmp_unsent == s.host_count);
    CHECK(fake.closes == 0u);

    setup(&s);
    CHECK(run_fake_icmp(&s, &fake, FAKE_ICMP_SEND_FAIL, 0u) == QN_RUN_FAILED);
    CHECK(s.icmp_errno == EIO && s.icmp_attempted == 0u);
    CHECK(s.icmp_unsent == s.host_count);

    setup(&s);
    CHECK(run_fake_icmp(&s, &fake, FAKE_ICMP_RECV_FAIL, 0u) == QN_RUN_FAILED);
    CHECK(s.icmp_errno == EIO && s.icmp_attempted == ICMP_BATCH);
    CHECK(s.icmp_unsent == s.host_count - ICMP_BATCH);

    setup(&s);
    CHECK(run_fake_icmp(&s, &fake, FAKE_ICMP_POLL_FAIL, 100u) == QN_RUN_FAILED);
    CHECK(s.icmp_errno == EIO && fake.waits == 1u);
    CHECK(s.icmp_attempted == s.host_count);

    setup(&s);
    CHECK(run_fake_icmp(&s, &fake, FAKE_ICMP_STALL, 0u) == QN_RUN_INCOMPLETE);
    CHECK(s.icmp_outcome == QN_RUN_INCOMPLETE && s.icmp_errno == 0);
    CHECK(s.icmp_attempted == 0u && s.icmp_unsent == s.host_count);

    setup(&s);
    CHECK(run_fake_icmp(&s, &fake, FAKE_ICMP_CLOSE_FAIL, 0u) == QN_RUN_FAILED);
    CHECK(s.icmp_errno == EIO && s.icmp_attempted == s.host_count);

    setup(&s);
    atomic_store_explicit(&cancel, true, memory_order_release);
    s.cancel = &cancel;
    CHECK(run_fake_icmp(&s, &fake, FAKE_ICMP_OK, 0u) == QN_RUN_CANCELLED);
    CHECK(s.icmp_outcome == QN_RUN_CANCELLED && s.icmp_errno == 0);
    CHECK(fake.opens == 0u && s.icmp_attempted == 0u);
}

/* Builds the echo reply a host at BASE+off would send back to our probe. */
static size_t make_reply(const host_discover *s, uint32_t off, uint8_t *out,
                         struct sockaddr_in *from)
{
    icmp_echo r;

    memset(&r, 0, sizeof r);
    r.type = 0;
    r.seq  = htons((uint16_t)off);
    icmp_payload(s, off, r.pad);
    r.cksum = icmp_cksum(&r, sizeof r);
    memcpy(out, &r, sizeof r);

    memset(from, 0, sizeof *from);
    from->sin_family      = AF_INET;
    from->sin_addr.s_addr = htonl(s->prefix.net.u.v4 + off);
    return sizeof r;
}

static void test_reply_must_answer_a_probe(void)
{
    host_discover      s;
    struct sockaddr_in from;
    uint8_t            buf[64];
    size_t             n;

    setup(&s);
    n = make_reply(&s, 7u, buf, &from);

    /* Never probed: a valid-looking reply proves nothing. */
    CHECK(valid_icmp_reply(&s, &from, buf, n, &(qn_addr){ 0 }) < 0);

    s.icmp_sent_ns[7] = qn_now_ns();
    CHECK(valid_icmp_reply(&s, &from, buf, n, &(qn_addr){ 0 }) == 7);
}

static void test_reply_is_consumed_once(void)
{
    host_discover      s;
    struct sockaddr_in from;
    uint8_t            buf[64];
    size_t             n;
    host_record        hosts[8];
    uint8_t            seen[SPAN];
    uint32_t           slot[SPAN];

    setup(&s);
    memset(seen, 0, sizeof seen);
    memset(slot, 0, sizeof slot);
    s.host = hosts;
    s.cap  = 8;
    s.seen = seen;
    s.slot = slot;

    n = make_reply(&s, 9u, buf, &from);
    s.icmp_sent_ns[9] = qn_now_ns();

    CHECK(accept_reply(&s, &from, buf, n));
    CHECK(s.icmp_replied == 1u && s.n == 1u);

    /* A duplicate answers nothing: the probe was already consumed. */
    CHECK(!accept_reply(&s, &from, buf, n));
    CHECK(s.icmp_replied == 1u);
    CHECK(s.icmp_rejected == 1u);
    CHECK(s.n == 1u);
}

static void test_forged_replies_are_refused(void)
{
    host_discover      s;
    struct sockaddr_in from;
    uint8_t            buf[64];
    qn_addr            a;
    size_t             n;

    setup(&s);
    n = make_reply(&s, 11u, buf, &from);
    s.icmp_sent_ns[11] = qn_now_ns();

    /* Someone who does not know this run's nonce cannot answer for it. */
    {
        host_discover other = s;
        uint8_t       forged[64];

        other.icmp_nonce = s.icmp_nonce ^ 1ull;
        make_reply(&other, 11u, forged, &from);
        CHECK(valid_icmp_reply(&s, &from, forged, n, &a) < 0);
    }

    /* Another offset's payload replayed under this offset's sequence. */
    {
        icmp_echo r;

        memcpy(&r, buf, sizeof r);
        icmp_payload(&s, 12u, r.pad);
        r.cksum = 0;
        r.cksum = icmp_cksum(&r, sizeof r);
        CHECK(valid_icmp_reply(&s, &from, (const uint8_t *)&r, sizeof r, &a) < 0);
    }

    /* Source address that does not match the sequence number. */
    {
        struct sockaddr_in wrong = from;

        wrong.sin_addr.s_addr = htonl(BASE + 12u);
        CHECK(valid_icmp_reply(&s, &wrong, buf, n, &a) < 0);
    }

    /* Wrong type, wrong code, broken checksum, wrong length. */
    {
        icmp_echo r;

        memcpy(&r, buf, sizeof r);
        r.type = 8;
        CHECK(valid_icmp_reply(&s, &from, (const uint8_t *)&r, sizeof r, &a) < 0);

        memcpy(&r, buf, sizeof r);
        r.code = 3;
        CHECK(valid_icmp_reply(&s, &from, (const uint8_t *)&r, sizeof r, &a) < 0);

        memcpy(&r, buf, sizeof r);
        r.cksum = (uint16_t)(r.cksum ^ 0xFFFFu);
        CHECK(valid_icmp_reply(&s, &from, (const uint8_t *)&r, sizeof r, &a) < 0);

        CHECK(valid_icmp_reply(&s, &from, buf, n - 1u, &a) < 0);
        CHECK(valid_icmp_reply(&s, &from, buf, n + 1u, &a) < 0);
    }

    /* Sequence beyond the probed span. */
    {
        icmp_echo r;

        memcpy(&r, buf, sizeof r);
        r.seq   = htons((uint16_t)(SPAN + 5u));
        r.cksum = 0;
        r.cksum = icmp_cksum(&r, sizeof r);
        CHECK(valid_icmp_reply(&s, &from, (const uint8_t *)&r, sizeof r, &a) < 0);
    }

    /* None of that consumed the outstanding probe, so the real reply still works. */
    CHECK(valid_icmp_reply(&s, &from, buf, n, &a) == 11);
}

/* Every offset must get a distinct payload, or one probe answers for another. */
static void test_payload_is_offset_bound(void)
{
    host_discover s;
    uint8_t       a[16], b[16];
    uint32_t      i;

    setup(&s);
    for (i = 0; i + 1u < 64u; i++) {
        icmp_payload(&s, i, a);
        icmp_payload(&s, i + 1u, b);
        CHECK(memcmp(a, b, sizeof a) != 0);
    }
    /* And a different run must not reuse a payload. */
    {
        host_discover other = s;

        other.icmp_nonce = s.icmp_nonce + 1ull;
        icmp_payload(&s, 5u, a);
        icmp_payload(&other, 5u, b);
        CHECK(memcmp(a, b, sizeof a) != 0);
    }
}

static void test_tcp_sweep_is_port_major(void)
{
    host_discover s;
    uint32_t      hosts[] = { 3u, 7u, 11u };
    qn_job        job;
    uint32_t      nports;
    const uint16_t *ports = qn_discover_ports(&nports);

    setup(&s);
    s.tcp_host = hosts;
    s.ntcp_host = (uint32_t)(sizeof hosts / sizeof hosts[0]);
    for (uint64_t i = 0; i < s.ntcp_host; i++) {
        CHECK(hd_next_tcp(&s, i, &job) == QN_TASK_JOB);
        CHECK(job.addr.u.v4 == BASE + hosts[i]);
        CHECK(job.port == ports[0]);
    }
    CHECK(hd_next_tcp(&s, s.ntcp_host, &job) == QN_TASK_JOB);
    CHECK(job.addr.u.v4 == BASE + hosts[0]);
    CHECK(job.port == ports[1]);
    /* Past the last host-port pair the domain is spent, not merely "false". */
    CHECK(hd_next_tcp(&s, (uint64_t)s.ntcp_host * nports, &job) == QN_TASK_EXHAUSTED);
}

/* Throttling on a battery or charger sensor measures the wrong thing. */
static void test_thermal_zone_selection(void)
{
    static const char *const cpu[] = {
        "cpu-0-0-usr", "cpu0-silver-usr", "soc_max", "tsens_tz_sensor4",
        "apc0_cpu0", "x86_pkg_temp", "coretemp", "mtktscpu", "gold-usr",
        "prime-usr", "big_cluster", "little_cluster", "package_thermal"
    };
    static const char *const other[] = {
        "battery", "charger", "usb_port", "skin-therm", "quiet-therm",
        "gpu-usr", "modem_tj", "display", "wifi-therm", "pm8350b_tz",
        "sdm-therm", "camera-therm", "ambient"
    };
    size_t i;

    for (i = 0; i < sizeof cpu / sizeof cpu[0]; i++)
        if (!cpu_thermal_zone(cpu[i])) {
            fprintf(stderr, "FAIL cpu zone rejected: %s\n", cpu[i]);
            failures++;
        }
    for (i = 0; i < sizeof other / sizeof other[0]; i++)
        if (cpu_thermal_zone(other[i])) {
            fprintf(stderr, "FAIL non-cpu zone accepted: %s\n", other[i]);
            failures++;
        }
}

static void test_arm_hwcap_is_not_interpreted_on_other_architectures(void)
{
#if !defined(__aarch64__) && !defined(__ARM_NEON)
    qn_topology topology;

    qn_topology_detect(&topology);
    CHECK(!topology.has_neon);
    CHECK(!topology.has_crc32);
    CHECK(!topology.has_asimddp);
#endif
}

int main(void)
{
    test_thermal_zone_selection();
    test_arm_hwcap_is_not_interpreted_on_other_architectures();
    test_icmp_failures_are_typed();
    test_reply_must_answer_a_probe();
    test_reply_is_consumed_once();
    test_forged_replies_are_refused();
    test_payload_is_offset_bound();
    test_tcp_sweep_is_port_major();
    if (failures) {
        fprintf(stderr, "discover tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("discover tests: ok");
    return 0;
}
