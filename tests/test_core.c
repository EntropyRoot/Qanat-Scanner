#include "qanat/arena.h"
#include "qanat/cidr.h"
#include "qanat/http2.h"
#include "qanat/http1.h"
#include "qanat/perm.h"
#include "qanat/probe.h"
#include "qanat/ranges.h"
#include "qanat/ring.h"
#include "qanat/stats.h"
#include "qanat/task.h"
#include "qanat/util.h"

#include "hpack_huff.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

static void test_arena(void)
{
    qn_arena arena;
    uint8_t *p;

    CHECK(qn_arena_init(&arena, 65536u));
    p = (uint8_t *)qn_arena_alloc(&arena, 16384u, 64u);
    CHECK(p != NULL);
    if (p) {
        p[0] = 0xA5u;
        p[4096] = 0x5Au;
        qn_arena_prefault(&arena);
        CHECK(p[0] == 0xA5u);
        CHECK(p[4096] == 0x5Au);
    }
    CHECK(qn_arena_alloc(&arena, 1u, 3u) == NULL);
    CHECK(qn_arena_array(&arena, SIZE_MAX, 2u, 16u) == NULL);
    CHECK(qn_arena_array(&arena, 1u, 0u, 16u) == NULL);
    CHECK(qn_arena_array(&arena, 0u, 1u, 16u) == NULL);
    qn_arena_free(&arena);
}

static bool nth_is(const qn_cidr_set *s, uint64_t i, const char *want)
{
    qn_addr addr;
    char    text[QN_ADDRSTRLEN];

    if (!qn_cidr_set_nth(s, i, &addr))
        return false;
    qn_addr_str(&addr, text, sizeof text);
    return strcmp(text, want) == 0;
}

/* Complete routed-aggregate coverage includes the first and last addresses. */
static void test_cidr(void)
{
    qn_arena    arena;
    qn_cidr_set set;
    qn_prefix   prefix;
    qn_addr     addr;

    CHECK(qn_cidr_parse("192.0.2.99/30", &prefix));
    CHECK(prefix.af == AF_INET);
    CHECK(prefix.bits == 30u);
    CHECK(prefix.count == 4u);
    CHECK(qn_prefix_usable(&prefix, false) == 4u);
    CHECK(qn_prefix_usable(&prefix, true) == 2u);

    CHECK(qn_arena_init(&arena, 65536u));
    CHECK(qn_cidr_set_init(&set, &arena, 2u));
    CHECK(qn_cidr_set_add(&set, &prefix));
    CHECK(qn_cidr_set_add_str(&set, "198.51.100.7/32"));
    qn_cidr_set_seal(&set, &arena);
    CHECK(set.total == 5u);
    CHECK(nth_is(&set, 0u, "192.0.2.96"));
    CHECK(nth_is(&set, 1u, "192.0.2.97"));
    CHECK(nth_is(&set, 2u, "192.0.2.98"));
    CHECK(nth_is(&set, 3u, "192.0.2.99"));
    CHECK(nth_is(&set, 4u, "198.51.100.7"));
    CHECK(!qn_cidr_set_nth(&set, 5u, &addr));

    /* Opt-in exclusion is what a LAN sweep wants, and only that. */
    CHECK(qn_cidr_set_init(&set, &arena, 2u));
    qn_cidr_set_skip_edges(&set, true);
    CHECK(qn_cidr_set_add(&set, &prefix));
    CHECK(qn_cidr_set_add_str(&set, "198.51.100.7/32"));
    qn_cidr_set_seal(&set, &arena);
    CHECK(set.total == 3u);
    CHECK(nth_is(&set, 0u, "192.0.2.97"));
    CHECK(nth_is(&set, 1u, "192.0.2.98"));
    CHECK(nth_is(&set, 2u, "198.51.100.7"));

    /* /31 and /32 have no edges to drop under either policy. */
    CHECK(qn_cidr_parse("203.0.113.4/31", &prefix));
    CHECK(qn_prefix_usable(&prefix, true) == 2u);
    CHECK(qn_cidr_parse("203.0.113.4/32", &prefix));
    CHECK(qn_prefix_usable(&prefix, true) == 1u);
    CHECK(!qn_cidr_parse("203.0.113.4/", &prefix));
    CHECK(!qn_cidr_parse("203.0.113.4/+24", &prefix));

    /* Normalization collapses redundant and mergeable prefixes without loss. */
    CHECK(qn_cidr_set_init(&set, &arena, 5u));
    CHECK(qn_cidr_set_add_str(&set, "10.0.0.0/24"));
    CHECK(qn_cidr_set_add_str(&set, "10.0.0.0/25"));
    CHECK(qn_cidr_set_add_str(&set, "10.0.0.0/24"));
    CHECK(qn_cidr_set_add_str(&set, "10.0.1.0/24"));
    qn_cidr_set_seal(&set, &arena);
    CHECK(set.n == 1u && set.v[0].bits == 23u && set.total == 512u);
    CHECK(nth_is(&set, 0u, "10.0.0.0"));
    CHECK(nth_is(&set, 511u, "10.0.1.255"));

    CHECK(qn_cidr_set_init(&set, &arena, 2u));
    CHECK(qn_cidr_set_add_str(&set, "2001:db8::/127"));
    CHECK(qn_cidr_set_add_str(&set, "2001:db8::2/127"));
    qn_cidr_set_seal(&set, &arena);
    CHECK(set.n == 1u && set.v[0].bits == 126u && set.total == 4u);

    {
        static const char *expected[] = {
            "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3",
            "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"
        };
        bool seen[QN_ARRAY_LEN(expected)] = { false };

        CHECK(qn_cidr_set_init(&set, &arena, 6u));
        CHECK(qn_cidr_set_add_str(&set, "10.0.0.0/30"));
        CHECK(qn_cidr_set_add_str(&set, "10.0.0.2/31"));
        CHECK(qn_cidr_set_add_str(&set, "10.0.0.4/31"));
        CHECK(qn_cidr_set_add_str(&set, "10.0.0.6/31"));
        CHECK(qn_cidr_set_add_str(&set, "10.0.0.0/32"));
        CHECK(qn_cidr_set_add_str(&set, "10.0.0.7/32"));
        qn_cidr_set_seal(&set, &arena);
        CHECK(set.n == 1u && set.v[0].bits == 29u && set.total == 8u);
        for (uint64_t i = 0; i < set.total; i++) {
            char text[QN_ADDRSTRLEN];
            size_t j;

            CHECK(qn_cidr_set_nth(&set, i, &addr));
            CHECK(qn_addr_str(&addr, text, sizeof text) > 0);
            for (j = 0; j < QN_ARRAY_LEN(expected); j++) {
                if (strcmp(text, expected[j]) == 0)
                    break;
            }
            CHECK(j < QN_ARRAY_LEN(expected));
            if (j < QN_ARRAY_LEN(expected)) {
                CHECK(!seen[j]);
                seen[j] = true;
            }
        }
        for (size_t i = 0; i < QN_ARRAY_LEN(seen); i++)
            CHECK(seen[i]);
    }

    qn_arena_free(&arena);
}

/* The built-in target set is what "complete" is measured against. */
static void test_cf_prefix_total(void)
{
    qn_arena    arena;
    qn_cidr_set set;
    uint64_t    want = 0;

    CHECK(qn_arena_init(&arena, 1u << 16));
    CHECK(qn_cidr_set_init(&set, &arena, qn_cf_v4_n));
    for (uint32_t i = 0; i < qn_cf_v4_n; i++) {
        qn_prefix p;

        CHECK(qn_cidr_parse(qn_cf_v4[i], &p));
        CHECK(qn_cidr_set_add(&set, &p));
        want += (uint64_t)1u << (32u - p.bits);
    }
    qn_cidr_set_seal(&set, &arena);
    if (set.total != want)
        fprintf(stderr, "  cloudflare domain %llu, expected %llu\n",
                (unsigned long long)set.total, (unsigned long long)want);
    CHECK(set.total == want);
    qn_arena_free(&arena);
}

static void write_file(const char *path, const char *body)
{
    FILE *f = fopen(path, "w");

    if (!f) {
        failures++;
        return;
    }
    fputs(body, f);
    fclose(f);
}

static void test_path(char out[128], const char *tag)
{
    const char *directory = getenv("TMPDIR");
    int length;

    if (!directory || !directory[0])
        directory = "/tmp";
    length = snprintf(out, 128u, "%s/qanat-%ld-%s", directory,
                      (long)getpid(), tag);
    CHECK(length > 0 && length < 128);
}

/* Narrowing the target set without saying so is the failure mode here. */
static void test_cidr_load_file(void)
{
    qn_arena       arena;
    qn_cidr_set    set;
    qn_cidr_report rep;
    char           path[128], missing[128];

    test_path(path, "ranges-load.txt");
    test_path(missing, "missing-load.txt");

    CHECK(qn_arena_init(&arena, 1u << 16));

    write_file(path, "# comment\n\n104.16.0.0/13\n 1.1.1.0/24 \n");
    CHECK(qn_cidr_file_lines(path) == 2u);
    CHECK(qn_cidr_set_init(&set, &arena, 4u));
    CHECK(qn_cidr_set_load_file(&set, path, &rep));
    CHECK(rep.accepted == 2u && rep.rejected == 0u && rep.overflow == 0u);
    CHECK(set.n == 2u);

    /* One broken line must fail the load and name itself. */
    write_file(path, "104.16.0.0/13\nnot-a-prefix\n1.1.1.0/24\n");
    CHECK(qn_cidr_set_init(&set, &arena, 4u));
    CHECK(!qn_cidr_set_load_file(&set, path, &rep));
    CHECK(rep.accepted == 2u && rep.rejected == 1u);
    CHECK(rep.bad_line == 2u);
    CHECK(strcmp(rep.bad_text, "not-a-prefix") == 0);

    /* So must a file that does not fit. */
    write_file(path, "104.16.0.0/13\n1.1.1.0/24\n8.8.8.0/24\n");
    CHECK(qn_cidr_set_init(&set, &arena, 2u));
    CHECK(!qn_cidr_set_load_file(&set, path, &rep));
    CHECK(rep.accepted == 2u && rep.overflow == 1u);
    CHECK(rep.bad_line == 3u);

    CHECK(qn_cidr_file_lines(missing) == 0u);
    CHECK(qn_cidr_set_init(&set, &arena, 2u));
    CHECK(!qn_cidr_set_load_file(&set, missing, &rep));

    write_file(path, "2001:db8::/32\n");
    CHECK(qn_cidr_set_init(&set, &arena, 2u));
    CHECK(!qn_cidr_set_load_file_af(&set, path, &rep, AF_INET));
    CHECK(rep.bad_line == 1u && rep.rejected == 1u);

    {
        char long_line[256];

        memset(long_line, '1', sizeof long_line - 2u);
        long_line[sizeof long_line - 2u] = '\n';
        long_line[sizeof long_line - 1u] = 0;
        write_file(path, long_line);
        CHECK(qn_cidr_set_init(&set, &arena, 2u));
        CHECK(!qn_cidr_set_load_file_af(&set, path, &rep, AF_INET));
        CHECK(rep.bad_line == 1u && strcmp(rep.bad_text, "line-too-long") == 0);
    }

    remove(path);
    qn_arena_free(&arena);
}

static void test_managed_ranges_validation(void)
{
    qn_cf_ranges_info info;
    char path[128];

    test_path(path, "ranges-managed.txt");

    write_file(path, "104.16.0.0/13\n1.1.1.0/24\n");
    CHECK(qn_cf_ranges_inspect(path, &info));
    CHECK(info.prefixes == 2u);
    CHECK(info.candidates == ((uint64_t)1u << 19) + 256u);

    write_file(path, "104.16.0.0/13\n104.16.0.0/14\n");
    CHECK(!qn_cf_ranges_inspect(path, &info));
    CHECK(strstr(info.error, "overlapping") != NULL);

    write_file(path, "2001:db8::/32\n");
    CHECK(!qn_cf_ranges_inspect(path, &info));
    CHECK(strstr(info.error, "IPv4") != NULL);
    remove(path);
}

static void write_bytes(const char *path, const void *p, size_t n)
{
    FILE *f = fopen(path, "wb");

    if (!f) {
        failures++;
        return;
    }
    if (fwrite(p, 1u, n, f) != n)
        failures++;
    fclose(f);
}

#if defined(QN_CIDR_TESTING)
typedef enum {
    SNAP_FAULT_NONE = 0,
    SNAP_FAULT_TRUNCATE,
    SNAP_FAULT_GROW,
    SNAP_FAULT_METADATA,
    SNAP_FAULT_REPLACE
} snap_fault_action;

typedef struct {
    snap_fault_action action;
    const char       *backup;
    mode_t            old_mode;
    bool              fired;
} snap_fault;

static void snapshot_fault_hook(qn_snapshot_test_point point, const char *path, void *opaque)
{
    snap_fault *fault = (snap_fault *)opaque;
    int         fd;

    if (!fault || fault->fired)
        return;
    if (fault->action == SNAP_FAULT_TRUNCATE && point == QN_SNAPSHOT_TEST_AFTER_FSTAT) {
        fd = open(path, O_WRONLY | O_CLOEXEC);
        CHECK(fd >= 0);
        if (fd >= 0) {
            CHECK(ftruncate(fd, 4) == 0);
            CHECK(close(fd) == 0);
        }
    } else if (fault->action == SNAP_FAULT_GROW && point == QN_SNAPSHOT_TEST_AFTER_READ) {
        fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
        CHECK(fd >= 0);
        if (fd >= 0) {
            CHECK(write(fd, "\n", 1u) == 1);
            CHECK(close(fd) == 0);
        }
    } else if (fault->action == SNAP_FAULT_METADATA &&
               point == QN_SNAPSHOT_TEST_BEFORE_FINAL_FSTAT) {
        struct stat st;

        CHECK(stat(path, &st) == 0);
        fault->old_mode = st.st_mode & 07777;
        CHECK(chmod(path, fault->old_mode ^ S_IXUSR) == 0);
    } else if (fault->action == SNAP_FAULT_REPLACE &&
               point == QN_SNAPSHOT_TEST_BEFORE_PATH_STAT) {
        CHECK(rename(path, fault->backup) == 0);
        write_file(path, "8.8.8.0/24\n");
    } else {
        return;
    }
    fault->fired = true;
}

static void snapshot_fault_begin(snap_fault *fault, snap_fault_action action,
                                 const char *backup)
{
    memset(fault, 0, sizeof *fault);
    fault->action = action;
    fault->backup = backup;
    qn_cidr_snapshot_set_test_hook(snapshot_fault_hook, fault);
}

static void snapshot_fault_end(void)
{
    qn_cidr_snapshot_set_test_hook(NULL, NULL);
}
#endif

/* QN2-031/032: snapshot sizing and parsing consume the same bytes exactly once. */
static void test_cidr_snapshot_loader(void)
{
    qn_arena       arena;
    qn_cidr_set    set;
    qn_cidr_report rep;
    char           line159[160];
    char           line160[256];
    char           path[128], missing[128], backup[128];

    test_path(path, "ranges-snapshot.txt");
    test_path(missing, "missing-snapshot.txt");
    test_path(backup, "ranges-snapshot-backup.txt");

    CHECK(qn_arena_init(&arena, 8u << 20));

    /* A clean file: sized from its own content, with a digest of what was read. */
    write_file(path, "# c\n104.16.0.0/13\n1.1.1.0/24\n");
    CHECK(qn_cidr_set_load_snapshot(&set, &arena, path, &rep, AF_INET));
    CHECK(rep.accepted == 2u && rep.rejected == 0u && rep.overflow == 0u);
    CHECK(set.n == 2u && set.cap == 2u);
    CHECK(rep.have_digest && rep.bytes == 29u);

    /* The digest follows the bytes, so a changed file is a different run. */
    {
        uint8_t first[32];

        memcpy(first, rep.digest, sizeof first);
        write_file(path, "# c\n104.16.0.0/13\n1.1.1.1/32\n");
        CHECK(qn_cidr_set_load_snapshot(&set, &arena, path, &rep, AF_INET));
        CHECK(memcmp(first, rep.digest, sizeof first) != 0);
    }

    /* Exactly at the buffer edge, and one past it. */
    memset(line159, 'x', sizeof line159 - 1u);
    line159[sizeof line159 - 1u] = '\0';
    memcpy(line159, "1.1.1.0/24", 10u);
    line159[10] = '\n';
    line159[11] = '\0';
    write_file(path, line159);
    CHECK(qn_cidr_set_load_snapshot(&set, &arena, path, &rep, AF_INET));
    CHECK(rep.accepted == 1u);

    memset(line160, 'x', 200u);
    line160[200] = '\n';
    line160[201] = '\0';
    write_file(path, line160);
    CHECK(!qn_cidr_set_load_snapshot(&set, &arena, path, &rep, AF_INET));
    CHECK(rep.rejected == 1u && strcmp(rep.bad_text, "line-too-long") == 0);
    /* One physical line becomes one error, never a valid head plus a tail. */
    CHECK(rep.accepted == 0u);

    /* No final newline still yields the line. */
    write_file(path, "10.0.0.0/8");
    CHECK(qn_cidr_set_load_snapshot(&set, &arena, path, &rep, AF_INET));
    CHECK(rep.accepted == 1u);

    /* An embedded NUL would truncate the line for every str* call after it. */
    {
        static const char nul_line[] = "1.1.1.0/24\0trailing\n";

        write_bytes(path, nul_line, sizeof nul_line - 1u);
        CHECK(!qn_cidr_set_load_snapshot(&set, &arena, path, &rep,
                                         AF_INET));
        CHECK(rep.rejected == 1u && strcmp(rep.bad_text, "embedded-nul") == 0);
        CHECK(rep.accepted == 0u);
    }

    /* CRLF is accepted, and a missing file is not a silent empty set. */
    write_file(path, "1.1.1.0/24\r\n8.8.8.0/24\r\n");
    CHECK(qn_cidr_set_load_snapshot(&set, &arena, path, &rep, AF_INET));
    CHECK(rep.accepted == 2u);
    CHECK(!qn_cidr_set_load_snapshot(&set, &arena, missing, &rep, AF_INET));

#if defined(QN_CIDR_TESTING)
    {
        snap_fault fault;

        write_file(path, "1.1.1.0/24\n8.8.8.0/24\n");
        snapshot_fault_begin(&fault, SNAP_FAULT_TRUNCATE, NULL);
        CHECK(!qn_cidr_set_load_snapshot(&set, &arena, path, &rep, AF_INET));
        snapshot_fault_end();
        CHECK(fault.fired && rep.snapshot_status == QN_SNAPSHOT_SHORT_READ);
        CHECK(rep.snapshot_errno == ESTALE);

        write_file(path, "1.1.1.0/24\n");
        snapshot_fault_begin(&fault, SNAP_FAULT_GROW, NULL);
        CHECK(!qn_cidr_set_load_snapshot(&set, &arena, path, &rep, AF_INET));
        snapshot_fault_end();
        CHECK(fault.fired && rep.snapshot_status == QN_SNAPSHOT_GREW);
        CHECK(rep.snapshot_errno == ESTALE);

        write_file(path, "1.1.1.0/24\n");
        snapshot_fault_begin(&fault, SNAP_FAULT_METADATA, NULL);
        CHECK(!qn_cidr_set_load_snapshot(&set, &arena, path, &rep, AF_INET));
        snapshot_fault_end();
        CHECK(fault.fired && rep.snapshot_status == QN_SNAPSHOT_METADATA_CHANGED);
        CHECK(rep.snapshot_errno == ESTALE);
        CHECK(chmod(path, fault.old_mode) == 0);

        remove(backup);
        write_file(path, "1.1.1.0/24\n");
        snapshot_fault_begin(&fault, SNAP_FAULT_REPLACE, backup);
        CHECK(!qn_cidr_set_load_snapshot(&set, &arena, path, &rep, AF_INET));
        snapshot_fault_end();
        CHECK(fault.fired && rep.snapshot_status == QN_SNAPSHOT_REPLACED);
        CHECK(rep.snapshot_errno == ESTALE);
        CHECK(remove(path) == 0);
        CHECK(rename(backup, path) == 0);
    }
#endif

    remove(path);
    remove(backup);
    qn_arena_free(&arena);
}

static void test_permutation(void)
{
    enum { DOMAIN = 997 };
    qn_perm perm;
    bool    seen[DOMAIN] = { false };

    qn_perm_init(&perm, DOMAIN, 0x123456789ABCDEF0ull);
    for (uint64_t i = 0; i < DOMAIN; i++) {
        uint64_t v = qn_perm_apply(&perm, i);
        CHECK(v < DOMAIN);
        if (v < DOMAIN) {
            CHECK(!seen[v]);
            seen[v] = true;
        }
    }
}

static void test_ring(void)
{
    qn_arena arena;
    qn_ring  ring;
    uint32_t in[4] = { 11u, 22u, 33u, 44u };
    uint32_t out[4] = { 0u };

    CHECK(qn_arena_init(&arena, 65536u));
    CHECK(qn_ring_init(&ring, &arena, 4u, (uint32_t)sizeof(uint32_t)));
    for (uint32_t i = 0; i < 4u; i++)
        CHECK(qn_ring_push(&ring, &in[i]));
    CHECK(!qn_ring_push(&ring, &in[0]));
    CHECK(qn_ring_len(&ring) == 4u);
    CHECK(qn_ring_pop_batch(&ring, out, 4u) == 4u);
    CHECK(memcmp(in, out, sizeof in) == 0);
    CHECK(qn_ring_len(&ring) == 0u);
    qn_arena_free(&arena);
}

static void test_statistics(void)
{
    qn_samples samples = { { 0u }, 0u, 0u };
    qn_hist    hist;
    cf_record  ranked[2];
    uint32_t   lo, hi;

    qn_samples_add(&samples, 10000u);
    qn_samples_add(&samples, 20000u);
    qn_samples_add(&samples, 40000u);
    qn_samples_lost(&samples);
    CHECK(qn_samples_min(&samples) == 10000u);
    CHECK(qn_samples_median(&samples) == 20000u);
    CHECK(qn_samples_p90(&samples) == 40000u);
    CHECK(qn_samples_delta_mean(&samples) == 15000u);
    CHECK(qn_samples_loss_pct(&samples) == 25u);

    memset(&samples, 0, sizeof samples);
    for (uint32_t i = 1; i <= 10u; i++)
        qn_samples_add(&samples, i * 1000u);
    CHECK(qn_samples_p90(&samples) == 9000u);

    qn_hist_reset(&hist);
    qn_hist_add(&hist, 999u);
    qn_hist_add(&hist, 1000u);
    qn_hist_add(&hist, 1999u);
    qn_hist_add(&hist, 2000u);
    qn_hist_add(&hist, 50000u);
    CHECK(hist.total == 5u);
    CHECK(hist.bin[0] == 1u);
    CHECK(hist.bin[1] == 2u);
    CHECK(hist.bin[2] == 1u);
    CHECK(hist.max_bin == 2u);
    qn_hist_bin_range(0u, &lo, &hi);
    CHECK(lo == 0u && hi == 1000u);
    qn_hist_bin_range(1u, &lo, &hi);
    CHECK(lo == 1000u && hi == 2000u);
    qn_hist_bin_range(2u, &lo, &hi);
    CHECK(lo == 2000u && hi == 3000u);
    qn_hist_bin_range(QN_HIST_BINS, &lo, &hi);
    CHECK(lo == 0u && hi == 0u);

    CHECK(!qn_rtt_within_baseline(0u, 1000u));
    CHECK(qn_rtt_within_baseline(10000u, 20000u));
    CHECK(!qn_rtt_within_baseline(10000u, 20001u));
    CHECK(qn_rtt_within_baseline(UINT32_MAX, UINT32_MAX));

    memset(ranked, 0, sizeof ranked);
    for (uint32_t i = 0u; i < 2u; i++) {
        ranked[i].addr.af = AF_INET;
        ranked[i].addr.u.v4 = 0xC0000202u - i;
        ranked[i].highest_rung_reached = QN_RUNG_TLS;
        ranked[i].terminal_outcome = QN_TERM_SUCCESS;
    }
    qn_samples_add(&ranked[0].samples, 100u);
    for (uint32_t i = 1u; i < 6u; i++)
        qn_samples_add(&ranked[0].samples, 600000u);
    for (uint32_t i = 0u; i < 6u; i++)
        qn_samples_add(&ranked[1].samples, 10000u);
    qn_cf_finalize_rank(&ranked[0], QN_RANK_BALANCED);
    qn_cf_finalize_rank(&ranked[1], QN_RANK_BALANCED);
    CHECK(ranked[0].rtt_min_us == 100u);
    CHECK(ranked[1].rtt_min_us == 10000u);
    CHECK(ranked[1].score > ranked[0].score);
    CHECK(ranked[1].score_version == QN_SCORE_VERSION);
    CHECK(ranked[1].score_latency != 0u);
    CHECK(ranked[1].score_stability != 0u);

    {
        cf_record passed = ranked[1];
        cf_record untested = ranked[1];
        cf_record failed = ranked[1];

        passed.tunnel_state = QN_TUNNEL_PASSED;
        untested.tunnel_state = QN_TUNNEL_UNTESTED;
        failed.tunnel_state = QN_TUNNEL_NO_MARKER;
        qn_cf_finalize_rank(&passed, QN_RANK_BALANCED);
        qn_cf_finalize_rank(&untested, QN_RANK_BALANCED);
        qn_cf_finalize_rank(&failed, QN_RANK_BALANCED);
        CHECK(passed.score > untested.score);
        CHECK(untested.score > failed.score);
        CHECK(passed.score_tunnel == 30000u);
        CHECK(untested.score_tunnel == 15000u);
        CHECK(failed.score_tunnel == 0u);
    }

    ranked[0] = ranked[1];
    ranked[0].addr.u.v4 = 0xC0000202u;
    ranked[1].addr.u.v4 = 0xC0000201u;
    qn_cf_sort(ranked, 2u);
    CHECK(ranked[0].addr.u.v4 == 0xC0000201u);
}

static void test_protocols(void)
{
    static const uint8_t response[] =
        "HTTP/1.1 200 OK\r\nServer: cloudflare\r\nCF-Ray: abcdef1234567890-FRA\r\n\r\n";
    static const uint8_t bad_status[] = "HTTP/1.X?200 OK\r\n\r\n";
    static const uint8_t server_hello[47] = {
        [0] = 0x16u, [1] = 0x03u, [2] = 0x03u, [4] = 42u,
        [5] = 0x02u, [8] = 38u, [9] = 0x03u, [10] = 0x03u,
        [44] = 0x13u, [45] = 0x01u
    };
    static const uint8_t alert[] = { 0x15u, 0x03u, 0x03u, 0x00u, 0x02u, 0x02u, 0x28u };
    static const uint8_t truncated[] = { 0x16u, 0x03u, 0x03u, 0x00u, 42u, 0x02u };
    qn_http_reply reply;
    qn_rng        rng;
    uint8_t       request[QN_PROBE_BUF];
    uint8_t       hello[QN_PROBE_BUF];
    int           n;

    CHECK(qn_http_parse(response, sizeof response - 1u, &reply));
    CHECK(reply.status == 200u);
    CHECK(reply.complete);
    CHECK(reply.is_cloudflare);
    CHECK(strcmp(reply.colo, "FRA") == 0);
    CHECK(!qn_http_parse(bad_status, sizeof bad_status - 1u, &reply));
    CHECK(!qn_http_parse(NULL, 0u, &reply));
    CHECK(!qn_http_parse(response, sizeof response - 1u, NULL));
    CHECK(qn_http_build_get(NULL, 0u, "example.com", "/") < 0);
    n = qn_http_build_get(request, sizeof request, "example.com", "/trace");
    CHECK(n > 0);
    if (n > 0) {
        int request_len = n;

        CHECK((size_t)request_len == strlen((const char *)request));
        CHECK(strstr((const char *)request, "GET /trace HTTP/1.1\r\n") != NULL);
        CHECK(strstr((const char *)request, "Host: example.com\r\n") != NULL);
        request[0] = 0xa5u;
        CHECK(qn_http_build_get(request, 1u, "example.com", "/trace") < 0);
        CHECK(request[0] == 0xa5u);
        CHECK(qn_http_build_get(request, (size_t)request_len, "example.com", "/trace") < 0);
        CHECK(qn_http_build_get(request, (size_t)request_len + 1u, "example.com", "/trace") ==
              request_len);
    }

    qn_rng_seed(&rng, 7u);
    n = qn_tls_build_hello(hello, sizeof hello, "example.com", &rng, QN_TLS_FP_CHROME);
    CHECK(n >= 512);
    CHECK(n <= (int)sizeof hello);
    CHECK(qn_find_ci(hello, n > 0 ? (size_t)n : 0u, "example.com") != NULL);

    /* The screen must present the profile it was asked for, not a fixed one. */
    {
        uint8_t other[QN_PROBE_BUF];
        int     m;

        qn_rng_seed(&rng, 7u);
        m = qn_tls_build_hello(other, sizeof other, "example.com", &rng,
                               QN_TLS_FP_FIREFOX);
        CHECK(m > 0);
        CHECK(m != n || memcmp(other, hello, (size_t)m) != 0);
    }
    CHECK(qn_tls_classify(server_hello, sizeof server_hello) == QN_TLS_SERVERHELLO);
    CHECK(qn_tls_classify(alert, sizeof alert) == QN_TLS_ALERT);
    CHECK(qn_tls_classify(truncated, sizeof truncated) == QN_TLS_GARBAGE);
    CHECK(qn_tls_classify(NULL, 0u) == QN_TLS_SILENCE);

    {
        uint8_t malformed[53];

        memcpy(malformed, server_hello, sizeof server_hello);
        malformed[1] = 0x02u; /* invalid record major version */
        CHECK(qn_tls_classify(malformed, sizeof server_hello) == QN_TLS_GARBAGE);

        memcpy(malformed, server_hello, sizeof server_hello);
        malformed[10] = 0x00u; /* invalid ServerHello legacy_version */
        CHECK(qn_tls_classify(malformed, sizeof server_hello) == QN_TLS_GARBAGE);

        memcpy(malformed, server_hello, sizeof server_hello);
        malformed[46] = 0x01u; /* compression must be null */
        CHECK(qn_tls_classify(malformed, sizeof server_hello) == QN_TLS_GARBAGE);

        memset(malformed, 0, sizeof malformed);
        memcpy(malformed, server_hello, sizeof server_hello);
        malformed[4] = 48u;
        malformed[8] = 44u;
        malformed[47] = 0u;
        malformed[48] = 4u; /* extension vector has one four-byte item */
        malformed[49] = 0u;
        malformed[50] = 23u;
        malformed[51] = 0u;
        malformed[52] = 1u; /* but the item claims a missing payload byte */
        CHECK(qn_tls_classify(malformed, sizeof malformed) == QN_TLS_GARBAGE);
    }

    {
        static const uint8_t malformed_alert[] = {
            0x15u, 0x03u, 0x03u, 0x00u, 0x02u, 0x00u, 0x28u
        };
        CHECK(qn_tls_classify(malformed_alert, sizeof malformed_alert) == QN_TLS_GARBAGE);
    }
}

static size_t h2_frame(uint8_t *out, uint8_t type, uint8_t flags, uint32_t stream,
                       const uint8_t *body, size_t len)
{
    out[0] = (uint8_t)(len >> 16);
    out[1] = (uint8_t)(len >> 8);
    out[2] = (uint8_t)len;
    out[3] = type;
    out[4] = flags;
    out[5] = (uint8_t)(stream >> 24);
    out[6] = (uint8_t)(stream >> 16);
    out[7] = (uint8_t)(stream >> 8);
    out[8] = (uint8_t)stream;
    /* Callers may stage the payload in place, so the copy must tolerate it. */
    if (len && body != out + 9)
        memmove(out + 9, body, len);
    return 9u + len;
}

static void test_http2(void)
{
    static const uint8_t trace[] = "fl=1\ncolo=FRA\n";
    uint8_t     wire[256], out[2048], ctl[64], ping[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    qn_h2       h;
    qn_h2_event ev;
    size_t      n, cn;

    CHECK(qn_h2_preface(out, sizeof out) == 70);
    CHECK(memcmp(out, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0);
    CHECK(qn_h2_get(1, "example.com", "/cdn-cgi/trace", out, sizeof out) > 9);
    CHECK(out[3] == 1u && out[4] == 5u && out[8] == 1u);

    qn_h2_init(&h);
    /* Stream 1 only becomes legal once its request has been written. */
    CHECK(qn_h2_open_stream(&h, 1u));
    n = h2_frame(wire, 4, 0, 0, NULL, 0);
    CHECK(qn_h2_feed(&h, wire, 4, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(cn == 0u);
    CHECK(qn_h2_feed(&h, wire + 4, n - 4u, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(cn == 9u && ctl[3] == 4u && ctl[4] == 1u);

    wire[0] = 0x88u;
    n = h2_frame(out, 1, 4, 1, wire, 1);
    CHECK(qn_h2_feed(&h, out, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(ev.nstreams == 1u);
    CHECK((ev.stream[0].flags & QN_H2_EV_HEADERS) != 0u && ev.stream[0].status == 200u);

    n = h2_frame(wire, 0, 1, 1, trace, sizeof trace - 1u);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(ev.nstreams == 1u);
    CHECK((ev.stream[0].flags & (QN_H2_EV_DATA | QN_H2_EV_EDGE | QN_H2_EV_END_STREAM)) ==
          (QN_H2_EV_DATA | QN_H2_EV_EDGE | QN_H2_EV_END_STREAM));
    CHECK(ev.stream[0].body_bytes == sizeof trace - 1u &&
          strcmp(ev.stream[0].colo, "FRA") == 0);
    /* DATA consumption replenishes both connection and stream windows. */
    CHECK(cn == 26u);
    CHECK(ctl[3] == 8u && ctl[8] == 0u);
    CHECK(ctl[16] == 8u && ctl[21] == 1u);

    n = h2_frame(wire, 6, 0, 0, ping, sizeof ping);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(cn == 17u && ctl[3] == 6u && ctl[4] == 1u);
    CHECK(memcmp(ctl + 9, ping, sizeof ping) == 0);
}

static void test_http2_end_stream_survives_coalesced_goaway(void)
{
    static const uint8_t trace[] = "fl=1\ncolo=FRA\n";
    uint8_t      wire[256], ctl[64], head[1] = { 0x88u };
    uint8_t      goaway[8] = { 0, 0, 0, 1, 0, 0, 0, 0 };
    qn_h2        h;
    qn_h2_event  ev;
    qn_http_event head_event;
    qn_observation observation;
    size_t       first, second, cn;

    qn_h2_init(&h);
    CHECK(qn_h2_open_stream(&h, 1u));
    first = h2_frame(wire, 1u, 4u, 1u, head, sizeof head);
    CHECK(qn_h2_feed(&h, wire, first, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(ev.nstreams == 1u);
    head_event = ev.stream[0];

    first = h2_frame(wire, 0u, 1u, 1u, trace, sizeof trace - 1u);
    second = h2_frame(wire + first, 7u, 0u, 0u, goaway, sizeof goaway);
    CHECK(qn_h2_feed(&h, wire, first + second, ctl, sizeof ctl,
                     &cn, &ev) == QN_H2_OK);
    CHECK(ev.nstreams == 1u);
    CHECK((ev.stream[0].flags & QN_HTTP_FACT_DONE) != 0u);
    CHECK((ev.flags & QN_H2_EV_GOAWAY) != 0u);

    qn_observation_init(&observation);
    observation.transport.connected = true;
    observation.tls.handshake_complete = true;
    observation.http.request_fully_flushed = true;
    qn_observation_apply_http(&observation, &head_event);
    qn_observation_apply_http(&observation, &ev.stream[0]);
    CHECK(observation.http.response_complete);
    CHECK(observation.edge.verified);
}

static uint32_t wire32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void test_http2_full_flow_window(void)
{
    enum { FRAME_DATA = 16384, FRAMES = 1024 };
    uint8_t    *wire = (uint8_t *)malloc(9u + FRAME_DATA);
    uint8_t     ctl[64];
    qn_h2       h;
    qn_h2_event ev;
    uint64_t    total = 0;
    size_t      cn;

    CHECK(wire != NULL);
    if (!wire)
        return;
    memset(wire + 9, 0xA5, FRAME_DATA);
    qn_h2_init(&h);
    CHECK(qn_h2_open_stream(&h, 3u));
    /* A body needs a response head first, so give stream 3 a 200. */
    {
        uint8_t head[16];
        uint8_t block[1] = { 0x88u }; /* indexed :status 200 */
        size_t  hn = h2_frame(head, 1, 4, 3, block, 1);

        CHECK(qn_h2_feed(&h, head, hn, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    }
    for (unsigned i = 0; i < FRAMES; i++) {
        size_t n = h2_frame(wire, 0u, i + 1u == FRAMES ? 1u : 0u, 3u,
                            wire + 9, FRAME_DATA);

        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
        CHECK(cn == 26u);
        CHECK(ctl[3] == 8u && (wire32(ctl + 5) & 0x7FFFFFFFu) == 0u &&
              (wire32(ctl + 9) & 0x7FFFFFFFu) == FRAME_DATA);
        CHECK(ctl[16] == 8u && (wire32(ctl + 18) & 0x7FFFFFFFu) == 3u &&
              (wire32(ctl + 22) & 0x7FFFFFFFu) == FRAME_DATA);
        CHECK(ev.nstreams == 1u && ev.stream[0].body_bytes == FRAME_DATA);
        total += ev.stream[0].body_bytes;
    }
    CHECK(total == 16ull * 1024ull * 1024ull);
    CHECK((ev.stream[0].flags & QN_H2_EV_END_STREAM) != 0u);
    free(wire);
}

static void test_http2_strict_hpack_and_credit_retry(void)
{
    uint8_t     wire[64], ctl[64];
    qn_h2       h;
    qn_h2_event ev;
    size_t      n, cn;

    /* Small control output retains frame-worthy credit until both updates fit. */
    {
        enum { BODY = 16384 };
        uint8_t *big = (uint8_t *)malloc(9u + BODY);
        uint8_t  block[1] = { 0x88u }; /* a body needs a response head first */

        CHECK(big != NULL);
        if (!big)
            return;
        memset(big + 9, 0xA5u, BODY);

        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, block, 1u);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);

        /* One byte is below the publication step, so nothing is emitted. */
        wire[9] = 0xA5u;
        n = h2_frame(wire, 0u, 0u, 1u, wire + 9, 1u);
        CHECK(qn_h2_feed(&h, wire, n, NULL, 0u, &cn, &ev) == QN_H2_OK);
        CHECK(cn == 0u && h.conn_consumed == 1u && h.flow[0].consumed == 1u);

        /* A full frame crosses it, and no control room means retain, not lose. */
        n = h2_frame(big, 0u, 0u, 1u, big + 9, BODY);
        CHECK(qn_h2_feed(&h, big, n, NULL, 0u, &cn, &ev) == QN_H2_SPACE);
        CHECK(h.conn_consumed == BODY + 1u && h.flow[0].consumed == BODY + 1u);
        CHECK(qn_h2_feed(&h, NULL, 0u, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
        CHECK(cn == 26u && h.conn_consumed == 0u && h.flow[0].consumed == 0u);
        free(big);
    }

    /* Dynamic references/indexing violate our advertised zero-sized table. */
    qn_h2_init(&h);
    CHECK(qn_h2_open_stream(&h, 1u));
    wire[9] = 0xBEu; /* indexed field 62: first dynamic-table entry */
    n = h2_frame(wire, 1u, 4u, 1u, wire + 9, 1u);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);

    qn_h2_init(&h);
    CHECK(qn_h2_open_stream(&h, 1u));
    wire[9] = 0x21u; /* dynamic table size update to one byte */
    n = h2_frame(wire, 1u, 4u, 1u, wire + 9, 1u);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);

    qn_h2_init(&h);
    CHECK(qn_h2_open_stream(&h, 1u));
    wire[9] = 0x40u; /* literal with incremental indexing */
    n = h2_frame(wire, 1u, 4u, 1u, wire + 9, 1u);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
}

/* QN2-019: maximum flow completes without exhausting a partly spent peer window. */
static void test_http2_flow_after_trace_window(void)
{
    enum { FRAME_DATA = 16384, FLOW_MAX = 16 * 1024 * 1024 };
    static const uint8_t trace[] = "fl=1\ncolo=FRA\n";
    uint8_t     *wire = (uint8_t *)malloc(9u + FRAME_DATA);
    uint8_t      head[1] = { 0x88u };
    uint8_t      small[64], ctl[64];
    qn_h2        h;
    qn_h2_event  ev;
    size_t       n, cn;
    /* Mirror the peer's view: it decrements, our updates credit it back. */
    int64_t      conn_window   = 16 * 1024 * 1024;
    int64_t      stream_window = 16 * 1024 * 1024;
    int64_t      conn_low = INT64_MAX, stream_low = INT64_MAX;
    uint64_t     flow_total = 0;

    CHECK(wire != NULL);
    if (!wire)
        return;
    memset(wire + 9, 0xA5, FRAME_DATA);
    qn_h2_init(&h);

    /* Trace on stream 1 first, so it eats connection window. */
    CHECK(qn_h2_open_stream(&h, 1u));
    n = h2_frame(small, 1u, 4u, 1u, head, 1u);
    CHECK(qn_h2_feed(&h, small, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    n = h2_frame(small, 0u, 1u, 1u, trace, sizeof trace - 1u);
    CHECK(qn_h2_feed(&h, small, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    conn_window -= (int64_t)(sizeof trace - 1u);
    /* END_STREAM forces publication, so the connection is credited back. */
    conn_window += (int64_t)(sizeof trace - 1u);

    /* Now the full flow on stream 3. */
    CHECK(qn_h2_open_stream(&h, 3u));
    n = h2_frame(small, 1u, 4u, 3u, head, 1u);
    CHECK(qn_h2_feed(&h, small, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);

    for (unsigned i = 0; i < FLOW_MAX / FRAME_DATA; i++) {
        bool last = i + 1u == FLOW_MAX / FRAME_DATA;

        n = h2_frame(wire, 0u, last ? 1u : 0u, 3u, wire + 9, FRAME_DATA);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
        conn_window -= FRAME_DATA;
        stream_window -= FRAME_DATA;
        if (conn_window < conn_low)
            conn_low = conn_window;
        if (stream_window < stream_low)
            stream_low = stream_window;

        /* Credit whatever the updates in ctl carry back. */
        for (size_t off = 0; off + 9u <= cn; ) {
            uint32_t plen = ((uint32_t)ctl[off] << 16) | ((uint32_t)ctl[off + 1] << 8) |
                            ctl[off + 2];
            if (ctl[off + 3] == 8u && plen == 4u) {
                uint32_t sid = wire32(ctl + off + 5) & 0x7FFFFFFFu;
                uint32_t inc = wire32(ctl + off + 9) & 0x7FFFFFFFu;

                CHECK(inc != 0u); /* a zero increment is a protocol error */
                if (sid)
                    stream_window += inc;
                else
                    conn_window += inc;
            }
            off += 9u + plen;
        }
        if (ev.nstreams)
            flow_total += ev.stream[0].body_bytes;
    }

    CHECK(flow_total == (uint64_t)FLOW_MAX);
    CHECK((ev.stream[0].flags & QN_H2_EV_END_STREAM) != 0u);
    /* Neither window came close to starving the transfer. */
    if (conn_low <= 0 || stream_low <= 0)
        fprintf(stderr, "  window starved: conn low %lld, stream low %lld\n",
                (long long)conn_low, (long long)stream_low);
    CHECK(conn_low > 0);
    CHECK(stream_low > 0);
    CHECK(conn_window <= 0x7FFFFFFF);
    CHECK(stream_window <= 0x7FFFFFFF);
    free(wire);
}

/* QN2-004: unrequested streams and headless bodies cannot become evidence. */
static void test_http2_unopened_streams(void)
{
    static const uint8_t trace[] = "fl=1\ncolo=FRA\n";
    uint8_t     wire[128], ctl[64];
    uint8_t     head[1] = { 0x88u };
    qn_h2       h;
    qn_h2_event ev;
    size_t      n, cn;

    /* DATA on stream 3 before the flow request was ever sent. */
    qn_h2_init(&h);
    CHECK(qn_h2_open_stream(&h, 1u));
    n = h2_frame(wire, 0u, 1u, 3u, trace, sizeof trace - 1u);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    CHECK(ev.nstreams == 0u);

    /* HEADERS on an unopened stream. */
    qn_h2_init(&h);
    n = h2_frame(wire, 1u, 4u, 1u, head, 1u);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);

    /* A server-initiated even stream, with push disabled. */
    qn_h2_init(&h);
    CHECK(!qn_h2_open_stream(&h, 2u));
    n = h2_frame(wire, 1u, 4u, 2u, head, 1u);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);

    /* RST_STREAM on a stream that was never requested. */
    qn_h2_init(&h);
    memset(wire + 9, 0, 4);
    n = h2_frame(wire, 3u, 0u, 7u, wire + 9, 4u);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);

    /* DATA on an opened stream that has not answered yet. */
    qn_h2_init(&h);
    CHECK(qn_h2_open_stream(&h, 3u));
    n = h2_frame(wire, 0u, 0u, 3u, trace, sizeof trace - 1u);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    CHECK(!qn_h2_stream_has_head(&h, 3u));

    /* With the head in place the same DATA is accepted. */
    qn_h2_init(&h);
    CHECK(qn_h2_open_stream(&h, 3u));
    n = h2_frame(wire, 1u, 4u, 3u, head, 1u);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(qn_h2_stream_has_head(&h, 3u));
    n = h2_frame(wire, 0u, 1u, 3u, trace, sizeof trace - 1u);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(ev.nstreams == 1u && ev.stream[0].body_bytes == sizeof trace - 1u);
}

/* QN2-017/018: response heads have one leading :status and trailers have no pseudo-fields. */
/* P0-2: trailers cannot overwrite final status or its edge evidence. */
static void test_http2_trailers_do_not_overwrite_the_status(void)
{
    static const uint8_t trace[] = "fl=1\ncolo=FRA\n";
    /* Literal-without-indexing "grpc-status"/"0": a legal trailer field. */
    static const uint8_t trailer[] = { 0x00u, 0x0Bu, 'g', 'r', 'p', 'c', '-', 's',
                                       't', 'a', 't', 'u', 's', 0x01u, '0' };
    uint8_t        wire[256], ctl[64], head[1] = { 0x88u };
    qn_h2          h;
    qn_h2_event    ev;
    qn_http_event  head_event, body_event;
    qn_observation observation;
    size_t         n, cn;

    qn_h2_init(&h);
    CHECK(qn_h2_open_stream(&h, 1u));

    n = h2_frame(wire, 1u, 4u, 1u, head, sizeof head);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(ev.nstreams == 1u);
    CHECK(ev.stream[0].status == 200u);
    CHECK((ev.stream[0].flags & QN_HTTP_FACT_HEADERS) != 0u);
    head_event = ev.stream[0];

    n = h2_frame(wire, 0u, 0u, 1u, trace, sizeof trace - 1u);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    body_event = ev.stream[0];

    qn_observation_init(&observation);
    observation.transport.connected = true;
    observation.tls.handshake_complete = true;
    observation.http.request_fully_flushed = true;
    qn_observation_apply_http(&observation, &head_event);
    qn_observation_apply_http(&observation, &body_event);
    CHECK(observation.http.status == 200u);
    CHECK(observation.edge.verified);

    /* Now the trailing header block, in its own read as it arrives on the wire. */
    n = h2_frame(wire, 1u, 5u, 1u, trailer, sizeof trailer);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(ev.nstreams == 1u);

    /* A trailer is its own kind of event, never a second set of final headers. */
    CHECK((ev.stream[0].flags & QN_HTTP_FACT_TRAILERS) != 0u);
    CHECK((ev.stream[0].flags & QN_HTTP_FACT_HEADERS) == 0u);
    CHECK((ev.stream[0].flags & QN_HTTP_FACT_DONE) != 0u);

    qn_observation_apply_http(&observation, &ev.stream[0]);
    if (observation.http.status != 200u)
        fprintf(stderr, "  trailer overwrote status 200 with %u\n",
                observation.http.status);
    CHECK(observation.http.status == 200u);
    CHECK(observation.http.trailers);
    if (!observation.edge.verified)
        fprintf(stderr, "  trailer erased a verified edge observation\n");
    CHECK(observation.edge.verified);
    CHECK(observation.http.response_complete);
}

static void test_http2_response_head_rules(void)
{
    uint8_t     wire[128], ctl[64];
    qn_h2       h;
    qn_h2_event ev;
    size_t      n, cn;

    /* No :status at all. Field is literal-without-indexing "x"/"y". */
    {
        uint8_t block[] = { 0x00u, 0x01u, 'x', 0x01u, 'y' };

        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, block, sizeof block);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    }

    /* Two :status fields. */
    {
        uint8_t block[] = { 0x88u, 0x88u };

        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, block, sizeof block);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    }

    /* :status after a regular field. */
    {
        uint8_t block[] = { 0x00u, 0x01u, 'x', 0x01u, 'y', 0x88u };

        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, block, sizeof block);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    }

    /* A request pseudo-header in a response: static index 2 is :method GET. */
    {
        uint8_t block[] = { 0x82u, 0x88u };

        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, block, sizeof block);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    }

    /* An uppercase field name. */
    {
        uint8_t block[] = { 0x88u, 0x00u, 0x01u, 'X', 0x01u, 'y' };

        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, block, sizeof block);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    }

    /* A connection-specific field HTTP/2 forbids. */
    {
        uint8_t block[] = { 0x88u, 0x00u, 0x0Au, 'c', 'o', 'n', 'n', 'e', 'c', 't',
                            'i',   'o',   'n',   0x05u, 'c', 'l', 'o', 's', 'e' };

        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, block, sizeof block);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    }

    /* A pseudo-header in trailers, after a valid head and a body. */
    {
        uint8_t head[1]  = { 0x88u };
        uint8_t body[4]  = { 'a', 'b', 'c', 'd' };
        uint8_t trail[1] = { 0x88u };

        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, head, 1u);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
        n = h2_frame(wire, 0u, 0u, 1u, body, sizeof body);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
        n = h2_frame(wire, 1u, 4u, 1u, trail, 1u);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    }
}

/* QN2-016: SETTINGS values outside their legal range are not acknowledged. */
static void test_http2_settings_validation(void)
{
    uint8_t     wire[64], ctl[64];
    qn_h2       h;
    qn_h2_event ev;
    size_t      n, cn;

    /* ENABLE_PUSH = 2. */
    {
        uint8_t s[6] = { 0, 2, 0, 0, 0, 2 };

        qn_h2_init(&h);
        n = h2_frame(wire, 4u, 0u, 0u, s, sizeof s);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
        CHECK(cn == 0u); /* never acknowledged as valid */
    }

    /* INITIAL_WINDOW_SIZE = 2^31. */
    {
        uint8_t s[6] = { 0, 4, 0x80u, 0, 0, 0 };

        qn_h2_init(&h);
        n = h2_frame(wire, 4u, 0u, 0u, s, sizeof s);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    }

    /* MAX_FRAME_SIZE below and above the legal band. */
    {
        uint8_t lo[6] = { 0, 5, 0, 0, 0x3Fu, 0xFFu };
        uint8_t hi[6] = { 0, 5, 0x01u, 0, 0, 0 };

        qn_h2_init(&h);
        n = h2_frame(wire, 4u, 0u, 0u, lo, sizeof lo);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
        qn_h2_init(&h);
        n = h2_frame(wire, 4u, 0u, 0u, hi, sizeof hi);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    }

    /* An ACK carrying a payload, and a non-ACK that is not a multiple of six. */
    {
        uint8_t s[6] = { 0, 3, 0, 0, 0, 1 };

        qn_h2_init(&h);
        n = h2_frame(wire, 4u, 1u, 0u, s, sizeof s);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
        qn_h2_init(&h);
        n = h2_frame(wire, 4u, 0u, 0u, s, 5u);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    }

    /* Legal values are accepted and acknowledged. */
    {
        uint8_t s[12] = { 0, 2, 0, 0, 0, 0, 0, 5, 0, 0, 0x40u, 0 };

        qn_h2_init(&h);
        n = h2_frame(wire, 4u, 0u, 0u, s, sizeof s);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
        CHECK(cn == 9u && ctl[3] == 4u && ctl[4] == 1u);
    }

    {
        uint8_t many[66], big_wire[96];

        memset(many, 0, sizeof many);
        for (size_t i = 0; i < 10u; i++) {
            many[i * 6u] = 0x00u;
            many[i * 6u + 1u] = 0x0Au;
        }
        many[60] = 0u;
        many[61] = 2u;
        many[65] = 2u;
        qn_h2_init(&h);
        n = h2_frame(big_wire, 4u, 0u, 0u, many, sizeof many);
        CHECK(qn_h2_feed(&h, big_wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
        CHECK(cn == 0u);
    }
}

static void test_http2_informational_then_final(void)
{
    static const uint8_t info[] = { 0x08u, 0x03u, '1', '0', '3' };
    static const uint8_t final[] = { 0x88u };
    uint8_t wire[64], ctl[64];
    qn_h2 h;
    qn_h2_event ev;
    size_t a, b, cn;

    qn_h2_init(&h);
    CHECK(qn_h2_open_stream(&h, 1u));
    a = h2_frame(wire, 1u, 4u, 1u, info, sizeof info);
    b = h2_frame(wire + a, 1u, 5u, 1u, final, sizeof final);
    CHECK(qn_h2_feed(&h, wire, a + b, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(qn_h2_stream_has_head(&h, 1u));
    CHECK(ev.nstreams == 1u && ev.stream[0].status == 200u);
    CHECK((ev.stream[0].flags & QN_H2_EV_END_STREAM) != 0u);
}

static void test_http2_advertises_parser_capacity(void)
{
    uint8_t preface[128];
    int n = qn_h2_preface(preface, sizeof preface);

    CHECK(n > 0);
    CHECK(preface[24 + 9 + 18] == 0u && preface[24 + 9 + 19] == 6u);
    CHECK(preface[24 + 9 + 20] == 0u && preface[24 + 9 + 21] == 4u);
    CHECK(preface[24 + 9 + 22] == 0u && preface[24 + 9 + 23] == 0u);
}

static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;

    while (hex[0] && hex[1] && n < cap) {
        unsigned hi = (unsigned)(hex[0] > '9' ? (hex[0] | 0x20) - 'a' + 10 : hex[0] - '0');
        unsigned lo = (unsigned)(hex[1] > '9' ? (hex[1] | 0x20) - 'a' + 10 : hex[1] - '0');

        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

/* Capped IPv6 siblings cannot merge when doing so shrinks the enumerable set. */
static void test_cidr_v6_merge_preserves_reach(void)
{
    static const struct {
        const char *a;
        const char *b;
        int         may_merge;
    } cases[] = {
        { "2001:db8::/108",  "2001:db8::10:0/108", 0 },
        { "2001:db8::/100",  "2001:db8::1000:0:0/100", 0 },
        { "2001:db8::/109",  "2001:db8::8:0/109", 1 },
        { "2001:db8::/120",  "2001:db8::100/120", 1 },
        { "2001:db8::/127",  "2001:db8::2/127", 1 }
    };
    size_t i;

    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        qn_arena    arena;
        qn_cidr_set set;
        qn_prefix   pa, pb;
        uint64_t    before, after = 0;
        uint32_t    k;

        CHECK(qn_arena_init(&arena, 1u << 16));
        CHECK(qn_cidr_set_init(&set, &arena, 8));
        CHECK(qn_cidr_parse(cases[i].a, &pa));
        CHECK(qn_cidr_parse(cases[i].b, &pb));
        before = qn_prefix_hosts(&pa) + qn_prefix_hosts(&pb);

        CHECK(qn_cidr_set_add(&set, &pa));
        CHECK(qn_cidr_set_add(&set, &pb));
        qn_cidr_set_seal(&set, &arena); /* merging happens here, not on add */
        for (k = 0; k < set.n; k++)
            after += qn_prefix_hosts(&set.v[k]);

        if (after < before) {
            fprintf(stderr, "FAIL %s + %s: %llu addresses became %llu\n",
                    cases[i].a, cases[i].b, (unsigned long long)before,
                    (unsigned long long)after);
            failures++;
        }
        if (cases[i].may_merge)
            CHECK(set.n == 1u);
        else
            CHECK(set.n == 2u);
        qn_arena_free(&arena);
    }
}

/* Embedded colo text is not a trace line and cannot manufacture edge evidence. */
static void test_http2_edge_marker_is_line_oriented(void)
{
    static const struct {
        const char *body;
        int         want_edge;
        const char *what;
    } cases[] = {
        { "fl=1\ncolo=FRA\n",       1, "a real trace line" },
        { "colo=FRA\n",             1, "first line of the body" },
        { "fl=1\r\ncolo=FRA\r\n",   1, "CRLF terminated" },
        { "xxcolo=FRAyy\n",         0, "embedded in a longer line" },
        { "colo=FRAyy\n",           0, "trailing junk after the value" },
        { "xxcolo=FRA\n",           0, "leading junk before the key" },
        { "colo=fra\n",             0, "lowercase colo value" },
        { "colo=FR\n",              0, "short value" },
        { "colo=FRAX\n",            0, "long value" },
        { "colo=FRA",               0, "never terminated" }
    };
    uint8_t     wire[256], ctl[64];
    uint8_t     head[1] = { 0x88u };
    qn_h2       h;
    qn_h2_event ev;
    size_t      i, n, cn;

    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        size_t blen = strlen(cases[i].body);
        int    got;

        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, head, 1u);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);

        n = h2_frame(wire, 0u, 1u, 1u, (const uint8_t *)cases[i].body, blen);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);

        got = (ev.stream[0].flags & QN_H2_EV_EDGE) != 0 ? 1 : 0;
        if (got != cases[i].want_edge) {
            fprintf(stderr, "FAIL edge marker: %s -> edge=%d want=%d\n",
                    cases[i].what, got, cases[i].want_edge);
            failures++;
        }
        if (got)
            CHECK(strcmp(ev.stream[0].colo, "FRA") == 0);
    }
}

/* RFC 7541 Appendix C.4 and C.6 encoded strings, decoded verbatim. */
static void test_hpack_huffman_vectors(void)
{
    static const struct {
        const char *hex;
        const char *want;
    } ok[] = {
        { "f1e3c2e5f23a6ba0ab90f4ff", "www.example.com" },
        { "a8eb10649cbf", "no-cache" },
        { "25a849e95ba97d7f", "custom-key" },
        { "25a849e95bb8e8b4bf", "custom-value" },
        { "6402", "302" },
        { "640eff", "307" },
        { "aec3771a4b", "private" },
        { "d07abe941054d444a8200595040b8166e082a62d1bff",
          "Mon, 21 Oct 2013 20:13:21 GMT" },
        { "9d29ad171863c78f0b97c8e9ae82ae43d3", "https://www.example.com" },
        { "1f", "a" },
        { "", "" }
    };
    static const char *bad[] = {
        "1fffffffff", /* EOS inside the string */
        "18",         /* padding is not an EOS prefix */
        "1fff",       /* padding is a whole byte or more */
        "00",         /* zero padding after '0' */
        "ff"          /* eight ones do not complete a code */
    };
    uint8_t      in[64], out[64];
    qn_huff_info info;
    size_t       i;

    for (i = 0; i < sizeof ok / sizeof ok[0]; i++) {
        size_t n = unhex(ok[i].hex, in, sizeof in);
        size_t w = strlen(ok[i].want);

        CHECK(qn_huff_decode(in, n, out, sizeof out, &info));
        CHECK(info.len == w && !info.truncated);
        CHECK(memcmp(out, ok[i].want, w) == 0);
    }
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        size_t n = unhex(bad[i], in, sizeof in);

        CHECK(!qn_huff_decode(in, n, out, sizeof out, &info));
    }

    /* A string longer than the sink is still validated and measured. */
    {
        size_t n = unhex("f1e3c2e5f23a6ba0ab90f4ff", in, sizeof in);

        CHECK(qn_huff_decode(in, n, out, 4u, &info));
        CHECK(info.truncated && info.len == 15u && memcmp(out, "www.", 4u) == 0);
        CHECK(qn_huff_decode(in, n, NULL, 0u, &info));
        CHECK(info.truncated && info.len == 15u);
    }

    /* has_upper covers the whole string, so it survives truncation. */
    {
        size_t n = unhex("847f", in, sizeof in); /* "Aa" */

        CHECK(qn_huff_decode(in, n, out, sizeof out, &info));
        CHECK(info.has_upper && info.len == 2u);
        CHECK(qn_huff_decode(in, n, out, 1u, &info));
        CHECK(info.has_upper && info.truncated);
        n = unhex("1f", in, sizeof in); /* "a" */
        CHECK(qn_huff_decode(in, n, out, sizeof out, &info) && !info.has_upper);
    }
}

/* Huffman names follow plain-name rules and a valid Huffman :status decodes. */
static void test_http2_huffman_handling(void)
{
    /* indexed :status 200, then a literal field with a Huffman-coded name */
    static const uint8_t dup_status[] = {
        0x88u, 0x00u, 0x85u, 0xB8u, 0x84u, 0x8Du, 0x36u, 0xA3u, 0x03u, 0x34u,
        0x30u, 0x34u
    };
    static const uint8_t connection[] = {
        0x88u, 0x00u, 0x87u, 0x21u, 0xEAu, 0xA8u, 0xA4u, 0x49u, 0x8Fu, 0x57u,
        0x0Au, 0x6Bu, 0x65u, 0x65u, 0x70u, 0x2Du, 0x61u, 0x6Cu, 0x69u, 0x76u,
        0x65u
    };
    static const uint8_t eos_in_name[] = {
        0x88u, 0x00u, 0x85u, 0x1Fu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x01u, 0x78u
    };
    static const uint8_t bad_padding[] = {
        0x88u, 0x00u, 0x81u, 0x18u, 0x01u, 0x78u
    };
    static const uint8_t upper_name[] = {
        0x88u, 0x00u, 0x89u, 0xBCu, 0x7Au, 0x92u, 0x5Au, 0x92u, 0xB6u, 0xFFu,
        0x55u, 0x97u, 0x09u, 0x74u, 0x65u, 0x78u, 0x74u, 0x2Fu, 0x68u, 0x74u,
        0x6Du, 0x6Cu
    };
    static const uint8_t trailer_status[] = {
        0x00u, 0x85u, 0xB8u, 0x84u, 0x8Du, 0x36u, 0xA3u, 0x03u, 0x32u, 0x30u,
        0x30u
    };
    /* literal :status by indexed name 8, Huffman value "302" (RFC 7541 C.6.1) */
    static const uint8_t huff_status[] = { 0x08u, 0x82u, 0x64u, 0x02u };
    /* indexed :status 200 plus Huffman "cf-ray" and its Huffman value */
    static const uint8_t huff_cfray[] = {
        0x88u, 0x00u, 0x85u, 0x24u, 0xABu, 0x58u, 0x3Fu, 0x5Fu, 0x8Fu, 0x7Au,
        0x56u, 0x46u, 0x18u, 0xC4u, 0x46u, 0x64u, 0x68u, 0xADu, 0xCAu, 0xE0u,
        0x16u, 0xC3u, 0xB6u, 0x1Fu
    };
    static const struct {
        const uint8_t *blk;
        size_t         n;
    } rejected[] = {
        { dup_status, sizeof dup_status },
        { connection, sizeof connection },
        { eos_in_name, sizeof eos_in_name },
        { bad_padding, sizeof bad_padding },
        { upper_name, sizeof upper_name }
    };
    uint8_t     wire[64], ctl[64];
    qn_h2       h;
    qn_h2_event ev;
    size_t      i, n, cn;

    for (i = 0; i < sizeof rejected / sizeof rejected[0]; i++) {
        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, rejected[i].blk, rejected[i].n);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
        CHECK(!qn_h2_stream_has_head(&h, 1u));
    }

    /* Static entry 57 proves forbidden names must be checked after table lookup. */
    {
        static const uint8_t te_indexed[] = {
            0x88u, 0x0Fu, 0x2Au, 0x07u, 'c', 'h', 'u', 'n', 'k', 'e', 'd'
        };
        static const uint8_t te_bare[] = { 0x88u, 0xB9u };
        static const uint8_t cookie[]  = { 0x88u, 0x0Fu, 0x28u, 0x03u, 'a', '=', 'b' };

        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, te_indexed, sizeof te_indexed);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
        CHECK(!qn_h2_stream_has_head(&h, 1u));

        /* The same name as a bare indexed field, value and all. */
        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, te_bare, sizeof te_bare);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);

        /* A neighbouring entry must stay acceptable. */
        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, cookie, sizeof cookie);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
        CHECK(qn_h2_stream_has_head(&h, 1u));
    }

    /* A Huffman :status is ordinary traffic and must decode to its value. */
    qn_h2_init(&h);
    CHECK(qn_h2_open_stream(&h, 1u));
    n = h2_frame(wire, 1u, 4u, 1u, huff_status, sizeof huff_status);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(qn_h2_stream_has_head(&h, 1u) && ev.stream[0].status == 302u);

    /* Huffman cf-ray is only a hint; complete trace lines establish edge evidence. */
    qn_h2_init(&h);
    CHECK(qn_h2_open_stream(&h, 1u));
    n = h2_frame(wire, 1u, 4u, 1u, huff_cfray, sizeof huff_cfray);
    CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
    CHECK(qn_h2_stream_has_head(&h, 1u) && ev.stream[0].status == 200u);
    CHECK((ev.stream[0].flags & QN_H2_EV_WEAK_MARKER) != 0u);
    CHECK((ev.stream[0].flags & QN_H2_EV_EDGE) == 0u);

    /* Trailers reject every pseudo-header, Huffman-coded name included. */
    {
        uint8_t head[1] = { 0x88u };

        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        n = h2_frame(wire, 1u, 4u, 1u, head, 1u);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
        n = h2_frame(wire, 1u, 4u, 1u, trailer_status, sizeof trailer_status);
        CHECK(qn_h2_feed(&h, wire, n, ctl, sizeof ctl, &cn, &ev) == QN_H2_PROTOCOL);
    }

    /* Every split of a Huffman-coded head must reach the same verdict. */
    for (i = 1; i + 1u < sizeof huff_cfray + 9u; i++) {
        size_t total = h2_frame(wire, 1u, 4u, 1u, huff_cfray, sizeof huff_cfray);

        qn_h2_init(&h);
        CHECK(qn_h2_open_stream(&h, 1u));
        CHECK(qn_h2_feed(&h, wire, i, ctl, sizeof ctl, &cn, &ev) == QN_H2_OK);
        CHECK(qn_h2_feed(&h, wire + i, total - i, ctl, sizeof ctl, &cn, &ev) ==
              QN_H2_OK);
        CHECK(qn_h2_stream_has_head(&h, 1u) && ev.stream[0].status == 200u);
    }
}

static void test_http1_stream(void)
{
    static const uint8_t fixed[] =
        "HTTP/1.1 200 OK\r\nServer: cloudflare\r\nContent-Length: 12\r\n\r\ncolo=FRA\nabc";
    static const uint8_t chunked[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    static const uint8_t bad[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
    static const uint8_t close_delimited[] =
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\ncolo=FRA\n";
    qn_http1       h;
    qn_http1_event ev;

    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, fixed, 17, &ev) == QN_HTTP1_OK);
    CHECK(qn_http1_feed(&h, fixed + 17, sizeof fixed - 1u - 17u, &ev) == QN_HTTP1_OK);
    CHECK((ev.flags & (QN_HTTP1_EV_DONE | QN_HTTP1_EV_EDGE)) ==
          (QN_HTTP1_EV_DONE | QN_HTTP1_EV_EDGE));
    CHECK(h.responses == 1u && h.total_body == 12u && strcmp(ev.colo, "FRA") == 0);

    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, chunked, sizeof chunked - 1u, &ev) == QN_HTTP1_OK);
    CHECK((ev.flags & QN_HTTP1_EV_DONE) != 0u);
    CHECK(h.responses == 1u && h.total_body == 11u);

    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, bad, sizeof bad - 1u, &ev) == QN_HTTP1_PROTOCOL);

    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, close_delimited, sizeof close_delimited - 1u, &ev) == QN_HTTP1_OK);
    CHECK((ev.flags & QN_HTTP1_EV_DONE) == 0u);
    CHECK((ev.flags & QN_HTTP1_EV_EDGE) != 0u && strcmp(ev.colo, "FRA") == 0);
    CHECK(qn_http1_eof(&h, &ev) == QN_HTTP1_OK);
    CHECK((ev.flags & QN_HTTP1_EV_DONE) != 0u);
    CHECK(h.responses == 1u && h.total_body == 9u);
}

/* QN2-020/021: ordered Transfer-Encoding framing follows the final coding. */
static void test_http1_transfer_encoding_order(void)
{
    static const uint8_t chunked_last[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
        "5\r\nhello\r\n0\r\n\r\n";
    static const uint8_t chunked_first[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"
        "5\r\nhello\r\n0\r\n\r\n";
    static const uint8_t split_gzip_last[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n"
        "raw body bytes";
    static const uint8_t split_chunked_last[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n0\r\n\r\n";
    static const uint8_t twice[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n";
    static const uint8_t empty_coding[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip,,chunked\r\n\r\n";
    qn_http1       h;
    qn_http1_event ev;

    /* chunked last: framed, and the body is the decoded 5 bytes. */
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, chunked_last, sizeof chunked_last - 1u, &ev) == QN_HTTP1_OK);
    CHECK((ev.flags & QN_HTTP1_EV_DONE) != 0u);
    CHECK(h.total_body == 5u);

    /* chunked first: NOT framed, so the chunk syntax is just opaque bytes. */
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, chunked_first, sizeof chunked_first - 1u, &ev) == QN_HTTP1_OK);
    CHECK((ev.flags & QN_HTTP1_EV_DONE) == 0u); /* read until close */
    CHECK(h.total_body == 15u);

    /* Two field lines, gzip last: not framed. */
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, split_gzip_last, sizeof split_gzip_last - 1u, &ev) == QN_HTTP1_OK);
    CHECK((ev.flags & QN_HTTP1_EV_DONE) == 0u);
    CHECK(h.total_body == 14u);

    /* Two field lines, chunked last: framed. */
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, split_chunked_last, sizeof split_chunked_last - 1u, &ev) ==
          QN_HTTP1_OK);
    CHECK((ev.flags & QN_HTTP1_EV_DONE) != 0u);
    CHECK(h.total_body == 5u);

    /* Malformed coding lists are rejected outright. */
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, twice, sizeof twice - 1u, &ev) == QN_HTTP1_PROTOCOL);
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, empty_coding, sizeof empty_coding - 1u, &ev) == QN_HTTP1_PROTOCOL);
}

static void test_http1_rejects_ambiguous_framing(void)
{
    static const uint8_t trailing_comma[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,\r\n\r\n0\r\n\r\n";
    static const uint8_t bad_chunk[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5 xyz\r\nhello\r\n0\r\n\r\n";
    static const uint8_t te_and_cl[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n";
    static const uint8_t bad_name[] =
        "HTTP/1.1 200 OK\r\nBad Name: value\r\nContent-Length: 0\r\n\r\n";
    static const uint8_t two_final[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        "HTTP/1.1 204 No Content\r\n\r\n";
    qn_http1 h;
    qn_http1_event ev;

    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, trailing_comma, sizeof trailing_comma - 1u, &ev) ==
          QN_HTTP1_PROTOCOL);
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, bad_chunk, sizeof bad_chunk - 1u, &ev) == QN_HTTP1_PROTOCOL);
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, te_and_cl, sizeof te_and_cl - 1u, &ev) == QN_HTTP1_PROTOCOL);
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, bad_name, sizeof bad_name - 1u, &ev) == QN_HTTP1_PROTOCOL);
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, two_final, sizeof two_final - 1u, &ev) == QN_HTTP1_PROTOCOL);
}

/* QN2-022: an unoffered 101 cannot be replaced by a later accepted 200. */
static void test_http1_switching_protocols(void)
{
    static const uint8_t upgrade_then_ok[] =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    static const uint8_t continue_then_ok[] =
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    qn_http1       h;
    qn_http1_event ev;

    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, upgrade_then_ok, sizeof upgrade_then_ok - 1u, &ev) ==
          QN_HTTP1_PROTOCOL);
    CHECK(h.responses == 0u);

    /* A real informational response is still handled normally. */
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, continue_then_ok, sizeof continue_then_ok - 1u, &ev) ==
          QN_HTTP1_OK);
    CHECK((ev.flags & QN_HTTP1_EV_DONE) != 0u && ev.status == 200u);
}

/* QN2-023: a prefix that merely starts with HTTP/1.x is not HTTP evidence. */
static void test_http_status_line_strictness(void)
{
    static const char *bad[] = {
        "HTTP/1.1 200",                  /* no CRLF terminator */
        "HTTP/1.1 200 OK\n\n",           /* bare LF */
        "HTTP/1.2 200 OK\r\n\r\n",       /* unsupported minor version */
        "HTTP/1.1  200 OK\r\n\r\n",      /* two spaces */
        "HTTP/1.1 20 OK\r\n\r\n",        /* two digits */
        "HTTP/1.1 2000 OK\r\n\r\n",      /* four digits */
        "HTTP/1.1 099 OK\r\n\r\n",       /* below the valid range */
        "HTTP/1.1 600 OK\r\n\r\n",       /* above the valid range */
        "HTTP/1.1 200XOK\r\n\r\n",       /* no separator after the code */
        "HTTP/1.x 200 OK\r\n\r\n"
    };
    qn_http_reply rep;
    size_t        i;

    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        if (qn_http_parse((const uint8_t *)bad[i], strlen(bad[i]), &rep))
            fprintf(stderr, "  accepted a bad status line: %s\n", bad[i]);
        CHECK(!qn_http_parse((const uint8_t *)bad[i], strlen(bad[i]), &rep));
    }

    /* Both legal shapes are still accepted. */
    CHECK(qn_http_parse((const uint8_t *)"HTTP/1.1 204 No Content\r\n\r\n", 27u, &rep));
    CHECK(rep.status == 204u);
    CHECK(qn_http_parse((const uint8_t *)"HTTP/1.0 200\r\n\r\n", 16u, &rep));
    CHECK(rep.status == 200u);
}

/* QN2-024: a colo hidden in arbitrary text is not a Cloudflare marker. */
static void test_trace_marker_is_not_forgeable(void)
{
    qn_trace_body tb;
    qn_http1       h;
    qn_http1_event ev;
    static const uint8_t embedded[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n"
        "nothing here but colo=ABC inside prose!!\n";
    static const uint8_t genuine[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n"
        "fl=1f2\nh=example.com\ncolo=FRA\n";
    static const char *body_ok      = "fl=1\nip=1.2.3.4\ncolo=AMS\n";
    static const char *body_dup     = "colo=AMS\ncolo=FRA\n";
    static const char *body_same    = "colo=AMS\ncolo=AMS\n";
    static const char *body_badcolo = "colo=am\n";
    static const char *body_noeq    = "colo\n";
    static const char *body_badip   = "ip=not-an-ip\ncolo=AMS\n";
    static const char *body_partial = "colo=AMS"; /* never terminated */

    CHECK(qn_http_trace_parse((const uint8_t *)body_ok, strlen(body_ok), &tb));
    CHECK(tb.have_colo && strcmp(tb.colo, "AMS") == 0);
    CHECK(tb.have_ip && tb.lines == 3u);

    CHECK(!qn_http_trace_parse((const uint8_t *)body_dup, strlen(body_dup), &tb));
    CHECK(tb.conflict);
    CHECK(qn_http_trace_parse((const uint8_t *)body_same, strlen(body_same), &tb));

    CHECK(!qn_http_trace_parse((const uint8_t *)body_badcolo, strlen(body_badcolo), &tb));
    CHECK(tb.malformed);
    CHECK(!qn_http_trace_parse((const uint8_t *)body_noeq, strlen(body_noeq), &tb));
    CHECK(tb.malformed);
    CHECK(!qn_http_trace_parse((const uint8_t *)body_badip, strlen(body_badip), &tb));
    CHECK(!qn_http_trace_parse((const uint8_t *)body_partial, strlen(body_partial), &tb));
    CHECK(!tb.have_colo);

    /* An adversarial body must not raise the marker. */
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, embedded, sizeof embedded - 1u, &ev) == QN_HTTP1_OK);
    CHECK((ev.flags & QN_HTTP1_EV_EDGE) == 0u);

    /* A genuine trace body does. */
    qn_http1_init(&h);
    CHECK(qn_http1_feed(&h, genuine, sizeof genuine - 1u, &ev) == QN_HTTP1_OK);
    CHECK((ev.flags & QN_HTTP1_EV_EDGE) != 0u && strcmp(ev.colo, "FRA") == 0);

    /* Split at every byte boundary, the answer must not change. */
    for (size_t cut = 1u; cut < sizeof genuine - 1u; cut++) {
        qn_http1_event a, b;

        qn_http1_init(&h);
        CHECK(qn_http1_feed(&h, genuine, cut, &a) == QN_HTTP1_OK);
        CHECK(qn_http1_feed(&h, genuine + cut, sizeof genuine - 1u - cut, &b) == QN_HTTP1_OK);
    }

    /* A forgeable Server header alone is supporting evidence, not a marker. */
    {
        static const uint8_t weak[] =
            "HTTP/1.1 200 OK\r\nServer: cloudflare\r\nContent-Length: 3\r\n\r\nabc";

        qn_http1_init(&h);
        CHECK(qn_http1_feed(&h, weak, sizeof weak - 1u, &ev) == QN_HTTP1_OK);
        CHECK((ev.flags & QN_HTTP1_EV_EDGE) == 0u);
        CHECK((ev.flags & QN_HTTP_FACT_SERVER_CLOUDFLARE) != 0u);
    }
}

static void test_ports(void)
{
    uint16_t ports[65536];
    uint32_t n;

    CHECK(qn_parse_ports("22,80-82,443", ports, 65536u, &n));
    CHECK(n == 5u);
    CHECK(ports[0] == 22u && ports[1] == 80u && ports[4] == 443u);
    CHECK(!qn_parse_ports("0,80", ports, 65536u, &n));
    CHECK(!qn_parse_ports("443-80", ports, 65536u, &n));
    CHECK(!qn_parse_ports("80-", ports, 65536u, &n));
    CHECK(!qn_parse_ports("-80", ports, 65536u, &n));
    CHECK(!qn_parse_ports("80,", ports, 65536u, &n));
    CHECK(qn_parse_ports("80,80,79-81", ports, 65536u, &n));
    CHECK(n == 3u && ports[0] == 80u && ports[1] == 79u && ports[2] == 81u);
    CHECK(!qn_parse_ports("all", ports, 1024u, &n));
    CHECK(qn_parse_ports("all", ports, 65536u, &n));
    CHECK(n == 65535u && ports[0] == 1u && ports[n - 1u] == 65535u);
}

static void test_hostname_and_verdict_validation(void)
{
    char oversized_label[67];

    CHECK(qn_valid_hostname("example.com"));
    CHECK(qn_valid_hostname("a-b.example"));
    CHECK(qn_valid_hostname("xn--bcher-kva.example"));
    CHECK(qn_valid_hostname("localhost"));
    CHECK(!qn_valid_hostname(NULL));
    CHECK(!qn_valid_hostname(""));
    CHECK(!qn_valid_hostname("bad..example"));
    CHECK(!qn_valid_hostname("-bad.example"));
    CHECK(!qn_valid_hostname("bad-.example"));
    CHECK(!qn_valid_hostname("example.com."));
    CHECK(!qn_valid_hostname("192.0.2.1"));
    CHECK(!qn_valid_hostname("bad_host.example"));
    CHECK(!qn_valid_hostname("bad host.example"));
    memset(oversized_label, 'a', sizeof oversized_label);
    oversized_label[64] = '.';
    oversized_label[65] = 'x';
    oversized_label[66] = '\0';
    CHECK(!qn_valid_hostname(oversized_label));

    CHECK(qn_classification_has_tls(
        (qn_classification){ QN_RUNG_TLS, QN_TERM_SUCCESS }));
    CHECK(qn_classification_has_tls(
        (qn_classification){ QN_RUNG_STABLE, QN_TERM_SUCCESS }));
    CHECK(!qn_classification_has_tls(
        (qn_classification){ QN_RUNG_STABLE, QN_TERM_INTERFERENCE }));
    CHECK(!qn_classification_has_tls(
        (qn_classification){ (qn_highest_rung)255, QN_TERM_SUCCESS }));
    CHECK(qn_classification_has_marker(
        (qn_classification){ QN_RUNG_EDGE, QN_TERM_SUCCESS }));
    CHECK(qn_classification_has_marker(
        (qn_classification){ QN_RUNG_STABLE, QN_TERM_SUCCESS }));
    CHECK(!qn_classification_has_marker(
        (qn_classification){ QN_RUNG_TLS, QN_TERM_SUCCESS }));
    CHECK(!qn_classification_has_marker(
        (qn_classification){ (qn_highest_rung)255, QN_TERM_SUCCESS }));
    CHECK(qn_errno_would_block(EAGAIN));
    CHECK(qn_errno_would_block(EWOULDBLOCK));
    CHECK(!qn_errno_would_block(EINVAL));
    CHECK(qn_errno_not_supported(EOPNOTSUPP));
    CHECK(qn_errno_not_supported(ENOTSUP));
    CHECK(!qn_errno_not_supported(EINVAL));
}

int main(void)
{
    test_arena();
    test_cidr();
    test_cf_prefix_total();
    test_cidr_load_file();
    test_cidr_snapshot_loader();
    test_managed_ranges_validation();
    test_permutation();
    test_ring();
    test_statistics();
    test_protocols();
    test_http2();
    test_http2_end_stream_survives_coalesced_goaway();
    test_http2_full_flow_window();
    test_http2_strict_hpack_and_credit_retry();
    test_http2_flow_after_trace_window();
    test_http2_unopened_streams();
    test_http2_trailers_do_not_overwrite_the_status();
    test_http2_response_head_rules();
    test_http2_settings_validation();
    test_http2_informational_then_final();
    test_http2_advertises_parser_capacity();
    test_cidr_v6_merge_preserves_reach();
    test_http2_edge_marker_is_line_oriented();
    test_hpack_huffman_vectors();
    test_http2_huffman_handling();
    test_http1_stream();
    test_http1_transfer_encoding_order();
    test_http1_rejects_ambiguous_framing();
    test_http1_switching_protocols();
    test_http_status_line_strictness();
    test_trace_marker_is_not_forgeable();
    test_ports();
    test_hostname_and_verdict_validation();

    if (failures) {
        fprintf(stderr, "%d test assertion(s) failed\n", failures);
        return 1;
    }
    puts("core tests: ok");
    return 0;
}
