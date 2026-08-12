#ifndef QANAT_CIDR_H
#define QANAT_CIDR_H

#include "qanat/arena.h"
#include "qanat/qanat.h"

typedef struct {
    qn_addr  net;
    uint8_t  bits;
    uint8_t  af;
    uint8_t  _pad[2];
    uint64_t count;
} qn_prefix;

/* Prefix sums map an index to an address without materialization. */
typedef struct {
    qn_prefix *v;
    uint32_t   n;
    uint32_t   cap;
    uint64_t  *cumsum;
    uint64_t   total;
    /* A BGP aggregate has no network or broadcast address; a LAN does. */
    bool skip_edges;
} qn_cidr_set;

/* What a range file actually yielded, so narrowing can never be silent. */
typedef struct {
    uint32_t accepted;
    uint32_t rejected;
    uint32_t overflow;
    uint32_t bad_line;
    char     bad_text[80];
    /* SHA-256 of the exact bytes parsed, so a run can name its own input. */
    uint8_t  digest[32];
    bool     have_digest;
    uint64_t bytes;
    uint8_t  snapshot_status;
    int      snapshot_errno;
} qn_cidr_report;

typedef enum {
    QN_SNAPSHOT_NONE = 0,
    QN_SNAPSHOT_OK,
    QN_SNAPSHOT_OPEN_FAILED,
    QN_SNAPSHOT_NOT_REGULAR,
    QN_SNAPSHOT_TOO_LARGE,
    QN_SNAPSHOT_SHORT_READ,
    QN_SNAPSHOT_GREW,
    QN_SNAPSHOT_METADATA_CHANGED,
    QN_SNAPSHOT_REPLACED,
    QN_SNAPSHOT_IO_FAILED,
    QN_SNAPSHOT_OVERFLOW
} qn_snapshot_status;

const char *qn_snapshot_status_str(qn_snapshot_status status);

bool qn_cidr_parse(const char *s, qn_prefix *out);

bool qn_cidr_set_init(qn_cidr_set *s, qn_arena *a, uint32_t cap);
void qn_cidr_set_skip_edges(qn_cidr_set *s, bool skip);
bool qn_cidr_set_add(qn_cidr_set *s, const qn_prefix *p);
bool qn_cidr_set_add_str(qn_cidr_set *s, const char *s_cidr);

/* False unless every non-comment line parsed and fitted; rep is always filled. */
bool     qn_cidr_set_load_file(qn_cidr_set *s, const char *path, qn_cidr_report *rep);
bool     qn_cidr_set_load_file_af(qn_cidr_set *s, const char *path, qn_cidr_report *rep,
                                  int required_af);
uint32_t qn_cidr_file_lines(const char *path);

/* Reads, validates, and parses one immutable byte snapshot. */
bool qn_cidr_set_load_snapshot(qn_cidr_set *s, qn_arena *a, const char *path,
                               qn_cidr_report *rep, int required_af);

#if defined(QN_CIDR_TESTING)
typedef enum {
    QN_SNAPSHOT_TEST_AFTER_FSTAT = 0,
    QN_SNAPSHOT_TEST_AFTER_READ,
    QN_SNAPSHOT_TEST_BEFORE_FINAL_FSTAT,
    QN_SNAPSHOT_TEST_BEFORE_PATH_STAT
} qn_snapshot_test_point;

typedef void (*qn_snapshot_test_hook)(qn_snapshot_test_point point, const char *path,
                                      void *ctx);

void qn_cidr_snapshot_set_test_hook(qn_snapshot_test_hook hook, void *ctx);
#endif

#define QN_CIDR_FILE_MAX (4u << 20)

void qn_cidr_set_seal(qn_cidr_set *s, qn_arena *a);
bool qn_cidr_set_nth(const qn_cidr_set *s, uint64_t idx, qn_addr *out);

/* The full span. Edge exclusion is the set's policy, not the prefix's. */
uint64_t qn_prefix_hosts(const qn_prefix *p);
uint64_t qn_prefix_usable(const qn_prefix *p, bool skip_edges);

#endif /* QANAT_CIDR_H */
