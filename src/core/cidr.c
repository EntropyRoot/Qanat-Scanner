#include "qanat/cidr.h"

#include "qanat/crypto.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define QN_V6_SPAN_CAP (1u << 20)

/* Every address in a routed aggregate is a host; .0 and .255 answer too. */
uint64_t qn_prefix_hosts(const qn_prefix *p)
{
    if (!p)
        return 0;
    if (p->af == AF_INET) {
        if (p->bits > 32u)
            return 0;
        if (p->bits >= 32)
            return 1;
        return (uint64_t)1u << (32 - p->bits);
    }
    if (p->af != AF_INET6 || p->bits > 128u)
        return 0;
    if (p->bits == 128u)
        return 1;
    if (128 - p->bits >= 20)
        return QN_V6_SPAN_CAP;
    return (uint64_t)1u << (128 - p->bits);
}

/* Only a LAN sweep wants the network and broadcast addresses left out. */
static bool prefix_has_edges(const qn_prefix *p)
{
    return p->af == AF_INET && p->bits < 31;
}

uint64_t qn_prefix_usable(const qn_prefix *p, bool skip_edges)
{
    uint64_t n = qn_prefix_hosts(p);

    return n && skip_edges && prefix_has_edges(p) ? n - 2u : n;
}

static void mask_v6(uint8_t *b, uint8_t bits)
{
    for (int i = 0; i < 16; i++) {
        int lo = i * 8;
        if (lo + 8 <= bits)
            continue;
        if (lo >= bits) {
            b[i] = 0;
        } else {
            uint8_t keep = (uint8_t)(bits - lo);
            b[i] = (uint8_t)(b[i] & (uint8_t)(0xFFu << (8 - keep)));
        }
    }
}

bool qn_cidr_parse(const char *s, qn_prefix *out)
{
    char        buf[128];
    char       *slash;
    unsigned    bits;
    qn_addr     a;

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!s || qn_strlcpy(buf, s, sizeof buf) >= sizeof buf || !buf[0])
        return false;

    slash = strchr(buf, '/');
    if (slash) {
        char *end;
        long  v;
        *slash = '\0';
        if (slash[1] < '0' || slash[1] > '9')
            return false;
        v      = strtol(slash + 1, &end, 10);
        if (*end || v < 0 || v > 128)
            return false;
        bits = (unsigned)v;
    } else {
        bits = 255; /* fill in after we know the family */
    }

    if (!qn_addr_parse(buf, &a))
        return false;

    if (bits == 255)
        bits = (a.af == AF_INET) ? 32u : 128u;
    if (a.af == AF_INET && bits > 32)
        return false;

    out->af   = a.af;
    out->bits = (uint8_t)bits;
    out->net  = a;

    if (a.af == AF_INET)
        out->net.u.v4 = bits ? (a.u.v4 & (uint32_t)(0xFFFFFFFFu << (32 - bits))) : 0u;
    else
        mask_v6(out->net.u.v6, (uint8_t)bits);

    out->count = qn_prefix_hosts(out);
    return true;
}

bool qn_cidr_set_init(qn_cidr_set *s, qn_arena *a, uint32_t cap)
{
    if (!s)
        return false;
    memset(s, 0, sizeof *s);
    if (!a || !cap)
        return false;
    s->v = QN_ARENA_ARRAY(a, qn_prefix, cap);
    if (!s->v)
        return false;
    s->cap = cap;
    return true;
}

void qn_cidr_set_skip_edges(qn_cidr_set *s, bool skip)
{
    if (s)
        s->skip_edges = skip;
}

bool qn_cidr_set_add(qn_cidr_set *s, const qn_prefix *p)
{
    qn_prefix normalized;

    if (!s || !p || !s->v || s->n >= s->cap || p->net.af != p->af ||
        p->count == 0 || p->count != qn_prefix_hosts(p))
        return false;
    normalized = *p;
    if (p->af == AF_INET) {
        uint32_t mask = p->bits ? (uint32_t)(0xFFFFFFFFu << (32u - p->bits)) : 0u;
        if ((p->net.u.v4 & mask) != p->net.u.v4)
            return false;
    } else if (p->af == AF_INET6) {
        mask_v6(normalized.net.u.v6, normalized.bits);
        if (memcmp(normalized.net.u.v6, p->net.u.v6, sizeof p->net.u.v6) != 0)
            return false;
    } else {
        return false;
    }
    s->v[s->n++] = *p;
    return true;
}

bool qn_cidr_set_add_str(qn_cidr_set *s, const char *str)
{
    qn_prefix p;
    return qn_cidr_parse(str, &p) && qn_cidr_set_add(s, &p);
}

/* A line worth parsing: not blank, not a comment. */
static char *range_line(char *line)
{
    char *p = line, *e;

    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '#' || *p == ';' || *p == '\n' || *p == '\r' || !*p)
        return NULL;
    e = p + strlen(p);
    while (e > p && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
        *--e = '\0';
    return *p ? p : NULL;
}

uint32_t qn_cidr_file_lines(const char *path)
{
    FILE    *f = fopen(path, "r");
    char     line[160];
    uint32_t n = 0;

    if (!f)
        return 0;
    while (fgets(line, sizeof line, f)) {
        bool complete = strchr(line, '\n') != NULL || feof(f);

        if (!complete) {
            int ch;
            while ((ch = fgetc(f)) != '\n' && ch != EOF)
                ;
        }
        if (complete && range_line(line))
            n++;
    }
    fclose(f);
    return n;
}

bool qn_cidr_set_load_file_af(qn_cidr_set *s, const char *path, qn_cidr_report *rep,
                              int required_af)
{
    FILE    *f;
    char     line[160];
    uint32_t lineno = 0;

    memset(rep, 0, sizeof *rep);
    f = fopen(path, "r");
    if (!f)
        return false;

    while (fgets(line, sizeof line, f)) {
        qn_prefix p;
        char     *t;
        bool      complete;

        lineno++;
        complete = strchr(line, '\n') != NULL || feof(f);
        if (!complete) {
            int ch;
            while ((ch = fgetc(f)) != '\n' && ch != EOF)
                ;
            rep->rejected++;
            if (!rep->bad_line) {
                rep->bad_line = lineno;
                qn_strlcpy(rep->bad_text, "line-too-long", sizeof rep->bad_text);
            }
            continue;
        }
        t = range_line(line);
        if (!t)
            continue;

        if (!qn_cidr_parse(t, &p) || (required_af && p.af != required_af)) {
            rep->rejected++;
        } else if (!qn_cidr_set_add(s, &p)) {
            rep->overflow++;
        } else {
            rep->accepted++;
            continue;
        }
        /* Keep the first offender: it is the one the user has to fix. */
        if (!rep->bad_line) {
            rep->bad_line = lineno;
            qn_strlcpy(rep->bad_text, t, sizeof rep->bad_text);
        }
    }
    if (ferror(f) && !rep->bad_line) {
        rep->bad_line = lineno + 1u;
        qn_strlcpy(rep->bad_text, "read-error", sizeof rep->bad_text);
        rep->rejected++;
    }
    fclose(f);

    /* Any rejected or dropped prefix invalidates the complete target set. */
    return rep->accepted && !rep->rejected && !rep->overflow;
}

bool qn_cidr_set_load_file(qn_cidr_set *s, const char *path, qn_cidr_report *rep)
{
    return qn_cidr_set_load_file_af(s, path, rep, 0);
}

static int prefix_cmp(const void *va, const void *vb)
{
    const qn_prefix *a = (const qn_prefix *)va;
    const qn_prefix *b = (const qn_prefix *)vb;

    if (a->af != b->af)
        return a->af < b->af ? -1 : 1;
    if (a->af == AF_INET) {
        if (a->net.u.v4 != b->net.u.v4)
            return a->net.u.v4 < b->net.u.v4 ? -1 : 1;
    } else {
        int c = memcmp(a->net.u.v6, b->net.u.v6, sizeof a->net.u.v6);
        if (c)
            return c;
    }
    return (a->bits > b->bits) - (a->bits < b->bits);
}

static bool prefix_contains(const qn_prefix *outer, const qn_prefix *inner)
{
    if (outer->af != inner->af || outer->bits > inner->bits)
        return false;
    if (outer->af == AF_INET) {
        uint32_t mask = outer->bits ? 0xFFFFFFFFu << (32u - outer->bits) : 0u;
        return (inner->net.u.v4 & mask) == outer->net.u.v4;
    }
    for (uint8_t bit = 0; bit < outer->bits; bit++) {
        uint8_t mask = (uint8_t)(0x80u >> (bit & 7u));
        if ((outer->net.u.v6[bit >> 3] & mask) != (inner->net.u.v6[bit >> 3] & mask))
            return false;
    }
    return true;
}

static bool merge_siblings(const qn_prefix *a, const qn_prefix *b, qn_prefix *out)
{
    uint64_t block;

    if (a->af != b->af || !a->bits || a->bits != b->bits)
        return false;
    if (a->af == AF_INET) {
        block = (uint64_t)1u << (32u - a->bits);
        if ((uint64_t)a->net.u.v4 + block != b->net.u.v4 ||
            ((uint64_t)a->net.u.v4 % (block * 2u)) != 0u)
            return false;
        *out = *a;
        out->bits--;
    } else {
        qn_prefix pa = *a, pb = *b;

        /* Merging capped IPv6 siblings would silently halve the enumerable set. */
        if (128u - a->bits >= 20u)
            return false;

        pa.bits--;
        pb.bits--;
        mask_v6(pa.net.u.v6, pa.bits);
        mask_v6(pb.net.u.v6, pb.bits);
        if (!memcmp(a->net.u.v6, b->net.u.v6, sizeof a->net.u.v6) ||
            memcmp(pa.net.u.v6, pb.net.u.v6, sizeof pa.net.u.v6))
            return false;
        *out = pa;
    }
    out->count = qn_prefix_hosts(out);
    return true;
}

static void normalize_prefixes(qn_cidr_set *s)
{
    uint32_t outn = 0;

    if (s->n > 1u)
        qsort(s->v, s->n, sizeof *s->v, prefix_cmp);
    for (uint32_t i = 0; i < s->n; i++) {
        qn_prefix cur = s->v[i];

        if (outn && prefix_contains(&s->v[outn - 1u], &cur))
            continue;
        while (outn) {
            qn_prefix merged;

            /* Merging LAN siblings would change which internal edges are excluded. */
            if (s->skip_edges || !merge_siblings(&s->v[outn - 1u], &cur, &merged))
                break;
            outn--;
            cur = merged;
            if (outn && prefix_contains(&s->v[outn - 1u], &cur))
                break;
        }
        if (outn && prefix_contains(&s->v[outn - 1u], &cur))
            continue;
        s->v[outn++] = cur;
    }
    s->n = outn;
}

/* One line of the snapshot, with the physical extent the caller must skip. */
typedef struct {
    const char *text;
    size_t      len;
    bool        overlong;
    bool        has_nul;
} snap_line;

const char *qn_snapshot_status_str(qn_snapshot_status status)
{
    switch (status) {
    case QN_SNAPSHOT_NONE:             return "none";
    case QN_SNAPSHOT_OK:               return "ok";
    case QN_SNAPSHOT_OPEN_FAILED:      return "open-failed";
    case QN_SNAPSHOT_NOT_REGULAR:      return "not-regular";
    case QN_SNAPSHOT_TOO_LARGE:        return "file-too-large";
    case QN_SNAPSHOT_SHORT_READ:       return "short-read";
    case QN_SNAPSHOT_GREW:             return "file-grew";
    case QN_SNAPSHOT_METADATA_CHANGED: return "metadata-changed";
    case QN_SNAPSHOT_REPLACED:         return "file-replaced";
    case QN_SNAPSHOT_IO_FAILED:        return "read-error";
    case QN_SNAPSHOT_OVERFLOW:         return "size-overflow";
    default:                           return "invalid";
    }
}

static bool snapshot_fail(qn_cidr_report *rep, qn_snapshot_status status, int error)
{
    rep->snapshot_status = (uint8_t)status;
    rep->snapshot_errno = error;
    rep->bad_line = 1u;
    rep->rejected = 1u;
    qn_strlcpy(rep->bad_text, qn_snapshot_status_str(status), sizeof rep->bad_text);
    return false;
}

static bool same_snapshot_metadata(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
           a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
           a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

#if defined(QN_CIDR_TESTING)
static qn_snapshot_test_hook snapshot_test_hook;
static void                 *snapshot_test_ctx;

void qn_cidr_snapshot_set_test_hook(qn_snapshot_test_hook hook, void *ctx)
{
    snapshot_test_hook = hook;
    snapshot_test_ctx  = ctx;
}

static void snapshot_test_inject(qn_snapshot_test_point point, const char *path)
{
    if (snapshot_test_hook)
        snapshot_test_hook(point, path, snapshot_test_ctx);
}
#else
#define snapshot_test_inject(point, path) ((void)0)
#endif

static size_t snap_next(const uint8_t *buf, size_t len, size_t pos, snap_line *out,
                        char *scratch, size_t scratch_cap)
{
    size_t end = pos, take;

    memset(out, 0, sizeof *out);
    while (end < len && buf[end] != '\n')
        end++;
    take = end - pos;
    if (take && buf[pos + take - 1u] == '\r')
        take--;

    /* An embedded NUL would truncate the line for every str* call after it. */
    if (memchr(buf + pos, 0, take))
        out->has_nul = true;
    if (take >= scratch_cap)
        out->overlong = true;
    else {
        memcpy(scratch, buf + pos, take);
        scratch[take] = '\0';
        out->text     = scratch;
        out->len      = take;
    }
    return end < len ? end + 1u : len;
}

bool qn_cidr_set_load_snapshot(qn_cidr_set *s, qn_arena *a, const char *path,
                               qn_cidr_report *rep, int required_af)
{
    struct stat before, after, path_after;
    int       fd = -1;
    uint8_t  *buf = NULL;
    char      scratch[160];
    size_t    len = 0, cap = 0, pos;
    uint32_t  lineno = 0, want = 0;
    qn_sha256 sha;

    if (!s || !a || !path || !rep)
        return false;
    memset(rep, 0, sizeof *rep);

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return snapshot_fail(rep, QN_SNAPSHOT_OPEN_FAILED, errno);
    if (fstat(fd, &before) != 0) {
        int error = errno;
        close(fd);
        return snapshot_fail(rep, QN_SNAPSHOT_IO_FAILED, error);
    }
    if (!S_ISREG(before.st_mode)) {
        close(fd);
        return snapshot_fail(rep, QN_SNAPSHOT_NOT_REGULAR, EINVAL);
    }
    if (before.st_size < 0 || (uintmax_t)before.st_size > QN_CIDR_FILE_MAX) {
        close(fd);
        return snapshot_fail(rep, QN_SNAPSHOT_TOO_LARGE, EFBIG);
    }
    snapshot_test_inject(QN_SNAPSHOT_TEST_AFTER_FSTAT, path);
    cap = (size_t)before.st_size;
    if (cap == SIZE_MAX) {
        close(fd);
        return snapshot_fail(rep, QN_SNAPSHOT_OVERFLOW, EOVERFLOW);
    }
    buf = (uint8_t *)qn_arena_alloc(a, cap + 1u, 16u);
    if (!buf) {
        close(fd);
        return snapshot_fail(rep, QN_SNAPSHOT_IO_FAILED, ENOMEM);
    }
    while (len < cap) {
        ssize_t got = read(fd, buf + len, cap - len);

        if (got > 0) {
            len += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR)
            continue;
        {
            int error = got < 0 ? errno : ESTALE;
            close(fd);
            return snapshot_fail(rep, got == 0 ? QN_SNAPSHOT_SHORT_READ
                                                : QN_SNAPSHOT_IO_FAILED,
                                 error);
        }
    }
    snapshot_test_inject(QN_SNAPSHOT_TEST_AFTER_READ, path);
    for (;;) {
        uint8_t extra;
        ssize_t got = read(fd, &extra, 1u);

        if (got > 0) {
            close(fd);
            return snapshot_fail(rep, QN_SNAPSHOT_GREW, ESTALE);
        }
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            int error = errno;
            close(fd);
            return snapshot_fail(rep, QN_SNAPSHOT_IO_FAILED, error);
        }
        break;
    }
    snapshot_test_inject(QN_SNAPSHOT_TEST_BEFORE_FINAL_FSTAT, path);
    if (fstat(fd, &after) != 0) {
        int error = errno;
        close(fd);
        return snapshot_fail(rep, QN_SNAPSHOT_IO_FAILED, error);
    }
    if (!same_snapshot_metadata(&before, &after)) {
        close(fd);
        return snapshot_fail(rep, QN_SNAPSHOT_METADATA_CHANGED, ESTALE);
    }
    snapshot_test_inject(QN_SNAPSHOT_TEST_BEFORE_PATH_STAT, path);
    if (stat(path, &path_after) != 0) {
        int error = errno;
        close(fd);
        return snapshot_fail(rep, QN_SNAPSHOT_REPLACED, error);
    }
    if (before.st_dev != path_after.st_dev || before.st_ino != path_after.st_ino) {
        close(fd);
        return snapshot_fail(rep, QN_SNAPSHOT_REPLACED, ESTALE);
    }
    if (!same_snapshot_metadata(&before, &path_after)) {
        close(fd);
        return snapshot_fail(rep, QN_SNAPSHOT_METADATA_CHANGED, ESTALE);
    }
    if (close(fd) != 0)
        return snapshot_fail(rep, QN_SNAPSHOT_IO_FAILED, errno);
    rep->snapshot_status = (uint8_t)QN_SNAPSHOT_OK;

    qn_sha256_init(&sha);
    qn_sha256_update(&sha, buf, len);
    qn_sha256_final(&sha, rep->digest);
    rep->have_digest = true;
    rep->bytes       = len;

    for (pos = 0; pos < len;) {
        snap_line ln;

        pos = snap_next(buf, len, pos, &ln, scratch, sizeof scratch);
        if (ln.overlong || ln.has_nul || !ln.text)
            continue;
        if (range_line(scratch))
            want++;
    }
    if (!qn_cidr_set_init(s, a, want ? want : 1u))
        return false;

    for (pos = 0; pos < len;) {
        snap_line ln;
        qn_prefix p;
        char     *t;

        lineno++;
        pos = snap_next(buf, len, pos, &ln, scratch, sizeof scratch);
        if (ln.overlong || ln.has_nul || !ln.text) {
            rep->rejected++;
            if (!rep->bad_line) {
                rep->bad_line = lineno;
                qn_strlcpy(rep->bad_text, ln.has_nul ? "embedded-nul" : "line-too-long",
                           sizeof rep->bad_text);
            }
            continue;
        }
        t = range_line(scratch);
        if (!t)
            continue;

        if (!qn_cidr_parse(t, &p) || (required_af && p.af != required_af)) {
            rep->rejected++;
        } else if (!qn_cidr_set_add(s, &p)) {
            rep->overflow++;
        } else {
            rep->accepted++;
            continue;
        }
        if (!rep->bad_line) {
            rep->bad_line = lineno;
            qn_strlcpy(rep->bad_text, t, sizeof rep->bad_text);
        }
    }
    return rep->accepted && !rep->rejected && !rep->overflow;
}

void qn_cidr_set_seal(qn_cidr_set *s, qn_arena *a)
{
    uint64_t acc = 0;

    if (!s || !a)
        return;
    normalize_prefixes(s);

    s->cumsum = QN_ARENA_ARRAY(a, uint64_t, s->n ? s->n : 1);
    if (!s->cumsum) {
        s->total = 0;
        return;
    }
    for (uint32_t i = 0; i < s->n; i++) {
        uint64_t add = qn_prefix_usable(&s->v[i], s->skip_edges);
        if (UINT64_MAX - acc < add) {
            s->total = 0;
            return;
        }
        acc += add;
        s->cumsum[i] = acc;
    }
    s->total = acc;
}

bool qn_cidr_set_nth(const qn_cidr_set *s, uint64_t idx, qn_addr *out)
{
    uint32_t lo = 0, hi;
    uint64_t base;
    const qn_prefix *p;

    if (!out || !s || !s->cumsum || idx >= s->total)
        return false;
    memset(out, 0, sizeof *out);

    hi = s->n - 1;
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        if (s->cumsum[mid] > idx)
            hi = mid;
        else
            lo = mid + 1;
    }

    p    = &s->v[lo];
    base = lo ? s->cumsum[lo - 1] : 0;
    idx -= base;

    if (p->af == AF_INET) {
        out->af = AF_INET;
        out->u.v4 =
            p->net.u.v4 + (uint32_t)idx + (s->skip_edges && prefix_has_edges(p) ? 1u : 0u);
        return true;
    }

    out->af = AF_INET6;
    memcpy(out->u.v6, p->net.u.v6, 16);
    for (int i = 15; i >= 0 && idx; i--) {
        uint32_t sum = (uint32_t)out->u.v6[i] + (uint32_t)(idx & 0xFFu);
        out->u.v6[i] = (uint8_t)sum;
        idx >>= 8;
        idx += (sum >> 8);
    }
    return true;
}
