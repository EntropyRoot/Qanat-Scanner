/* Persistent evidence with exponential decay, so old results fade. */

#include "qanat/store.h"

#include "qanat/util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define Q10 1024u

static uint32_t decay_q10(uint64_t dt_sec)
{
    uint64_t half = QN_STORE_HALFLIFE_SEC;
    uint32_t q    = Q10;

    while (dt_sec >= half && q > 1u) {
        q >>= 1;
        dt_sec -= half;
    }
    if (q > 1u)
        q -= (uint32_t)(((uint64_t)(q / 2u) * dt_sec) / half);
    return q;
}

static uint32_t oper_bit(const char *oper)
{
    uint32_t h = 2166136261u;

    while (oper && *oper) {
        h ^= (uint8_t)*oper++;
        h *= 16777619u;
    }
    return 1u << (h & 31u);
}

bool qn_store_init(qn_store *s, qn_arena *a, uint32_t cap)
{
    if (!s)
        return false;
    memset(s, 0, sizeof *s);
    if (!a || !cap)
        return false;
    s->e = QN_ARENA_ARRAY(a, qn_store_entry, cap);
    if (!s->e)
        return false;
    s->cap = cap;
    return true;
}

const qn_store_entry *qn_store_find(const qn_store *s, const qn_addr *a)
{
    uint32_t i;

    if (!s || !a || !s->e)
        return NULL;
    for (i = 0; i < s->n; i++)
        if (qn_addr_eq(&s->e[i].addr, a))
            return &s->e[i];
    return NULL;
}

/* Decayed rate scaled by decayed weight, so an old 1-of-1 cannot win. */
static uint64_t standing(const qn_store_entry *e, uint64_t now)
{
    uint32_t d = e->last_seen && now > e->last_seen ? decay_q10(now - e->last_seen) : Q10;
    uint64_t w = ((uint64_t)e->weight_q10 * d) / Q10;
    uint64_t v = ((uint64_t)e->score_q10 * d) / Q10;

    return (v * Q10 / (w + 1u)) * (w + 1u);
}

static qn_store_entry *slot_for(qn_store *s, const qn_addr *a, uint64_t now)
{
    uint32_t i, worst = 0;

    for (i = 0; i < s->n; i++)
        if (qn_addr_eq(&s->e[i].addr, a))
            return &s->e[i];

    if (s->n < s->cap) {
        qn_store_entry *e = &s->e[s->n++];
        memset(e, 0, sizeof *e);
        e->addr = *a;
        return e;
    }

    /* Evict on standing at now, not on a raw ratio frozen at its own last_seen. */
    for (i = 1; i < s->n; i++)
        if (standing(&s->e[i], now) < standing(&s->e[worst], now))
            worst = i;
    memset(&s->e[worst], 0, sizeof s->e[worst]);
    s->e[worst].addr = *a;
    return &s->e[worst];
}

void qn_store_observe(qn_store *s, const qn_addr *a, const char *oper, bool good,
                      uint32_t handshake_us, uint64_t now)
{
    qn_store_entry *e;
    uint32_t        d;
    uint64_t        event_now, score, weight;

    if (!s || !a || !s->e || !s->cap || (a->af != AF_INET && a->af != AF_INET6))
        return;
    e = slot_for(s, a, now);

    /* Wall-clock corrections must not move evidence backwards in time. */
    event_now = e->last_seen && now < e->last_seen ? e->last_seen : now;
    d = e->last_seen && event_now > e->last_seen ? decay_q10(event_now - e->last_seen) : Q10;

    score = ((uint64_t)e->score_q10 * d) / Q10;
    weight = ((uint64_t)e->weight_q10 * d) / Q10;
    /* Preserve the ratio instead of allowing long-running histories to wrap. */
    if (score > UINT32_MAX - Q10 || weight > UINT32_MAX - Q10) {
        score = (score + 1u) / 2u;
        weight = (weight + 1u) / 2u;
    }
    if (good)
        score += Q10;
    weight += Q10;
    e->score_q10  = (uint32_t)score;
    e->weight_q10 = (uint32_t)weight;
    e->last_seen  = event_now;
    if (e->runs != UINT32_MAX)
        e->runs++;
    if (good) {
        e->oper_mask |= oper_bit(oper);
        e->handshake_us = e->handshake_us
                              ? (uint32_t)(((uint64_t)e->handshake_us + handshake_us) / 2u)
                              : handshake_us;
    }
}

uint32_t qn_store_confidence(const qn_store *s, const qn_addr *a, uint64_t now)
{
    const qn_store_entry *e = qn_store_find(s, a);
    uint64_t              rate, conf;
    uint32_t              d, paths;

    if (!e || !e->weight_q10)
        return 0;

    d = e->last_seen && now > e->last_seen ? decay_q10(now - e->last_seen) : Q10;

    /* Reserve 300 points for repeated and multi-path confirmation. */
    rate = ((uint64_t)e->score_q10 * 1000u) / e->weight_q10;
    conf = (rate * 7u) / 10u;

    paths = (uint32_t)__builtin_popcount(e->oper_mask);
    if (paths > 1u)
        conf += QN_MIN(paths - 1u, 3u) * 60u;
    if (e->runs >= 3u)
        conf += 60u;
    if (e->runs >= 8u)
        conf += 60u;

    /* Staleness fades the whole thing, breadth included. */
    conf = (conf * d) / Q10;
    return conf > 1000u ? 1000u : (uint32_t)conf;
}

static bool parse_u64(const char *text, uint64_t max, uint64_t *out)
{
    char               *end;
    unsigned long long  value;

    if (!text || !*text || *text == '-' || *text == '+')
        return false;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno == ERANGE || *end || value > max)
        return false;
    *out = (uint64_t)value;
    return true;
}

static size_t split_fields(char *line, char **field, size_t cap)
{
    size_t n = 0;
    char  *p = line;

    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (!*p)
            return n;
        if (n == cap)
            return cap + 1u;
        field[n++] = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
            p++;
        if (*p)
            *p++ = '\0';
    }
}

/* The version line is a contract: unreadable columns are refused, not guessed. */
static bool read_schema(const char *line, uint32_t *ver)
{
    const char *tag = "# qanat history v";
    size_t      n   = strlen(tag);
    uint32_t    v   = 0;

    if (strncmp(line, tag, n) != 0)
        return false;
    line += n;
    if (*line < '0' || *line > '9')
        return false;
    while (*line >= '0' && *line <= '9') {
        if (v > (UINT32_MAX - 9u) / 10u)
            return false;
        v = v * 10u + (uint32_t)(*line++ - '0');
    }
    *ver = v;
    return true;
}

/* Reads path into loaded[], which must hold cap entries. */
static bool load_into(qn_store_entry *loaded, uint32_t cap, const char *path,
                      uint32_t *out_n, bool *absent)
{
    char     line[256];
    uint32_t loaded_n = 0;
    uint32_t schema   = 0;
    bool     seen_schema = false;
    FILE    *f;
    bool     ok = true;

    *absent = false;
    *out_n  = 0;
    f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) {
            *absent = true;
            return true; /* absent history is a fresh, valid store */
        }
        return false;
    }

    while (fgets(line, sizeof line, f)) {
        char     *field[7];
        char     *p = line;
        size_t    nf;
        uint64_t  value[6];
        qn_addr   a;

        if (!strchr(line, '\n') && !feof(f)) {
            ok = false;
            break;
        }
        if (!seen_schema && read_schema(line, &schema)) {
            seen_schema = true;
            /* v1 and v2 share every column; only the last one was misnamed. */
            if (schema < 1u || schema > QN_STORE_SCHEMA) {
                ok = false;
                break;
            }
            continue;
        }
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p || *p == '\r' || *p == '\n' || *p == '#')
            continue;
        if (!seen_schema) {
            ok = false; /* data before any version line */
            break;
        }
        nf = split_fields(p, field, QN_ARRAY_LEN(field));
        if (nf != QN_ARRAY_LEN(field) || !qn_addr_parse(field[0], &a) ||
            !parse_u64(field[1], UINT64_MAX, &value[0])) {
            ok = false;
            break;
        }
        for (size_t i = 1; i < QN_ARRAY_LEN(value); i++) {
            if (!parse_u64(field[i + 1u], UINT32_MAX, &value[i])) {
                ok = false;
                break;
            }
        }
        if (!ok || loaded_n >= cap || value[2] > value[3] ||
            (value[1] == 0u) != (value[3] == 0u)) {
            ok = false;
            break;
        }
        for (uint32_t i = 0; i < loaded_n; i++)
            if (qn_addr_eq(&loaded[i].addr, &a)) {
                ok = false;
                break;
            }
        if (!ok)
            break;

        loaded[loaded_n].addr         = a;
        loaded[loaded_n].last_seen    = value[0];
        loaded[loaded_n].runs         = (uint32_t)value[1];
        loaded[loaded_n].score_q10    = (uint32_t)value[2];
        loaded[loaded_n].weight_q10   = (uint32_t)value[3];
        loaded[loaded_n].oper_mask    = (uint32_t)value[4];
        loaded[loaded_n].handshake_us = (uint32_t)value[5];
        loaded_n++;
    }
    {
        bool read_failed = ferror(f) != 0;

        /* Always close after a read error; short-circuiting here leaks the descriptor. */
        if (fclose(f) != 0)
            read_failed = true;
        if (read_failed)
            ok = false;
    }
    if (ok && !seen_schema && loaded_n)
        ok = false;
    *out_n = loaded_n;
    return ok;
}

bool qn_store_load(qn_store *s, const char *path)
{
    qn_store_entry *loaded;
    uint32_t        loaded_n = 0;
    bool            absent, ok;

    if (!s || !s->e || !s->cap || !path || !*path)
        return false;
    loaded = (qn_store_entry *)calloc(s->cap, sizeof *loaded);
    if (!loaded)
        return false;
    ok = load_into(loaded, s->cap, path, &loaded_n, &absent);
    if (ok) {
        memcpy(s->e, loaded, (size_t)loaded_n * sizeof *loaded);
        s->n = loaded_n;
    }
    free(loaded);
    return ok;
}

static bool sync_parent_dir(const char *path)
{
    char *dir = strdup(path);
    char *slash;
    int   fd, rc, saved;

    if (!dir)
        return false;
    slash = strrchr(dir, '/');
    if (!slash) {
        free(dir);
        dir = strdup(".");
        if (!dir)
            return false;
    } else if (slash == dir) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    fd = open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    saved = errno;
    free(dir);
    if (fd < 0) {
        errno = saved;
        return false;
    }
    rc = fsync(fd);
    saved = errno;
    close(fd);
    if (rc == 0 || saved == EINVAL || saved == ENOTSUP || saved == EROFS)
        return true;
    errno = saved;
    return false;
}

/* Keep every address from both sides; on a collision the fresher one wins. */
static uint32_t merge_disk(qn_store_entry *out, uint32_t cap, const qn_store *s,
                           const char *path)
{
    qn_store_entry *disk;
    uint32_t        disk_n = 0, n = 0, i, j;
    bool            absent;

    for (i = 0; i < s->n && i < cap; i++)
        out[n++] = s->e[i];

    disk = (qn_store_entry *)calloc(cap, sizeof *disk);
    if (!disk)
        return n;
    if (!load_into(disk, cap, path, &disk_n, &absent) || absent) {
        free(disk);
        return n; /* unreadable or gone: our own view is the best we have */
    }

    for (i = 0; i < disk_n; i++) {
        for (j = 0; j < n; j++)
            if (qn_addr_eq(&out[j].addr, &disk[i].addr))
                break;
        if (j == n) {
            if (n < cap)
                out[n++] = disk[i];
            continue;
        }
        out[j].oper_mask |= disk[i].oper_mask;
        if (disk[i].runs > out[j].runs)
            out[j].runs = disk[i].runs;
        if (disk[i].last_seen > out[j].last_seen ||
            (disk[i].last_seen == out[j].last_seen &&
             disk[i].weight_q10 > out[j].weight_q10)) {
            uint32_t mask = out[j].oper_mask, runs = out[j].runs;

            out[j] = disk[i];
            out[j].oper_mask = mask;
            out[j].runs      = runs;
        }
    }
    free(disk);
    return n;
}

/* Lock beside the history, so a reader of the history is never blocked. */
static int lock_open(const char *path, char **lockpath)
{
    size_t n = strlen(path);
    int    fd;

    if (n > SIZE_MAX - sizeof ".lock")
        return -1;
    *lockpath = (char *)malloc(n + sizeof ".lock");
    if (!*lockpath)
        return -1;
    memcpy(*lockpath, path, n);
    memcpy(*lockpath + n, ".lock", sizeof ".lock");
    fd = open(*lockpath, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        free(*lockpath);
        *lockpath = NULL;
        return -1;
    }
    if (flock(fd, LOCK_EX) != 0) {
        int saved = errno;
        close(fd);
        free(*lockpath);
        *lockpath = NULL;
        errno = saved;
        return -1;
    }
    return fd;
}

bool qn_store_save(const qn_store *s, const char *path)
{
    char              ip[QN_ADDRSTRLEN];
    char             *tmp = NULL;
    char             *lockpath = NULL;
    qn_store_entry   *merged = NULL;
    uint32_t          merged_n = 0;
    FILE             *f = NULL;
    size_t            path_n;
    int               fd = -1, lockfd = -1;
    bool              ok = true;

    if (!s || !s->e || s->n > s->cap || !path || !*path)
        return false;

    lockfd = lock_open(path, &lockpath);
    if (lockfd < 0)
        return false;
    merged = (qn_store_entry *)calloc(s->cap ? s->cap : 1u, sizeof *merged);
    if (!merged) {
        close(lockfd);
        free(lockpath);
        return false;
    }
    merged_n = merge_disk(merged, s->cap, s, path);

    /* Atomic replacement preserves history, and all later failures release the lock and buffer. */
    path_n = strlen(path);
    if (path_n > SIZE_MAX - sizeof ".tmp.XXXXXX")
        goto fail;
    tmp = (char *)malloc(path_n + sizeof ".tmp.XXXXXX");
    if (!tmp)
        goto fail;
    memcpy(tmp, path, path_n);
    memcpy(tmp + path_n, ".tmp.XXXXXX", sizeof ".tmp.XXXXXX");
    fd = mkstemp(tmp);
    if (fd < 0)
        goto fail;
    f = fdopen(fd, "w");
    if (!f)
        goto fail;
    fd = -1; /* owned by f */

    if (fprintf(f, "# qanat history v%u: address last_seen runs score weight paths"
                   " handshake_us\n", QN_STORE_SCHEMA) < 0)
        ok = false;
    for (uint32_t i = 0; ok && i < merged_n; i++) {
        const qn_store_entry *e = &merged[i];

        if (qn_addr_str(&e->addr, ip, sizeof ip) <= 0 ||
            fprintf(f, "%s %llu %u %u %u %u %u\n", ip,
                    (unsigned long long)e->last_seen, e->runs, e->score_q10,
                    e->weight_q10, e->oper_mask, e->handshake_us) < 0)
            ok = false;
    }
    if (ok && (fflush(f) != 0 || fsync(fileno(f)) != 0))
        ok = false;
    if (fclose(f) != 0)
        ok = false;
    f = NULL;
    if (!ok || rename(tmp, path) != 0)
        goto fail;
    ok = sync_parent_dir(path);
    free(tmp);
    free(merged);
    close(lockfd);
    free(lockpath);
    return ok;

fail:
    {
        int saved = errno;
        if (f)
            fclose(f);
        if (fd >= 0)
            close(fd);
        if (tmp) {
            unlink(tmp);
            free(tmp);
        }
        free(merged);
        if (lockfd >= 0)
            close(lockfd);
        free(lockpath);
        errno = saved;
    }
    return false;
}
