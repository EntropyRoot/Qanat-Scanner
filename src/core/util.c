#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qanat/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

bool qn_size_mul(size_t count, size_t width, size_t *bytes)
{
    if (!bytes || (width != 0u && count > SIZE_MAX / width))
        return false;
    *bytes = count * width;
    return true;
}

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#define QN_HAVE_NEON 1
#endif

uint64_t qn_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

uint64_t qn_now_ms(void)
{
    struct timespec ts;
#ifdef CLOCK_MONOTONIC_COARSE
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts) != 0)
#endif
        clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

/* Use the syscall because bionic's getrandom wrapper depends on the API level. */
static size_t entropy_syscall(uint8_t *dst, size_t n)
{
    size_t done = 0;

#if defined(__linux__) && defined(SYS_getrandom)
    while (done < n) {
        long r = syscall(SYS_getrandom, dst + done, n - done, 0);
        if (r > 0) {
            done += (size_t)r;
            continue;
        }
        if (r < 0 && errno == EINTR)
            continue;
        break;
    }
#else
    (void)dst;
    (void)n;
#endif
    return done;
}

static bool entropy_urandom(uint8_t *dst, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        return false;
    while (n) {
        ssize_t r = read(fd, dst, n);
        if (r <= 0) {
            if (r < 0 && errno == EINTR)
                continue;
            close(fd);
            return false;
        }
        dst += (size_t)r;
        n -= (size_t)r;
    }
    close(fd);
    return true;
}

bool qn_os_entropy(void *dst, size_t n)
{
    uint8_t *p    = (uint8_t *)dst;
    size_t   done = entropy_syscall(p, n);

    return done == n || entropy_urandom(p + done, n - done);
}

void qn_sleep_ms(uint32_t ms)
{
    struct timespec ts = { (time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L };
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
        ;
}

bool qn_addr_parse(const char *s, qn_addr *out)
{
    struct in_addr  a4;
    struct in6_addr a6;

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!s || !*s)
        return false;

    if (inet_pton(AF_INET, s, &a4) == 1) {
        out->af   = AF_INET;
        out->u.v4 = ntohl(a4.s_addr);
        return true;
    }
    if (inet_pton(AF_INET6, s, &a6) == 1) {
        out->af = AF_INET6;
        memcpy(out->u.v6, &a6, 16);
        return true;
    }
    return false;
}

int qn_ipv4_str(uint32_t h, char *buf16)
{
    char *p = buf16;
    int   i;

    for (i = 3; i >= 0; i--) {
        uint32_t v = (h >> (i * 8)) & 0xFFu;
        if (v >= 100) {
            *p++ = (char)('0' + v / 100);
            v %= 100;
            *p++ = (char)('0' + v / 10);
            *p++ = (char)('0' + v % 10);
        } else if (v >= 10) {
            *p++ = (char)('0' + v / 10);
            *p++ = (char)('0' + v % 10);
        } else {
            *p++ = (char)('0' + v);
        }
        if (i)
            *p++ = '.';
    }
    *p = '\0';
    return (int)(p - buf16);
}

int qn_addr_str(const qn_addr *a, char *buf, size_t buflen)
{
    if (!a || !buf || !buflen)
        return 0;
    if (a->af == AF_INET) {
        char tmp[16];
        int  n = qn_ipv4_str(a->u.v4, tmp);
        if ((size_t)n + 1 > buflen) {
            if (buflen)
                buf[0] = '\0';
            return 0;
        }
        memcpy(buf, tmp, (size_t)n + 1);
        return n;
    }
    if (a->af != AF_INET6 || !inet_ntop(AF_INET6, a->u.v6, buf, (socklen_t)buflen)) {
        if (buflen)
            buf[0] = '\0';
        return 0;
    }
    return (int)strlen(buf);
}

bool qn_addr_eq(const qn_addr *a, const qn_addr *b)
{
    if (!a || !b || (a->af != AF_INET && a->af != AF_INET6))
        return false;
    if (a->af != b->af)
        return false;
    return a->af == AF_INET ? a->u.v4 == b->u.v4 : memcmp(a->u.v6, b->u.v6, 16) == 0;
}

bool qn_resolve(const char *host, bool want6, qn_addr *out)
{
    struct addrinfo  hints, *res = NULL, *it;
    int              rc;
    bool             ok = false;

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!host || !*host)
        return false;
    if (qn_addr_parse(host, out))
        return true;

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0 || !res)
        return false;

    for (it = res; it; it = it->ai_next) {
        if (!want6 && it->ai_family == AF_INET) {
            const struct sockaddr_in *sa = (const struct sockaddr_in *)(const void *)it->ai_addr;
            out->af   = AF_INET;
            out->u.v4 = ntohl(sa->sin_addr.s_addr);
            ok        = true;
            break;
        }
        if (want6 && it->ai_family == AF_INET6) {
            const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)(const void *)it->ai_addr;
            out->af = AF_INET6;
            memcpy(out->u.v6, &sa->sin6_addr, 16);
            ok = true;
            break;
        }
    }
    if (!ok) { /* fall back to whatever the resolver gave us first */
        if (res->ai_family == AF_INET) {
            const struct sockaddr_in *sa = (const struct sockaddr_in *)(const void *)res->ai_addr;
            out->af   = AF_INET;
            out->u.v4 = ntohl(sa->sin_addr.s_addr);
            ok        = true;
        } else if (res->ai_family == AF_INET6) {
            const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)(const void *)res->ai_addr;
            out->af = AF_INET6;
            memcpy(out->u.v6, &sa->sin6_addr, 16);
            ok = true;
        }
    }
    freeaddrinfo(res);
    return ok;
}

bool qn_valid_hostname(const char *name)
{
    size_t len, label = 0;
    bool   numeric = true;

    if (!name || !(len = strlen(name)) || len > 253u || name[len - 1u] == '.')
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];

        if (c == '.') {
            if (!label || label > 63u || name[i - 1u] == '-')
                return false;
            label = 0;
            continue;
        }
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-'))
            return false;
        if (!label && c == '-')
            return false;
        if (c < '0' || c > '9')
            numeric = false;
        label++;
    }
    return label && label <= 63u && name[len - 1u] != '-' && !numeric;
}

bool qn_valid_field(const char *s, size_t max)
{
    size_t i;

    if (!s)
        return false;
    for (i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];

        if (i >= max || c <= 0x20u || c == 0x7Fu)
            return false;
    }
    return i != 0u;
}

/* 2020-01-01 and 2100-01-01: outside this we cannot date evidence at all. */
#define QN_WALL_MIN 1577836800ull
#define QN_WALL_MAX 4102444800ull

bool qn_wall_now(uint64_t *out)
{
    time_t t = time(NULL);

    if (!out || t == (time_t)-1 || t <= 0)
        return false;
    if ((uint64_t)t < QN_WALL_MIN || (uint64_t)t > QN_WALL_MAX)
        return false;
    *out = (uint64_t)t;
    return true;
}

bool qn_errno_would_block(int error)
{
    if (error == EAGAIN)
        return true;
#if EWOULDBLOCK != EAGAIN
    if (error == EWOULDBLOCK)
        return true;
#endif
    return false;
}

bool qn_errno_not_supported(int error)
{
    if (error == EOPNOTSUPP)
        return true;
#if ENOTSUP != EOPNOTSUPP
    if (error == ENOTSUP)
        return true;
#endif
    return false;
}

#ifdef QN_HAVE_NEON
/* ARM64 has no pmovmskb; narrow lanes into a mask. */
static inline uint64_t neon_movemask(uint8x16_t v)
{
    uint8x8_t n = vshrn_n_u16(vreinterpretq_u16_u8(v), 4);
    return vget_lane_u64(vreinterpret_u64_u8(n), 0);
}
#endif

long qn_find_headers_end(const uint8_t *buf, size_t len)
{
    size_t i = 0;

    if (len < 4)
        return -1;

#ifdef QN_HAVE_NEON
    {
        const uint8x16_t cr = vdupq_n_u8('\r');
        for (; i + 16 <= len; i += 16) {
            uint64_t m = neon_movemask(vceqq_u8(vld1q_u8(buf + i), cr));
            while (m) {
                size_t off = (size_t)(__builtin_ctzll(m) >> 2);
                size_t p   = i + off;
                if (p + 4 <= len && buf[p + 1] == '\n' && buf[p + 2] == '\r' && buf[p + 3] == '\n')
                    return (long)(p + 4);
                m &= ~(0xFull << (off * 4)); /* each match sets a whole nibble */
            }
        }
    }
#endif
    for (; i + 4 <= len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return (long)(i + 4);
    }
    return -1;
}

static inline uint8_t lc(uint8_t c)
{
    return (uint8_t)((c >= 'A' && c <= 'Z') ? c + 32 : c);
}

const uint8_t *qn_find_ci(const uint8_t *hay, size_t hlen, const char *needle)
{
    size_t  nlen = strlen(needle);
    uint8_t n0;

    if (!nlen || nlen > hlen)
        return NULL;
    n0 = lc((uint8_t)needle[0]);

    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (lc(hay[i]) != n0)
            continue;
        size_t j = 1;
        while (j < nlen && lc(hay[i + j]) == lc((uint8_t)needle[j]))
            j++;
        if (j == nlen)
            return hay + i;
    }
    return NULL;
}

size_t qn_strlcpy(char *dst, const char *src, size_t dstsz)
{
    size_t srclen = strlen(src);
    size_t n;

    if (!dstsz)
        return srclen;
    n = QN_MIN(srclen, dstsz - 1u);
    if (n)
        memcpy(dst, src, n);
    dst[n] = '\0';
    return srclen;
}

int qn_fmt_dur(uint32_t us, char *buf, size_t buflen)
{
    if (us == 0)
        return snprintf(buf, buflen, "-");
    if (us < 1000)
        return snprintf(buf, buflen, "%uus", us);
    if (us < 1000000)
        return snprintf(buf, buflen, "%u.%ums", us / 1000u, (us % 1000u) / 100u);
    return snprintf(buf, buflen, "%u.%us", us / 1000000u, (us % 1000000u) / 100000u);
}

int qn_fmt_count(uint64_t n, char *buf, size_t buflen)
{
    static const char suf[] = { 0, 'K', 'M', 'G', 'T' };
    unsigned          i     = 0;
    uint64_t          v     = n;

    while (v >= 10000 && i + 1 < sizeof suf) {
        v /= 1000;
        i++;
    }
    if (!i)
        return snprintf(buf, buflen, "%llu", (unsigned long long)v);
    return snprintf(buf, buflen, "%llu%c", (unsigned long long)v, suf[i]);
}

void qn_die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs(QN_NAME ": ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

void qn_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs(QN_NAME ": ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

const char *qn_result_str(qn_result r)
{
    switch (r) {
    case QN_R_PENDING: return "pending";
    case QN_R_OPEN:    return "open";
    case QN_R_REFUSED: return "closed";
    case QN_R_TIMEOUT: return "filtered";
    case QN_R_UNREACH: return "unreachable";
    case QN_R_RESET:   return "reset";
    case QN_R_CANCELLED: return "cancelled";
    default:           return "error";
    }
}

const char *qn_failure_origin_str(qn_failure_origin origin)
{
    switch (origin) {
    case QN_FAIL_NONE:        return "none";
    case QN_FAIL_LOCAL:       return "local";
    case QN_FAIL_PEER:        return "peer";
    case QN_FAIL_PATH:        return "path";
    case QN_FAIL_PROTOCOL:    return "protocol";
    case QN_FAIL_UNSUPPORTED: return "unsupported";
    case QN_FAIL_CANCELLED:   return "cancelled";
    default:                  return "invalid";
    }
}

void qn_config_defaults(qn_config *c)
{
    memset(c, 0, sizeof *c);
    c->mode       = QN_MODE_NONE;
    c->sni        = "www.cloudflare.com";
    c->samples    = 5;
    c->timeout_ms = 1200;
    c->retries    = 1;
    c->scan = (qn_scan_request)QN_SCAN_REQUEST_INIT;
    c->deep       = true;
    c->warm_mode  = QN_WARM_AUTO;
    c->discover_method = QN_DISCOVER_AUTO;
    c->flow_bytes = 0;
    c->idle_ms    = 5000;
    c->verify_concurrency = 64;
    c->stability_concurrency = 512;
}
