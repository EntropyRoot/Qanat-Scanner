#ifndef QANAT_UTIL_H
#define QANAT_UTIL_H

#include "qanat/qanat.h"

#if defined(__GNUC__) || defined(__clang__)
#define QN_LIKELY(x)   __builtin_expect(!!(x), 1)
#define QN_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define QN_PREFETCH(p) __builtin_prefetch((p), 0, 3)
#define QN_NOINLINE    __attribute__((noinline))
#define QN_PURE        __attribute__((pure))
#define QN_HOT         __attribute__((hot))
#define QN_FMT(a, b)   __attribute__((format(printf, a, b)))
#else
#define QN_LIKELY(x)   (x)
#define QN_UNLIKELY(x) (x)
#define QN_PREFETCH(p) ((void)0)
#define QN_NOINLINE
#define QN_PURE
#define QN_HOT
#define QN_FMT(a, b)
#endif

#define QN_CACHELINE  64
#define QN_ALIGNED(n) __attribute__((aligned(n)))

#define QN_ARRAY_LEN(a)     (sizeof(a) / sizeof((a)[0]))
#define QN_MIN(a, b)        ((a) < (b) ? (a) : (b))
#define QN_MAX(a, b)        ((a) > (b) ? (a) : (b))
#define QN_CLAMP(v, lo, hi) QN_MIN(QN_MAX((v), (lo)), (hi))

bool qn_size_mul(size_t count, size_t width, size_t *bytes);

uint64_t qn_now_ns(void);
uint64_t qn_now_ms(void); /* COARSE where available */
void     qn_sleep_ms(uint32_t ms);

/* The one OS entropy path; false means neither the syscall nor /dev/urandom. */
bool qn_os_entropy(void *dst, size_t n);

bool qn_addr_parse(const char *s, qn_addr *out);
int  qn_addr_str(const qn_addr *a, char *buf, size_t buflen);
bool qn_addr_eq(const qn_addr *a, const qn_addr *b);
bool qn_resolve(const char *host, bool want6, qn_addr *out);
int  qn_ipv4_str(uint32_t host_order, char *buf16);
bool qn_valid_hostname(const char *name);

/* Safe in a request line: no control character, space or DEL, at most max. */
bool qn_valid_field(const char *s, size_t max);

/* Wall-clock seconds, or false when the clock failed or reads implausibly. */
bool qn_wall_now(uint64_t *out);
bool qn_errno_would_block(int error);
bool qn_errno_not_supported(int error);

long           qn_find_headers_end(const uint8_t *buf, size_t len);
const uint8_t *qn_find_ci(const uint8_t *hay, size_t hlen, const char *needle);

size_t qn_strlcpy(char *dst, const char *src, size_t dstsz);
int    qn_fmt_dur(uint32_t us, char *buf, size_t buflen);
int    qn_fmt_count(uint64_t n, char *buf, size_t buflen);

void qn_die(const char *fmt, ...) QN_FMT(1, 2);
void qn_warn(const char *fmt, ...) QN_FMT(1, 2);

#endif /* QANAT_UTIL_H */
