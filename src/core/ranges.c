#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qanat/ranges.h"

#include "qanat/cidr.h"
#include "qanat/util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define QN_RANGE_FILE_MAX  (64u << 10)
#define QN_RANGE_MAX       256u
#define QN_CF_MIN_PREFIXES 8u
#define QN_CF_MIN_HOSTS    (64u << 10)

static void range_error(qn_cf_ranges_info *out, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(out->error, sizeof out->error, fmt, ap);
    va_end(ap);
}

static bool path_suffix(char *out, size_t outsz, const char *base, const char *suffix)
{
    size_t base_n, suffix_n;

    if (!out || !outsz || !base || !suffix)
        return false;
    base_n = strlen(base);
    suffix_n = strlen(suffix);
    if (base_n > SIZE_MAX - suffix_n - 1u || base_n + suffix_n + 1u > outsz)
        return false;
    memcpy(out, base, base_n);
    memcpy(out + base_n, suffix, suffix_n + 1u);
    return true;
}

bool qn_cf_ranges_default_path(char *out, size_t outsz)
{
    const char *base = getenv("XDG_CACHE_HOME");
    const char *home;

    if (!out || !outsz)
        return false;
    if (base && base[0] == '/')
        return path_suffix(out, outsz, base, "/qanat/cloudflare-v4.txt");
    home = getenv("HOME");
    return home && home[0] == '/' &&
           path_suffix(out, outsz, home, "/.cache/qanat/cloudflare-v4.txt");
}

static bool ranges_overlap(const qn_prefix *a, const qn_prefix *b)
{
    uint64_t alo = a->net.u.v4;
    uint64_t blo = b->net.u.v4;
    uint64_t ahi = alo + ((uint64_t)1u << (32u - a->bits)) - 1u;
    uint64_t bhi = blo + ((uint64_t)1u << (32u - b->bits)) - 1u;

    return alo <= bhi && blo <= ahi;
}

bool qn_cf_ranges_inspect(const char *path, qn_cf_ranges_info *out)
{
    qn_prefix  prefixes[QN_RANGE_MAX];
    struct stat st;
    FILE       *f;
    char        line[256];
    uint32_t    n = 0, lineno = 0;
    uint64_t    candidates = 0;
    int         fd;

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!path || !*path || strlen(path) >= sizeof out->path) {
        range_error(out, "invalid range-file path");
        return false;
    }
    qn_strlcpy(out->path, path, sizeof out->path);

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        range_error(out, "cannot open %s: %s", path, strerror(errno));
        return false;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > (off_t)QN_RANGE_FILE_MAX) {
        range_error(out, "range file is not a regular file smaller than %u bytes",
                    QN_RANGE_FILE_MAX);
        close(fd);
        return false;
    }
    f = fdopen(fd, "r");
    if (!f) {
        range_error(out, "cannot read %s: %s", path, strerror(errno));
        close(fd);
        return false;
    }

    while (fgets(line, sizeof line, f)) {
        char     *p = line, *e;
        qn_prefix prefix;

        lineno++;
        if (!strchr(line, '\n') && !feof(f)) {
            range_error(out, "line %u is too long", lineno);
            fclose(f);
            return false;
        }
        while (*p == ' ' || *p == '\t')
            p++;
        e = p + strlen(p);
        while (e > p && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
            *--e = 0;
        if (!*p || *p == '#' || *p == ';')
            continue;
        if (n >= QN_RANGE_MAX) {
            range_error(out, "range file has more than %u prefixes", QN_RANGE_MAX);
            fclose(f);
            return false;
        }
        if (!qn_cidr_parse(p, &prefix) || prefix.af != AF_INET) {
            range_error(out, "invalid IPv4 prefix at line %u", lineno);
            fclose(f);
            return false;
        }
        for (uint32_t i = 0; i < n; i++) {
            if (ranges_overlap(&prefixes[i], &prefix)) {
                range_error(out, "duplicate or overlapping prefix at line %u", lineno);
                fclose(f);
                return false;
            }
        }
        if (UINT64_MAX - candidates < prefix.count) {
            range_error(out, "candidate count overflow at line %u", lineno);
            fclose(f);
            return false;
        }
        prefixes[n++] = prefix;
        candidates += prefix.count;
    }

    if (ferror(f)) {
        range_error(out, "could not read %s", path);
        fclose(f);
        return false;
    }
    if (fclose(f) != 0) {
        range_error(out, "could not close %s", path);
        return false;
    }
    if (!n || !candidates) {
        range_error(out, "range file contains no usable IPv4 prefixes");
        return false;
    }
    out->prefixes = n;
    out->candidates = candidates;
    return true;
}

bool qn_cf_ranges_cached(qn_cf_ranges_info *out)
{
    char path[QN_PATH_CAP];

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!qn_cf_ranges_default_path(path, sizeof path)) {
        range_error(out, "HOME or XDG_CACHE_HOME is not an absolute path");
        return false;
    }
    if (!qn_cf_ranges_inspect(path, out))
        return false;
    if (out->prefixes < QN_CF_MIN_PREFIXES || out->candidates < QN_CF_MIN_HOSTS) {
        range_error(out, "managed range cache is unexpectedly small");
        return false;
    }
    return true;
}

static bool mkdir_checked(const char *path)
{
    struct stat st;

    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return false;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool make_parent_dirs(const char *path)
{
    char  dir[QN_PATH_CAP];
    char *slash;

    if (qn_strlcpy(dir, path, sizeof dir) >= sizeof dir)
        return false;
    slash = strrchr(dir, '/');
    if (!slash || slash == dir)
        return false;
    *slash = 0;
    for (char *p = dir + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = 0;
        if (!mkdir_checked(dir))
            return false;
        *p = '/';
    }
    return mkdir_checked(dir);
}

static bool find_curl(char *out, size_t outsz)
{
    static const char *const fallbacks[] = {
        "/data/data/com.termux/files/usr/bin/curl", "/usr/bin/curl", "/bin/curl"
    };
    const char *path = getenv("PATH");

    if (path) {
        const char *p = path;

        while (*p) {
            const char *e = strchr(p, ':');
            size_t      len = e ? (size_t)(e - p) : strlen(p);
            int         rc = -1;

            /* Relative and empty PATH entries are intentionally ignored. */
            if (len && *p == '/' && len <= (size_t)INT_MAX && len + 6u < outsz)
                rc = snprintf(out, outsz, "%.*s/curl", (int)len, p);
            if (rc > 0 && (size_t)rc < outsz && access(out, X_OK) == 0)
                return true;
            if (!e)
                break;
            p = e + 1;
        }
    }
    for (uint32_t i = 0; i < QN_ARRAY_LEN(fallbacks); i++) {
        if (access(fallbacks[i], X_OK) == 0) {
            qn_strlcpy(out, fallbacks[i], outsz);
            return true;
        }
    }
    return false;
}

#if defined(QN_STATIC_ANALYZER) && defined(__GNUC__) && !defined(__clang__)
/* stdout intentionally survives execv so curl owns the validated temporary output. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-fd-leak"
#endif
static int download_ranges(const char *curl, int output_fd)
{
    const char *const argv[] = {
        curl, "--fail", "--silent", "--show-error", "--location",
        "--proto", "=https", "--proto-redir", "=https",
        "--connect-timeout", "8", "--max-time", "20", "--retry", "1",
        "--retry-max-time", "25", "--max-filesize", "65536",
        "--user-agent", QN_NAME "/" QN_VERSION, QN_CF_RANGES_URL, NULL
    };
    pid_t pid;
    int   status;

    pid = fork();
    if (pid == 0) {
        struct rlimit limit = { QN_RANGE_FILE_MAX, QN_RANGE_FILE_MAX };
        int nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);

        (void)setrlimit(RLIMIT_FSIZE, &limit);
        if (dup2(output_fd, STDOUT_FILENO) < 0)
            _exit(126);
        if (nullfd >= 0)
            (void)dup2(nullfd, STDERR_FILENO);
        if (output_fd != STDOUT_FILENO)
            close(output_fd);
        if (nullfd >= 0 && nullfd != STDERR_FILENO)
            close(nullfd);
        execv(curl, (char *const *)(void *)argv);
        /* execv failure keeps this image alive, so close its duplicated output. */
        close(STDOUT_FILENO);
        _exit(127);
    }
    if (pid < 0)
        return -1;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (!WIFEXITED(status))
        return 128;
    return WEXITSTATUS(status);
}
#if defined(QN_STATIC_ANALYZER) && defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

static void sync_parent(const char *path)
{
    char  dir[QN_PATH_CAP];
    char *slash;
    int   fd;

    if (qn_strlcpy(dir, path, sizeof dir) >= sizeof dir)
        return;
    slash = strrchr(dir, '/');
    if (!slash)
        return;
    *slash = 0;
    fd = open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (fd >= 0) {
        (void)fsync(fd);
        close(fd);
    }
}

bool qn_cf_ranges_update(qn_cf_ranges_info *out)
{
    qn_cf_ranges_info check;
    struct stat       st;
    char              curl[QN_PATH_CAP], tmp[QN_PATH_CAP], lock_path[QN_PATH_CAP];
    int               tmpfd = -1, lockfd = -1, rc;
    bool              tmp_live = false, ok = false;

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!qn_cf_ranges_default_path(out->path, sizeof out->path)) {
        range_error(out, "HOME or XDG_CACHE_HOME is not an absolute path");
        return false;
    }
    if (!make_parent_dirs(out->path)) {
        range_error(out, "could not create the range-cache directory: %s", strerror(errno));
        return false;
    }
    if (!find_curl(curl, sizeof curl)) {
        range_error(out, "curl was not found; in Termux run: pkg install curl");
        return false;
    }
    if (!path_suffix(lock_path, sizeof lock_path, out->path, ".lock") ||
        !path_suffix(tmp, sizeof tmp, out->path, ".tmp.XXXXXX")) {
        range_error(out, "range-cache path is too long");
        return false;
    }

    lockfd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lockfd < 0 || flock(lockfd, LOCK_EX) != 0) {
        range_error(out, "could not lock the range cache: %s", strerror(errno));
        goto done;
    }
    tmpfd = mkstemp(tmp);
    if (tmpfd < 0) {
        range_error(out, "could not create a temporary range file: %s", strerror(errno));
        goto done;
    }
    tmp_live = true;
    (void)fcntl(tmpfd, F_SETFD, FD_CLOEXEC);

    rc = download_ranges(curl, tmpfd);
    if (rc != 0) {
        range_error(out, "Cloudflare range download failed (curl exit %d)", rc);
        goto done;
    }
    if (fstat(tmpfd, &st) != 0 || st.st_size <= 0 || st.st_size > (off_t)QN_RANGE_FILE_MAX) {
        range_error(out, "downloaded range list has an invalid size");
        goto done;
    }
    if (fsync(tmpfd) != 0) {
        range_error(out, "could not sync the downloaded range list: %s", strerror(errno));
        goto done;
    }
    close(tmpfd);
    tmpfd = -1;

    if (!qn_cf_ranges_inspect(tmp, &check)) {
        range_error(out, "downloaded range list was rejected: %s", check.error);
        goto done;
    }
    if (check.prefixes < QN_CF_MIN_PREFIXES || check.candidates < QN_CF_MIN_HOSTS) {
        range_error(out, "downloaded range list is unexpectedly small");
        goto done;
    }
    if (rename(tmp, out->path) != 0) {
        range_error(out, "could not install the updated range list: %s", strerror(errno));
        goto done;
    }
    tmp_live = false;
    sync_parent(out->path);
    out->prefixes = check.prefixes;
    out->candidates = check.candidates;
    out->error[0] = 0;
    ok = true;

done:
    if (tmpfd >= 0)
        close(tmpfd);
    if (tmp_live)
        (void)unlink(tmp);
    if (lockfd >= 0) {
        (void)flock(lockfd, LOCK_UN);
        close(lockfd);
    }
    return ok;
}
