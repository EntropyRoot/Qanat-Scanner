#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qanat/cpuinfo.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<sys/auxv.h>)
#include <sys/auxv.h>
#define QN_HAVE_AUXV 1
#endif
#endif

#ifndef HWCAP_ASIMD
#define HWCAP_ASIMD (1u << 1)
#endif
#ifndef HWCAP_CRC32
#define HWCAP_CRC32 (1u << 7)
#endif
#ifndef HWCAP_ASIMDDP
#define HWCAP_ASIMDDP (1u << 20)
#endif

static bool read_u32_file(const char *path, uint32_t *out)
{
    char buf[32];
    int  fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n;

    if (fd < 0)
        return false;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return false;
    buf[n] = '\0';
    *out   = (uint32_t)strtoul(buf, NULL, 10);
    return true;
}

static void read_soc_name(char *dst, size_t cap)
{
    FILE *f = fopen("/proc/cpuinfo", "r");
    char  line[256];

    dst[0] = '\0';
    if (!f)
        return;

    while (fgets(line, sizeof line, f)) {
        const char *key = NULL;
        if (!strncmp(line, "Hardware", 8))
            key = "Hardware";
        else if (!strncmp(line, "model name", 10))
            key = "model name";
        if (!key)
            continue;
        {
            char *colon = strchr(line, ':');
            char *e;
            if (!colon)
                continue;
            colon++;
            while (*colon == ' ' || *colon == '\t')
                colon++;
            e = colon + strlen(colon);
            while (e > colon && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' '))
                *--e = '\0';
            if (*colon) {
                qn_strlcpy(dst, colon, cap);
                if (!strcmp(key, "Hardware"))
                    break;
            }
        }
    }
    fclose(f);
}

static void sort_clusters(qn_topology *t)
{
    for (uint32_t i = 1; i < t->nclusters; i++) {
        for (uint32_t j = i; j && t->cluster[j].khz > t->cluster[j - 1].khz; j--) {
            qn_cluster tmp    = t->cluster[j];
            t->cluster[j]     = t->cluster[j - 1];
            t->cluster[j - 1] = tmp;
        }
    }
}

void qn_topology_detect(qn_topology *t)
{
    long nconf;

    memset(t, 0, sizeof *t);

    nconf = sysconf(_SC_NPROCESSORS_CONF);
    if (nconf < 1)
        nconf = 1;
    t->ncpu = (uint32_t)QN_MIN(nconf, QN_MAX_CPUS);

    for (uint32_t i = 0; i < t->ncpu; i++) {
        char     path[128];
        uint32_t v = 0;

        t->cpu[i].id = i;

        snprintf(path, sizeof path, "/sys/devices/system/cpu/cpu%u/cpufreq/cpuinfo_max_freq", i);
        if (!read_u32_file(path, &v) || !v) {
            snprintf(path, sizeof path, "/sys/devices/system/cpu/cpu%u/cpufreq/scaling_max_freq", i);
            if ((!read_u32_file(path, &v) || !v)) {
                snprintf(path, sizeof path, "/sys/devices/system/cpu/cpu%u/cpu_capacity", i);
                (void)read_u32_file(path, &v);
            }
        }
        t->cpu[i].max_khz = v;

        snprintf(path, sizeof path, "/sys/devices/system/cpu/cpu%u/online", i);
        if (read_u32_file(path, &v))
            t->cpu[i].online = (uint8_t)(v != 0);
        else
            t->cpu[i].online = 1;

        if (t->cpu[i].online)
            t->nonline++;
    }

    for (uint32_t i = 0; i < t->ncpu; i++) {
        uint32_t khz = t->cpu[i].max_khz;
        uint32_t c;

        if (!t->cpu[i].online)
            continue;

        for (c = 0; c < t->nclusters; c++) {
            /* Merge sibling cores that differ by at most one bin. */
            uint32_t a = t->cluster[c].khz, b = khz;
            uint32_t d = a > b ? a - b : b - a;
            if (a && b && d * 20u <= a)
                break;
            if (a == b)
                break;
        }
        if (c == t->nclusters) {
            if (t->nclusters >= QN_MAX_CLUSTERS)
                c = t->nclusters - 1;
            else {
                t->cluster[c].khz   = khz;
                t->cluster[c].first = i;
                t->nclusters++;
            }
        }
        t->cpu[i].cluster = (uint8_t)c;
        t->cluster[c].count++;
        t->cluster[c].mask |= (1u << i);
    }

    sort_clusters(t);
    for (uint32_t c = 0; c < t->nclusters; c++)
        for (uint32_t i = 0; i < t->ncpu; i++)
            if (t->cluster[c].mask & (1u << i))
                t->cpu[i].cluster = (uint8_t)c;

    if (!t->nclusters) {
        t->nclusters        = 1;
        t->cluster[0].count = 1;
        t->cluster[0].mask  = 1u;
    }
    t->perf_mask     = t->cluster[0].mask;
    t->perf_count    = t->nclusters ? t->cluster[0].count : 1u;
    t->heterogeneous = t->nclusters > 1;

#if defined(QN_HAVE_AUXV) && defined(__aarch64__)
    {
        unsigned long hw = getauxval(AT_HWCAP);
        t->has_neon     = (hw & HWCAP_ASIMD) != 0;
        t->has_crc32    = (hw & HWCAP_CRC32) != 0;
        t->has_asimddp  = (hw & HWCAP_ASIMDDP) != 0;
    }
#else
#if defined(__ARM_NEON) || defined(__aarch64__)
    t->has_neon = true;
#endif
#endif

    read_soc_name(t->soc, sizeof t->soc);
}

uint32_t qn_topology_workers(const qn_topology *t, bool io_bound)
{
    uint32_t n;

    if (!t->heterogeneous)
        return QN_CLAMP(t->nonline ? t->nonline : 1u, 1u, 16u);

    n = t->perf_count;
    /* I/O workers also use the mid cluster, never the slowest one. */
    if (io_bound && t->nclusters > 1)
        n += t->cluster[1].count;

    return QN_CLAMP(n, 2u, 16u);
}

bool qn_pin_thread(uint32_t cpu)
{
    cpu_set_t set;

    if (cpu >= (uint32_t)CPU_SETSIZE)
        return false;
    CPU_ZERO(&set);
    CPU_SET((size_t)cpu, &set);
    return sched_setaffinity(0, sizeof set, &set) == 0;
}

bool qn_pin_thread_mask(uint32_t mask)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    for (uint32_t i = 0; i < QN_MAX_CPUS && i < (uint32_t)CPU_SETSIZE; i++)
        if (mask & (1u << i))
            CPU_SET((size_t)i, &set);
    return sched_setaffinity(0, sizeof set, &set) == 0;
}

/* A phone's hottest zone is usually the battery, so only CPU and SoC count. */
static bool cpu_thermal_zone(const char *type)
{
    static const char *const want[] = { "cpu", "soc", "tsens", "apc", "package",
                                        "pkg", "coretemp", "gold", "silver",
                                        "prime", "big", "little" };
    size_t i;

    for (i = 0; i < sizeof want / sizeof want[0]; i++)
        if (strstr(type, want[i]))
            return true;
    return false;
}

static bool read_zone_type(uint32_t z, char *out, size_t cap)
{
    char  path[96];
    FILE *f;
    char *nl;

    if (snprintf(path, sizeof path, "/sys/class/thermal/thermal_zone%u/type", z) <= 0)
        return false;
    f = fopen(path, "r");
    if (!f)
        return false;
    if (!fgets(out, (int)cap, f)) {
        fclose(f);
        return false;
    }
    fclose(f);
    nl = strchr(out, '\n');
    if (nl)
        *nl = '\0';
    for (nl = out; *nl; nl++)
        if (*nl >= 'A' && *nl <= 'Z')
            *nl = (char)(*nl + ('a' - 'A'));
    return true;
}

/* Millidegrees from the hottest recognised CPU zone, or 0 when none is. */
uint32_t qn_thermal_read(void)
{
    uint32_t best = 0;

    for (uint32_t z = 0; z < 24; z++) {
        char     path[96], type[64];
        uint32_t v = 0;

        if (!read_zone_type(z, type, sizeof type) || !cpu_thermal_zone(type))
            continue;
        snprintf(path, sizeof path, "/sys/class/thermal/thermal_zone%u/temp", z);
        if (!read_u32_file(path, &v))
            continue;
        if (v > 1000000u)
            continue;
        if (v < 1000u)
            v *= 1000u;
        if (v > best && v < 150000u)
            best = v;
    }
    return best;
}

uint32_t qn_raise_nofile(void)
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return 1024;

    if (rl.rlim_cur < rl.rlim_max) {
        struct rlimit want = rl;
        want.rlim_cur      = rl.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &want) == 0)
            rl = want;
    }
    if (rl.rlim_cur == RLIM_INFINITY)
        return 65536;
    return (uint32_t)QN_MIN((uint64_t)rl.rlim_cur, 1048576ull);
}
