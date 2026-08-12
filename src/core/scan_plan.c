#include "qanat/scan_plan.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define QN_MIB (UINT64_C(1) << 20)
#define QN_PLAN_FD_RESERVE UINT64_C(64)
#define QN_PLAN_TUNNEL_FDS UINT64_C(3)
#define QN_PLAN_TUNNEL_WORKER_BYTES UINT64_C(65536)

static bool add_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a > UINT64_MAX - b)
        return false;
    *out = a + b;
    return true;
}

static bool mul_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a && b > UINT64_MAX / a)
        return false;
    *out = a * b;
    return true;
}

static bool text_eq(const char *a, const char *b)
{
    if (!a || !b)
        return false;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return false;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

const char *qn_scan_mode_str(qn_scan_mode mode)
{
    switch (mode) {
    case QN_SCAN_AUTO:      return "auto";
    case QN_SCAN_FULL:      return "full";
    case QN_SCAN_COVERAGE:  return "coverage";
    case QN_SCAN_BUDGET:    return "budget";
    case QN_SCAN_REACHABLE: return "reachable";
    default:                return "invalid";
    }
}

const char *qn_selection_str(qn_selection_policy policy)
{
    switch (policy) {
    case QN_SELECTION_UNIFORM:    return "uniform";
    case QN_SELECTION_STRATIFIED: return "stratified";
    case QN_SELECTION_ADAPTIVE:   return "adaptive";
    case QN_SELECTION_HYBRID:     return "hybrid";
    default:                      return "invalid";
    }
}

const char *qn_rank_policy_str(qn_rank_policy policy)
{
    switch (policy) {
    case QN_RANK_BALANCED:   return "balanced";
    case QN_RANK_LATENCY:    return "latency";
    case QN_RANK_STABILITY:  return "stability";
    case QN_RANK_THROUGHPUT: return "throughput";
    default:                 return "invalid";
    }
}

bool qn_scan_mode_parse(const char *text, qn_scan_mode *mode)
{
    if (!mode)
        return false;
    for (int i = QN_SCAN_AUTO; i <= QN_SCAN_REACHABLE; i++) {
        if (text_eq(text, qn_scan_mode_str((qn_scan_mode)i))) {
            *mode = (qn_scan_mode)i;
            return true;
        }
    }
    return false;
}

bool qn_selection_parse(const char *text, qn_selection_policy *policy)
{
    if (!policy)
        return false;
    for (int i = QN_SELECTION_UNIFORM; i <= QN_SELECTION_HYBRID; i++) {
        if (text_eq(text, qn_selection_str((qn_selection_policy)i))) {
            *policy = (qn_selection_policy)i;
            return true;
        }
    }
    return false;
}

bool qn_rank_policy_parse(const char *text, qn_rank_policy *policy)
{
    if (!policy)
        return false;
    for (int i = QN_RANK_BALANCED; i <= QN_RANK_THROUGHPUT; i++) {
        if (text_eq(text, qn_rank_policy_str((qn_rank_policy)i))) {
            *policy = (qn_rank_policy)i;
            return true;
        }
    }
    return false;
}

void qn_scan_request_defaults(qn_scan_request *request)
{
    if (!request)
        return;
    *request = (qn_scan_request)QN_SCAN_REQUEST_INIT;
}

static bool request_error(char *error, size_t capacity, const char *message)
{
    if (error && capacity)
        (void)snprintf(error, capacity, "%s", message);
    return false;
}

bool qn_scan_request_validate(const qn_scan_request *request,
                              char *error, size_t error_capacity)
{
    if (error && error_capacity)
        error[0] = '\0';
    if (!request)
        return request_error(error, error_capacity, "scan request is missing");
    if (request->mode < QN_SCAN_AUTO || request->mode > QN_SCAN_REACHABLE)
        return request_error(error, error_capacity, "Scan Scope is invalid");
    if (request->selection < QN_SELECTION_UNIFORM ||
        request->selection > QN_SELECTION_HYBRID)
        return request_error(error, error_capacity, "Address Selection is invalid");
    if (request->rank_by < QN_RANK_BALANCED ||
        request->rank_by > QN_RANK_THROUGHPUT)
        return request_error(error, error_capacity, "Rank By is invalid");
    if (request->coverage_ppm < 100u ||
        request->coverage_ppm > QN_COVERAGE_SCALE)
        return request_error(error, error_capacity, "Coverage must be from 0.01% to 100%");
    if (request->explore_percent > 100u)
        return request_error(error, error_capacity, "Explore Percent must be from 0 to 100");
    if (request->mode == QN_SCAN_BUDGET && !request->address_budget)
        return request_error(error, error_capacity, "Address Budget must be greater than zero");
    if (request->mode == QN_SCAN_REACHABLE && !request->reachable_target)
        return request_error(error, error_capacity, "Reachable Target must be greater than zero");
    if (!request->candidate_auto &&
        (!request->candidate_capacity || request->candidate_capacity > UINT32_MAX))
        return request_error(error, error_capacity,
                             "Candidate Capacity must be from 1 to 4294967295");
    if (request->finalists_all && request->finalists_auto)
        return request_error(error, error_capacity,
                             "Finalist Count cannot be both Auto and All Candidates");
    if (!request->finalists_all && !request->finalists_auto &&
        (!request->finalist_limit || request->finalist_limit > UINT32_MAX))
        return request_error(error, error_capacity,
                             "Finalist Count must be from 1 to 4294967295");
    if (!request->candidate_auto && !request->finalists_auto &&
        !request->finalists_all &&
        request->finalist_limit > request->candidate_capacity)
        return request_error(error, error_capacity,
                             "Finalist Count cannot exceed Candidate Capacity");
    if (request->mode == QN_SCAN_REACHABLE && !request->candidate_auto &&
        request->reachable_target > request->candidate_capacity)
        return request_error(error, error_capacity,
                             "Reachable Target cannot exceed Candidate Capacity");
    if (!request->output_all &&
        (!request->output_limit || request->output_limit > UINT32_MAX))
        return request_error(error, error_capacity,
                             "Output Top must be from 1 to 4294967295 or All Verified");
    if (!request->memory_auto && !request->memory_budget_bytes)
        return request_error(error, error_capacity, "Memory Budget must be greater than zero");
    if ((!request->scan_concurrency_auto && !request->scan_concurrency) ||
        (!request->verify_concurrency_auto && !request->verify_concurrency) ||
        (!request->stability_concurrency_auto && !request->stability_concurrency))
        return request_error(error, error_capacity, "Concurrency must be greater than zero");
    if (request->tunnel_enabled && !request->tunnel_all && !request->tunnel_target)
        return request_error(error, error_capacity,
                             "Tunnel Target must be greater than zero or All");
    if (request->tunnel_enabled &&
        (!request->tunnel_concurrency || request->tunnel_concurrency > 32u))
        return request_error(error, error_capacity,
                             "Tunnel Concurrency must be from 1 to 32");
    if (request->tunnel_enabled &&
        (!request->tunnel_attempts || request->tunnel_attempts > 2u))
        return request_error(error, error_capacity,
                             "Tunnel Attempts must be from 1 to 2");
    return true;
}

const char *qn_scan_preset_str(qn_scan_preset preset)
{
    switch (preset) {
    case QN_PRESET_CUSTOM:   return "custom";
    case QN_PRESET_QUICK:    return "quick";
    case QN_PRESET_BALANCED: return "balanced";
    case QN_PRESET_DEEP:     return "deep";
    case QN_PRESET_FULL:     return "full";
    default:                 return "invalid";
    }
}

void qn_scan_preset_apply(qn_scan_request *request, qn_scan_preset preset)
{
    if (!request || preset == QN_PRESET_CUSTOM)
        return;
    qn_scan_request_defaults(request);
    request->selection = QN_SELECTION_HYBRID;
    switch (preset) {
    case QN_PRESET_QUICK:
        request->mode = QN_SCAN_COVERAGE;
        request->coverage_ppm = 10000u;
        request->finalists_auto = false;
        request->finalist_limit = 64u;
        request->output_limit = 20u;
        break;
    case QN_PRESET_BALANCED:
        request->mode = QN_SCAN_COVERAGE;
        request->coverage_ppm = 100000u;
        request->candidate_auto = false;
        request->candidate_capacity = 16384u;
        request->finalists_auto = false;
        request->finalist_limit = 256u;
        request->output_limit = 50u;
        break;
    case QN_PRESET_DEEP:
        request->mode = QN_SCAN_COVERAGE;
        request->coverage_ppm = 250000u;
        request->candidate_auto = false;
        request->candidate_capacity = 65536u;
        request->finalists_auto = false;
        request->finalist_limit = 1024u;
        request->output_limit = 100u;
        break;
    case QN_PRESET_FULL:
        request->mode = QN_SCAN_FULL;
        request->output_limit = 100u;
        break;
    default:
        break;
    }
}

bool qn_scan_request_equal(const qn_scan_request *a, const qn_scan_request *b)
{
    return a && b && a->mode == b->mode && a->selection == b->selection &&
           a->rank_by == b->rank_by && a->coverage_ppm == b->coverage_ppm &&
           a->explore_percent == b->explore_percent &&
           a->address_budget == b->address_budget &&
           a->reachable_target == b->reachable_target &&
           a->candidate_capacity == b->candidate_capacity &&
           a->finalist_limit == b->finalist_limit &&
           a->output_limit == b->output_limit &&
           a->memory_budget_bytes == b->memory_budget_bytes &&
           a->scan_concurrency == b->scan_concurrency &&
           a->verify_concurrency == b->verify_concurrency &&
           a->stability_concurrency == b->stability_concurrency &&
           a->tunnel_target == b->tunnel_target &&
           a->tunnel_concurrency == b->tunnel_concurrency &&
           a->tunnel_attempts == b->tunnel_attempts &&
           a->candidate_auto == b->candidate_auto &&
           a->finalists_auto == b->finalists_auto &&
           a->finalists_all == b->finalists_all &&
           a->output_all == b->output_all && a->memory_auto == b->memory_auto &&
           a->scan_concurrency_auto == b->scan_concurrency_auto &&
           a->verify_concurrency_auto == b->verify_concurrency_auto &&
           a->stability_concurrency_auto == b->stability_concurrency_auto &&
           a->tunnel_enabled == b->tunnel_enabled &&
           a->tunnel_all == b->tunnel_all;
}

qn_scan_preset qn_scan_preset_detect(const qn_scan_request *request)
{
    qn_scan_request expected;

    if (!request)
        return QN_PRESET_CUSTOM;
    for (int preset = QN_PRESET_QUICK; preset <= QN_PRESET_FULL; preset++) {
        qn_scan_preset_apply(&expected, (qn_scan_preset)preset);
        if (qn_scan_request_equal(request, &expected))
            return (qn_scan_preset)preset;
    }
    return QN_PRESET_CUSTOM;
}

typedef enum {
    QN_SETTING_MODE = 0,
    QN_SETTING_SELECTION,
    QN_SETTING_RANK,
    QN_SETTING_U32,
    QN_SETTING_U64,
    QN_SETTING_BOOL
} qn_setting_kind;

typedef struct {
    const char      *name;
    qn_setting_kind kind;
    size_t           offset;
    uint64_t         maximum;
} qn_setting_desc;

#define QN_SETTING(name_, kind_, member_, max_) \
    { name_, kind_, offsetof(qn_scan_request, member_), max_ }

static const qn_setting_desc setting_desc[] = {
    QN_SETTING("mode", QN_SETTING_MODE, mode, QN_SCAN_REACHABLE),
    QN_SETTING("selection", QN_SETTING_SELECTION, selection, QN_SELECTION_HYBRID),
    QN_SETTING("rank_by", QN_SETTING_RANK, rank_by, QN_RANK_THROUGHPUT),
    QN_SETTING("coverage_ppm", QN_SETTING_U32, coverage_ppm, QN_COVERAGE_SCALE),
    QN_SETTING("explore_percent", QN_SETTING_U32, explore_percent, 100u),
    QN_SETTING("address_budget", QN_SETTING_U64, address_budget, UINT64_MAX),
    QN_SETTING("reachable_target", QN_SETTING_U64, reachable_target, UINT64_MAX),
    QN_SETTING("candidate_capacity", QN_SETTING_U64, candidate_capacity, UINT32_MAX),
    QN_SETTING("finalist_limit", QN_SETTING_U64, finalist_limit, UINT32_MAX),
    QN_SETTING("output_limit", QN_SETTING_U64, output_limit, UINT32_MAX),
    QN_SETTING("memory_budget_bytes", QN_SETTING_U64, memory_budget_bytes, UINT64_MAX),
    QN_SETTING("scan_concurrency", QN_SETTING_U32, scan_concurrency, UINT32_MAX),
    QN_SETTING("verify_concurrency", QN_SETTING_U32, verify_concurrency, UINT32_MAX),
    QN_SETTING("stability_concurrency", QN_SETTING_U32, stability_concurrency, UINT32_MAX),
    QN_SETTING("tunnel_target", QN_SETTING_U64, tunnel_target, UINT32_MAX),
    QN_SETTING("tunnel_concurrency", QN_SETTING_U32, tunnel_concurrency, 32u),
    QN_SETTING("tunnel_attempts", QN_SETTING_U32, tunnel_attempts, 2u),
    QN_SETTING("candidate_auto", QN_SETTING_BOOL, candidate_auto, 1u),
    QN_SETTING("finalists_auto", QN_SETTING_BOOL, finalists_auto, 1u),
    QN_SETTING("finalists_all", QN_SETTING_BOOL, finalists_all, 1u),
    QN_SETTING("output_all", QN_SETTING_BOOL, output_all, 1u),
    QN_SETTING("memory_auto", QN_SETTING_BOOL, memory_auto, 1u),
    QN_SETTING("scan_concurrency_auto", QN_SETTING_BOOL, scan_concurrency_auto, 1u),
    QN_SETTING("verify_concurrency_auto", QN_SETTING_BOOL, verify_concurrency_auto, 1u),
    QN_SETTING("stability_concurrency_auto", QN_SETTING_BOOL,
               stability_concurrency_auto, 1u),
    QN_SETTING("tunnel_enabled", QN_SETTING_BOOL, tunnel_enabled, 1u),
    QN_SETTING("tunnel_all", QN_SETTING_BOOL, tunnel_all, 1u)
};

#undef QN_SETTING

static bool decimal_u64(const char *text, uint64_t *value)
{
    char *end;
    unsigned long long parsed;

    if (!text || !*text || *text == '+' || *text == '-' || !value)
        return false;
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno == ERANGE || *end)
        return false;
    *value = (uint64_t)parsed;
    return true;
}

static uint64_t setting_get(const qn_scan_request *request,
                            const qn_setting_desc *desc)
{
    const uint8_t *base = (const uint8_t *)(const void *)request + desc->offset;

    switch (desc->kind) {
    case QN_SETTING_MODE:      return (uint64_t)*(const qn_scan_mode *)(const void *)base;
    case QN_SETTING_SELECTION: return (uint64_t)*(const qn_selection_policy *)(const void *)base;
    case QN_SETTING_RANK:      return (uint64_t)*(const qn_rank_policy *)(const void *)base;
    case QN_SETTING_U32:       return *(const uint32_t *)(const void *)base;
    case QN_SETTING_U64:       return *(const uint64_t *)(const void *)base;
    case QN_SETTING_BOOL:      return *(const bool *)(const void *)base ? 1u : 0u;
    default:                   return 0u;
    }
}

static void setting_put(qn_scan_request *request, const qn_setting_desc *desc,
                        uint64_t value)
{
    uint8_t *base = (uint8_t *)(void *)request + desc->offset;

    switch (desc->kind) {
    case QN_SETTING_MODE:      *(qn_scan_mode *)(void *)base = (qn_scan_mode)value; break;
    case QN_SETTING_SELECTION: *(qn_selection_policy *)(void *)base = (qn_selection_policy)value; break;
    case QN_SETTING_RANK:      *(qn_rank_policy *)(void *)base = (qn_rank_policy)value; break;
    case QN_SETTING_U32:       *(uint32_t *)(void *)base = (uint32_t)value; break;
    case QN_SETTING_U64:       *(uint64_t *)(void *)base = value; break;
    case QN_SETTING_BOOL:      *(bool *)(void *)base = value != 0u; break;
    }
}

bool qn_scan_settings_default_path(char *path, size_t capacity)
{
    const char *base = getenv("XDG_CONFIG_HOME");
    const char *home;
    int length;

    if (!path || !capacity)
        return false;
    if (base && *base)
        length = snprintf(path, capacity, "%s/qanat/scan-plan.conf", base);
    else {
        home = getenv("HOME");
        if (!home || !*home)
            return false;
        length = snprintf(path, capacity, "%s/.config/qanat/scan-plan.conf", home);
    }
    return length >= 0 && (size_t)length < capacity;
}

static bool create_parent_directories(const char *path)
{
    char copy[PATH_MAX];
    size_t length;

    if (!path)
        return false;
    length = strlen(path);
    if (!length || length >= sizeof copy)
        return false;
    memcpy(copy, path, length + 1u);
    for (char *p = copy + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(copy, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return true;
}

static bool sync_parent_directory(const char *path)
{
    char parent[PATH_MAX];
    char *slash;
    int fd;
    bool ok;

    if (strlen(path) >= sizeof parent)
        return false;
    strcpy(parent, path);
    slash = strrchr(parent, '/');
    if (slash) {
        if (slash == parent)
            slash[1] = '\0';
        else
            *slash = '\0';
    } else {
        strcpy(parent, ".");
    }
    fd = open(parent, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (fd < 0)
        return false;
    ok = fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    return ok;
}

bool qn_scan_settings_save(const char *path, const qn_scan_request *request,
                           char *error, size_t error_capacity)
{
    char temp[PATH_MAX];
    int fd, length;
    FILE *file;
    bool ok = true;

    if (!qn_scan_request_validate(request, error, error_capacity))
        return false;
    if (!path || !*path || !create_parent_directories(path))
        return request_error(error, error_capacity, "cannot create the settings directory");
    length = snprintf(temp, sizeof temp, "%s.tmp.XXXXXX", path);
    if (length < 0 || (size_t)length >= sizeof temp)
        return request_error(error, error_capacity, "settings path is too long");
    fd = mkstemp(temp);
    if (fd < 0)
        return request_error(error, error_capacity, "cannot create the temporary settings file");
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        unlink(temp);
        return request_error(error, error_capacity, "cannot protect the temporary settings file");
    }
    file = fdopen(fd, "w");
    if (!file) {
        close(fd);
        unlink(temp);
        return request_error(error, error_capacity, "cannot open the temporary settings stream");
    }
    if (fprintf(file, "version=%u\n", QN_SCAN_SETTINGS_VERSION) < 0)
        ok = false;
    for (size_t i = 0u; ok && i < sizeof setting_desc / sizeof setting_desc[0]; i++)
        if (fprintf(file, "%s=%" PRIu64 "\n", setting_desc[i].name,
                    setting_get(request, &setting_desc[i])) < 0)
            ok = false;
    if (ok && fflush(file) != 0)
        ok = false;
    if (ok && fsync(fd) != 0)
        ok = false;
    if (fclose(file) != 0)
        ok = false;
    if (!ok) {
        unlink(temp);
        return request_error(error, error_capacity, "cannot write the settings file completely");
    }
    if (rename(temp, path) != 0) {
        unlink(temp);
        return request_error(error, error_capacity, "cannot replace the settings file atomically");
    }
    if (!sync_parent_directory(path))
        return request_error(error, error_capacity, "settings saved but directory sync failed");
    if (error && error_capacity)
        error[0] = '\0';
    return true;
}

static const qn_setting_desc *setting_find(const char *name, size_t *index)
{
    for (size_t i = 0u; i < sizeof setting_desc / sizeof setting_desc[0]; i++) {
        if (!strcmp(name, setting_desc[i].name)) {
            if (index)
                *index = i;
            return &setting_desc[i];
        }
    }
    return NULL;
}

static uint64_t settings_mask(bool tunnel)
{
    uint64_t mask = 0u;

    for (size_t i = 0u; i < sizeof setting_desc / sizeof setting_desc[0]; i++) {
        bool is_tunnel = !strncmp(setting_desc[i].name, "tunnel_", 7u);

        if (is_tunnel == tunnel)
            mask |= UINT64_C(1) << i;
    }
    return mask;
}

bool qn_scan_settings_load(const char *path, qn_scan_request *request,
                           char *error, size_t error_capacity)
{
    qn_scan_request loaded;
    FILE *file;
    char *line = NULL;
    size_t line_capacity = 0u;
    uint64_t seen = 0u;
    uint64_t settings_version = 0u;
    bool version_seen = false;
    bool ok = true;

    if (!path || !*path || !request)
        return request_error(error, error_capacity, "settings path or destination is missing");
    file = fopen(path, "r");
    if (!file)
        return request_error(error, error_capacity, "cannot open the settings file");
    qn_scan_request_defaults(&loaded);
    for (;;) {
        ssize_t count = getline(&line, &line_capacity, file);
        char *equals;
        uint64_t value;
        size_t index;
        const qn_setting_desc *desc;

        if (count < 0)
            break;
        if ((size_t)count > 4096u || memchr(line, '\0', (size_t)count) != NULL) {
            ok = false;
            break;
        }
        while (count > 0 && (line[count - 1] == '\n' || line[count - 1] == '\r'))
            line[--count] = '\0';
        if (!count)
            continue;
        equals = strchr(line, '=');
        if (!equals || equals == line || strchr(equals + 1, '=')) {
            ok = false;
            break;
        }
        *equals++ = '\0';
        if (!decimal_u64(equals, &value)) {
            ok = false;
            break;
        }
        if (!strcmp(line, "version")) {
            if (version_seen || (value != 1u &&
                                 value != QN_SCAN_SETTINGS_VERSION)) {
                ok = false;
                break;
            }
            version_seen = true;
            settings_version = value;
            continue;
        }
        desc = setting_find(line, &index);
        if (!desc || index >= 64u || (seen & (UINT64_C(1) << index)) ||
            value > desc->maximum) {
            ok = false;
            break;
        }
        setting_put(&loaded, desc, value);
        seen |= UINT64_C(1) << index;
    }
    if (ferror(file) || fclose(file) != 0)
        ok = false;
    free(line);
    if (!version_seen)
        ok = false;
    else if (settings_version == QN_SCAN_SETTINGS_VERSION) {
        uint64_t all = (UINT64_C(1) <<
                        (sizeof setting_desc / sizeof setting_desc[0])) - 1u;

        if (seen != all)
            ok = false;
    } else {
        uint64_t tunnel = settings_mask(true);

        if (seen != settings_mask(false) || (seen & tunnel))
            ok = false;
        loaded.tunnel_enabled = false;
        loaded.tunnel_all = false;
        loaded.tunnel_target = 0u;
    }
    if (!ok)
        return request_error(error, error_capacity, "settings file is malformed or incomplete");
    if (!qn_scan_request_validate(&loaded, error, error_capacity))
        return false;
    *request = loaded;
    if (error && error_capacity)
        error[0] = '\0';
    return true;
}

bool qn_coverage_parse(const char *text, uint32_t *coverage_ppm)
{
    uint64_t whole = 0u, fraction = 0u;
    unsigned digits = 0u;
    const char *p;

    if (!text || !*text || !coverage_ppm || *text == '+' || *text == '-')
        return false;
    p = text;
    if (!isdigit((unsigned char)*p))
        return false;
    while (isdigit((unsigned char)*p)) {
        whole = whole * 10u + (uint64_t)(*p - '0');
        if (whole > 100u)
            return false;
        p++;
    }
    if (*p == '.') {
        p++;
        if (!isdigit((unsigned char)*p))
            return false;
        while (isdigit((unsigned char)*p)) {
            if (digits >= 4u)
                return false;
            fraction = fraction * 10u + (uint64_t)(*p - '0');
            digits++;
            p++;
        }
    }
    if (*p == '%')
        p++;
    if (*p)
        return false;
    while (digits < 4u) {
        fraction *= 10u;
        digits++;
    }
    fraction += whole * 10000u;
    if (fraction < 100u || fraction > QN_COVERAGE_SCALE)
        return false;
    *coverage_ppm = (uint32_t)fraction;
    return true;
}

bool qn_coverage_count(uint64_t total, uint32_t coverage_ppm, uint64_t *count)
{
    uint64_t whole, remainder, scaled_remainder, tail;

    if (!count || !total || coverage_ppm < 100u || coverage_ppm > QN_COVERAGE_SCALE)
        return false;
    whole = total / QN_COVERAGE_SCALE;
    remainder = total % QN_COVERAGE_SCALE;
    if (!mul_u64(whole, coverage_ppm, &whole) ||
        !mul_u64(remainder, coverage_ppm, &scaled_remainder))
        return false;
    tail = scaled_remainder / QN_COVERAGE_SCALE;
    if (scaled_remainder % QN_COVERAGE_SCALE)
        tail++;
    return add_u64(whole, tail, count);
}

bool qn_size_parse(const char *text, uint64_t *bytes)
{
    char *end;
    unsigned long long value;
    uint64_t multiplier = 1u;

    if (!text || !*text || !bytes || *text == '+' || *text == '-')
        return false;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (end == text || errno == ERANGE)
        return false;
    if (*end) {
        if (text_eq(end, "k") || text_eq(end, "kb") || text_eq(end, "kib"))
            multiplier = UINT64_C(1) << 10;
        else if (text_eq(end, "m") || text_eq(end, "mb") || text_eq(end, "mib"))
            multiplier = UINT64_C(1) << 20;
        else if (text_eq(end, "g") || text_eq(end, "gb") || text_eq(end, "gib"))
            multiplier = UINT64_C(1) << 30;
        else if (!text_eq(end, "b"))
            return false;
    }
    return mul_u64((uint64_t)value, multiplier, bytes);
}

static bool plan_error(qn_scan_plan *plan, const char *message)
{
    (void)snprintf(plan->error, sizeof plan->error, "%s", message);
    plan->valid = false;
    return false;
}

static uint64_t auto_memory(const qn_scan_environment *environment)
{
    uint64_t preferred = (environment->mobile ? 128u : 256u) * QN_MIB;

    if (environment->available_memory_bytes) {
        uint64_t safe = environment->available_memory_bytes / 2u;
        if (safe < preferred)
            preferred = safe;
    }
    return preferred;
}

static uint32_t auto_scan_concurrency(const qn_scan_environment *environment)
{
    uint64_t by_cpu = (uint64_t)(environment->cpu_count ? environment->cpu_count : 1u) * 32u;
    uint64_t by_fd = environment->fd_limit > QN_PLAN_FD_RESERVE
                         ? environment->fd_limit - QN_PLAN_FD_RESERVE
                         : 1u;

    if (by_cpu < 32u)
        by_cpu = 32u;
    return (uint32_t)(by_cpu < by_fd ? by_cpu : by_fd);
}

static uint32_t auto_verify_concurrency(const qn_scan_environment *environment)
{
    uint64_t value = (uint64_t)(environment->cpu_count ? environment->cpu_count : 1u) * 4u;
    uint64_t ceiling = environment->mobile ? 32u : 64u;
    uint64_t floor = environment->mobile ? 4u : 8u;

    if (value < floor)
        value = floor;
    if (value > ceiling)
        value = ceiling;
    return (uint32_t)value;
}

static uint32_t auto_stability_concurrency(const qn_scan_environment *environment)
{
    uint64_t value = (uint64_t)(environment->cpu_count ? environment->cpu_count : 1u) * 32u;
    uint64_t ceiling = environment->mobile ? 128u : 512u;

    if (value < 32u)
        value = 32u;
    if (value > ceiling)
        value = ceiling;
    return (uint32_t)value;
}

static bool resolve_scope(const qn_scan_request *request,
                          const qn_scan_environment *environment,
                          qn_scan_plan *plan)
{
    plan->requested_mode = request->mode;
    plan->mode = request->mode;
    plan->coverage_ppm = request->coverage_ppm;
    if (plan->mode == QN_SCAN_AUTO) {
        if (environment->total_addresses <= 65536u) {
            plan->mode = QN_SCAN_FULL;
        } else {
            plan->mode = QN_SCAN_COVERAGE;
            plan->coverage_ppm = 100000u;
        }
        plan->auto_adjusted = true;
    }
    switch (plan->mode) {
    case QN_SCAN_FULL:
        plan->planned_addresses = environment->total_addresses;
        plan->coverage_ppm = QN_COVERAGE_SCALE;
        plan->exact_full = true;
        break;
    case QN_SCAN_COVERAGE:
        if (!qn_coverage_count(environment->total_addresses, plan->coverage_ppm,
                               &plan->planned_addresses))
            return plan_error(plan, "coverage must be between 0.01% and 100%");
        if (plan->coverage_ppm == QN_COVERAGE_SCALE) {
            plan->mode = QN_SCAN_FULL;
            plan->exact_full = true;
        }
        break;
    case QN_SCAN_BUDGET:
        if (!request->address_budget)
            return plan_error(plan, "address budget must be greater than zero");
        plan->planned_addresses = request->address_budget < environment->total_addresses
                                      ? request->address_budget
                                      : environment->total_addresses;
        plan->exact_full = plan->planned_addresses == environment->total_addresses;
        break;
    case QN_SCAN_REACHABLE:
        if (!request->reachable_target || request->reachable_target > environment->total_addresses)
            return plan_error(plan, "reachable target must be within the loaded address set");
        plan->reachable_target = request->reachable_target;
        plan->planned_addresses = environment->total_addresses;
        break;
    default:
        return plan_error(plan, "invalid scan mode");
    }
    return true;
}

static bool resolve_concurrency(const qn_scan_request *request,
                                const qn_scan_environment *environment,
                                qn_scan_plan *plan)
{
    uint64_t available = environment->fd_limit > QN_PLAN_FD_RESERVE
                             ? environment->fd_limit - QN_PLAN_FD_RESERVE
                             : 0u;
    uint64_t verify_fds, tunnel_fds = 0u, phase_fds;

    plan->scan_concurrency = request->scan_concurrency_auto
                                 ? auto_scan_concurrency(environment)
                                 : request->scan_concurrency;
    plan->verify_concurrency = request->verify_concurrency_auto
                                   ? auto_verify_concurrency(environment)
                                   : request->verify_concurrency;
    plan->stability_concurrency = request->stability_concurrency_auto
                                      ? auto_stability_concurrency(environment)
                                      : request->stability_concurrency;
    if (!plan->scan_concurrency || !plan->verify_concurrency ||
        !plan->stability_concurrency)
        return plan_error(plan, "concurrency values must be greater than zero");
    if (available < 2u)
        return plan_error(plan, "file descriptor limit leaves fewer than two verifier slots");

    verify_fds = (uint64_t)plan->verify_concurrency + plan->stability_concurrency;
    if (request->tunnel_enabled &&
        !mul_u64(request->tunnel_concurrency, QN_PLAN_TUNNEL_FDS,
                 &tunnel_fds))
        return plan_error(plan, "tunnel file descriptor estimate overflowed");
    phase_fds = verify_fds > tunnel_fds ? verify_fds : tunnel_fds;
    if (tunnel_fds > available)
        return plan_error(plan, "Tunnel Concurrency exceeds the file descriptor budget");
    if (verify_fds > available) {
        if (!request->verify_concurrency_auto || !request->stability_concurrency_auto)
            return plan_error(plan, "requested verifier concurrency exceeds the file descriptor budget");
        plan->stability_concurrency = available > plan->verify_concurrency
                                          ? (uint32_t)(available - plan->verify_concurrency)
                                          : 1u;
        if ((uint64_t)plan->verify_concurrency + plan->stability_concurrency > available)
            plan->verify_concurrency = available > 1u ? (uint32_t)(available - 1u) : 1u;
        plan->auto_adjusted = true;
    }
    if (plan->scan_concurrency > available) {
        if (!request->scan_concurrency_auto)
            return plan_error(plan, "requested scan concurrency exceeds the file descriptor budget");
        plan->scan_concurrency = (uint32_t)available;
        plan->auto_adjusted = true;
    }
    phase_fds = (uint64_t)plan->verify_concurrency +
                plan->stability_concurrency;
    if (tunnel_fds > phase_fds)
        phase_fds = tunnel_fds;
    if ((uint64_t)plan->scan_concurrency > phase_fds)
        phase_fds = plan->scan_concurrency;
    plan->estimated_fds = QN_PLAN_FD_RESERVE + phase_fds;
    return true;
}

static bool memory_estimate(qn_scan_plan *plan,
                            const qn_scan_environment *environment)
{
    uint64_t slots, results, verifier, tunnel = 0u, tunnel_worker;
    uint64_t transient, candidate, working, page;

    if (!mul_u64(plan->candidate_capacity, environment->candidate_bytes, &candidate) ||
        !add_u64(candidate, environment->candidate_fixed_bytes, &candidate) ||
        !add_u64(plan->verify_concurrency, plan->stability_concurrency, &slots) ||
        !mul_u64(slots, environment->verifier_slot_bytes, &verifier) ||
        !mul_u64(plan->verification_batch_size, environment->verifier_result_bytes, &results) ||
        !add_u64(verifier, results, &verifier) ||
        !add_u64(verifier, environment->verifier_fixed_bytes, &verifier))
        return plan_error(plan, "resource plan arithmetic overflowed");
    if (plan->tunnel_enabled) {
        if (!add_u64(environment->verifier_slot_bytes,
                     environment->verifier_result_bytes, &tunnel_worker) ||
            !add_u64(tunnel_worker, environment->verifier_fixed_bytes,
                     &tunnel_worker) ||
            !add_u64(tunnel_worker, QN_PLAN_TUNNEL_WORKER_BYTES,
                     &tunnel_worker) ||
            !mul_u64(plan->tunnel_concurrency, tunnel_worker, &tunnel))
            return plan_error(plan, "tunnel resource plan arithmetic overflowed");
    }
    working = environment->working_bytes;
    page = environment->page_size ? environment->page_size : 4096u;
    if (page > 1u) {
        uint64_t remainder = candidate % page;

        if (remainder && !add_u64(candidate, page - remainder, &candidate))
            return plan_error(plan, "resource plan arithmetic overflowed");
        remainder = working % page;
        if (remainder && !add_u64(working, page - remainder, &working))
            return plan_error(plan, "resource plan arithmetic overflowed");
    }
    plan->estimated_candidate_bytes = candidate;
    plan->estimated_verifier_bytes = verifier;
    plan->estimated_tunnel_bytes = tunnel;
    plan->estimated_working_bytes = working;
    transient = verifier > tunnel ? verifier : tunnel;
    if (!add_u64(candidate, transient, &plan->estimated_total_bytes) ||
        !add_u64(plan->estimated_total_bytes, working,
                 &plan->estimated_total_bytes))
        return plan_error(plan, "resource plan arithmetic overflowed");
    return true;
}

bool qn_scan_plan_resolve(const qn_scan_request *request,
                          const qn_scan_environment *environment,
                          qn_scan_plan *plan)
{
    uint64_t candidate, finalist, output, batch;
    char request_message[192];

    if (!plan)
        return false;
    memset(plan, 0, sizeof *plan);
    plan->version = QN_SCAN_PLAN_VERSION;
    if (!request || !environment || !environment->total_addresses ||
        !environment->candidate_bytes || !environment->verifier_slot_bytes ||
        !environment->verifier_result_bytes)
        return plan_error(plan, "scan plan environment is incomplete");
    if (!qn_scan_request_validate(request, request_message,
                                  sizeof request_message))
        return plan_error(plan, request_message);
    if (environment->working_capacity_bytes &&
        environment->working_bytes > environment->working_capacity_bytes)
        return plan_error(plan, "range metadata exceeds the working arena capacity");
    if (request->selection < QN_SELECTION_UNIFORM ||
        request->selection > QN_SELECTION_HYBRID || request->rank_by < QN_RANK_BALANCED ||
        request->rank_by > QN_RANK_THROUGHPUT || request->explore_percent > 100u)
        return plan_error(plan, "scan selection or ranking policy is invalid");

    plan->selection = request->selection;
    plan->rank_by = request->rank_by;
    plan->explore_percent = request->explore_percent;
    plan->total_addresses = environment->total_addresses;
    plan->input_prefixes = environment->input_prefixes;
    plan->normalized_prefixes = environment->normalized_prefixes;
    plan->input_addresses = environment->input_addresses;
    plan->duplicate_addresses = environment->duplicate_addresses;
    plan->tunnel_enabled = request->tunnel_enabled;
    plan->tunnel_all = request->tunnel_all;
    plan->tunnel_concurrency = request->tunnel_concurrency;
    plan->tunnel_attempts = request->tunnel_attempts;
    plan->fd_limit = environment->fd_limit;
    plan->representative = request->selection == QN_SELECTION_UNIFORM ||
                           request->selection == QN_SELECTION_STRATIFIED;
    if (!resolve_scope(request, environment, plan) ||
        !resolve_concurrency(request, environment, plan))
        return false;

    plan->memory_budget_bytes = request->memory_auto
                                    ? auto_memory(environment)
                                    : request->memory_budget_bytes;
    if (!plan->memory_budget_bytes)
        return plan_error(plan, "memory budget must be greater than zero");

    if (request->candidate_auto) {
        uint64_t budget_for_candidates = plan->memory_budget_bytes / 2u;
        candidate = budget_for_candidates / environment->candidate_bytes;
        if (candidate > 65536u)
            candidate = 65536u;
        if (plan->mode == QN_SCAN_REACHABLE && candidate < plan->reachable_target)
            candidate = plan->reachable_target;
        if (candidate < 4096u && plan->planned_addresses >= 4096u)
            candidate = 4096u;
        if (candidate > plan->planned_addresses)
            candidate = plan->planned_addresses;
    } else {
        candidate = request->candidate_capacity;
    }
    if (!candidate || candidate > UINT32_MAX)
        return plan_error(plan, "Candidate Capacity must be between 1 and 4294967295");
    if (plan->mode == QN_SCAN_REACHABLE && candidate < plan->reachable_target)
        return plan_error(plan, "Candidate Capacity must be at least the Reachable Target");
    plan->candidate_capacity = candidate;

    if (request->finalists_all) {
        finalist = candidate;
        plan->finalists_all = true;
    } else if (request->finalists_auto) {
        finalist = candidate < (plan->exact_full ? 1024u : 256u)
                       ? candidate
                       : (plan->exact_full ? 1024u : 256u);
    } else {
        finalist = request->finalist_limit;
    }
    if (!finalist || finalist > candidate)
        return plan_error(plan, "Finalist Count must be between 1 and Candidate Capacity");
    plan->finalist_limit = finalist;

    if (request->tunnel_enabled) {
        plan->tunnel_target = request->tunnel_all ? finalist
                                                  : request->tunnel_target;
        if (plan->tunnel_target > finalist) {
            plan->tunnel_target = finalist;
            plan->auto_adjusted = true;
        }
        if (plan->tunnel_concurrency > plan->tunnel_target) {
            plan->tunnel_concurrency = (uint32_t)plan->tunnel_target;
            plan->auto_adjusted = true;
        }
        if (!plan->tunnel_target || !plan->tunnel_concurrency ||
            !plan->tunnel_attempts)
            return plan_error(plan, "tunnel resource plan is empty");
    }

    if (request->output_all) {
        output = finalist;
        plan->output_all = true;
    } else {
        output = request->output_limit;
        if (!output)
            return plan_error(plan, "Output Top must be greater than zero or all");
        if (output > finalist) {
            output = finalist;
            plan->auto_adjusted = true;
        }
    }
    plan->output_limit = output;

    batch = (uint64_t)plan->verify_concurrency * 4u;
    if (batch < 32u)
        batch = 32u;
    if (batch > finalist)
        batch = finalist;
    if (!batch || batch > UINT32_MAX)
        return plan_error(plan, "verification batch size exceeds the platform limit");
    plan->verification_batch_size = (uint32_t)batch;

    if (!memory_estimate(plan, environment))
        return false;
    if (plan->estimated_total_bytes > plan->memory_budget_bytes) {
        uint64_t fixed, candidate_budget, page, transient;

        if (!request->candidate_auto)
            return plan_error(plan, "requested Candidate Capacity exceeds the memory budget");
        transient = plan->estimated_verifier_bytes > plan->estimated_tunnel_bytes
                        ? plan->estimated_verifier_bytes
                        : plan->estimated_tunnel_bytes;
        if (!add_u64(plan->estimated_working_bytes, transient, &fixed) ||
            !add_u64(fixed, environment->candidate_fixed_bytes, &fixed) ||
            fixed >= plan->memory_budget_bytes)
            return plan_error(plan, "working set and verifier exceed the memory budget");
        candidate_budget = plan->memory_budget_bytes -
                           plan->estimated_working_bytes -
                           transient;
        page = environment->page_size ? environment->page_size : 4096u;
        if (page > 1u)
            candidate_budget -= candidate_budget % page;
        if (candidate_budget <= environment->candidate_fixed_bytes)
            return plan_error(plan, "memory budget cannot hold one candidate page");
        candidate = (candidate_budget - environment->candidate_fixed_bytes) /
                    environment->candidate_bytes;
        if (candidate > plan->planned_addresses)
            candidate = plan->planned_addresses;
        if (candidate < plan->reachable_target || !candidate)
            return plan_error(plan, "memory budget cannot retain the requested Reachable Target");
        plan->candidate_capacity = candidate;
        if (plan->finalist_limit > candidate) {
            if (!request->finalists_auto && !request->finalists_all)
                return plan_error(plan, "Finalist Count exceeds memory-adjusted Candidate Capacity");
            plan->finalist_limit = candidate;
        }
        if (plan->output_limit > plan->finalist_limit)
            plan->output_limit = plan->finalist_limit;
        if (plan->verification_batch_size > plan->finalist_limit)
            plan->verification_batch_size = (uint32_t)plan->finalist_limit;
        plan->auto_adjusted = true;
        if (!memory_estimate(plan, environment) ||
            plan->estimated_total_bytes > plan->memory_budget_bytes)
            return plan_error(plan, "automatic resource plan cannot fit the memory budget");
    }
    plan->valid = true;
    return true;
}
