#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qanat/netinfo.h"
#include "qanat/menu.h"
#include "qanat/http2.h"
#include "qanat/profile.h"
#include "qanat/ranges.h"
#include "qanat/task.h"
#include "qanat/tls.h"
#include "qanat/tls_capability.h"
#include "qanat/tls_hello.h"
#include "qanat/ui.h"
#include "qanat/verify.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <unistd.h>

enum {
    SEEN_CF     = 1u << 0,
    SEEN_PORTS  = 1u << 1,
    SEEN_LAN    = 1u << 2,
    SEEN_ENGINE = 1u << 3,
    SEEN_SEED   = 1u << 4,
    SEEN_TIMEOUT = 1u << 5,
    SEEN_RESULT_OUTPUT = 1u << 6,
    SEEN_SCAN_MODE = 1u << 7,
    SEEN_COVERAGE = 1u << 8,
    SEEN_ADDRESS_BUDGET = 1u << 9,
    SEEN_REACHABLE_TARGET = 1u << 10,
    SEEN_LEGACY_LIMIT = 1u << 11
};

#define QN_CANON_PATH_CAP 4096u

typedef enum {
    SO_SCAN_MODE = 0,
    SO_COVERAGE,
    SO_ADDRESS_BUDGET,
    SO_REACHABLE_TARGET,
    SO_SELECTION,
    SO_EXPLORE_PERCENT,
    SO_CANDIDATE_CAP,
    SO_FINALISTS,
    SO_OUTPUT_TOP,
    SO_RANK_BY,
    SO_MEMORY_BUDGET,
    SO_TUNNEL_TARGET,
    SO_TUNNEL_CONCURRENCY,
    SO_TUNNEL_ATTEMPTS,
    SO_TUNNEL_LINK,
    SO_TUNNEL_LINK_FILE,
    SO_XRAY_PATH,
    SO_TUNNEL_CONFIRM
} scan_option_id;

typedef struct {
    const char    *name;
    scan_option_id id;
    const char    *value;
    const char    *description;
    bool           takes_value;
} scan_option;

static const scan_option SCAN_OPTIONS[] = {
    { "--scan-mode", SO_SCAN_MODE, "auto|full|coverage|budget|reachable", "traversal and stop policy", true },
    { "--coverage", SO_COVERAGE, "PERCENT", "fixed-point percentage, 0.01%..100%", true },
    { "--address-budget", SO_ADDRESS_BUDGET, "N", "unique addresses to attempt", true },
    { "--reachable-target", SO_REACHABLE_TARGET, "N", "successful reachable candidates to retain", true },
    { "--selection", SO_SELECTION, "uniform|stratified|adaptive|hybrid", "address-selection policy", true },
    { "--explore-percent", SO_EXPLORE_PERCENT, "PERCENT", "hybrid exploration share, 0..100", true },
    { "--candidate-cap", SO_CANDIDATE_CAP, "N|auto", "streaming promising-candidate capacity", true },
    { "--finalists", SO_FINALISTS, "N|auto|all", "total deep-verification cohort", true },
    { "--output-top", SO_OUTPUT_TOP, "N|all", "results displayed and exported", true },
    { "--rank-by", SO_RANK_BY, "balanced|latency|stability|throughput", "versioned final ranking", true },
    { "--memory-budget", SO_MEMORY_BUDGET, "SIZE|auto", "hard resource-plan memory ceiling", true },
    { "--tunnel-target", SO_TUNNEL_TARGET, "N|all", "explicitly enable tunnel verification", true },
    { "--tunnel-concurrency", SO_TUNNEL_CONCURRENCY, "N", "independent tunnel concurrency, 1..32", true },
    { "--tunnel-attempts", SO_TUNNEL_ATTEMPTS, "N", "attempts per tunnel candidate, 1..2", true },
    { "--tunnel-link", SO_TUNNEL_LINK, "URI", "VLESS/Trojan/VMess link; file is safer", true },
    { "--tunnel-link-file", SO_TUNNEL_LINK_FILE, "FILE", "private file containing one link", true },
    { "--xray", SO_XRAY_PATH, "PATH|auto", "Xray executable or PATH discovery", true },
    { "--tunnel-confirm", SO_TUNNEL_CONFIRM, "", "confirm real tunnel traffic in headless mode", false }
};

static const scan_option *scan_option_find(const char *name)
{
    for (size_t i = 0; i < QN_ARRAY_LEN(SCAN_OPTIONS); i++)
        if (!strcmp(name, SCAN_OPTIONS[i].name))
            return &SCAN_OPTIONS[i];
    return NULL;
}

static void usage(FILE *f)
{
    fprintf(f,
        QN_NAME " " QN_VERSION " - high-throughput connectivity analysis for Termux/ARM64\n"
        "\n"
        "USAGE\n"
        "  " QN_NAME "                    numeric interactive launcher\n"
        "  " QN_NAME " --cf [options]\n"
        "  " QN_NAME " scan cf [options]\n"
        "  " QN_NAME " --ports <host> [options]\n"
        "  " QN_NAME " --discover [cidr]\n"
        "  " QN_NAME " --net\n"
        "  " QN_NAME " doctor\n"
        "  " QN_NAME " fingerprint list\n"
        "  " QN_NAME " fingerprint show PROFILE [--seed N] [--sni HOST]\n"
        "  " QN_NAME " fingerprint diff LEFT RIGHT [--seed N] [--sni HOST]\n"
        "\n"
        "MODES\n"
        "  --cf                 sweep Cloudflare's edge ranges and rank what still works\n"
        "  --ports <host>       port sweep against one host\n"
        "  --discover [cidr]    find live hosts on the local prefix (or the given one)\n"
        "  --net                link, route, resolver and path diagnostics\n"
        "\n"
        "TARGETING\n"
        "  -p, --port <spec>    ports: 'top', '-' for all, or '22,80,443,8000-8100'\n"
        "                       (default: all 65535)\n"
        "      --sni <name>     server name to present, and Host: for the HTTP rung\n"
        "                       (default: www.cloudflare.com)\n"
        "      --ranges <file>  prefix list to use instead of the built-in one\n"
        "  -U, --update-ranges securely refresh the managed Cloudflare IPv4 list\n"
        "      --method <m>     discovery: auto, icmp, tcp, or both\n"
        "      --limit <n>      deprecated alias for reachable scan mode\n"
        "      --samples <n>    RTT evidence budget per finalist (default: 5)\n"
        "                       clear cases stop early; ambiguous ones may use up to\n"
        "                       min(12, 2*n) measurement rounds\n"
        "      --fingerprint <p> chrome-android-151, firefox-android-153,\n"
        "                       safari-ios-26, random (short aliases accepted)\n"
        "      --cert-strict    refuse a compressed certificate instead of accepting\n"
        "                       its framing without reading the chain\n"
        "      --flow-bytes <n> bulk bytes to pull for a throughput reading (default: off).\n"
        "                       Needs an --sni that serves them, e.g.\n"
        "                       --sni speed.cloudflare.com --flow-bytes 262144\n"
        "      --idle <ms>      post-transfer stability hold (default: 5000)\n"
        "      --verify-concurrency <n> full TLS sessions in flight (default: 64)\n"
        "      --stability-concurrency <n> completed sessions held independently\n"
        "                       for stability checks (default: 512)\n"
        "      --seed <n>       fix sweep order and handshake randomness. Which probes\n"
        "                       answer first still depends on the network, so the set\n"
        "                       collected is not identical between runs\n"
        "      --event-log <f>  append every verified outcome, for auditing\n"
        "      --history <f>    carry results across runs. Evidence decays with a\n"
        "                       three-day half-life, and repeated confirmation on more\n"
        "                       than one path counts for more than one lucky moment\n"
        "      --deep           enable transfer and stability checks (default)\n"
        "      --quick          handshake and trace only\n"
        "  -6, --ipv6           prefer IPv6 when resolving a --ports host\n"
        "\n"
        "ENGINE\n"
        "  -w, --workers <n>    worker threads (default: from CPU topology)\n"
        "  -c, --concurrency    in-flight ceiling, 32..4096 (default: topology-aware)\n"
        "  -r, --rate <n>       new sweep connections per second (default: unmetered)\n"
        "  -t, --timeout <ms>   deadline ceiling per stage (default: 1200)\n"
        "      --retries <n>    confirmation passes, 0..3 (default: 1)\n"
        "      --select         use the POSIX select compatibility backend\n"
        "      --no-adaptive    pin the window; disable congestion control\n"
        "      --no-affinity    disable cluster-aware worker pinning\n"
        "      --warm-radio <m> radio warm-up: auto, on, or off\n"
        "      --no-warm        alias for --warm-radio off\n"
        "      --no-thermal     disable thermal window reduction\n"
        "\n"
        "OUTPUT\n"
        "      --json <file>    write results as JSON\n"
        "      --csv <file>     write results as CSV\n"
        "      --export <fmt>   verified CDN template: list, xray, or singbox\n"
        "      --export-file <f> output path (stdout when omitted)\n"
        "      --headless       no TUI; print lines and exit\n"
        "      --tui            use the interactive terminal UI\n"
        "      --no-color       monochrome\n"
        "  -h, --help           this text\n"
        "  -V, --version        version\n");
    fprintf(f, "\nSCAN PLAN\n");
    for (size_t i = 0; i < QN_ARRAY_LEN(SCAN_OPTIONS); i++)
        fprintf(f, "  %-21s %-43s %s\n", SCAN_OPTIONS[i].name,
                SCAN_OPTIONS[i].value, SCAN_OPTIONS[i].description);
}

static bool arg_u32(const char *v, uint32_t *out, uint32_t lo, uint32_t hi)
{
    char *end;
    long long n;

    if (!v || !*v)
        return false;
    n = strtoll(v, &end, 10);
    if (*end || n < (long long)lo || n > (long long)hi)
        return false;
    *out = (uint32_t)n;
    return true;
}

/* Accepts 0x/0 prefixes; rejects the sign strtoull would silently wrap. */
static bool arg_u64(const char *v, uint64_t *out)
{
    char              *end;
    unsigned long long n;

    if (!v || !*v || *v == '-' || *v == '+')
        return false;
    errno = 0;
    n     = strtoull(v, &end, 0);
    if (*end || errno == ERANGE)
        return false;
    *out = (uint64_t)n;
    return true;
}

static bool arg_count(const char *text, uint64_t *value)
{
    return arg_u64(text, value) && *value > 0u && *value <= UINT32_MAX;
}

static bool parse_scan_option(const scan_option *option, const char *value,
                              qn_config *config, uint32_t *seen)
{
    uint64_t count;
    uint32_t percent;

    if (!option || !value || !config || !seen)
        return false;
    switch (option->id) {
    case SO_SCAN_MODE:
        if (!qn_scan_mode_parse(value, &config->scan.mode)) {
            qn_warn("--scan-mode takes auto, full, coverage, budget, or reachable");
            return false;
        }
        *seen |= SEEN_SCAN_MODE;
        return true;
    case SO_COVERAGE:
        if (!qn_coverage_parse(value, &config->scan.coverage_ppm)) {
            qn_warn("--coverage takes a fixed-point percentage from 0.01%% through 100%%");
            return false;
        }
        *seen |= SEEN_COVERAGE;
        return true;
    case SO_ADDRESS_BUDGET:
        if (!arg_u64(value, &count) || !count) {
            qn_warn("--address-budget takes a positive integer");
            return false;
        }
        config->scan.address_budget = count;
        *seen |= SEEN_ADDRESS_BUDGET;
        return true;
    case SO_REACHABLE_TARGET:
        if (!arg_count(value, &count)) {
            qn_warn("--reachable-target takes an integer from 1 through 4294967295");
            return false;
        }
        config->scan.reachable_target = count;
        *seen |= SEEN_REACHABLE_TARGET;
        return true;
    case SO_SELECTION:
        if (!qn_selection_parse(value, &config->scan.selection)) {
            qn_warn("--selection takes uniform, stratified, adaptive, or hybrid");
            return false;
        }
        return true;
    case SO_EXPLORE_PERCENT:
        if (!arg_u32(value, &percent, 0u, 100u)) {
            qn_warn("--explore-percent takes an integer from 0 through 100");
            return false;
        }
        config->scan.explore_percent = percent;
        return true;
    case SO_CANDIDATE_CAP:
        if (!strcmp(value, "auto")) {
            config->scan.candidate_auto = true;
            config->scan.candidate_capacity = 0u;
            return true;
        }
        if (!arg_count(value, &count)) {
            qn_warn("--candidate-cap takes auto or an integer from 1 through 4294967295");
            return false;
        }
        config->scan.candidate_auto = false;
        config->scan.candidate_capacity = count;
        return true;
    case SO_FINALISTS:
        config->scan.finalists_all = false;
        if (!strcmp(value, "auto")) {
            config->scan.finalists_auto = true;
            return true;
        }
        if (!strcmp(value, "all")) {
            config->scan.finalists_auto = false;
            config->scan.finalists_all = true;
            return true;
        }
        if (!arg_count(value, &count)) {
            qn_warn("--finalists takes auto, all, or an integer from 1 through 4294967295");
            return false;
        }
        config->scan.finalists_auto = false;
        config->scan.finalist_limit = count;
        return true;
    case SO_OUTPUT_TOP:
        if (!strcmp(value, "all")) {
            config->scan.output_all = true;
            return true;
        }
        if (!arg_count(value, &count)) {
            qn_warn("--output-top takes all or an integer from 1 through 4294967295");
            return false;
        }
        config->scan.output_all = false;
        config->scan.output_limit = count;
        return true;
    case SO_RANK_BY:
        if (!qn_rank_policy_parse(value, &config->scan.rank_by)) {
            qn_warn("--rank-by takes balanced, latency, stability, or throughput");
            return false;
        }
        return true;
    case SO_MEMORY_BUDGET:
        if (!strcmp(value, "auto")) {
            config->scan.memory_auto = true;
            config->scan.memory_budget_bytes = 0u;
            return true;
        }
        if (!qn_size_parse(value, &count) || !count) {
            qn_warn("--memory-budget takes auto or a positive size such as 128MiB");
            return false;
        }
        config->scan.memory_auto = false;
        config->scan.memory_budget_bytes = count;
        return true;
    case SO_TUNNEL_TARGET:
        config->scan.tunnel_enabled = true;
        config->scan.tunnel_all = !strcmp(value, "all");
        if (config->scan.tunnel_all) {
            config->scan.tunnel_target = 0u;
            return true;
        }
        if (!arg_count(value, &count)) {
            qn_warn("--tunnel-target takes all or an integer from 1 through 4294967295");
            return false;
        }
        config->scan.tunnel_target = count;
        return true;
    case SO_TUNNEL_CONCURRENCY:
        if (!arg_u32(value, &percent, 1u, 32u)) {
            qn_warn("--tunnel-concurrency takes an integer from 1 through 32");
            return false;
        }
        config->scan.tunnel_concurrency = percent;
        return true;
    case SO_TUNNEL_ATTEMPTS:
        if (!arg_u32(value, &percent, 1u, 2u)) {
            qn_warn("--tunnel-attempts takes an integer from 1 through 2");
            return false;
        }
        config->scan.tunnel_attempts = percent;
        return true;
    case SO_TUNNEL_LINK:
        if (strlen(value) > QN_TUNNEL_LINK_MAX) {
            qn_warn("--tunnel-link exceeds the bounded link length");
            return false;
        }
        config->tunnel_link = value;
        return true;
    case SO_TUNNEL_LINK_FILE:
        config->tunnel_link_file = value;
        return true;
    case SO_XRAY_PATH:
        config->xray_path = value;
        return true;
    case SO_TUNNEL_CONFIRM:
        config->tunnel_confirmed = true;
        return true;
    default:
        return false;
    }
}

static bool canonical_path(const char *path, char out[QN_CANON_PATH_CAP])
{
    char   work[QN_CANON_PATH_CAP];
    char   leaf[QN_CANON_PATH_CAP];
    char  *resolved;
    char  *slash;
    size_t n, leaf_n, parent_n, separator;

    if (!path || !*path)
        return false;
    resolved = realpath(path, NULL);
    if (resolved) {
        n = strlen(resolved);
        if (n < QN_CANON_PATH_CAP)
            memcpy(out, resolved, n + 1u);
        free(resolved);
        return n < QN_CANON_PATH_CAP;
    }

    n = strlen(path);
    if (n >= sizeof work)
        return false;
    memcpy(work, path, n + 1u);
    slash = strrchr(work, '/');
    if (slash) {
        leaf_n = strlen(slash + 1);
        if (!leaf_n)
            return false;
        memcpy(leaf, slash + 1, leaf_n + 1u);
        if (slash == work)
            work[1] = '\0';
        else
            *slash = '\0';
    } else {
        leaf_n = n;
        memcpy(leaf, work, leaf_n + 1u);
        work[0] = '.';
        work[1] = '\0';
    }
    resolved = realpath(work, NULL);
    if (!resolved)
        return false;

    parent_n = strlen(resolved);
    separator = parent_n && resolved[parent_n - 1u] != '/' ? 1u : 0u;
    if (parent_n + separator >= QN_CANON_PATH_CAP ||
        leaf_n > QN_CANON_PATH_CAP - parent_n - separator - 1u) {
        free(resolved);
        return false;
    }
    memcpy(out, resolved, parent_n);
    free(resolved);
    if (separator)
        out[parent_n++] = '/';
    memcpy(out + parent_n, leaf, leaf_n + 1u);
    return true;
}

static bool paths_alias(const char *a, const char *b)
{
    struct stat sa, sb;
    char        ca[QN_CANON_PATH_CAP], cb[QN_CANON_PATH_CAP];

    if (!a || !b)
        return false;
    if (!strcmp(a, b))
        return true;
    if (stat(a, &sa) == 0 && stat(b, &sb) == 0 && sa.st_dev == sb.st_dev &&
        sa.st_ino == sb.st_ino)
        return true;
    return canonical_path(a, ca) && canonical_path(b, cb) && !strcmp(ca, cb);
}

static bool validate_options(const qn_config *c, uint32_t seen)
{
    const char *outputs[] = { c->out_json, c->out_csv, c->export_file,
                              c->event_log, c->history };

    if ((seen & SEEN_CF) && c->mode != QN_MODE_CF) {
        qn_warn("a Cloudflare-only option was used outside --cf");
        return false;
    }
    if ((seen & SEEN_LEGACY_LIMIT) &&
        (seen & (SEEN_SCAN_MODE | SEEN_COVERAGE | SEEN_ADDRESS_BUDGET |
                 SEEN_REACHABLE_TARGET))) {
        qn_warn("--limit cannot be combined with --scan-mode or its scope arguments");
        return false;
    }
    if (!(seen & SEEN_SCAN_MODE) &&
        (seen & (SEEN_COVERAGE | SEEN_ADDRESS_BUDGET | SEEN_REACHABLE_TARGET))) {
        qn_warn("--coverage, --address-budget, and --reachable-target require --scan-mode");
        return false;
    }
    if (seen & SEEN_SCAN_MODE) {
        uint32_t scope = seen & (SEEN_COVERAGE | SEEN_ADDRESS_BUDGET |
                                 SEEN_REACHABLE_TARGET);

        if (c->scan.mode == QN_SCAN_COVERAGE && scope != SEEN_COVERAGE) {
            qn_warn("--scan-mode coverage requires only --coverage");
            return false;
        }
        if (c->scan.mode == QN_SCAN_BUDGET && scope != SEEN_ADDRESS_BUDGET) {
            qn_warn("--scan-mode budget requires only --address-budget");
            return false;
        }
        if (c->scan.mode == QN_SCAN_REACHABLE && scope != SEEN_REACHABLE_TARGET) {
            qn_warn("--scan-mode reachable requires only --reachable-target");
            return false;
        }
        if ((c->scan.mode == QN_SCAN_AUTO || c->scan.mode == QN_SCAN_FULL) && scope) {
            qn_warn("--scan-mode auto/full cannot be combined with a scope value");
            return false;
        }
    }
    if ((seen & SEEN_PORTS) && c->mode != QN_MODE_PORTS) {
        qn_warn("--port/--ipv6 are valid only with --ports");
        return false;
    }
    if ((seen & SEEN_LAN) && c->mode != QN_MODE_DISCOVER) {
        qn_warn("--method is valid only with --discover");
        return false;
    }
    if ((seen & SEEN_ENGINE) &&
        (c->mode == QN_MODE_NONE || c->mode == QN_MODE_NETINFO)) {
        qn_warn("scan-engine options are not valid for this mode");
        return false;
    }
    if ((seen & SEEN_TIMEOUT) && c->mode == QN_MODE_NONE) {
        qn_warn("--timeout requires a scan or diagnostic mode");
        return false;
    }
    if ((seen & SEEN_RESULT_OUTPUT) && c->mode == QN_MODE_NONE) {
        qn_warn("--json/--csv require a scan or diagnostic mode");
        return false;
    }
    if ((seen & SEEN_SEED) && c->mode != QN_MODE_CF && c->mode != QN_MODE_PORTS) {
        qn_warn("--seed currently affects --cf and --ports only");
        return false;
    }
    if (c->mode == QN_MODE_CF && c->target) {
        qn_warn("--cf does not take a positional target");
        return false;
    }
    if (c->mode == QN_MODE_NETINFO && c->target) {
        qn_warn("--net does not take a positional target");
        return false;
    }
    if (c->mode == QN_MODE_CF && !qn_valid_hostname(c->sni)) {
        qn_warn("--sni must be an ASCII DNS hostname (labels 1..63 bytes)");
        return false;
    }
    if (c->update_ranges && c->mode != QN_MODE_NONE && c->mode != QN_MODE_CF) {
        qn_warn("--update-ranges can be used alone or with --cf");
        return false;
    }
    if (c->export_file && !c->export_on) {
        qn_warn("--export-file requires --export");
        return false;
    }
    if (c->scan.tunnel_enabled && !c->tunnel_link && !c->tunnel_link_file) {
        qn_warn("--tunnel-target requires --tunnel-link or --tunnel-link-file");
        return false;
    }
    if (c->tunnel_link && c->tunnel_link_file) {
        qn_warn("--tunnel-link and --tunnel-link-file are mutually exclusive");
        return false;
    }
    if (!c->scan.tunnel_enabled &&
        (c->tunnel_link || c->tunnel_link_file || c->xray_path)) {
        qn_warn("tunnel link and Xray options require --tunnel-target");
        return false;
    }
    if (c->scan.tunnel_enabled && c->headless && !c->tunnel_confirmed) {
        qn_warn("headless tunnel traffic requires --tunnel-confirm after reviewing the target");
        return false;
    }
    for (size_t i = 0; i < QN_ARRAY_LEN(outputs); i++) {
        if (outputs[i] && !outputs[i][0]) {
            qn_warn("output paths must not be empty");
            return false;
        }
        if (outputs[i] && strlen(outputs[i]) >= QN_CANON_PATH_CAP) {
            qn_warn("an output path is too long");
            return false;
        }
        if (outputs[i] && paths_alias(outputs[i], c->ranges_file)) {
            qn_warn("an output path must not overwrite --ranges");
            return false;
        }
        for (size_t j = i + 1u; outputs[i] && j < QN_ARRAY_LEN(outputs); j++) {
            if (outputs[j] && paths_alias(outputs[i], outputs[j])) {
                qn_warn("JSON, CSV, config, event-log, and history paths must be distinct");
                return false;
            }
        }
    }
    return true;
}

static bool load_tunnel_link(qn_config *config)
{
    size_t length = 0u;
    qn_tunnel_link parsed;
    qn_tunnel_parse_code code;

    if (!config->scan.tunnel_enabled)
        return true;
    if (config->tunnel_link_file) {
        struct stat status;
        int fd = open(config->tunnel_link_file,
                      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        bool read_ok = true;

        if (fd < 0) {
            qn_warn("could not open tunnel link file");
            return false;
        }
        if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
            status.st_uid != geteuid() || (status.st_mode & 077u) != 0u) {
            (void)close(fd);
            qn_warn("tunnel link file must be owned by this user and mode 600 or stricter");
            return false;
        }
        while (length <= QN_TUNNEL_LINK_MAX) {
            ssize_t got = read(fd, config->input_tunnel_link + length,
                               QN_TUNNEL_LINK_MAX + 1u - length);

            if (got < 0 && errno == EINTR)
                continue;
            if (got < 0) {
                read_ok = false;
                break;
            }
            if (!got)
                break;
            length += (size_t)got;
        }
        if (close(fd) != 0)
            read_ok = false;
        if (!read_ok || length > QN_TUNNEL_LINK_MAX) {
            qn_warn("tunnel link file is unreadable or exceeds the bound");
            return false;
        }
        while (length && (config->input_tunnel_link[length - 1u] == '\n' ||
                          config->input_tunnel_link[length - 1u] == '\r'))
            length--;
        config->input_tunnel_link[length] = '\0';
        config->tunnel_link = config->input_tunnel_link;
    }
    code = qn_tunnel_link_parse_cstr(config->tunnel_link, &parsed);
    if (code != QN_TUNNEL_PARSE_OK) {
        qn_warn("tunnel link rejected: %s", qn_tunnel_parse_str(code));
        return false;
    }
    qn_tunnel_link_clear(&parsed);
    return true;
}

#define NEED_ARG(name)                                                    \
    do {                                                                  \
        if (i + 1 >= argc) {                                              \
            qn_warn("%s needs a value", name);                            \
            return false;                                                 \
        }                                                                 \
    } while (0)

static bool set_mode(qn_config *c, qn_mode mode, const char *option)
{
    if (c->mode != QN_MODE_NONE) {
        qn_warn("scan modes are mutually exclusive (unexpected %s)", option);
        return false;
    }
    c->mode = mode;
    return true;
}

static bool parse_args(int argc, char **argv, qn_config *c, uint32_t *seen)
{
    for (int i = 1; i < argc; i++) {
        const char *s = argv[i];

        if (!strcmp(s, "-h") || !strcmp(s, "--help")) {
            usage(stdout);
            exit(0);
        }
        if (!strcmp(s, "-V") || !strcmp(s, "--version")) {
            printf("%s %s (build %s)\n", QN_NAME, QN_VERSION, QN_BUILD_FINGERPRINT);
            exit(0);
        }

        {
            const scan_option *option = scan_option_find(s);

            if (option) {
                const char *value = "";

                *seen |= SEEN_CF;
                if (option->takes_value) {
                    NEED_ARG(option->name);
                    value = argv[++i];
                }
                if (!parse_scan_option(option, value, c, seen))
                    return false;
                continue;
            }
        }

        if (!strcmp(s, "scan")) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "cf")) {
                qn_warn("scan currently requires the 'cf' subcommand");
                return false;
            }
            if (!set_mode(c, QN_MODE_CF, "scan cf"))
                return false;
            i++;
        } else if (!strcmp(s, "--cf")) {
            if (!set_mode(c, QN_MODE_CF, s))
                return false;
            if (!(*seen & SEEN_SCAN_MODE))
                c->scan.mode = QN_SCAN_FULL;
        } else if (!strcmp(s, "--ports")) {
            NEED_ARG("--ports");
            if (!set_mode(c, QN_MODE_PORTS, s))
                return false;
            c->target = argv[++i];
        } else if (!strcmp(s, "--discover")) {
            if (!set_mode(c, QN_MODE_DISCOVER, s))
                return false;
            if (i + 1 < argc && argv[i + 1][0] != '-')
                c->target = argv[++i];
        } else if (!strcmp(s, "--net")) {
            if (!set_mode(c, QN_MODE_NETINFO, s))
                return false;

        } else if (!strcmp(s, "-p") || !strcmp(s, "--port")) {
            *seen |= SEEN_PORTS;
            NEED_ARG("--port");
            c->port_spec = argv[++i];
        } else if (!strcmp(s, "--sni")) {
            *seen |= SEEN_CF;
            NEED_ARG("--sni");
            c->sni = argv[++i];
        } else if (!strcmp(s, "--ranges")) {
            *seen |= SEEN_CF;
            NEED_ARG("--ranges");
            c->ranges_file = argv[++i];
        } else if (!strcmp(s, "-U") || !strcmp(s, "--update-ranges")) {
            c->update_ranges = true;
        } else if (!strcmp(s, "--method")) {
            *seen |= SEEN_LAN;
            const char *v;

            NEED_ARG("--method");
            v = argv[++i];
            if (!strcmp(v, "auto"))
                c->discover_method = (uint8_t)QN_DISCOVER_AUTO;
            else if (!strcmp(v, "icmp"))
                c->discover_method = (uint8_t)QN_DISCOVER_ICMP;
            else if (!strcmp(v, "tcp"))
                c->discover_method = (uint8_t)QN_DISCOVER_TCP;
            else if (!strcmp(v, "both"))
                c->discover_method = (uint8_t)QN_DISCOVER_BOTH;
            else {
                qn_warn("--method takes auto, icmp, tcp, or both");
                return false;
            }
        } else if (!strcmp(s, "--limit")) {
            *seen |= SEEN_CF;
            *seen |= SEEN_LEGACY_LIMIT;
            NEED_ARG("--limit");
            {
                uint64_t value;

                if (!arg_count(argv[++i], &value)) {
                    qn_warn("--limit takes an integer from 1 through 4294967295");
                    return false;
                }
                c->scan.mode = QN_SCAN_REACHABLE;
                c->scan.reachable_target = value;
            }
            qn_warn("--limit is deprecated; use --scan-mode reachable --reachable-target N");
        } else if (!strcmp(s, "--samples")) {
            *seen |= SEEN_CF;
            uint32_t v;
            NEED_ARG("--samples");
            if (!arg_u32(argv[++i], &v, 1, QN_MAX_SAMPLES))
                return false;
            c->samples = (uint8_t)v;
        } else if (!strcmp(s, "--fingerprint")) {
            *seen |= SEEN_CF;
            qn_tls_fp fp;
            NEED_ARG("--fingerprint");
            if (!qn_tls_fp_parse(argv[++i], &fp))
                return false;
            c->fingerprint = (uint8_t)fp;
        } else if (!strcmp(s, "--cert-strict")) {
            *seen |= SEEN_CF;
            c->cert_strict = true;
        } else if (!strcmp(s, "--flow-bytes")) {
            *seen |= SEEN_CF;
            NEED_ARG("--flow-bytes");
            if (!arg_u32(argv[++i], &c->flow_bytes, 0, 16u << 20))
                return false;
        } else if (!strcmp(s, "--seed")) {
            *seen |= SEEN_SEED;
            NEED_ARG("--seed");
            if (!arg_u64(argv[++i], &c->seed)) {
                qn_warn("--seed takes a non-negative integer");
                return false;
            }
            c->seed_explicit = true;
        } else if (!strcmp(s, "--export")) {
            *seen |= SEEN_CF;
            NEED_ARG("--export");
            if (!qn_export_fmt_parse(argv[++i], &c->export_fmt)) {
                qn_warn("--export takes list, xray or singbox");
                return false;
            }
            c->export_on = true;
        } else if (!strcmp(s, "--export-file")) {
            *seen |= SEEN_CF;
            NEED_ARG("--export-file");
            c->export_file = argv[++i];
        } else if (!strcmp(s, "--history")) {
            *seen |= SEEN_CF;
            NEED_ARG("--history");
            c->history = argv[++i];
        } else if (!strcmp(s, "--event-log")) {
            *seen |= SEEN_CF;
            NEED_ARG("--event-log");
            c->event_log = argv[++i];
        } else if (!strcmp(s, "--idle")) {
            *seen |= SEEN_CF;
            NEED_ARG("--idle");
            if (!arg_u32(argv[++i], &c->idle_ms, 0, 60000))
                return false;
        } else if (!strcmp(s, "--verify-concurrency")) {
            *seen |= SEEN_CF;
            NEED_ARG("--verify-concurrency");
            if (!arg_u32(argv[++i], &c->verify_concurrency, 1, 256))
                return false;
            c->scan.verify_concurrency_auto = false;
            c->scan.verify_concurrency = c->verify_concurrency;
        } else if (!strcmp(s, "--stability-concurrency")) {
            *seen |= SEEN_CF;
            NEED_ARG("--stability-concurrency");
            if (!arg_u32(argv[++i], &c->stability_concurrency, 1, 4096))
                return false;
            c->scan.stability_concurrency_auto = false;
            c->scan.stability_concurrency = c->stability_concurrency;
        } else if (!strcmp(s, "--deep")) {
            *seen |= SEEN_CF;
            c->deep = true;
        } else if (!strcmp(s, "--quick")) {
            *seen |= SEEN_CF;
            c->deep = false;
        } else if (!strcmp(s, "-6") || !strcmp(s, "--ipv6")) {
            *seen |= SEEN_PORTS;
            c->v6 = true;

        } else if (!strcmp(s, "-w") || !strcmp(s, "--workers")) {
            *seen |= SEEN_ENGINE;
            NEED_ARG("--workers");
            if (!arg_u32(argv[++i], &c->workers, 1, 16))
                return false;
        } else if (!strcmp(s, "-c") || !strcmp(s, "--concurrency")) {
            *seen |= SEEN_ENGINE;
            NEED_ARG("--concurrency");
            if (!arg_u32(argv[++i], &c->concurrency, 32, 4096))
                return false;
            c->scan.scan_concurrency_auto = false;
            c->scan.scan_concurrency = c->concurrency;
        } else if (!strcmp(s, "-r") || !strcmp(s, "--rate")) {
            *seen |= SEEN_ENGINE;
            NEED_ARG("--rate");
            if (!arg_u32(argv[++i], &c->rate, 1, 2000000))
                return false;
        } else if (!strcmp(s, "-t") || !strcmp(s, "--timeout")) {
            *seen |= SEEN_TIMEOUT;
            NEED_ARG("--timeout");
            if (!arg_u32(argv[++i], &c->timeout_ms, 50, 60000))
                return false;
        } else if (!strcmp(s, "--retries")) {
            *seen |= SEEN_ENGINE;
            NEED_ARG("--retries");
            if (!arg_u32(argv[++i], &c->retries, 0, 3))
                return false;
        } else if (!strcmp(s, "--select")) {
            *seen |= SEEN_ENGINE;
            c->select_backend = true;
        } else if (!strcmp(s, "--no-adaptive")) {
            *seen |= SEEN_ENGINE;
            c->no_adaptive = true;
        } else if (!strcmp(s, "--no-affinity")) {
            *seen |= SEEN_ENGINE;
            c->no_affinity = true;
        } else if (!strcmp(s, "--warm-radio")) {
            *seen |= SEEN_ENGINE;
            const char *v;

            NEED_ARG("--warm-radio");
            v = argv[++i];
            if (!strcmp(v, "auto"))
                c->warm_mode = (uint8_t)QN_WARM_AUTO;
            else if (!strcmp(v, "on"))
                c->warm_mode = (uint8_t)QN_WARM_ON;
            else if (!strcmp(v, "off"))
                c->warm_mode = (uint8_t)QN_WARM_OFF;
            else {
                qn_warn("--warm-radio takes auto, on, or off");
                return false;
            }
        } else if (!strcmp(s, "--no-warm")) {
            *seen |= SEEN_ENGINE;
            c->warm_mode = (uint8_t)QN_WARM_OFF;
        } else if (!strcmp(s, "--no-thermal")) {
            *seen |= SEEN_ENGINE;
            c->no_thermal = true;

        } else if (!strcmp(s, "--json")) {
            *seen |= SEEN_RESULT_OUTPUT;
            NEED_ARG("--json");
            c->out_json = argv[++i];
        } else if (!strcmp(s, "--csv")) {
            *seen |= SEEN_RESULT_OUTPUT;
            NEED_ARG("--csv");
            c->out_csv = argv[++i];
        } else if (!strcmp(s, "--headless")) {
            c->headless = true;
        } else if (!strcmp(s, "--tui")) {
            c->headless = false;
        } else if (!strcmp(s, "--no-color")) {
            c->no_color = true;
        } else if (!strcmp(s, "-q") || !strcmp(s, "--quiet")) {
            c->quiet = true;

        } else if (s[0] == '-') {
            qn_warn("unknown option: %s", s);
            return false;
        } else if (!c->target) {
            c->target = s;
        } else {
            qn_warn("unexpected argument: %s", s);
            return false;
        }
    }
    return true;
}

/* Non-const on purpose: drawing progress also samples the rate EWMA. */
static void hl_progress(qn_engine *e, const char *label, bool quiet)
{
    static int         tty = -1;
    static char        last[16];
    static uint64_t    last_ms;
    qn_engine_snapshot sn;
    uint64_t           domain, now;

    if (quiet)
        return;
    if (tty < 0)
        tty = isatty(STDERR_FILENO) ? 1 : 0;

    qn_engine_rate_sample(e);
    qn_engine_stats(e, &sn);
    domain = e->task ? e->task->domain : 0;

    /* Non-TTY progress is throttled and newline-delimited for readable logs. */
    if (!tty) {
        now = qn_now_ms();
        if (strcmp(last, label) == 0 && now - last_ms < 1000u)
            return;
        qn_strlcpy(last, label, sizeof last);
        last_ms = now;
        fprintf(stderr, "  %-10s %llu%s%llu  %u/s  win %u  %ums\n", label,
                (unsigned long long)sn.completed, domain ? "/" : "",
                (unsigned long long)domain, sn.rate_now, sn.window,
                qn_engine_deadline_ms(e));
        return;
    }

    fprintf(stderr, "\r  %-10s %8llu%s%-10llu  %6u/s  win %-5u  %ums  %u%%     ", label,
            (unsigned long long)sn.completed, domain ? "/" : "", (unsigned long long)domain,
            sn.rate_now, sn.window, qn_engine_deadline_ms(e), sn.thermal_pct);
    fflush(stderr);
}

static void print_scan_plan(const qn_scan_plan *plan, bool quiet)
{
    if (!plan || !plan->valid || quiet)
        return;
    fprintf(stderr,
            "  scan-plan  mode=%s selection=%s rank=%s\n"
            "  ranges     input=%u normalized=%u unique=%llu duplicates=%llu\n"
            "  pipeline   planned=%llu candidates=%llu finalists=%llu output=%llu batch=%u\n"
            "  resources  memory=%llu/%llu bytes working=%llu candidate=%llu verifier=%llu\n"
            "  resources  fds=%llu/%llu scan=%u verify=%u stability=%u\n",
            qn_scan_mode_str(plan->mode), qn_selection_str(plan->selection),
            qn_rank_policy_str(plan->rank_by), plan->input_prefixes,
            plan->normalized_prefixes, (unsigned long long)plan->total_addresses,
            (unsigned long long)plan->duplicate_addresses,
            (unsigned long long)plan->planned_addresses,
            (unsigned long long)plan->candidate_capacity,
            (unsigned long long)plan->finalist_limit,
            (unsigned long long)plan->output_limit, plan->verification_batch_size,
            (unsigned long long)plan->estimated_total_bytes,
            (unsigned long long)plan->memory_budget_bytes,
            (unsigned long long)plan->estimated_working_bytes,
            (unsigned long long)plan->estimated_candidate_bytes,
            (unsigned long long)plan->estimated_verifier_bytes,
            (unsigned long long)plan->estimated_fds,
            (unsigned long long)plan->fd_limit, plan->scan_concurrency,
            plan->verify_concurrency, plan->stability_concurrency);
}

static int run_headless(qn_config *cfg)
{
    qn_topology   topo;
    qn_engine     eng;
    qn_arena      arena;
    cf_scan       cf;
    port_scan     ps;
    host_discover hd;
    qn_netinfo    ni;
    qn_profile_instance profile_instance;
    char          addr[QN_ADDRSTRLEN];
    int           rc = 0;
    /* Headless and the TUI settle on the same outcome, so exit codes agree. */
    qn_run_outcome outcome = QN_RUN_SUCCESS;
    bool          arena_live = false;
    bool          engine_live = false;
    bool          results_context = false;
    bool          emit_rows = !(cfg->export_on && !cfg->export_file);

    memset(&cf, 0, sizeof cf);
    memset(&ps, 0, sizeof ps);
    memset(&hd, 0, sizeof hd);
    memset(&ni, 0, sizeof ni);
    if (cfg->mode == QN_MODE_CF) {
        uint64_t profile_seed = qn_profile_seed_from_run(cfg->effective_seed);

        if (!qn_profile_instance_init(&profile_instance,
                                      (qn_tls_fp)cfg->fingerprint,
                                      profile_seed, cfg->sni, true,
                                      cfg->cert_strict)) {
            qn_warn("could not instantiate the requested client profile");
            return qn_run_exit_code(QN_RUN_FAILED);
        }
        cfg->profile_instance = &profile_instance;
    }

    qn_topology_detect(&topo);

    if (cfg->mode != QN_MODE_NETINFO)
        fprintf(stderr, "  effective-seed %llu (%s)\n",
                (unsigned long long)cfg->effective_seed,
                cfg->seed_explicit ? "explicit; deterministic measurement mode" : "automatic");

    if (cfg->mode == QN_MODE_NETINFO) {
        qn_netinfo_collect(&ni, cfg->timeout_ms);
        results_context = true;
        for (uint32_t i = 0; i < ni.niface; i++) {
            const qn_iface *f = &ni.iface[i];
            qn_addr_str(&f->addr, addr, sizeof addr);
            printf("link\t%s\t%s\t%s/%u\tmtu=%u\n", f->name,
                   qn_link_kind_str((qn_link_kind)f->kind), addr, f->prefix_bits, f->mtu);
        }
        if (ni.has_gateway) {
            qn_addr_str(&ni.gateway, addr, sizeof addr);
            printf("gateway\t%s\t%uus\n", addr, ni.gw_rtt_us);
        }
        for (uint32_t i = 0; i < ni.ndns; i++) {
            qn_addr_str(&ni.dns[i], addr, sizeof addr);
            printf("resolver\t%s\n", addr);
        }
        if (ni.has_public) {
            qn_addr_str(&ni.public_v4, addr, sizeof addr);
            printf("public\t%s\tcolo=%s\n", addr, ni.public_colo);
        }
        printf("internet-test\t%s\n",
               qn_diag_state_str((qn_diag_state)ni.internet_state));
        printf("public-ip-test\t%s\n",
               qn_diag_state_str((qn_diag_state)ni.public_state));
        printf("dns-divergence\t%s%s\n",
               qn_diag_state_str((qn_diag_state)ni.dns_state),
               ni.dns_state == QN_DIAG_POSITIVE ? " (observed)" : "");
        printf("captive-portal\t%s%s\n",
               qn_diag_state_str((qn_diag_state)ni.captive_state),
               ni.captive_state == QN_DIAG_POSITIVE ? " (detected)" : "");
        goto out_export;
    }

    if (!qn_arena_init(&arena, 48u << 20)) {
        qn_warn("could not reserve the working arena");
        outcome = QN_RUN_FAILED;
        goto out_export;
    }
    arena_live = true;

    switch (cfg->mode) {
    case QN_MODE_CF:
        if (!cf_scan_init(&cf, &arena, cfg)) {
            qn_warn("could not build the Cloudflare range set or resource plan");
            outcome = QN_RUN_FAILED;
            goto out_export;
        }
        print_scan_plan(&cfg->scan_plan, cfg->quiet);
        break;
    case QN_MODE_PORTS:
        if (!port_scan_init(&ps, &arena, cfg)) {
            qn_warn("could not resolve '%s' or parse the port list", cfg->target);
            outcome = QN_RUN_FAILED;
            goto out_export;
        }
        break;
    case QN_MODE_DISCOVER:
        if (!host_discover_init(&hd, &arena, cfg)) {
            qn_warn("no local prefix to sweep (pass one as the target, /16 or narrower)");
            outcome = QN_RUN_FAILED;
            goto out_export;
        }
        results_context = true;
        if (cfg->discover_method != QN_DISCOVER_TCP) {
            qn_run_outcome icmp = host_discover_icmp(&hd, 900);

            if (icmp == QN_RUN_FAILED)
                qn_warn("ICMP discovery failed: %s",
                        strerror(hd.icmp_errno ? hd.icmp_errno : EIO));
            else if (icmp == QN_RUN_INCOMPLETE)
                qn_warn("ICMP discovery left %u of %u probes unsent",
                        hd.icmp_unsent, hd.host_count);
            if (cfg->discover_method != QN_DISCOVER_AUTO)
                outcome = qn_run_outcome_worst(outcome, icmp);
            if (cfg->discover_method == QN_DISCOVER_ICMP)
                goto finish_results;
        }
        break;
    default:
        usage(stderr);
        return 2;
    }

    if (!qn_engine_init(&eng, cfg, &topo)) {
        qn_warn("could not initialise the scan engine: %s",
                strerror(eng.init_errno ? eng.init_errno : EIO));
        outcome = QN_RUN_FAILED;
        goto out_export;
    }
    engine_live = true;
    results_context = true;
    if (!cfg->quiet)
        fprintf(stderr, "  engine     %s, %u workers, %u sockets\n",
                qn_engine_backend(&eng), eng.nworkers, eng.concurrency);
    if (cfg->mode == QN_MODE_CF && !cfg->quiet) {
        qn_verify_cfg vc;
        char          ja3[33], ja4[40];

        qn_verify_defaults(&vc);
        vc.sni = cfg->sni;
        vc.fp = (qn_tls_fp)cfg->fingerprint;
        vc.profile = cfg->profile_instance;
        vc.seed = cfg->effective_seed;
        vc.deterministic = cfg->seed_explicit;
        if (qn_verify_fingerprint(&vc, ja3, ja4))
            fprintf(stderr, "  fingerprint %s  JA3=%s  JA4=%s\n",
                    qn_tls_fp_str(vc.fp), ja3, ja4);
        else
            qn_warn("secure entropy was unavailable for the fingerprint preview");
    }

    qn_engine_warm_radio(cfg);

    for (;;) {
        const qn_task *t = NULL;

        switch (cfg->mode) {
        case QN_MODE_CF:       if (cf_scan_next_phase(&cf)) t = &cf.task; break;
        case QN_MODE_PORTS:    if (port_scan_next_phase(&ps)) t = &ps.task; break;
        case QN_MODE_DISCOVER: if (host_discover_next_phase(&hd)) t = &hd.task; break;
        default: break;
        }
        if (!t)
            break;

        if (!qn_engine_start(&eng, t)) {
            outcome = QN_RUN_FAILED;
            break;
        }
        while (!qn_engine_done(&eng)) {
            qn_engine_poll(&eng, 8192);
            hl_progress(&eng, t->label ? t->label : "scan", cfg->quiet);
            qn_sleep_ms(40);
        }
        qn_engine_finalization final;

        qn_engine_finalize(&eng, false, &final);
        if (cfg->mode == QN_MODE_CF)
            cf_scan_account_phase(&cf, &final);
        hl_progress(&eng, t->label ? t->label : "scan", cfg->quiet);
        {
            qn_engine_snapshot sn = final.stats;
            const char *label = t->label ? t->label : "?";

            if (final.failed)
                qn_warn("engine worker %u failed: %s", final.fatal_worker,
                        strerror(final.fatal_errno ? final.fatal_errno : EIO));
            if (sn.events_dropped)
                qn_warn("result queue overflowed (%llu records)",
                        (unsigned long long)sn.events_dropped);
            /* Every claimed index ended, was skipped on purpose, or is owed. */
            if (!final.accounted)
                qn_warn("phase '%s' lost %llu of %llu claimed jobs", label,
                        (unsigned long long)final.missing,
                        (unsigned long long)sn.claimed);
            if (sn.local_terminal_failures)
                qn_warn("phase '%s' had %llu terminal local failure(s)", label,
                        (unsigned long long)sn.local_terminal_failures);
            if (sn.unattempted)
                qn_warn("phase '%s': %llu of %llu candidates were never attempted (%s)",
                        label, (unsigned long long)sn.unattempted,
                        (unsigned long long)sn.claimed,
                        qn_engine_status_str(sn.status));
            if (!cfg->quiet && sn.status == QN_ENGINE_STOPPED)
                fprintf(stderr, "\n  phase '%s' met its stop condition after %llu of %llu\n",
                        label, (unsigned long long)sn.completed,
                        (unsigned long long)sn.claimed);
            outcome = qn_run_outcome_worst(outcome, final.outcome);
        }
        if (!cfg->quiet)
            fputc('\n', stderr);
        if (outcome == QN_RUN_FAILED)
            break;
    }
finish_results:
    switch (cfg->mode) {
    case QN_MODE_CF:
        if (outcome != QN_RUN_FAILED && !cf_scan_verify(&cf)) {
            qn_verify_state verify_state = (qn_verify_state)cf.verify_state;

            if (verify_state == QN_VERIFY_CANCELLED) {
                qn_warn("deep verification was cancelled; preliminary evidence was kept");
            } else if (verify_state == QN_VERIFY_PARTIAL) {
                qn_warn("deep verification was incomplete after %u/%u results",
                        cf.verify_completed, cf.verify_attempted);
            } else {
                qn_warn("deep verifier failed after %u/%u results: %s",
                        cf.verify_completed, cf.verify_attempted,
                        strerror(cf.verify_errno ? cf.verify_errno : EIO));
            }
            outcome = qn_run_outcome_worst(outcome,
                                           qn_verify_run_outcome(verify_state));
        }
        if (outcome != QN_RUN_FAILED && cfg->scan_plan.tunnel_enabled) {
            qn_run_outcome tunnel = cf_scan_tunnel(&cf);

            outcome = qn_run_outcome_worst(outcome, tunnel);
            if (!cfg->quiet)
                fprintf(stderr,
                        "  tunnel     queued=%u passed=%u failed=%u skipped=%u\n",
                        atomic_load_explicit(&cf.tunnel_queued, memory_order_acquire),
                        atomic_load_explicit(&cf.tunnel_passed, memory_order_acquire),
                        atomic_load_explicit(&cf.tunnel_failed, memory_order_acquire),
                        atomic_load_explicit(&cf.tunnel_skipped, memory_order_acquire));
        }
        cf_scan_finish(&cf);
        if (cf.io_warn[0]) {
            qn_warn("%s", cf.io_warn);
            outcome = qn_run_outcome_worst(outcome, QN_RUN_INCOMPLETE);
        }
        if (emit_rows) {
            uint32_t output_n = (uint32_t)QN_MIN((uint64_t)cf.n,
                                                 cfg->scan_plan.output_limit);

            if (!cfg->quiet)
                fprintf(stderr, "  %s (%u results)\n",
                        cfg->scan_plan.exact_full
                            ? "best observed after the complete loaded range set"
                            : "best observed among scanned addresses",
                        output_n);
            for (uint32_t i = 0; i < output_n; i++) {
                const cf_record *r = &cf.rec[i];
                qn_addr_str(&r->addr, addr, sizeof addr);
                printf("%s\t%s\tmedian=%uus\tp90=%uus\t", addr,
                       qn_classification_str(qn_cf_record_classification(r)),
                       r->rtt_med_us,
                       r->rtt_p90_us);
                if (r->rtt_ci90_valid)
                    printf("ci90=[%u-%u]us\t", r->rtt_ci90_lo_us, r->rtt_ci90_hi_us);
                else
                    printf("ci90=n/a\t");
                printf("n=%u\tdelta_mean=%uus\tloss=%u%%\t%s\tconf=%u\t"
                       "tunnel=%s\ttunnel_ttfb=%uus\tscore=%u\n",
                       r->samples.n, r->rtt_delta_mean_us, r->loss_pct,
                       r->colo[0] ? r->colo : "-", r->confidence,
                       qn_tunnel_state_str((qn_tunnel_state)r->tunnel_state),
                       r->tunnel_ttfb_us, r->score);
            }
        }
        break;

    case QN_MODE_PORTS:
        port_scan_finish(&ps);
        for (uint32_t i = 0; i < ps.nopen; i++) {
            const port_record *r = &ps.open[i];
            printf("%u\topen\t%s\t%uus\t%s\n", r->port, qn_service_name(r->port), r->rtt_us,
                   r->banner);
        }
        break;

    case QN_MODE_DISCOVER:
        host_discover_finish(&hd);
        for (uint32_t i = 0; i < hd.n; i++) {
            const host_record *r = &hd.host[i];
            qn_addr_str(&r->addr, addr, sizeof addr);
            printf("%s\t%uus\t%u\n", addr, r->rtt_us, r->open_hint);
        }
        break;

    default:
        break;
    }

out_export:
    if (results_context && cfg->out_json) {
        qn_run_outcome output = qn_export_json(cfg->out_json, &cf, &ps, &hd, &ni);

        if (output != QN_RUN_SUCCESS) {
            qn_warn("could not write JSON output: %s", cfg->out_json);
            outcome = qn_run_outcome_worst(outcome, output);
        }
    }
    if (results_context && cfg->export_on) {
        qn_run_outcome output =
            qn_export_config(cfg->export_file, cfg->export_fmt, &cf);

        if (output != QN_RUN_SUCCESS) {
            qn_warn("could not write the config export");
            outcome = qn_run_outcome_worst(outcome, output);
        }
    }

    if (results_context && cfg->out_csv) {
        qn_run_outcome output = qn_export_csv(cfg->out_csv, &cf, &ps, &hd);

        if (output != QN_RUN_SUCCESS) {
            qn_warn("could not write CSV output: %s", cfg->out_csv);
            outcome = qn_run_outcome_worst(outcome, output);
        }
    }
    if (engine_live)
        qn_engine_destroy(&eng);
    if (cfg->mode == QN_MODE_CF)
        cf_scan_destroy(&cf);
    if (arena_live)
        qn_arena_free(&arena);
    rc = qn_run_exit_code(outcome);
    return rc;
}

static void use_managed_ranges(qn_config *cfg, const qn_cf_ranges_info *info)
{
    if (cfg->ranges_file)
        return;
    if (qn_strlcpy(cfg->managed_ranges, info->path, sizeof cfg->managed_ranges) <
        sizeof cfg->managed_ranges)
        cfg->ranges_file = cfg->managed_ranges;
}

static void print_hex(const char *name, const uint8_t *data, size_t n)
{
    printf("%s=", name);
    for (size_t i = 0; i < n; i++)
        printf("%02x", data[i]);
    putchar('\n');
}

static const char *pseudo_name(uint8_t header)
{
    switch ((qn_pseudo_header)header) {
    case QN_PSEUDO_METHOD:    return ":method";
    case QN_PSEUDO_AUTHORITY: return ":authority";
    case QN_PSEUDO_SCHEME:    return ":scheme";
    case QN_PSEUDO_PATH:      return ":path";
    default:                  return "invalid";
    }
}

static const char *header_name(uint8_t header)
{
    switch ((qn_regular_header)header) {
    case QN_HEADER_USER_AGENT:      return "user-agent";
    case QN_HEADER_ACCEPT:          return "accept";
    case QN_HEADER_ACCEPT_ENCODING: return "accept-encoding";
    case QN_HEADER_ACCEPT_LANGUAGE: return "accept-language";
    case QN_HEADER_UPGRADE_INSECURE: return "upgrade-insecure-requests";
    case QN_HEADER_SEC_FETCH_DEST:   return "sec-fetch-dest";
    case QN_HEADER_SEC_FETCH_MODE:   return "sec-fetch-mode";
    case QN_HEADER_SEC_FETCH_SITE:   return "sec-fetch-site";
    case QN_HEADER_SEC_FETCH_USER:   return "sec-fetch-user";
    case QN_HEADER_SEC_CH_UA:        return "sec-ch-ua";
    case QN_HEADER_SEC_CH_UA_MOBILE: return "sec-ch-ua-mobile";
    case QN_HEADER_SEC_CH_UA_PLATFORM: return "sec-ch-ua-platform";
    case QN_HEADER_PRIORITY:         return "priority";
    case QN_HEADER_TE:               return "te";
    default:                        return "invalid";
    }
}

typedef struct {
    qn_profile_instance  instance;
    qn_hello_info        hello_info;
    /* Read off the hello that was actually built, never off the profile table. */
    qn_capability_report capability;
    uint8_t hello[4096], preface[256], headers[2048], http1[2048];
    size_t hello_n, preface_n, headers_n, http1_n;
    char ja3_string[QN_JA3_STR_MAX], ja3[33], ja4[40];
} fingerprint_snapshot;

static bool fingerprint_snapshot_build(const char *name, uint64_t run_seed,
                                       const char *host, fingerprint_snapshot *snapshot)
{
    qn_tls_fp requested;
    qn_tls_session tls;
    qn_tls_config config;
    qn_rng rng;
    int n;
    bool ok = false;

    if (!snapshot || !qn_client_profile_parse(name, &requested))
        return false;
    memset(snapshot, 0, sizeof *snapshot);
    if (!qn_profile_instance_init(&snapshot->instance, requested,
                                  qn_profile_seed_from_run(run_seed), host, true, false))
        return false;
    memset(&config, 0, sizeof config);
    config.profile = &snapshot->instance;
    qn_rng_seed(&rng, qn_profile_wire_seed(run_seed, 0u));
    config.rng = &rng;
    qn_tls_init(&tls, &config);
    n = qn_tls_start(&tls, snapshot->hello, sizeof snapshot->hello);
    if (n <= 0)
        goto out;
    snapshot->hello_n = (size_t)n;
    if (!qn_tls_hello_inspect(snapshot->hello, snapshot->hello_n,
                              &snapshot->hello_info) ||
        !qn_tls_hello_capability_check(&snapshot->hello_info,
                                       snapshot->instance.allow_tls12, NULL, 0u) ||
        !qn_tls_ja3(&snapshot->hello_info, snapshot->ja3_string,
                    sizeof snapshot->ja3_string, snapshot->ja3) ||
        !qn_tls_ja4(&snapshot->hello_info, snapshot->ja4) ||
        strcmp(snapshot->ja3, tls.ja3) != 0 || strcmp(snapshot->ja4, tls.ja4) != 0)
        goto out;
    qn_tls_capability_assess(&snapshot->hello_info, snapshot->instance.allow_tls12,
                             &snapshot->capability);
    n = qn_h2_preface_instance(&snapshot->instance, snapshot->preface,
                                sizeof snapshot->preface);
    if (n <= 0)
        goto out;
    snapshot->preface_n = (size_t)n;
    n = qn_h2_get_instance(&snapshot->instance, 1u, host, "/cdn-cgi/trace",
                           snapshot->headers, sizeof snapshot->headers);
    if (n <= 0)
        goto out;
    snapshot->headers_n = (size_t)n;
    n = qn_profile_instance_http1_get(&snapshot->instance, host, "/cdn-cgi/trace",
                                      snapshot->http1, sizeof snapshot->http1);
    if (n <= 0)
        goto out;
    snapshot->http1_n = (size_t)n;
    ok = true;
out:
    qn_tls_free(&tls);
    return ok;
}

static int fingerprint_show(const char *name, uint64_t seed, const char *host)
{
    fingerprint_snapshot snapshot;
    const qn_profile_instance *instance = &snapshot.instance;
    const qn_client_profile *profile;
    size_t i;

    if (!fingerprint_snapshot_build(name, seed, host, &snapshot)) {
        qn_warn("could not build capability-honest profile '%s'", name ? name : "");
        return 3;
    }
    profile = instance->profile;
    /* Echo what was asked for, not what it resolved to: a pinned version that
       no longer exists must be visible, not silently answered with another. */
    printf("requested_profile=%s\nprofile=%s\nsupport=%s\n",
           name ? name : "", profile->name,
           qn_profile_support_str(snapshot.capability.support));
    if (name && strcmp(name, qn_tls_fp_str(instance->requested)) != 0)
        printf("alias_of=%s\n", qn_tls_fp_str(instance->requested));
    printf("capability_gaps=%zu%s\n", snapshot.capability.ngaps,
           snapshot.capability.truncated ? " (truncated)" : "");
    for (i = 0; i < snapshot.capability.ngaps; i++) {
        const qn_capability_gap *gap = &snapshot.capability.gap[i];

        printf("capability_gap=%s 0x%04X %s\n",
               qn_capability_gap_kind_str(gap->kind), gap->codepoint, gap->reason);
    }
    printf("profile_instance_version=%u\npeer_authentication=not-verified\n",
           instance->version);
    printf("browser=%s\nplatform=%s\nversion=%s\nsni=%s\n",
           profile->browser, profile->platform, profile->version, instance->sni);
    printf("snapshot_seed=%llu\nwire_index=0\nja3_string=%s\nja3_hash=%s\nja4=%s\n",
           (unsigned long long)seed, snapshot.ja3_string, snapshot.ja3, snapshot.ja4);
    print_hex("client_hello_hex", snapshot.hello, snapshot.hello_n);
    printf("h2_settings=");
    for (i = 0; i < instance->h2_settings_n; i++)
        printf("%s%u:%u", i ? "," : "", instance->h2_settings[i].id,
               instance->h2_settings[i].value);
    putchar('\n');
    printf("h2_connection_window=%u\n", instance->h2_connection_window);
    printf("h2_pseudo_order=");
    for (i = 0; i < QN_ARRAY_LEN(instance->h2_pseudo_order); i++)
        printf("%s%s", i ? "," : "", pseudo_name(instance->h2_pseudo_order[i]));
    putchar('\n');
    printf("http_header_order=");
    for (i = 0; i < instance->http1_header_order_n; i++)
        printf("%s%s", i ? "," : "", header_name(instance->http1_header_order[i]));
    putchar('\n');
    print_hex("h2_preface_hex", snapshot.preface, snapshot.preface_n);
    print_hex("h2_headers_hex", snapshot.headers, snapshot.headers_n);
    print_hex("http1_request_hex", snapshot.http1, snapshot.http1_n);
    printf("user_agent=%s\naccept=%s\naccept_encoding=%s\n",
           profile->http.user_agent, profile->http.accept, profile->http.accept_encoding);
    return 0;
}

static int fingerprint_list(void)
{
    size_t i;

    puts("PROFILE\tSUPPORT\tAUTHENTICATION");
    for (i = 0; i < QN_TLS_FP_COUNT; i++)
        printf("%s\t%s\tnot-verified\n", qn_tls_fp_str((qn_tls_fp)i),
               qn_profile_support_str(QN_PROFILE_CAPABILITY_CONSTRAINED));
    return 0;
}

static const char *same_bytes(const uint8_t *left, size_t left_n,
                              const uint8_t *right, size_t right_n)
{
    return left_n == right_n && !memcmp(left, right, left_n) ? "same" : "different";
}

static int fingerprint_diff(const char *left_name, const char *right_name,
                            uint64_t seed, const char *host)
{
    fingerprint_snapshot left, right;

    if (!fingerprint_snapshot_build(left_name, seed, host, &left) ||
        !fingerprint_snapshot_build(right_name, seed, host, &right)) {
        qn_warn("could not build both capability-honest profile snapshots");
        return 3;
    }
    printf("left=%s\nright=%s\nleft_resolved=%s\nright_resolved=%s\n"
           "seed=%llu\nsni=%s\n",
           qn_tls_fp_str(left.instance.requested),
           qn_tls_fp_str(right.instance.requested),
           left.instance.profile->name, right.instance.profile->name,
           (unsigned long long)seed, host);
    printf("client_hello=%s\nh2_preface=%s\nh2_headers=%s\nhttp1_request=%s\n",
           same_bytes(left.hello, left.hello_n, right.hello, right.hello_n),
           same_bytes(left.preface, left.preface_n, right.preface, right.preface_n),
           same_bytes(left.headers, left.headers_n, right.headers, right.headers_n),
           same_bytes(left.http1, left.http1_n, right.http1, right.http1_n));
    printf("left_ja3=%s\nright_ja3=%s\nleft_ja4=%s\nright_ja4=%s\n",
           left.ja3, right.ja3, left.ja4, right.ja4);
    return 0;
}

static bool fingerprint_options(int argc, char **argv, int start,
                                uint64_t *seed, const char **host)
{
    bool saw_seed = false, saw_sni = false;
    int i;

    *seed = UINT64_C(0x514E2D46502D5348);
    *host = "www.cloudflare.com";
    for (i = start; i < argc; i += 2) {
        if (i + 1 >= argc)
            return false;
        if (!strcmp(argv[i], "--seed") && !saw_seed) {
            if (!arg_u64(argv[i + 1], seed))
                return false;
            saw_seed = true;
        } else if (!strcmp(argv[i], "--sni") && !saw_sni) {
            *host = argv[i + 1];
            saw_sni = true;
        } else {
            return false;
        }
    }
    return true;
}

static int fingerprint_command(int argc, char **argv)
{
    uint64_t seed;
    const char *host;

    if (argc == 3 && !strcmp(argv[2], "list"))
        return fingerprint_list();
    if (argc >= 4 && !strcmp(argv[2], "show") &&
        fingerprint_options(argc, argv, 4, &seed, &host))
        return fingerprint_show(argv[3], seed, host);
    if (argc >= 5 && !strcmp(argv[2], "diff") &&
        fingerprint_options(argc, argv, 5, &seed, &host))
        return fingerprint_diff(argv[3], argv[4], seed, host);
    qn_warn("fingerprint takes list, show PROFILE, or diff LEFT RIGHT");
    return 2;
}

static const char *compiled_arch(void)
{
#if defined(__aarch64__)
    return "aarch64";
#elif defined(__x86_64__)
    return "x86_64";
#elif defined(__arm__)
    return "arm";
#elif defined(__i386__)
    return "x86";
#else
    return "unknown";
#endif
}

static int doctor_command(void)
{
    struct utsname system;
    struct sysinfo memory;
    struct rlimit  files;
    qn_topology    topology;
    qn_run_outcome outcome = QN_RUN_SUCCESS;
    uint64_t       available = 0u, fd_limit = 0u;
    uint32_t       profiles_ok = 0u;
    long           page = sysconf(_SC_PAGESIZE);

    memset(&system, 0, sizeof system);
    memset(&memory, 0, sizeof memory);
    memset(&files, 0, sizeof files);
    qn_topology_detect(&topology);
    if (uname(&system) != 0) {
        qn_strlcpy(system.sysname, "unknown", sizeof system.sysname);
        qn_strlcpy(system.release, "unknown", sizeof system.release);
        outcome = qn_run_outcome_worst(outcome, QN_RUN_INCOMPLETE);
    }
    if (sysinfo(&memory) == 0) {
        if (memory.mem_unit && (uint64_t)memory.freeram > UINT64_MAX / memory.mem_unit)
            available = UINT64_MAX;
        else
            available = (uint64_t)memory.freeram * memory.mem_unit;
    } else {
        outcome = qn_run_outcome_worst(outcome, QN_RUN_INCOMPLETE);
    }
    if (getrlimit(RLIMIT_NOFILE, &files) == 0)
        fd_limit = files.rlim_cur == RLIM_INFINITY ? UINT64_MAX
                                                   : (uint64_t)files.rlim_cur;
    else
        outcome = qn_run_outcome_worst(outcome, QN_RUN_INCOMPLETE);

    for (uint32_t i = 0u; i < QN_TLS_FP_COUNT; i++) {
        fingerprint_snapshot snapshot;

        if (fingerprint_snapshot_build(qn_tls_fp_str((qn_tls_fp)i), 1u,
                                       "doctor.invalid", &snapshot))
            profiles_ok++;
    }
    if (profiles_ok != QN_TLS_FP_COUNT)
        outcome = qn_run_outcome_worst(outcome, QN_RUN_FAILED);
    if (!strcmp(QN_BUILD_FINGERPRINT, "unrecorded"))
        outcome = qn_run_outcome_worst(outcome, QN_RUN_INCOMPLETE);

    printf("version=%s\nbuild_fingerprint=%s\nexport_schema=%u\n",
           QN_VERSION, QN_BUILD_FINGERPRINT, QN_EXPORT_SCHEMA);
    printf("system=%s %s\ncompiled_arch=%s\ncpu_online=%u\ncpu_clusters=%u\n",
           system.sysname, system.release, compiled_arch(), topology.nonline,
           topology.nclusters);
    printf("cpu_neon=%s\ncpu_crc32=%s\ncpu_dotprod=%s\n",
           topology.has_neon ? "yes" : "no",
           topology.has_crc32 ? "yes" : "no",
           topology.has_asimddp ? "yes" : "no");
    printf("page_bytes=%llu\navailable_memory_bytes=%llu\nfd_limit=%llu\n",
           (unsigned long long)(page > 0 ? (uint64_t)page : 0u),
           (unsigned long long)available, (unsigned long long)fd_limit);
    printf("candidate_record_bytes=%llu\ncandidate_aux_bytes=%llu\n",
           (unsigned long long)sizeof(cf_record),
           (unsigned long long)(sizeof(uint32_t) * 4u + sizeof(qn_sprt)));
    printf("verifier_slot_bytes=%llu\nverifier_batch_entry_bytes=%llu\n"
           "verifier_fixed_bytes=%llu\n",
           (unsigned long long)qn_verify_slot_bytes(),
           (unsigned long long)qn_verify_result_bytes(),
           (unsigned long long)qn_verify_fixed_bytes());
    printf("tls_profiles=%u/%u\ntls_support=capability-constrained\n"
           "peer_authentication=not-verified\nnetwork_checks=not-run\n",
           profiles_ok, (unsigned)QN_TLS_FP_COUNT);
    {
        char xray[QN_TUNNEL_XRAY_PATH_MAX + 1u];
        qn_xray_find_code xray_state = qn_xray_find("auto", xray, sizeof xray);

        printf("xray_runtime=%s\n", qn_xray_find_str(xray_state));
    }
    printf("outcome=%s\n", qn_run_outcome_str(outcome));
    return qn_run_exit_code(outcome);
}

int main(int argc, char **argv)
{
    qn_config cfg;
    uint32_t  seen = 0;

    qn_config_defaults(&cfg);
    if (argc >= 2 && !strcmp(argv[1], "doctor")) {
        if (argc != 2) {
            qn_warn("doctor takes no arguments");
            return 2;
        }
        return doctor_command();
    }
    if (argc >= 3 && !strcmp(argv[1], "fingerprint"))
        return fingerprint_command(argc, argv);
    if (argc == 1 && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
        qn_menu_result menu = qn_menu_run(&cfg);

        if (menu == QN_MENU_EXIT)
            return 0;
        if (menu == QN_MENU_ERROR) {
            qn_warn("could not read the interactive menu input");
            return 2;
        }
    } else if (!parse_args(argc, argv, &cfg, &seen)) {
        return 2;
    }
    if (!validate_options(&cfg, seen))
        return 2;
    if (!load_tunnel_link(&cfg))
        return 2;
    if (cfg.scan.tunnel_enabled) {
        uint64_t shown_target = cfg.scan.tunnel_all
                                    ? (cfg.scan.finalists_all
                                           ? cfg.scan.candidate_capacity
                                           : cfg.scan.finalist_limit)
                                    : cfg.scan.tunnel_target;

        fprintf(stderr,
                "  tunnel     destination=www.cloudflare.com:443 candidates=%s%llu "
                "concurrency=%u attempts=%u\n",
                cfg.scan.tunnel_all ? "all; current bound " : "",
                (unsigned long long)shown_target,
                cfg.scan.tunnel_concurrency, cfg.scan.tunnel_attempts);
    }

    cfg.effective_seed = cfg.seed_explicit ? cfg.seed : qn_rng_entropy();

    if (cfg.update_ranges) {
        qn_cf_ranges_info info;

        if (!qn_cf_ranges_update(&info)) {
            qn_warn("range update failed: %s", info.error[0] ? info.error : "unknown error");
            return 3;
        }
        fprintf(stderr, "  ranges     %u prefixes, %llu addresses -> %s\n", info.prefixes,
                (unsigned long long)info.candidates, info.path);
        use_managed_ranges(&cfg, &info);
        if (cfg.mode == QN_MODE_NONE)
            return 0;
    } else if (cfg.mode == QN_MODE_CF && !cfg.ranges_file) {
        qn_cf_ranges_info info;

        if (qn_cf_ranges_cached(&info)) {
            use_managed_ranges(&cfg, &info);
            fprintf(stderr, "  ranges     managed cache: %s\n", info.path);
        } else {
            char path[QN_PATH_CAP];

            if (qn_cf_ranges_default_path(path, sizeof path) && access(path, F_OK) == 0)
                qn_warn("managed range cache was rejected (%s); using the built-in snapshot",
                        info.error);
        }
    }
    /* A managed path is resolved after the first CLI validation pass. */
    if (!validate_options(&cfg, seen))
        return 2;

    if (cfg.mode == QN_MODE_NONE) {
        usage(stderr);
        return 2;
    }
    if (cfg.mode == QN_MODE_PORTS && !cfg.target) {
        qn_warn("--ports needs a host");
        return 2;
    }
    if (cfg.v6 && cfg.mode != QN_MODE_PORTS) {
        qn_warn("--ipv6 is supported by the single-host port scanner");
        return 2;
    }
    if (!cfg.port_spec)
        cfg.port_spec = "-";
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
        cfg.headless = true;

    return cfg.headless ? run_headless(&cfg) : qn_app_run(&cfg);
}
