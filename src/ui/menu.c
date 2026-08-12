#include "qanat/menu.h"

#include "qanat/cidr.h"
#include "qanat/ranges.h"
#include "qanat/task.h"
#include "qanat/tls.h"
#include "qanat/util.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

typedef enum {
    INPUT_OK = 0,
    INPUT_EOF,
    INPUT_ERROR,
    INPUT_TOO_LONG
} input_result;

static input_result read_line(const char *prompt, char *buf, size_t cap)
{
    size_t n;

    fputs(prompt, stdout);
    fflush(stdout);
    if (!fgets(buf, (int)cap, stdin))
        return feof(stdin) ? INPUT_EOF : INPUT_ERROR;

    n = strlen(buf);
    if (n && buf[n - 1u] == '\n') {
        buf[--n] = '\0';
        if (n && buf[n - 1u] == '\r')
            buf[--n] = '\0';
    } else if (!feof(stdin)) {
        int ch;
        while ((ch = fgetc(stdin)) != '\n' && ch != EOF)
            ;
        buf[0] = '\0';
        return ferror(stdin) ? INPUT_ERROR : INPUT_TOO_LONG;
    }

    {
        char *first = buf;
        char *last;

        while (*first == ' ' || *first == '\t')
            first++;
        last = first + strlen(first);
        while (last > first && (last[-1] == ' ' || last[-1] == '\t'))
            last--;
        *last = '\0';
        if (first != buf)
            memmove(buf, first, (size_t)(last - first) + 1u);
    }
    return INPUT_OK;
}

static bool decimal_u32(const char *s, uint32_t *out)
{
    char         *end;
    unsigned long value;

    if (!s || !*s || *s == '+' || *s == '-')
        return false;
    errno = 0;
    value = strtoul(s, &end, 10);
    if (*end || errno == ERANGE || value > UINT32_MAX)
        return false;
    *out = (uint32_t)value;
    return true;
}

static bool decimal_u64(const char *s, uint64_t *out)
{
    char *end;
    unsigned long long value;

    if (!s || !*s || *s == '+' || *s == '-' || !out)
        return false;
    errno = 0;
    value = strtoull(s, &end, 10);
    if (*end || errno == ERANGE)
        return false;
    *out = (uint64_t)value;
    return true;
}

static input_result ask_choice(const char *prompt, uint32_t hi, uint32_t *choice)
{
    char line[32];

    for (;;) {
        input_result rc = read_line(prompt, line, sizeof line);

        if (rc == INPUT_EOF || rc == INPUT_ERROR)
            return rc;
        if (rc == INPUT_TOO_LONG || !decimal_u32(line, choice) || *choice > hi) {
            printf("Invalid choice. Enter a number from 0 to %u.\n", hi);
            continue;
        }
        return INPUT_OK;
    }
}

static input_result edit_u32(const char *label, uint32_t *value, uint32_t lo,
                             uint32_t hi, bool allow_zero)
{
    char prompt[128], line[64];

    snprintf(prompt, sizeof prompt, "%s [%u]: ", label, *value);
    for (;;) {
        uint32_t     next;
        input_result rc = read_line(prompt, line, sizeof line);

        if (rc == INPUT_EOF || rc == INPUT_ERROR)
            return rc;
        if (rc == INPUT_TOO_LONG) {
            puts("Value is too long.");
            continue;
        }
        if (!line[0])
            return INPUT_OK;
        if (decimal_u32(line, &next) && ((allow_zero && next == 0u) ||
                                        (next >= lo && next <= hi))) {
            *value = next;
            return INPUT_OK;
        }
        if (allow_zero)
            printf("Enter 0 for automatic, or a value from %u to %u.\n", lo, hi);
        else
            printf("Enter a value from %u to %u.\n", lo, hi);
    }
}

static input_result edit_u64(const char *label, uint64_t *value, uint64_t lo,
                             uint64_t hi, bool allow_zero)
{
    char prompt[160], line[64];

    snprintf(prompt, sizeof prompt, "%s [%" PRIu64 "]: ", label, *value);
    for (;;) {
        uint64_t next;
        input_result rc = read_line(prompt, line, sizeof line);

        if (rc == INPUT_EOF || rc == INPUT_ERROR)
            return rc;
        if (rc == INPUT_TOO_LONG) {
            puts("Value is too long.");
            continue;
        }
        if (!line[0])
            return INPUT_OK;
        if (decimal_u64(line, &next) && ((allow_zero && next == 0u) ||
                                        (next >= lo && next <= hi))) {
            *value = next;
            return INPUT_OK;
        }
        if (allow_zero)
            printf("Enter 0 for automatic, or a value from %" PRIu64
                   " to %" PRIu64 ".\n", lo, hi);
        else
            printf("Enter a value from %" PRIu64 " to %" PRIu64 ".\n", lo, hi);
    }
}

static input_result edit_choice(const char *title, const char *choices, uint32_t hi,
                                uint32_t *value)
{
    char     prompt[96];
    uint32_t choice;

    printf("%s\n%s", title, choices);
    snprintf(prompt, sizeof prompt, "Choice [%u]: ", *value);
    for (;;) {
        char         line[32];
        input_result rc = read_line(prompt, line, sizeof line);

        if (rc == INPUT_EOF || rc == INPUT_ERROR)
            return rc;
        if (rc == INPUT_TOO_LONG) {
            puts("Invalid choice.");
            continue;
        }
        if (!line[0])
            return INPUT_OK;
        if (decimal_u32(line, &choice) && choice >= 1u && choice <= hi) {
            *value = choice;
            return INPUT_OK;
        }
        printf("Enter a number from 1 to %u.\n", hi);
    }
}

static bool visible_token(const char *s)
{
    if (!s || !*s || strlen(s) > 253u)
        return false;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c <= 0x20u || c >= 0x7fu)
            return false;
    }
    return true;
}

static bool valid_port_spec(const char *spec)
{
    uint16_t *ports = malloc(65536u * sizeof *ports);
    uint32_t  n = 0;
    bool      ok;

    if (!ports)
        return false;
    ok = qn_parse_ports(spec, ports, 65536u, &n);
    free(ports);
    return ok;
}

static input_result edit_sni(qn_config *cfg)
{
    char prompt[320], line[sizeof cfg->input_sni];

    snprintf(prompt, sizeof prompt, "SNI hostname [%s]: ", cfg->sni);
    for (;;) {
        input_result rc = read_line(prompt, line, sizeof line);

        if (rc == INPUT_EOF || rc == INPUT_ERROR)
            return rc;
        if (rc == INPUT_TOO_LONG) {
            puts("Hostname is too long (maximum 253 bytes).");
            continue;
        }
        if (!line[0])
            return INPUT_OK;
        if (!qn_valid_hostname(line)) {
            puts("Use an ASCII DNS hostname with valid 1..63 byte labels.");
            continue;
        }
        qn_strlcpy(cfg->input_sni, line, sizeof cfg->input_sni);
        cfg->sni = cfg->input_sni;
        return INPUT_OK;
    }
}

static input_result edit_host(qn_config *cfg, bool required)
{
    char prompt[320], line[sizeof cfg->input_host];

    if (cfg->target)
        snprintf(prompt, sizeof prompt, "Host or IP [%s]: ", cfg->target);
    else
        qn_strlcpy(prompt, "Host or IP: ", sizeof prompt);

    for (;;) {
        input_result rc = read_line(prompt, line, sizeof line);

        if (rc == INPUT_EOF || rc == INPUT_ERROR)
            return rc;
        if (rc == INPUT_TOO_LONG) {
            puts("Target is too long (maximum 253 bytes).");
            continue;
        }
        if (!line[0]) {
            if (cfg->target || !required)
                return INPUT_OK;
            puts("A host or IP address is required.");
            continue;
        }
        if (!visible_token(line)) {
            puts("The target must be one printable token without spaces.");
            continue;
        }
        qn_strlcpy(cfg->input_host, line, sizeof cfg->input_host);
        cfg->target = cfg->input_host;
        return INPUT_OK;
    }
}

static input_result edit_ports(qn_config *cfg)
{
    char prompt[600], line[sizeof cfg->input_port_spec];
    const char *current = cfg->port_spec ? cfg->port_spec : "all";

    snprintf(prompt, sizeof prompt, "Ports (top, all, or 22,80,443,8000-8100) [%s]: ",
             current);
    for (;;) {
        input_result rc = read_line(prompt, line, sizeof line);

        if (rc == INPUT_EOF || rc == INPUT_ERROR)
            return rc;
        if (rc == INPUT_TOO_LONG) {
            puts("Port specification is too long.");
            continue;
        }
        if (!line[0])
            return INPUT_OK;
        if (!valid_port_spec(line)) {
            puts("Invalid port list. Ranges must be closed, ordered, and within 1..65535.");
            continue;
        }
        qn_strlcpy(cfg->input_port_spec, line, sizeof cfg->input_port_spec);
        cfg->port_spec = cfg->input_port_spec;
        return INPUT_OK;
    }
}

static input_result edit_prefix(qn_config *cfg)
{
    char prompt[384], line[sizeof cfg->input_prefix];

    snprintf(prompt, sizeof prompt, "LAN CIDR (blank = automatic)%s%s%s: ",
             cfg->target ? " [" : "", cfg->target ? cfg->target : "",
             cfg->target ? "]" : "");
    for (;;) {
        qn_prefix    prefix;
        input_result rc = read_line(prompt, line, sizeof line);

        if (rc == INPUT_EOF || rc == INPUT_ERROR)
            return rc;
        if (rc == INPUT_TOO_LONG) {
            puts("Prefix is too long.");
            continue;
        }
        if (!line[0]) {
            cfg->input_prefix[0] = '\0';
            cfg->target = NULL;
            return INPUT_OK;
        }
        if (!qn_cidr_parse(line, &prefix) || prefix.af != AF_INET || prefix.bits < 16u) {
            puts("Enter an IPv4 LAN prefix from /16 through /32.");
            continue;
        }
        qn_strlcpy(cfg->input_prefix, line, sizeof cfg->input_prefix);
        cfg->target = cfg->input_prefix;
        return INPUT_OK;
    }
}

static input_result common_settings(qn_config *cfg)
{
    for (;;) {
        uint32_t choice;
        input_result rc;

        printf("\nEngine settings\n"
               "  1) Concurrency       %u%s\n"
               "  2) Worker threads    %u%s\n"
               "  3) Start rate        %u%s\n"
               "  4) Adaptive control  %s\n"
               "  5) Radio warm-up     %s\n"
               "  6) Thermal control   %s\n"
               "  7) CPU affinity      %s\n"
               "  0) Done\n",
               cfg->concurrency, cfg->concurrency ? "" : " (auto)",
               cfg->workers, cfg->workers ? "" : " (auto)",
               cfg->rate, cfg->rate ? "/s" : " (adaptive)",
               cfg->no_adaptive ? "off" : "on",
               cfg->warm_mode == QN_WARM_AUTO ? "auto" :
                   (cfg->warm_mode == QN_WARM_ON ? "on" : "off"),
               cfg->no_thermal ? "off" : "on", cfg->no_affinity ? "off" : "on");
        rc = ask_choice("Select setting: ", 7u, &choice);
        if (rc != INPUT_OK)
            return rc;
        if (!choice)
            return INPUT_OK;
        if (choice == 1u)
            rc = edit_u32("Concurrency (0 = auto)", &cfg->concurrency, 32u, 4096u, true);
        else if (choice == 2u)
            rc = edit_u32("Worker threads (0 = auto)", &cfg->workers, 1u, 16u, true);
        else if (choice == 3u)
            rc = edit_u32("Connections/second (0 = adaptive)", &cfg->rate, 1u, 2000000u,
                          true);
        else if (choice == 4u) {
            uint32_t value = cfg->no_adaptive ? 2u : 1u;
            rc = edit_choice("Adaptive congestion control", "  1) On\n  2) Off\n", 2u,
                             &value);
            cfg->no_adaptive = value == 2u;
        } else if (choice == 5u) {
            uint32_t value = (uint32_t)cfg->warm_mode + 1u;
            rc = edit_choice("Radio warm-up", "  1) Auto\n  2) On\n  3) Off\n", 3u,
                             &value);
            cfg->warm_mode = (uint8_t)(value - 1u);
        } else if (choice == 6u) {
            uint32_t value = cfg->no_thermal ? 2u : 1u;
            rc = edit_choice("Thermal window reduction", "  1) On\n  2) Off\n", 2u,
                             &value);
            cfg->no_thermal = value == 2u;
        } else {
            uint32_t value = cfg->no_affinity ? 2u : 1u;
            rc = edit_choice("Topology-aware CPU affinity", "  1) On\n  2) Off\n", 2u,
                             &value);
            cfg->no_affinity = value == 2u;
        }
        if (rc != INPUT_OK)
            return rc;
    }
}

static input_result edit_coverage(qn_scan_request *request)
{
    char prompt[128], line[64];

    snprintf(prompt, sizeof prompt, "Percentage [%.4f%%]: ",
             (double)request->coverage_ppm / 10000.0);
    for (;;) {
        uint32_t coverage;
        input_result rc = read_line(prompt, line, sizeof line);

        if (rc == INPUT_EOF || rc == INPUT_ERROR)
            return rc;
        if (rc == INPUT_TOO_LONG) {
            puts("Percentage is too long.");
            continue;
        }
        if (!line[0])
            return INPUT_OK;
        if (qn_coverage_parse(line, &coverage)) {
            request->coverage_ppm = coverage;
            return INPUT_OK;
        }
        puts("Enter a percentage from 0.01 through 100 with at most four decimals.");
    }
}

static input_result edit_candidate_capacity(qn_scan_request *request)
{
    uint32_t choice = 1u;
    input_result rc;

    rc = edit_choice("Candidate Capacity",
                     "  1) Auto\n  2) 4,096\n  3) 8,192\n  4) 16,384\n"
                     "  5) 32,768\n  6) 65,536\n  7) 131,072\n  8) Custom\n",
                     8u, &choice);
    if (rc != INPUT_OK)
        return rc;
    if (choice == 1u) {
        request->candidate_auto = true;
    } else if (choice == 8u) {
        uint64_t value = request->candidate_auto ? 16384u : request->candidate_capacity;

        rc = edit_u64("Custom Candidate Capacity", &value, 1u, UINT32_MAX, false);
        if (rc == INPUT_OK) {
            request->candidate_auto = false;
            request->candidate_capacity = value;
        }
    } else {
        static const uint64_t values[] = {
            4096u, 8192u, 16384u, 32768u, 65536u, 131072u
        };

        request->candidate_auto = false;
        request->candidate_capacity = values[choice - 2u];
    }
    return rc;
}

static input_result edit_finalists(qn_scan_request *request)
{
    uint32_t choice = 1u;
    input_result rc;

    rc = edit_choice("Finalist Count",
                     "  1) Auto\n  2) 32\n  3) 64\n  4) 128\n  5) 256\n"
                     "  6) 512\n  7) 1,024\n  8) 2,048\n"
                     "  9) All Candidates\n 10) Custom\n",
                     10u, &choice);
    if (rc != INPUT_OK)
        return rc;
    request->finalists_auto = choice == 1u;
    request->finalists_all = choice == 9u;
    if (choice >= 2u && choice <= 8u) {
        static const uint64_t values[] = { 32u, 64u, 128u, 256u, 512u, 1024u, 2048u };

        request->finalist_limit = values[choice - 2u];
    } else if (choice == 10u) {
        uint64_t value = request->finalist_limit ? request->finalist_limit : 64u;

        rc = edit_u64("Custom Finalist Count", &value, 1u, UINT32_MAX, false);
        if (rc == INPUT_OK) {
            request->finalists_auto = false;
            request->finalists_all = false;
            request->finalist_limit = value;
        }
    }
    return rc;
}

static input_result edit_output_limit(qn_scan_request *request)
{
    uint32_t choice = 2u;
    input_result rc;

    rc = edit_choice("Output Top",
                     "  1) 10\n  2) 20\n  3) 50\n  4) 100\n"
                     "  5) 256\n  6) All Verified\n  7) Custom\n",
                     7u, &choice);
    if (rc != INPUT_OK)
        return rc;
    request->output_all = choice == 6u;
    if (choice <= 5u) {
        static const uint64_t values[] = { 10u, 20u, 50u, 100u, 256u };

        request->output_limit = values[choice - 1u];
    } else if (choice == 7u) {
        uint64_t value = request->output_limit ? request->output_limit : 20u;

        rc = edit_u64("Custom Output Top", &value, 1u, UINT32_MAX, false);
        if (rc == INPUT_OK) {
            request->output_all = false;
            request->output_limit = value;
        }
    }
    return rc;
}

static input_result edit_memory_budget(qn_scan_request *request)
{
    uint32_t choice = 1u;
    input_result rc;

    rc = edit_choice("Memory Budget",
                     "  1) Auto\n  2) 64 MiB\n  3) 128 MiB\n"
                     "  4) 256 MiB\n  5) 512 MiB\n  6) Custom MiB\n",
                     6u, &choice);
    if (rc != INPUT_OK)
        return rc;
    if (choice == 1u) {
        request->memory_auto = true;
    } else if (choice == 6u) {
        uint64_t mib = request->memory_auto ? 128u : request->memory_budget_bytes >> 20;

        rc = edit_u64("Custom Memory Budget in MiB", &mib, 1u,
                      UINT64_MAX >> 20, false);
        if (rc == INPUT_OK) {
            request->memory_auto = false;
            request->memory_budget_bytes = mib << 20;
        }
    } else {
        request->memory_auto = false;
        request->memory_budget_bytes = (UINT64_C(16) << choice) << 20;
    }
    return rc;
}

static void scan_plan_text(const qn_scan_request *request,
                           char candidate[32], char finalists[32],
                           char output[32], char memory[32],
                           char scan_concurrency[32],
                           char verify_concurrency[32],
                           char stability_concurrency[32])
{
    if (request->candidate_auto)
        strcpy(candidate, "Auto");
    else
        snprintf(candidate, 32u, "%" PRIu64, request->candidate_capacity);
    if (request->finalists_all)
        strcpy(finalists, "All Candidates");
    else if (request->finalists_auto)
        strcpy(finalists, "Auto");
    else
        snprintf(finalists, 32u, "%" PRIu64, request->finalist_limit);
    if (request->output_all)
        strcpy(output, "All Verified");
    else
        snprintf(output, 32u, "%" PRIu64, request->output_limit);
    if (request->memory_auto)
        strcpy(memory, "Auto");
    else
        snprintf(memory, 32u, "%" PRIu64 " MiB", request->memory_budget_bytes >> 20);
    if (request->scan_concurrency_auto)
        strcpy(scan_concurrency, "Auto");
    else
        snprintf(scan_concurrency, 32u, "%u", request->scan_concurrency);
    if (request->verify_concurrency_auto)
        strcpy(verify_concurrency, "Auto");
    else
        snprintf(verify_concurrency, 32u, "%u", request->verify_concurrency);
    if (request->stability_concurrency_auto)
        strcpy(stability_concurrency, "Auto");
    else
        snprintf(stability_concurrency, 32u, "%u", request->stability_concurrency);
}

static void save_scan_plan_menu(const qn_scan_request *request)
{
    char path[1024], error[192];

    if (!qn_scan_settings_default_path(path, sizeof path)) {
        puts("Cannot derive a settings path from HOME or XDG_CONFIG_HOME.");
        return;
    }
    if (!qn_scan_settings_save(path, request, error, sizeof error)) {
        printf("Save failed: %s\n", error);
        return;
    }
    printf("Saved scan settings: %s\n", path);
}

static bool load_scan_plan_menu(qn_scan_request *request)
{
    char path[1024], error[192];
    qn_scan_request loaded;

    if (!qn_scan_settings_default_path(path, sizeof path)) {
        puts("Cannot derive a settings path from HOME or XDG_CONFIG_HOME.");
        return false;
    }
    if (!qn_scan_settings_load(path, &loaded, error, sizeof error)) {
        printf("Restore failed: %s\n", error);
        return false;
    }
    *request = loaded;
    printf("Restored scan settings: %s\n", path);
    return true;
}

static input_result scan_plan_settings(qn_config *cfg)
{
    qn_scan_preset preset = qn_scan_preset_detect(&cfg->scan);

    for (;;) {
        qn_scan_request *request = &cfg->scan;
        char candidate[32], finalists[32], output[32], memory[32];
        char scan_concurrency[32], verify_concurrency[32], stability_concurrency[32];
        uint32_t choice;
        input_result rc;

        scan_plan_text(request, candidate, finalists, output, memory,
                       scan_concurrency, verify_concurrency, stability_concurrency);
        printf("\nScan Plan settings\n"
               "  1) Preset                %s\n"
               "  2) Scan Scope            %s\n"
               "  3) Percentage            %.4f%%\n"
               "  4) Address Budget        %" PRIu64 "\n"
               "  5) Reachable Target      %" PRIu64 "\n"
               "  6) Address Selection     %s\n"
               "  7) Explore Percent       %u%%\n"
               "  8) Candidate Capacity    %s\n"
               "  9) Finalist Count        %s\n"
               " 10) Output Top            %s\n"
               " 11) Rank By               %s\n"
               " 12) Scan Concurrency      %s\n"
               " 13) Verify Concurrency    %s\n"
               " 14) Stability Concurrency %s\n"
               " 15) Memory Budget         %s\n"
               " 16) Save settings\n"
               " 17) Restore settings\n"
               "  0) Done\n",
               qn_scan_preset_str(preset), qn_scan_mode_str(request->mode),
               (double)request->coverage_ppm / 10000.0,
               request->address_budget, request->reachable_target,
               qn_selection_str(request->selection), request->explore_percent,
               candidate, finalists, output, qn_rank_policy_str(request->rank_by),
               scan_concurrency, verify_concurrency, stability_concurrency, memory);
        rc = ask_choice("Select Scan Plan setting: ", 17u, &choice);
        if (rc != INPUT_OK || !choice)
            return rc;
        if (choice == 1u) {
            uint32_t value = 1u;

            rc = edit_choice("Preset",
                             "  1) Quick\n  2) Balanced\n  3) Deep\n"
                             "  4) Full\n  5) Custom\n",
                             5u, &value);
            if (rc == INPUT_OK) {
                preset = value == 5u ? QN_PRESET_CUSTOM : (qn_scan_preset)value;
                qn_scan_preset_apply(request, preset);
            }
        } else if (choice == 2u) {
            uint32_t value = (uint32_t)request->mode + 1u;

            rc = edit_choice("Scan Scope",
                             "  1) Auto\n  2) Full Range\n  3) Percentage of All Ranges\n"
                             "  4) Fixed Address Budget\n  5) Reachable Target\n",
                             5u, &value);
            if (rc == INPUT_OK)
                request->mode = (qn_scan_mode)(value - 1u);
        } else if (choice == 3u) {
            rc = edit_coverage(request);
        } else if (choice == 4u) {
            rc = edit_u64("Fixed Address Budget", &request->address_budget,
                          1u, UINT64_MAX, false);
        } else if (choice == 5u) {
            rc = edit_u64("Reachable Target", &request->reachable_target,
                          1u, UINT32_MAX, false);
        } else if (choice == 6u) {
            uint32_t value = (uint32_t)request->selection + 1u;

            rc = edit_choice("Address Selection",
                             "  1) Uniform\n  2) Stratified\n"
                             "  3) Adaptive\n  4) Hybrid\n",
                             4u, &value);
            if (rc == INPUT_OK)
                request->selection = (qn_selection_policy)(value - 1u);
        } else if (choice == 7u) {
            rc = edit_u32("Explore Percent", &request->explore_percent,
                          0u, 100u, false);
        } else if (choice == 8u) {
            rc = edit_candidate_capacity(request);
        } else if (choice == 9u) {
            rc = edit_finalists(request);
        } else if (choice == 10u) {
            rc = edit_output_limit(request);
        } else if (choice == 11u) {
            uint32_t value = (uint32_t)request->rank_by + 1u;

            rc = edit_choice("Rank By",
                             "  1) Balanced\n  2) Latency\n"
                             "  3) Stability\n  4) Throughput\n",
                             4u, &value);
            if (rc == INPUT_OK)
                request->rank_by = (qn_rank_policy)(value - 1u);
        } else if (choice >= 12u && choice <= 14u) {
            uint32_t *value = choice == 12u ? &request->scan_concurrency
                              : (choice == 13u ? &request->verify_concurrency
                                               : &request->stability_concurrency);
            bool *automatic = choice == 12u ? &request->scan_concurrency_auto
                              : (choice == 13u ? &request->verify_concurrency_auto
                                               : &request->stability_concurrency_auto);
            uint32_t edited = *automatic ? 0u : *value;

            rc = edit_u32(choice == 12u ? "Scan Concurrency (0 = Auto)"
                          : (choice == 13u ? "Verify Concurrency (0 = Auto)"
                                           : "Stability Concurrency (0 = Auto)"),
                          &edited, 1u, UINT32_MAX, true);
            if (rc == INPUT_OK) {
                *automatic = edited == 0u;
                if (edited)
                    *value = edited;
            }
        } else if (choice == 15u) {
            rc = edit_memory_budget(request);
        } else if (choice == 16u) {
            save_scan_plan_menu(request);
            rc = INPUT_OK;
        } else {
            if (load_scan_plan_menu(request))
                preset = qn_scan_preset_detect(request);
            rc = INPUT_OK;
        }
        if (rc != INPUT_OK)
            return rc;
        if (choice <= 15u) {
            preset = choice == 1u ? preset : QN_PRESET_CUSTOM;
        }
    }
}

static input_result cdn_settings(qn_config *cfg)
{
    for (;;) {
        uint32_t choice;
        input_result rc;

        printf("\nCDN settings\n"
               "  1) SNI hostname          %s\n"
               "  2) Scan Plan settings\n"
               "  3) RTT samples           %u\n"
               "  4) Stage timeout         %u ms\n"
               "  5) Verification          %s\n"
               "  6) Fingerprint           %s\n"
               "  7) Flow bytes            %u%s\n"
               "  8) Idle hold             %u ms%s\n"
               "  9) Engine settings\n"
               "  0) Done\n",
               cfg->sni, cfg->samples, cfg->timeout_ms, cfg->deep ? "deep" : "quick",
               qn_tls_fp_str((qn_tls_fp)cfg->fingerprint), cfg->flow_bytes,
               cfg->flow_bytes ? "" : " (off)", cfg->idle_ms,
               cfg->idle_ms ? "" : " (off)");
        rc = ask_choice("Select setting: ", 9u, &choice);
        if (rc != INPUT_OK)
            return rc;
        if (!choice)
            return INPUT_OK;
        if (choice == 1u)
            rc = edit_sni(cfg);
        else if (choice == 2u)
            rc = scan_plan_settings(cfg);
        else if (choice == 3u) {
            uint32_t value = cfg->samples;
            rc = edit_u32("RTT sample budget", &value, 1u, QN_MAX_SAMPLES, false);
            cfg->samples = (uint8_t)value;
        } else if (choice == 4u)
            rc = edit_u32("Per-stage timeout (ms)", &cfg->timeout_ms, 50u, 60000u, false);
        else if (choice == 5u) {
            uint32_t value = cfg->deep ? 2u : 1u;
            rc = edit_choice("Verification depth", "  1) Quick\n  2) Deep\n", 2u, &value);
            cfg->deep = value == 2u;
        } else if (choice == 6u) {
            uint32_t value = (uint32_t)cfg->fingerprint + 1u;
            rc = edit_choice("TLS fingerprint",
                             "  1) Chrome\n  2) Firefox\n  3) Safari\n  4) Random\n",
                             4u, &value);
            if (rc == INPUT_OK)
                cfg->fingerprint = (uint8_t)(value - 1u);
        } else if (choice == 7u) {
            rc = edit_u32("Flow bytes (0 = off)", &cfg->flow_bytes, 1u, 16u << 20, true);
        } else if (choice == 8u) {
            rc = edit_u32("Idle hold (ms, 0 = off)", &cfg->idle_ms, 1u, 60000u, true);
        } else {
            rc = common_settings(cfg);
        }
        if (rc != INPUT_OK)
            return rc;
    }
}

static input_result host_settings(qn_config *cfg)
{
    for (;;) {
        uint32_t choice;
        input_result rc;

        printf("\nHost settings\n"
               "  1) Target          %s\n"
               "  2) Ports           %s\n"
               "  3) Address family  %s\n"
               "  4) Stage timeout   %u ms\n"
               "  5) Retries         %u\n"
               "  6) Engine settings\n"
               "  0) Done\n",
               cfg->target ? cfg->target : "(required)",
               cfg->port_spec ? cfg->port_spec : "all", cfg->v6 ? "prefer IPv6" : "prefer IPv4",
               cfg->timeout_ms, cfg->retries);
        rc = ask_choice("Select setting: ", 6u, &choice);
        if (rc != INPUT_OK)
            return rc;
        if (!choice)
            return INPUT_OK;
        if (choice == 1u)
            rc = edit_host(cfg, false);
        else if (choice == 2u)
            rc = edit_ports(cfg);
        else if (choice == 3u) {
            uint32_t value = cfg->v6 ? 2u : 1u;
            rc = edit_choice("Resolver preference", "  1) IPv4\n  2) IPv6\n", 2u, &value);
            cfg->v6 = value == 2u;
        } else if (choice == 4u)
            rc = edit_u32("Per-stage timeout (ms)", &cfg->timeout_ms, 50u, 60000u, false);
        else if (choice == 5u)
            rc = edit_u32("Confirmation retries", &cfg->retries, 0u, 3u, false);
        else
            rc = common_settings(cfg);
        if (rc != INPUT_OK)
            return rc;
    }
}

static const char *discover_method_name(uint8_t method)
{
    switch ((qn_discover_method)method) {
    case QN_DISCOVER_AUTO: return "auto";
    case QN_DISCOVER_ICMP: return "icmp";
    case QN_DISCOVER_TCP:  return "tcp";
    case QN_DISCOVER_BOTH: return "both";
    default:               return "invalid";
    }
}

static input_result network_settings(qn_config *cfg)
{
    for (;;) {
        uint32_t choice;
        input_result rc;

        printf("\nNetwork settings\n"
               "  1) Operation       %s\n"
               "  2) LAN prefix      %s\n"
               "  3) Discovery       %s\n"
               "  4) Stage timeout   %u ms\n"
               "  5) Engine settings\n"
               "  0) Done\n",
               cfg->mode == QN_MODE_DISCOVER ? "LAN discovery" : "network diagnostics",
               cfg->target ? cfg->target : "automatic", discover_method_name(cfg->discover_method),
               cfg->timeout_ms);
        rc = ask_choice("Select setting: ", 5u, &choice);
        if (rc != INPUT_OK)
            return rc;
        if (!choice)
            return INPUT_OK;
        if (choice == 1u) {
            uint32_t value = cfg->mode == QN_MODE_DISCOVER ? 2u : 1u;
            rc = edit_choice("Network operation",
                             "  1) Network diagnostics\n  2) LAN host discovery\n", 2u,
                             &value);
            if (value == 2u) {
                cfg->mode = QN_MODE_DISCOVER;
                cfg->target = cfg->input_prefix[0] ? cfg->input_prefix : NULL;
            } else {
                cfg->mode = QN_MODE_NETINFO;
                cfg->target = NULL;
            }
        } else if (choice == 2u) {
            rc = edit_prefix(cfg);
            if (rc == INPUT_OK)
                cfg->mode = QN_MODE_DISCOVER;
        } else if (choice == 3u) {
            uint32_t value = (uint32_t)cfg->discover_method + 1u;
            rc = edit_choice("Discovery method",
                             "  1) Auto\n  2) ICMP\n  3) TCP\n  4) Both\n", 4u, &value);
            cfg->discover_method = (uint8_t)(value - 1u);
            cfg->mode = QN_MODE_DISCOVER;
        } else if (choice == 4u) {
            rc = edit_u32("Per-stage timeout (ms)", &cfg->timeout_ms, 50u, 60000u, false);
        } else {
            rc = common_settings(cfg);
        }
        if (rc != INPUT_OK)
            return rc;
    }
}

static void engine_auto(qn_config *cfg)
{
    cfg->workers = 0;
    cfg->concurrency = 0;
    cfg->rate = 0;
    cfg->timeout_ms = 1200;
    cfg->retries = 1;
    cfg->no_adaptive = false;
    cfg->no_affinity = false;
    cfg->no_thermal = false;
    cfg->select_backend = false;
    cfg->warm_mode = (uint8_t)QN_WARM_AUTO;
}

static void apply_auto(qn_config *cfg, uint32_t selected)
{
    engine_auto(cfg);
    if (selected == 1u) {
        cfg->mode = QN_MODE_CF;
        cfg->sni = "www.cloudflare.com";
        cfg->input_sni[0] = '\0';
        qn_scan_preset_apply(&cfg->scan, QN_PRESET_QUICK);
        cfg->samples = 5u;
        cfg->fingerprint = (uint8_t)QN_TLS_FP_CHROME;
        cfg->deep = true;
        cfg->flow_bytes = 0u;
        cfg->idle_ms = 5000u;
        cfg->verify_concurrency = 64u;
        cfg->stability_concurrency = 512u;
    } else if (selected == 2u) {
        cfg->mode = QN_MODE_PORTS;
        cfg->port_spec = "top";
        cfg->input_port_spec[0] = '\0';
        cfg->v6 = false;
    } else {
        cfg->mode = QN_MODE_NETINFO;
        cfg->target = NULL;
        cfg->discover_method = (uint8_t)QN_DISCOVER_AUTO;
    }
}

static bool ready_to_start(qn_config *cfg, uint32_t selected, input_result *input)
{
    if (selected == 1u) {
        char error[192];
        uint32_t confirm;

        cfg->mode = QN_MODE_CF;
        cfg->target = NULL;
        if (!qn_valid_hostname(cfg->sni)) {
            puts("The configured SNI hostname is invalid.");
            return false;
        }
        if (!qn_scan_request_validate(&cfg->scan, error, sizeof error)) {
            printf("Invalid Scan Plan: %s\n", error);
            return false;
        }
        if (cfg->scan.mode == QN_SCAN_FULL ||
            (cfg->scan.mode == QN_SCAN_COVERAGE &&
             cfg->scan.coverage_ppm == QN_COVERAGE_SCALE)) {
            puts("Full sweep is enabled. This traverses the complete configured range set and "
                 "can take a long time or create substantial network load.");
            *input = ask_choice("Enter 1 to continue or 0 to cancel: ", 1u, &confirm);
            if (*input != INPUT_OK || !confirm)
                return false;
        }
    } else if (selected == 2u) {
        cfg->mode = QN_MODE_PORTS;
        if (!cfg->target) {
            *input = edit_host(cfg, true);
            if (*input != INPUT_OK)
                return false;
        }
        if (cfg->port_spec && !valid_port_spec(cfg->port_spec)) {
            puts("The configured port list is invalid.");
            return false;
        }
    } else if (cfg->mode != QN_MODE_DISCOVER) {
        cfg->mode = QN_MODE_NETINFO;
    }
    return true;
}

static void update_ranges(qn_config *cfg)
{
    qn_cf_ranges_info info;

    puts("\nRefreshing the managed Cloudflare IPv4 list...");
    if (!qn_cf_ranges_update(&info)) {
        printf("Update failed: %s\n", info.error[0] ? info.error : "unknown error");
        puts("Any previously validated cache was left untouched.");
        return;
    }
    if (qn_strlcpy(cfg->managed_ranges, info.path, sizeof cfg->managed_ranges) >=
        sizeof cfg->managed_ranges) {
        puts("Update succeeded, but the cache path is too long to use.");
        return;
    }
    cfg->ranges_file = cfg->managed_ranges;
    printf("Updated: %u prefixes, %llu addresses\nCache: %s\n", info.prefixes,
           (unsigned long long)info.candidates, info.path);
}

static const char *selected_name(uint32_t selected)
{
    if (selected == 1u)
        return "CDN analyzer";
    if (selected == 2u)
        return "Host scanner";
    return "Network tools";
}

qn_menu_result qn_menu_run(qn_config *cfg)
{
    qn_mode network_mode = QN_MODE_NETINFO;

    if (!cfg)
        return QN_MENU_ERROR;
    /* The interactive launcher begins with the documented Quick preset. */
    qn_scan_preset_apply(&cfg->scan, QN_PRESET_QUICK);

    for (;;) {
        uint32_t     selected;
        input_result rc;

        printf("\n%s %s\n"
               "Connectivity analysis for Termux / ARM64\n\n"
               "  1) CDN analyzer\n"
               "  2) Host scanner\n"
               "  3) LAN and network tools\n"
               "  0) Exit\n",
               QN_NAME, QN_VERSION);
        rc = ask_choice("Select mode: ", 3u, &selected);
        if (rc == INPUT_EOF)
            return QN_MENU_EXIT;
        if (rc == INPUT_ERROR)
            return QN_MENU_ERROR;
        if (!selected)
            return QN_MENU_EXIT;

        if (selected == 1u) {
            cfg->mode = QN_MODE_CF;
            cfg->target = NULL;
        } else if (selected == 2u) {
            cfg->mode = QN_MODE_PORTS;
            cfg->target = cfg->input_host[0] ? cfg->input_host : NULL;
        } else {
            cfg->mode = network_mode;
            cfg->target = network_mode == QN_MODE_DISCOVER && cfg->input_prefix[0]
                              ? cfg->input_prefix
                              : NULL;
        }

        for (;;) {
            uint32_t action;

            printf("\n%s\n"
                   "  1) Start\n"
                   "  2) Settings\n"
                   "  3) Auto mode (configure and start)\n"
                   "  4) Update CDN ranges\n"
                   "  0) Back\n",
                   selected_name(selected));
            rc = ask_choice("Select action: ", 4u, &action);
            if (rc == INPUT_EOF)
                return QN_MENU_EXIT;
            if (rc == INPUT_ERROR)
                return QN_MENU_ERROR;
            if (!action)
                break;
            if (action == 2u) {
                if (selected == 1u)
                    rc = cdn_settings(cfg);
                else if (selected == 2u)
                    rc = host_settings(cfg);
                else {
                    rc = network_settings(cfg);
                    network_mode = cfg->mode;
                }
                if (rc == INPUT_EOF)
                    return QN_MENU_EXIT;
                if (rc == INPUT_ERROR)
                    return QN_MENU_ERROR;
                continue;
            }
            if (action == 4u) {
                update_ranges(cfg);
                continue;
            }
            if (action == 3u)
                apply_auto(cfg, selected);
            rc = INPUT_OK;
            if (ready_to_start(cfg, selected, &rc))
                return QN_MENU_START;
            if (rc == INPUT_EOF)
                return QN_MENU_EXIT;
            if (rc == INPUT_ERROR)
                return QN_MENU_ERROR;
        }
    }
}
