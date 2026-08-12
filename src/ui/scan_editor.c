#include "qanat/ui.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QN_EDITOR_MIB (UINT64_C(1) << 20)

static void editor_message(char *message, size_t capacity, const char *text)
{
    if (message && capacity)
        (void)snprintf(message, capacity, "%s", text ? text : "");
}

void qn_scan_editor_init(qn_scan_editor *editor)
{
    if (!editor)
        return;
    memset(editor, 0, sizeof *editor);
    editor->preset = QN_PRESET_CUSTOM;
}

const char *qn_scan_field_label(qn_scan_field field)
{
    switch (field) {
    case QN_SCAN_FIELD_PRESET:                return "Preset";
    case QN_SCAN_FIELD_SCOPE:                 return "Scan Scope";
    case QN_SCAN_FIELD_COVERAGE:              return "Percentage";
    case QN_SCAN_FIELD_ADDRESS_BUDGET:        return "Address Budget";
    case QN_SCAN_FIELD_REACHABLE_TARGET:      return "Reachable Target";
    case QN_SCAN_FIELD_SELECTION:             return "Selection";
    case QN_SCAN_FIELD_EXPLORE:               return "Explore Percent";
    case QN_SCAN_FIELD_CANDIDATE:             return "Candidate Capacity";
    case QN_SCAN_FIELD_FINALISTS:             return "Finalist Count";
    case QN_SCAN_FIELD_OUTPUT:                return "Output Top";
    case QN_SCAN_FIELD_RANK:                  return "Rank By";
    case QN_SCAN_FIELD_SCAN_CONCURRENCY:      return "Scan Concurrency";
    case QN_SCAN_FIELD_VERIFY_CONCURRENCY:    return "Verify Concurrency";
    case QN_SCAN_FIELD_STABILITY_CONCURRENCY: return "Stability Concurrency";
    case QN_SCAN_FIELD_MEMORY:                return "Memory Budget";
    case QN_SCAN_FIELD_REVIEW:                return "Review / Start";
    default:                                  return "Invalid";
    }
}

const char *qn_scan_field_group(qn_scan_field field)
{
    switch (field) {
    case QN_SCAN_FIELD_PRESET: return "PRESETS";
    case QN_SCAN_FIELD_SCOPE:
    case QN_SCAN_FIELD_COVERAGE:
    case QN_SCAN_FIELD_ADDRESS_BUDGET:
    case QN_SCAN_FIELD_REACHABLE_TARGET:
        return "SCAN SCOPE";
    case QN_SCAN_FIELD_SELECTION:
    case QN_SCAN_FIELD_EXPLORE:
        return "ADDRESS SELECTION";
    case QN_SCAN_FIELD_CANDIDATE: return "CANDIDATE POOL";
    case QN_SCAN_FIELD_FINALISTS: return "FINALISTS";
    case QN_SCAN_FIELD_OUTPUT:
    case QN_SCAN_FIELD_RANK:
        return "OUTPUT RESULTS";
    case QN_SCAN_FIELD_SCAN_CONCURRENCY:
    case QN_SCAN_FIELD_VERIFY_CONCURRENCY:
    case QN_SCAN_FIELD_STABILITY_CONCURRENCY:
        return "CONCURRENCY";
    case QN_SCAN_FIELD_MEMORY: return "RESOURCE BUDGET";
    case QN_SCAN_FIELD_REVIEW: return "SUMMARY";
    default:                   return "";
    }
}

bool qn_scan_field_active(qn_scan_field field, const qn_scan_request *request)
{
    if (!request)
        return false;
    switch (field) {
    case QN_SCAN_FIELD_COVERAGE:         return request->mode == QN_SCAN_COVERAGE;
    case QN_SCAN_FIELD_ADDRESS_BUDGET:   return request->mode == QN_SCAN_BUDGET;
    case QN_SCAN_FIELD_REACHABLE_TARGET: return request->mode == QN_SCAN_REACHABLE;
    case QN_SCAN_FIELD_EXPLORE:          return request->selection == QN_SELECTION_HYBRID;
    default:                             return true;
    }
}

bool qn_scan_field_editable(qn_scan_field field)
{
    switch (field) {
    case QN_SCAN_FIELD_COVERAGE:
    case QN_SCAN_FIELD_ADDRESS_BUDGET:
    case QN_SCAN_FIELD_REACHABLE_TARGET:
    case QN_SCAN_FIELD_EXPLORE:
    case QN_SCAN_FIELD_CANDIDATE:
    case QN_SCAN_FIELD_FINALISTS:
    case QN_SCAN_FIELD_OUTPUT:
    case QN_SCAN_FIELD_SCAN_CONCURRENCY:
    case QN_SCAN_FIELD_VERIFY_CONCURRENCY:
    case QN_SCAN_FIELD_STABILITY_CONCURRENCY:
    case QN_SCAN_FIELD_MEMORY:
        return true;
    default:
        return false;
    }
}

static int format_coverage(uint32_t ppm, char *buffer, size_t capacity)
{
    char fraction[5];
    uint32_t remainder = ppm % 10000u;

    if (!remainder)
        return snprintf(buffer, capacity, "%u%%", ppm / 10000u);
    (void)snprintf(fraction, sizeof fraction, "%04u", remainder);
    for (int i = 3; i > 0 && fraction[i] == '0'; i--)
        fraction[i] = '\0';
    return snprintf(buffer, capacity, "%u.%s%%", ppm / 10000u, fraction);
}

int qn_scan_field_value(const qn_scan_editor *editor, const qn_scan_request *request,
                        qn_scan_field field, char *buffer, size_t capacity)
{
    if (!request || !buffer || !capacity)
        return -1;
    if (editor && editor->editing && editor->field == field)
        return snprintf(buffer, capacity, "%s_", editor->edit);
    switch (field) {
    case QN_SCAN_FIELD_PRESET:
        return snprintf(buffer, capacity, "%s", qn_scan_preset_str(
                            editor ? editor->preset : QN_PRESET_CUSTOM));
    case QN_SCAN_FIELD_SCOPE:
        return snprintf(buffer, capacity, "%s", qn_scan_mode_str(request->mode));
    case QN_SCAN_FIELD_COVERAGE:
        return format_coverage(request->coverage_ppm, buffer, capacity);
    case QN_SCAN_FIELD_ADDRESS_BUDGET:
        return snprintf(buffer, capacity, "%" PRIu64, request->address_budget);
    case QN_SCAN_FIELD_REACHABLE_TARGET:
        return snprintf(buffer, capacity, "%" PRIu64, request->reachable_target);
    case QN_SCAN_FIELD_SELECTION:
        return snprintf(buffer, capacity, "%s", qn_selection_str(request->selection));
    case QN_SCAN_FIELD_EXPLORE:
        return snprintf(buffer, capacity, "%u%%", request->explore_percent);
    case QN_SCAN_FIELD_CANDIDATE:
        return request->candidate_auto
                   ? snprintf(buffer, capacity, "Auto")
                   : snprintf(buffer, capacity, "%" PRIu64, request->candidate_capacity);
    case QN_SCAN_FIELD_FINALISTS:
        if (request->finalists_all)
            return snprintf(buffer, capacity, "All Candidates");
        return request->finalists_auto
                   ? snprintf(buffer, capacity, "Auto")
                   : snprintf(buffer, capacity, "%" PRIu64, request->finalist_limit);
    case QN_SCAN_FIELD_OUTPUT:
        return request->output_all
                   ? snprintf(buffer, capacity, "All Verified")
                   : snprintf(buffer, capacity, "%" PRIu64, request->output_limit);
    case QN_SCAN_FIELD_RANK:
        return snprintf(buffer, capacity, "%s", qn_rank_policy_str(request->rank_by));
    case QN_SCAN_FIELD_SCAN_CONCURRENCY:
        return request->scan_concurrency_auto
                   ? snprintf(buffer, capacity, "Auto")
                   : snprintf(buffer, capacity, "%u", request->scan_concurrency);
    case QN_SCAN_FIELD_VERIFY_CONCURRENCY:
        return request->verify_concurrency_auto
                   ? snprintf(buffer, capacity, "Auto")
                   : snprintf(buffer, capacity, "%u", request->verify_concurrency);
    case QN_SCAN_FIELD_STABILITY_CONCURRENCY:
        return request->stability_concurrency_auto
                   ? snprintf(buffer, capacity, "Auto")
                   : snprintf(buffer, capacity, "%u", request->stability_concurrency);
    case QN_SCAN_FIELD_MEMORY:
        return request->memory_auto
                   ? snprintf(buffer, capacity, "Auto")
                   : snprintf(buffer, capacity, "%" PRIu64 " MiB",
                              request->memory_budget_bytes / QN_EDITOR_MIB);
    case QN_SCAN_FIELD_REVIEW:
        return snprintf(buffer, capacity, "Press Enter");
    default:
        return snprintf(buffer, capacity, "invalid");
    }
}

static size_t find_value(const uint64_t *values, size_t count, uint64_t current)
{
    for (size_t i = 0u; i < count; i++)
        if (values[i] == current)
            return i;
    return count;
}

static uint64_t cycle_value(const uint64_t *values, size_t count, uint64_t current,
                            int direction)
{
    size_t index = find_value(values, count, current);

    if (index == count)
        return direction > 0 ? values[0] : values[count - 1u];
    if (direction > 0)
        index = (index + 1u) % count;
    else
        index = index ? index - 1u : count - 1u;
    return values[index];
}

static void mark_custom(qn_scan_editor *editor)
{
    editor->preset = QN_PRESET_CUSTOM;
    editor->dirty = true;
}

static void cycle_field(qn_scan_editor *editor, qn_scan_request *request, int direction)
{
    static const uint64_t coverage[] = {
        100u, 10000u, 100000u, 125000u, 250000u, 500000u, QN_COVERAGE_SCALE
    };
    static const uint64_t address_budget[] = {
        10000u, 100000u, 250000u, 1000000u
    };
    static const uint64_t reachable_target[] = { 256u, 1024u, 4096u, 16384u };
    static const uint64_t explore[] = { 0u, 10u, 20u, 25u, 50u, 100u };
    static const uint64_t candidate[] = {
        0u, 4096u, 8192u, 16384u, 32768u, 65536u, 131072u
    };
    static const uint64_t finalists[] = {
        0u, 32u, 64u, 128u, 256u, 512u, 1024u, 2048u, UINT64_MAX
    };
    static const uint64_t output[] = { 10u, 20u, 50u, 100u, 256u, UINT64_MAX };
    static const uint64_t scan_concurrency[] = { 0u, 64u, 128u, 256u, 512u, 1024u };
    static const uint64_t verify_concurrency[] = { 0u, 16u, 32u, 64u, 128u, 256u };
    static const uint64_t stability_concurrency[] = {
        0u, 32u, 64u, 128u, 256u, 512u, 1024u
    };
    static const uint64_t memory[] = {
        0u, 64u * QN_EDITOR_MIB, 128u * QN_EDITOR_MIB,
        256u * QN_EDITOR_MIB, 512u * QN_EDITOR_MIB
    };
    uint64_t value;

    switch (editor->field) {
    case QN_SCAN_FIELD_PRESET:
        editor->preset = (qn_scan_preset)(((int)editor->preset + direction + 5) % 5);
        qn_scan_preset_apply(request, editor->preset);
        editor->dirty = true;
        return;
    case QN_SCAN_FIELD_SCOPE:
        request->mode = (qn_scan_mode)(((int)request->mode + direction + 5) % 5);
        break;
    case QN_SCAN_FIELD_SELECTION:
        request->selection = (qn_selection_policy)(((int)request->selection + direction + 4) % 4);
        break;
    case QN_SCAN_FIELD_RANK:
        request->rank_by = (qn_rank_policy)(((int)request->rank_by + direction + 4) % 4);
        break;
    case QN_SCAN_FIELD_COVERAGE:
        request->coverage_ppm = (uint32_t)cycle_value(
            coverage, sizeof coverage / sizeof coverage[0], request->coverage_ppm,
            direction);
        break;
    case QN_SCAN_FIELD_ADDRESS_BUDGET:
        request->address_budget = cycle_value(
            address_budget, sizeof address_budget / sizeof address_budget[0],
            request->address_budget, direction);
        break;
    case QN_SCAN_FIELD_REACHABLE_TARGET:
        request->reachable_target = cycle_value(
            reachable_target, sizeof reachable_target / sizeof reachable_target[0],
            request->reachable_target, direction);
        break;
    case QN_SCAN_FIELD_EXPLORE:
        request->explore_percent = (uint32_t)cycle_value(
            explore, sizeof explore / sizeof explore[0], request->explore_percent, direction);
        break;
    case QN_SCAN_FIELD_CANDIDATE:
        value = cycle_value(candidate, sizeof candidate / sizeof candidate[0],
                            request->candidate_auto ? 0u : request->candidate_capacity,
                            direction);
        request->candidate_auto = value == 0u;
        if (value)
            request->candidate_capacity = value;
        break;
    case QN_SCAN_FIELD_FINALISTS:
        value = cycle_value(finalists, sizeof finalists / sizeof finalists[0],
                            request->finalists_all ? UINT64_MAX
                            : (request->finalists_auto ? 0u : request->finalist_limit),
                            direction);
        request->finalists_all = value == UINT64_MAX;
        request->finalists_auto = value == 0u;
        if (value && value != UINT64_MAX)
            request->finalist_limit = value;
        break;
    case QN_SCAN_FIELD_OUTPUT:
        value = cycle_value(output, sizeof output / sizeof output[0],
                            request->output_all ? UINT64_MAX : request->output_limit,
                            direction);
        request->output_all = value == UINT64_MAX;
        if (value != UINT64_MAX)
            request->output_limit = value;
        break;
    case QN_SCAN_FIELD_SCAN_CONCURRENCY:
        value = cycle_value(scan_concurrency,
                            sizeof scan_concurrency / sizeof scan_concurrency[0],
                            request->scan_concurrency_auto ? 0u : request->scan_concurrency,
                            direction);
        request->scan_concurrency_auto = value == 0u;
        if (value)
            request->scan_concurrency = (uint32_t)value;
        break;
    case QN_SCAN_FIELD_VERIFY_CONCURRENCY:
        value = cycle_value(verify_concurrency,
                            sizeof verify_concurrency / sizeof verify_concurrency[0],
                            request->verify_concurrency_auto ? 0u : request->verify_concurrency,
                            direction);
        request->verify_concurrency_auto = value == 0u;
        if (value)
            request->verify_concurrency = (uint32_t)value;
        break;
    case QN_SCAN_FIELD_STABILITY_CONCURRENCY:
        value = cycle_value(stability_concurrency,
                            sizeof stability_concurrency / sizeof stability_concurrency[0],
                            request->stability_concurrency_auto
                                ? 0u : request->stability_concurrency,
                            direction);
        request->stability_concurrency_auto = value == 0u;
        if (value)
            request->stability_concurrency = (uint32_t)value;
        break;
    case QN_SCAN_FIELD_MEMORY:
        value = cycle_value(memory, sizeof memory / sizeof memory[0],
                            request->memory_auto ? 0u : request->memory_budget_bytes,
                            direction);
        request->memory_auto = value == 0u;
        if (value)
            request->memory_budget_bytes = value;
        break;
    default:
        return;
    }
    mark_custom(editor);
}

static bool parse_u64(const char *text, uint64_t *value)
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

static bool commit_edit(qn_scan_editor *editor, qn_scan_request *request,
                        char *message, size_t message_capacity)
{
    uint64_t value;
    uint32_t coverage;

    if (!editor->edit_length) {
        editor_message(message, message_capacity, "enter a custom value or press Esc");
        return false;
    }
    if (editor->field == QN_SCAN_FIELD_COVERAGE) {
        if (!qn_coverage_parse(editor->edit, &coverage)) {
            editor_message(message, message_capacity,
                           "Percentage must be from 0.01 to 100 with at most four decimals");
            return false;
        }
        request->coverage_ppm = coverage;
    } else {
        if (!parse_u64(editor->edit, &value)) {
            editor_message(message, message_capacity, "custom value is not a bounded integer");
            return false;
        }
        switch (editor->field) {
        case QN_SCAN_FIELD_ADDRESS_BUDGET:
            if (!value)
                goto positive;
            request->address_budget = value;
            break;
        case QN_SCAN_FIELD_REACHABLE_TARGET:
            if (!value)
                goto positive;
            request->reachable_target = value;
            break;
        case QN_SCAN_FIELD_EXPLORE:
            if (value > 100u) {
                editor_message(message, message_capacity,
                               "Explore Percent must be from 0 to 100");
                return false;
            }
            request->explore_percent = (uint32_t)value;
            break;
        case QN_SCAN_FIELD_CANDIDATE:
            if (!value || value > UINT32_MAX)
                goto bounded;
            request->candidate_auto = false;
            request->candidate_capacity = value;
            break;
        case QN_SCAN_FIELD_FINALISTS:
            if (!value || value > UINT32_MAX)
                goto bounded;
            request->finalists_auto = false;
            request->finalists_all = false;
            request->finalist_limit = value;
            break;
        case QN_SCAN_FIELD_OUTPUT:
            if (!value || value > UINT32_MAX)
                goto bounded;
            request->output_all = false;
            request->output_limit = value;
            break;
        case QN_SCAN_FIELD_SCAN_CONCURRENCY:
            if (!value || value > UINT32_MAX)
                goto bounded;
            request->scan_concurrency_auto = false;
            request->scan_concurrency = (uint32_t)value;
            break;
        case QN_SCAN_FIELD_VERIFY_CONCURRENCY:
            if (!value || value > UINT32_MAX)
                goto bounded;
            request->verify_concurrency_auto = false;
            request->verify_concurrency = (uint32_t)value;
            break;
        case QN_SCAN_FIELD_STABILITY_CONCURRENCY:
            if (!value || value > UINT32_MAX)
                goto bounded;
            request->stability_concurrency_auto = false;
            request->stability_concurrency = (uint32_t)value;
            break;
        case QN_SCAN_FIELD_MEMORY:
            if (!value || value > UINT64_MAX / QN_EDITOR_MIB) {
                editor_message(message, message_capacity, "Memory Budget in MiB overflows");
                return false;
            }
            request->memory_auto = false;
            request->memory_budget_bytes = value * QN_EDITOR_MIB;
            break;
        default:
            return false;
        }
    }
    editor->editing = false;
    editor->edit_length = 0u;
    editor->edit[0] = '\0';
    mark_custom(editor);
    editor_message(message, message_capacity, "custom value accepted; review the effective plan");
    return true;

positive:
    editor_message(message, message_capacity, "custom value must be greater than zero");
    return false;
bounded:
    editor_message(message, message_capacity, "custom value must be from 1 to 4294967295");
    return false;
}

static void begin_edit(qn_scan_editor *editor)
{
    editor->editing = true;
    editor->edit_length = 0u;
    editor->edit[0] = '\0';
}

qn_scan_edit_action qn_scan_editor_key(qn_scan_editor *editor,
                                       qn_scan_request *request,
                                       const qn_key *key,
                                       char *message, size_t message_capacity)
{
    if (!editor || !request || !key)
        return QN_SCAN_EDIT_NONE;
    if (editor->editing) {
        if (key->kind == QN_KEY_ESC) {
            editor->editing = false;
            editor->edit_length = 0u;
            editor->edit[0] = '\0';
            editor_message(message, message_capacity, "custom edit cancelled");
            return QN_SCAN_EDIT_CANCELLED;
        }
        if (key->kind == QN_KEY_BACKSPACE) {
            if (editor->edit_length)
                editor->edit[--editor->edit_length] = '\0';
            return QN_SCAN_EDIT_NONE;
        }
        if (key->kind == QN_KEY_ENTER)
            return commit_edit(editor, request, message, message_capacity)
                       ? QN_SCAN_EDIT_CHANGED : QN_SCAN_EDIT_NONE;
        if (key->kind == QN_KEY_CHAR &&
            ((key->ch >= '0' && key->ch <= '9') ||
             (key->ch == '.' && editor->field == QN_SCAN_FIELD_COVERAGE))) {
            if (editor->edit_length + 1u >= sizeof editor->edit) {
                editor_message(message, message_capacity, "custom value is too long");
                return QN_SCAN_EDIT_NONE;
            }
            editor->edit[editor->edit_length++] = (char)key->ch;
            editor->edit[editor->edit_length] = '\0';
        }
        return QN_SCAN_EDIT_NONE;
    }

    switch (key->kind) {
    case QN_KEY_UP:
        if (editor->field > QN_SCAN_FIELD_PRESET)
            editor->field = (qn_scan_field)(editor->field - 1);
        return QN_SCAN_EDIT_NONE;
    case QN_KEY_DOWN:
        if (editor->field + 1 < QN_SCAN_FIELD__COUNT)
            editor->field = (qn_scan_field)(editor->field + 1);
        return QN_SCAN_EDIT_NONE;
    case QN_KEY_PGUP:
        editor->field = editor->field > 5
                            ? (qn_scan_field)(editor->field - 5)
                            : QN_SCAN_FIELD_PRESET;
        return QN_SCAN_EDIT_NONE;
    case QN_KEY_PGDN:
        editor->field = editor->field + 5 < QN_SCAN_FIELD__COUNT
                            ? (qn_scan_field)(editor->field + 5)
                            : QN_SCAN_FIELD_REVIEW;
        return QN_SCAN_EDIT_NONE;
    case QN_KEY_HOME:
        editor->field = QN_SCAN_FIELD_PRESET;
        return QN_SCAN_EDIT_NONE;
    case QN_KEY_END:
        editor->field = QN_SCAN_FIELD_REVIEW;
        return QN_SCAN_EDIT_NONE;
    case QN_KEY_LEFT:
        cycle_field(editor, request, -1);
        return QN_SCAN_EDIT_CHANGED;
    case QN_KEY_RIGHT:
        cycle_field(editor, request, 1);
        return QN_SCAN_EDIT_CHANGED;
    case QN_KEY_ENTER:
        if (editor->field == QN_SCAN_FIELD_REVIEW)
            return QN_SCAN_EDIT_REVIEW;
        if (qn_scan_field_editable(editor->field))
            begin_edit(editor);
        return QN_SCAN_EDIT_NONE;
    case QN_KEY_ESC:
        return QN_SCAN_EDIT_CANCELLED;
    default:
        break;
    }
    if (key->kind == QN_KEY_CHAR && key->ch >= '0' && key->ch <= '9' &&
        qn_scan_field_editable(editor->field)) {
        begin_edit(editor);
        editor->edit[0] = (char)key->ch;
        editor->edit[1] = '\0';
        editor->edit_length = 1u;
    }
    return QN_SCAN_EDIT_NONE;
}
