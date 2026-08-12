#include "qanat/ui.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); failures++; } } while (0)

static qn_scan_edit_action press(qn_scan_editor *editor, qn_scan_request *request,
                                 qn_key_kind kind, uint32_t ch, char message[192])
{
    qn_key key;

    memset(&key, 0, sizeof key);
    key.kind = kind;
    key.ch = ch;
    return qn_scan_editor_key(editor, request, &key, message, 192u);
}

static void type_text(qn_scan_editor *editor, qn_scan_request *request,
                      const char *text, char message[192])
{
    for (size_t i = 0u; text[i]; i++)
        (void)press(editor, request, QN_KEY_CHAR, (uint8_t)text[i], message);
}

static void test_presets_and_independent_fields(void)
{
    qn_scan_editor editor;
    qn_scan_request request;
    char message[192] = "";

    qn_scan_request_defaults(&request);
    qn_scan_editor_init(&editor);
    CHECK(press(&editor, &request, QN_KEY_RIGHT, 0u, message) == QN_SCAN_EDIT_CHANGED);
    CHECK(editor.preset == QN_PRESET_QUICK);
    CHECK(request.mode == QN_SCAN_COVERAGE);
    CHECK(request.finalist_limit == 64u);

    editor.field = QN_SCAN_FIELD_CANDIDATE;
    type_text(&editor, &request, "131072", message);
    CHECK(press(&editor, &request, QN_KEY_ENTER, 0u, message) == QN_SCAN_EDIT_CHANGED);
    CHECK(!request.candidate_auto && request.candidate_capacity == 131072u);
    CHECK(editor.preset == QN_PRESET_CUSTOM);

    editor.field = QN_SCAN_FIELD_FINALISTS;
    request.finalists_auto = true;
    request.finalists_all = false;
    CHECK(press(&editor, &request, QN_KEY_LEFT, 0u, message) == QN_SCAN_EDIT_CHANGED);
    CHECK(request.finalists_all && !request.finalists_auto);

    editor.field = QN_SCAN_FIELD_OUTPUT;
    request.output_all = false;
    request.output_limit = 256u;
    (void)press(&editor, &request, QN_KEY_RIGHT, 0u, message);
    CHECK(request.output_all);

    editor.field = QN_SCAN_FIELD_VERIFY_CONCURRENCY;
    type_text(&editor, &request, "32", message);
    CHECK(press(&editor, &request, QN_KEY_ENTER, 0u, message) == QN_SCAN_EDIT_CHANGED);
    CHECK(!request.verify_concurrency_auto && request.verify_concurrency == 32u);
    CHECK(request.finalists_all);
}

static void test_decimal_validation_and_overflow(void)
{
    qn_scan_editor editor;
    qn_scan_request request;
    char message[192] = "";
    uint32_t old_coverage;

    qn_scan_request_defaults(&request);
    qn_scan_editor_init(&editor);
    editor.field = QN_SCAN_FIELD_COVERAGE;
    type_text(&editor, &request, "12.5", message);
    CHECK(press(&editor, &request, QN_KEY_ENTER, 0u, message) == QN_SCAN_EDIT_CHANGED);
    CHECK(request.coverage_ppm == 125000u);

    old_coverage = request.coverage_ppm;
    type_text(&editor, &request, "0.001", message);
    CHECK(press(&editor, &request, QN_KEY_ENTER, 0u, message) == QN_SCAN_EDIT_NONE);
    CHECK(editor.editing);
    CHECK(request.coverage_ppm == old_coverage);
    CHECK(strstr(message, "0.01") != NULL);
    CHECK(press(&editor, &request, QN_KEY_ESC, 0u, message) == QN_SCAN_EDIT_CANCELLED);

    editor.field = QN_SCAN_FIELD_CANDIDATE;
    type_text(&editor, &request, "9999999999999999999999999999999", message);
    CHECK(press(&editor, &request, QN_KEY_ENTER, 0u, message) == QN_SCAN_EDIT_NONE);
    CHECK(editor.editing);
    CHECK(request.candidate_auto);
    (void)press(&editor, &request, QN_KEY_ESC, 0u, message);

    editor.field = QN_SCAN_FIELD_MEMORY;
    type_text(&editor, &request, "256", message);
    CHECK(press(&editor, &request, QN_KEY_ENTER, 0u, message) == QN_SCAN_EDIT_CHANGED);
    CHECK(!request.memory_auto);
    CHECK(request.memory_budget_bytes == (UINT64_C(256) << 20));
}

static void test_navigation_and_review(void)
{
    qn_scan_editor editor;
    qn_scan_request request;
    char message[192] = "";

    qn_scan_request_defaults(&request);
    qn_scan_editor_init(&editor);
    (void)press(&editor, &request, QN_KEY_END, 0u, message);
    CHECK(editor.field == QN_SCAN_FIELD_REVIEW);
    CHECK(press(&editor, &request, QN_KEY_ENTER, 0u, message) == QN_SCAN_EDIT_REVIEW);
    (void)press(&editor, &request, QN_KEY_HOME, 0u, message);
    CHECK(editor.field == QN_SCAN_FIELD_PRESET);
    CHECK(press(&editor, &request, QN_KEY_ESC, 0u, message) == QN_SCAN_EDIT_CANCELLED);
}

static void test_tunnel_fields(void)
{
    qn_scan_editor editor;
    qn_scan_request request;
    char message[192] = "";
    char value[64];

    qn_scan_request_defaults(&request);
    qn_scan_editor_init(&editor);
    editor.field = QN_SCAN_FIELD_TUNNEL_STAGE;
    CHECK(press(&editor, &request, QN_KEY_RIGHT, 0u, message) ==
          QN_SCAN_EDIT_CHANGED);
    CHECK(request.tunnel_enabled && request.tunnel_target == 5u);
    editor.field = QN_SCAN_FIELD_TUNNEL_TARGET;
    type_text(&editor, &request, "10", message);
    CHECK(press(&editor, &request, QN_KEY_ENTER, 0u, message) ==
          QN_SCAN_EDIT_CHANGED);
    CHECK(!request.tunnel_all && request.tunnel_target == 10u);
    editor.field = QN_SCAN_FIELD_TUNNEL_CONCURRENCY;
    type_text(&editor, &request, "33", message);
    CHECK(press(&editor, &request, QN_KEY_ENTER, 0u, message) ==
          QN_SCAN_EDIT_NONE);
    CHECK(strstr(message, "1 to 32") != NULL);
    (void)press(&editor, &request, QN_KEY_ESC, 0u, message);
    CHECK(qn_scan_field_value(&editor, &request, QN_SCAN_FIELD_TUNNEL_STAGE,
                              value, sizeof value) > 0);
    CHECK(!strcmp(value, "Enabled"));
}

int main(void)
{
    test_presets_and_independent_fields();
    test_decimal_validation_and_overflow();
    test_navigation_and_review();
    test_tunnel_fields();
    if (failures) {
        fprintf(stderr, "scan editor tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("scan editor tests: ok");
    return 0;
}
