#include "qanat/ui.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); failures++; } } while (0)

static void test_burst_preserved(void)
{
    static const uint8_t burst[] = "abc\033[Axyz";
    static const uint32_t chars[] = { 'a', 'b', 'c', 'x', 'y', 'z' };
    qn_input input;
    qn_key key;
    size_t character = 0u, events = 0u;

    qn_input_init(&input);
    CHECK(qn_input_feed(&input, burst, sizeof burst - 1u));
    while (qn_input_next(&input, 100u, &key)) {
        events++;
        if (events == 4u)
            CHECK(key.kind == QN_KEY_UP);
        else {
            CHECK(key.kind == QN_KEY_CHAR);
            CHECK(character < sizeof chars / sizeof chars[0]);
            if (character < sizeof chars / sizeof chars[0])
                CHECK(key.ch == chars[character++]);
        }
    }
    CHECK(events == 7u && character == 6u && input.count == 0u);
}

static void test_split_escape_and_standalone(void)
{
    qn_input input;
    qn_key key;
    uint8_t byte;

    qn_input_init(&input);
    byte = 0x1bu;
    CHECK(qn_input_feed(&input, &byte, 1u));
    CHECK(!qn_input_next(&input, 10u, &key));
    byte = '[';
    CHECK(qn_input_feed(&input, &byte, 1u));
    CHECK(!qn_input_next(&input, 20u, &key));
    byte = 'A';
    CHECK(qn_input_feed(&input, &byte, 1u));
    CHECK(qn_input_next(&input, 21u, &key) && key.kind == QN_KEY_UP);

    byte = 0x1bu;
    CHECK(qn_input_feed(&input, &byte, 1u));
    CHECK(!qn_input_next(&input, 100u, &key));
    CHECK(!qn_input_next(&input, 129u, &key));
    CHECK(qn_input_next(&input, 130u, &key) && key.kind == QN_KEY_ESC);
}

static void test_utf8_and_malformed(void)
{
    static const uint8_t globe[] = { 0xf0u, 0x9fu, 0x8cu, 0x8du };
    static const uint8_t bad[] = { 0xc0u, 'x', 0xe2u, 'y' };
    qn_input input;
    qn_key key;

    qn_input_init(&input);
    for (size_t i = 0; i < sizeof globe; i++) {
        CHECK(qn_input_feed(&input, &globe[i], 1u));
        if (i + 1u < sizeof globe)
            CHECK(!qn_input_next(&input, 1u + i, &key));
    }
    CHECK(qn_input_next(&input, 9u, &key));
    CHECK(key.kind == QN_KEY_CHAR && key.ch == 0x1f30du);

    CHECK(qn_input_feed(&input, bad, sizeof bad));
    CHECK(qn_input_next(&input, 10u, &key) && key.ch == 0xfffdu);
    CHECK(qn_input_next(&input, 10u, &key) && key.ch == 'x');
    CHECK(qn_input_next(&input, 10u, &key) && key.ch == 0xfffdu);
    CHECK(qn_input_next(&input, 10u, &key) && key.ch == 'y');
}

static void test_bracketed_paste(void)
{
    static const uint8_t bytes[] = "\033[200~ab\xc3\xa9\033[201~q";
    static const uint32_t chars[] = { 'a', 'b', 0xe9u, 'q' };
    qn_input input;
    qn_key key;
    size_t n = 0u;

    qn_input_init(&input);
    for (size_t i = 0; i < sizeof bytes - 1u; i++) {
        CHECK(qn_input_feed(&input, &bytes[i], 1u));
        while (qn_input_next(&input, (uint64_t)i, &key)) {
            CHECK(n < sizeof chars / sizeof chars[0]);
            if (n < sizeof chars / sizeof chars[0]) {
                CHECK(key.kind == QN_KEY_CHAR && key.ch == chars[n]);
                CHECK(key.paste == (n < 3u));
                n++;
            }
        }
    }
    CHECK(n == sizeof chars / sizeof chars[0]);
    CHECK(input.count == 0u && input.state == QN_INPUT_GROUND);
}

/* A modified or unknown CSI must never reach the UI as a printable character. */
static void test_parameterised_csi(void)
{
    static const struct {
        const char *bytes;
        size_t      len;
        qn_key_kind kind; /* QN_KEY_NONE means: consume it and emit nothing */
    } cases[] = {
        { "\033[A", 3u, QN_KEY_UP },
        { "\033[1;5A", 6u, QN_KEY_UP },    /* ctrl-up */
        { "\033[1;2B", 6u, QN_KEY_DOWN },  /* shift-down */
        { "\033[1;3D", 6u, QN_KEY_LEFT },  /* alt-left */
        { "\033[1;5C", 6u, QN_KEY_RIGHT }, /* ctrl-right */
        { "\033[1;5H", 6u, QN_KEY_HOME },
        { "\033[5;5~", 6u, QN_KEY_PGUP },  /* ctrl-pgup */
        { "\033[999Z", 6u, QN_KEY_NONE },  /* well framed, not a key we act on */
        { "\033[?1049h", 8u, QN_KEY_NONE } /* a private-mode echo */
    };
    qn_input input;
    qn_key   key;

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int seen = 0;

        qn_input_init(&input);
        CHECK(qn_input_feed(&input, (const uint8_t *)cases[i].bytes, cases[i].len));
        while (qn_input_next(&input, 100000u, &key)) {
            seen++;
            if (key.kind == QN_KEY_CHAR)
                fprintf(stderr, "  %s decoded as character U+%04X\n", cases[i].bytes + 1,
                        key.ch);
            CHECK(key.kind != QN_KEY_CHAR);
            CHECK(key.kind == cases[i].kind);
        }
        CHECK(seen == (cases[i].kind == QN_KEY_NONE ? 0 : 1));
        CHECK(input.count == 0u && input.state == QN_INPUT_GROUND);
    }

    /* The sequence is consumed either way, so what follows still arrives. */
    qn_input_init(&input);
    CHECK(qn_input_feed(&input, (const uint8_t *)"\033[1;5Az", 7u));
    CHECK(qn_input_next(&input, 100000u, &key) && key.kind == QN_KEY_UP);
    CHECK(qn_input_next(&input, 100000u, &key) && key.kind == QN_KEY_CHAR && key.ch == 'z');
    CHECK(!qn_input_next(&input, 100000u, &key));
}

int main(void)
{
    test_burst_preserved();
    test_parameterised_csi();
    test_split_escape_and_standalone();
    test_utf8_and_malformed();
    test_bracketed_paste();
    if (failures) {
        fprintf(stderr, "input tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("input tests: ok");
    return 0;
}
