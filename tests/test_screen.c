/* Untrusted text must never put a control code point in a cell. */

#include "qanat/ui.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failures;

#define CHECK(expr)                                                                  \
    do {                                                                             \
        if (!(expr)) {                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);          \
            failures++;                                                              \
        }                                                                            \
    } while (0)

static bool any_control_cell(const qn_screen *s)
{
    uint32_t i, n = (uint32_t)s->w * s->h;

    for (i = 0; i < n; i++) {
        uint32_t c = s->back[i].ch;

        if (c < 0x20u || c == 0x7Fu || (c >= 0x80u && c <= 0x9Fu))
            return true;
        if ((c >= 0xD800u && c <= 0xDFFFu) || c > 0x10FFFFu)
            return true;
    }
    return false;
}

static void test_control_sequences_never_reach_a_cell(void)
{
    static const char *hostile[] = {
        "\x1b[31mRED",                  /* SGR */
        "\x1b]0;title\x07",             /* OSC with BEL terminator */
        "\x1b[2J\x1b[H",                /* clear and home */
        "a\rb\nc\td",                   /* bare C0 */
        "\x7f\x08",                     /* DEL and backspace */
        "\xc2\x9b\x33\x31m",            /* C1 CSI as valid UTF-8 */
        "\xc0\xaf",                     /* overlong solidus */
        "\xed\xa0\x80",                 /* lone surrogate */
        "\xf7\xbf\xbf\xbf",             /* beyond U+10FFFF */
        "\xe0\x80\x80"                  /* overlong three-byte */
    };
    qn_screen s;
    size_t    i;

    CHECK(qn_screen_init(&s, 80, 24));
    for (i = 0; i < sizeof hostile / sizeof hostile[0]; i++) {
        qn_screen_clear(&s, 0);
        qn_text(&s, 0, 0, hostile[i], 0xFFFFFFu, 0, 0);
        if (any_control_cell(&s)) {
            fprintf(stderr, "FAIL hostile string %zu reached a cell\n", i);
            failures++;
        }
    }

    /* The C1 case must not merely be dropped: it has to occupy a cell. */
    qn_screen_clear(&s, 0);
    CHECK(qn_text(&s, 0, 0, "\x1b[31mX", 0xFFFFFFu, 0, 0) == 6);

    qn_screen_free(&s);
}

static void test_valid_text_survives(void)
{
    qn_screen s;

    CHECK(qn_screen_init(&s, 80, 24));
    qn_screen_clear(&s, 0);
    /* "café ✓ 🌍": two, three and four byte scalars must pass through whole. */
    CHECK(qn_text(&s, 0, 0, "caf\xc3\xa9 \xe2\x9c\x93 \xf0\x9f\x8c\x8d", 0xFFFFFFu, 0, 0) == 8);
    CHECK(s.back[0].ch == 'c');
    CHECK(s.back[3].ch == 0xE9u);
    CHECK(s.back[5].ch == 0x2713u);
    CHECK(s.back[7].ch == 0x1F30Du);
    CHECK(!any_control_cell(&s));
    qn_screen_free(&s);
}

static void test_writes_outside_the_screen_are_dropped(void)
{
    qn_screen s;

    CHECK(qn_screen_init(&s, 10, 4));
    qn_screen_clear(&s, 0);
    qn_put(&s, -1, 0, 'a', 0, 0, 0);
    qn_put(&s, 0, -1, 'b', 0, 0, 0);
    qn_put(&s, 10, 0, 'c', 0, 0, 0);
    qn_put(&s, 0, 4, 'd', 0, 0, 0);
    CHECK(qn_text(&s, 0, 4, "off-screen", 0, 0, 0) == 0);
    /* A long line stops at the edge rather than wrapping into the next row. */
    CHECK(qn_text(&s, 5, 1, "abcdefghij", 0, 0, 0) == 5);
    CHECK(s.back[1u * 10u + 9u].ch == 'e');
    qn_screen_free(&s);
}

static void test_flush_commits_only_after_complete_write(void)
{
    qn_screen s;
    qn_term term;
    int pipefd[2];
    uint32_t before;

    CHECK(qn_screen_init(&s, 4u, 2u));
    qn_screen_clear(&s, 0u);
    qn_put(&s, 0, 0, 'X', 0xffffffu, 0u, 0u);
    before = s.front[0].ch;
    memset(&term, 0, sizeof term);
    term.fd = -1;
    term.utf8 = true;
    CHECK(!qn_screen_flush(&s, &term));
    CHECK(s.front[0].ch == before);
    CHECK(s.frames == 0u);

    CHECK(pipe(pipefd) == 0);
    term.fd = pipefd[1];
    CHECK(qn_screen_flush(&s, &term));
    CHECK(s.front[0].ch == 'X');
    CHECK(s.frames == 1u);
    close(pipefd[0]);
    close(pipefd[1]);
    qn_screen_free(&s);
}

int main(void)
{
    test_control_sequences_never_reach_a_cell();
    test_valid_text_survives();
    test_writes_outside_the_screen_are_dropped();
    test_flush_commits_only_after_complete_write();
    if (failures) {
        fprintf(stderr, "screen tests: %d failure(s)\n", failures);
        return 1;
    }
    puts("screen tests: ok");
    return 0;
}
