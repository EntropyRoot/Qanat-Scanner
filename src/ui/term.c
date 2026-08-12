#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qanat/ui.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

static struct termios g_saved;
static volatile sig_atomic_t g_winch = 1;
static volatile sig_atomic_t g_intr;
static struct sigaction g_old_winch, g_old_int, g_old_term, g_old_hup, g_old_pipe;
static qn_term *g_active_term;
static bool g_handlers_saved;
static bool g_atexit_registered;

static bool write_all(int fd, const char *bytes, size_t count)
{
    size_t offset = 0u;

    while (offset < count) {
        ssize_t written = write(fd, bytes + offset, count - offset);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return false;
        offset += (size_t)written;
    }
    return true;
}

static void restore_handlers(void)
{
    if (!g_handlers_saved)
        return;
    (void)sigaction(SIGWINCH, &g_old_winch, NULL);
    (void)sigaction(SIGINT, &g_old_int, NULL);
    (void)sigaction(SIGTERM, &g_old_term, NULL);
    (void)sigaction(SIGHUP, &g_old_hup, NULL);
    (void)sigaction(SIGPIPE, &g_old_pipe, NULL);
    g_handlers_saved = false;
}

static void emergency_restore(void)
{
    qn_term *term = g_active_term;

    if (!term)
        return;
    if (term->alt) {
        static const char sequence[] = "\033[?2004l\033[0m\033[?7h\033[?25h\033[?1049l";

        (void)write_all(term->fd, sequence, sizeof sequence - 1u);
        term->alt = false;
    }
    if (term->raw) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved);
        term->raw = false;
    }
    restore_handlers();
    g_active_term = NULL;
}

static void on_winch(int sig)
{
    (void)sig;
    g_winch = 1;
}

static void on_intr(int sig)
{
    (void)sig;
    g_intr = 1;
}

static qn_color_depth detect_depth(void)
{
    const char *ct = getenv("COLORTERM");
    const char *t  = getenv("TERM");

    if (ct && (strstr(ct, "truecolor") || strstr(ct, "24bit")))
        return QN_COLOR_TRUE;
    if (!t)
        return QN_COLOR_256;
    if (strstr(t, "256"))
        return QN_COLOR_256;
    if (!strcmp(t, "dumb"))
        return QN_COLOR_NONE;
    return QN_COLOR_256;
}

static void query_size(qn_term *t)
{
    struct winsize ws;

    if (ioctl(t->fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col && ws.ws_row) {
        t->w = ws.ws_col;
        t->h = ws.ws_row;
    } else {
        t->w = 80;
        t->h = 24;
    }
}

bool qn_term_open(qn_term *t, bool want_color)
{
    struct termios raw;
    struct sigaction sa;
    const char      *lang;

    memset(t, 0, sizeof *t);
    t->fd = STDOUT_FILENO;

    if (!isatty(t->fd) || !isatty(STDIN_FILENO))
        return false;
    if (tcgetattr(STDIN_FILENO, &g_saved) != 0)
        return false;

    raw = g_saved;
    raw.c_lflag &= (tcflag_t) ~(ECHO | ICANON | ISIG | IEXTEN);
    raw.c_iflag &= (tcflag_t) ~(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
    raw.c_oflag &= (tcflag_t) ~(OPOST);
    raw.c_cc[VMIN]  = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0)
        return false;
    t->raw = true;

    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGWINCH, NULL, &g_old_winch) != 0 ||
        sigaction(SIGINT, NULL, &g_old_int) != 0 ||
        sigaction(SIGTERM, NULL, &g_old_term) != 0 ||
        sigaction(SIGHUP, NULL, &g_old_hup) != 0 ||
        sigaction(SIGPIPE, NULL, &g_old_pipe) != 0)
        goto fail;
    g_handlers_saved = true;
    sa.sa_handler = on_winch;
    if (sigaction(SIGWINCH, &sa, NULL) != 0)
        goto fail_handlers;
    sa.sa_handler = on_intr;
    if (sigaction(SIGINT, &sa, NULL) != 0 ||
        sigaction(SIGTERM, &sa, NULL) != 0 ||
        sigaction(SIGHUP, &sa, NULL) != 0)
        goto fail_handlers;
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) != 0)
        goto fail_handlers;

    lang     = getenv("LANG");
    t->utf8  = !lang || strstr(lang, "UTF-8") || strstr(lang, "utf8") || strstr(lang, "UTF8");
    t->depth = want_color ? detect_depth() : QN_COLOR_NONE;

    query_size(t);

    {
        static const char seq[] = "\033[?1049h\033[?25l\033[?7l\033[?2004h";
        if (!write_all(t->fd, seq, sizeof seq - 1u))
            goto fail_handlers;
    }
    t->alt = true;
    g_active_term = t;
    if (!g_atexit_registered) {
        if (atexit(emergency_restore) != 0)
            goto fail_active;
        g_atexit_registered = true;
    }
    return true;

fail_active:
    g_active_term = NULL;
fail_handlers:
    restore_handlers();
fail:
    if (t->raw) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved);
        t->raw = false;
    }
    return false;
}

void qn_term_close(qn_term *t)
{
    if (t->alt) {
        static const char seq[] = "\033[?2004l\033[0m\033[?7h\033[?25h\033[?1049l";
        (void)write_all(t->fd, seq, sizeof seq - 1u);
        t->alt = false;
    }
    if (t->raw) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved);
        t->raw = false;
    }
    restore_handlers();
    if (g_active_term == t)
        g_active_term = NULL;
}

bool qn_term_resized(qn_term *t)
{
    if (!g_winch)
        return false;
    g_winch = 0;
    query_size(t);
    return true;
}

bool qn_term_interrupted(void)
{
    return g_intr != 0;
}
