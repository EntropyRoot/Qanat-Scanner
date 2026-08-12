#include "qanat/ui.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static qn_color_depth g_depth = QN_COLOR_256;
static bool           g_utf8  = true;

static void ob_reserve(qn_screen *s, size_t n)
{
    size_t required;

    if (s->build_failed)
        return;
    if (n > SIZE_MAX - s->olen) {
        s->build_failed = true;
        return;
    }
    required = s->olen + n;
    if (required <= s->ocap)
        return;
    {
        size_t want = (s->ocap ? s->ocap : 8192);
        char  *p;
        while (want < required) {
            if (want > SIZE_MAX / 2u) {
                s->build_failed = true;
                return;
            }
            want *= 2;
        }
        p = (char *)realloc(s->obuf, want);
        if (!p) {
            s->build_failed = true;
            return;
        }
        s->obuf = p;
        s->ocap = want;
    }
}

static void ob_put(qn_screen *s, const char *str, size_t n)
{
    ob_reserve(s, n);
    if (s->build_failed)
        return;
    memcpy(s->obuf + s->olen, str, n);
    s->olen += n;
}

static void ob_str(qn_screen *s, const char *str)
{
    ob_put(s, str, strlen(str));
}

static void ob_uint(qn_screen *s, uint32_t v)
{
    char  tmp[12];
    int   i = 0;

    if (!v) {
        ob_put(s, "0", 1);
        return;
    }
    while (v) {
        tmp[i++] = (char)('0' + v % 10u);
        v /= 10u;
    }
    ob_reserve(s, (size_t)i);
    while (i--)
        ob_put(s, &tmp[i], 1);
}

static void ob_utf8(qn_screen *s, uint32_t cp)
{
    char b[4];

    if (cp < 0x80) {
        b[0] = (char)cp;
        ob_put(s, b, 1);
    } else if (!g_utf8) {
        ob_put(s, "?", 1);
    } else if (cp < 0x800) {
        b[0] = (char)(0xC0u | (cp >> 6));
        b[1] = (char)(0x80u | (cp & 0x3Fu));
        ob_put(s, b, 2);
    } else if (cp < 0x10000) {
        b[0] = (char)(0xE0u | (cp >> 12));
        b[1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        b[2] = (char)(0x80u | (cp & 0x3Fu));
        ob_put(s, b, 3);
    } else {
        b[0] = (char)(0xF0u | (cp >> 18));
        b[1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
        b[2] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        b[3] = (char)(0x80u | (cp & 0x3Fu));
        ob_put(s, b, 4);
    }
}

static uint8_t rgb_to_256(uint32_t c)
{
    uint32_t r = (c >> 16) & 0xFFu, g = (c >> 8) & 0xFFu, b = c & 0xFFu;

    /* Preserve neutral greys before cube quantisation. */
    if (r == g && g == b) {
        if (r < 8)
            return 16;
        if (r > 248)
            return 231;
        return (uint8_t)(232u + (r - 8u) * 24u / 240u);
    }
    return (uint8_t)(16u + 36u * (r * 5u / 255u) + 6u * (g * 5u / 255u) + (b * 5u / 255u));
}

static void emit_color(qn_screen *s, uint32_t c, bool fg)
{
    if (g_depth == QN_COLOR_NONE)
        return;
    if (c == QN_COL_DEFAULT) {
        ob_str(s, fg ? "\033[39m" : "\033[49m");
        return;
    }

    if (g_depth == QN_COLOR_TRUE) {
        ob_str(s, fg ? "\033[38;2;" : "\033[48;2;");
        ob_uint(s, (c >> 16) & 0xFFu);
        ob_put(s, ";", 1);
        ob_uint(s, (c >> 8) & 0xFFu);
        ob_put(s, ";", 1);
        ob_uint(s, c & 0xFFu);
        ob_put(s, "m", 1);
    } else {
        ob_str(s, fg ? "\033[38;5;" : "\033[48;5;");
        ob_uint(s, rgb_to_256(c));
        ob_put(s, "m", 1);
    }
}

static void apply_style(qn_screen *s, const qn_cell *c)
{
    if (c->attr != s->cur_attr) {
        ob_str(s, "\033[0m");
        s->cur_fg   = QN_COL_DEFAULT;
        s->cur_bg   = QN_COL_DEFAULT;
        s->cur_attr = 0;

        if (c->attr & QN_ATTR_BOLD)
            ob_str(s, "\033[1m");
        if (c->attr & QN_ATTR_DIM)
            ob_str(s, "\033[2m");
        if (c->attr & QN_ATTR_ITALIC)
            ob_str(s, "\033[3m");
        if (c->attr & QN_ATTR_UNDER)
            ob_str(s, "\033[4m");
        if (c->attr & QN_ATTR_REVERSE)
            ob_str(s, "\033[7m");
        s->cur_attr = c->attr;
    }
    if (c->fg != s->cur_fg) {
        emit_color(s, c->fg, true);
        s->cur_fg = c->fg;
    }
    if (c->bg != s->cur_bg) {
        emit_color(s, c->bg, false);
        s->cur_bg = c->bg;
    }
}

bool qn_screen_init(qn_screen *s, uint16_t w, uint16_t h)
{
    memset(s, 0, sizeof *s);
    return qn_screen_resize(s, w, h);
}

bool qn_screen_resize(qn_screen *s, uint16_t w, uint16_t h)
{
    uint32_t n = (uint32_t)w * h;
    qn_cell *f, *b;

    if (!n)
        return false;
    f = (qn_cell *)calloc(n, sizeof *f);
    b = (qn_cell *)calloc(n, sizeof *b);
    if (!f || !b) {
        free(f);
        free(b);
        return false;
    }

    free(s->front);
    free(s->back);
    s->front  = f;
    s->back   = b;
    s->w      = w;
    s->h      = h;
    s->ncells = n;

    /* Terminal contents are unknown after resize. */
    for (uint32_t i = 0; i < n; i++)
        s->front[i].ch = 0xFFFFFFFFu;

    s->cur_x = s->cur_y = -1;
    s->cur_fg = s->cur_bg = QN_COL_DEFAULT;
    s->cur_attr           = 0xFFFFu;
    return true;
}

void qn_screen_free(qn_screen *s)
{
    free(s->front);
    free(s->back);
    free(s->obuf);
    memset(s, 0, sizeof *s);
}

void qn_screen_clear(qn_screen *s, uint32_t bg)
{
    for (uint32_t i = 0; i < s->ncells; i++) {
        s->back[i].ch   = ' ';
        s->back[i].fg   = QN_COL_DEFAULT;
        s->back[i].bg   = bg;
        s->back[i].attr = 0;
    }
}

/* Cells go straight to the terminal, so no control scalar may be stored. */
static uint32_t safe_cell(uint32_t cp)
{
    if (cp < 0x20u || cp == 0x7Fu || (cp >= 0x80u && cp <= 0x9Fu))
        return 0x00B7u;
    if ((cp >= 0xD800u && cp <= 0xDFFFu) || cp > 0x10FFFFu)
        return 0x00B7u;
    return cp;
}

void qn_put(qn_screen *s, int x, int y, uint32_t ch, uint32_t fg, uint32_t bg, uint16_t attr)
{
    qn_cell *c;

    if (x < 0 || y < 0 || x >= (int)s->w || y >= (int)s->h)
        return;
    c       = &s->back[(uint32_t)y * s->w + (uint32_t)x];
    c->ch   = safe_cell(ch);
    c->fg   = fg;
    c->bg   = bg;
    c->attr = attr;
}

/* Invalid UTF-8 renders as a middle dot; overlong and surrogate both count. */
static uint32_t utf8_next(const char **p)
{
    const uint8_t *u = (const uint8_t *)*p;
    uint32_t       c = u[0], v;

    if (c < 0x80u) {
        *p += 1;
        return c;
    }
    if (c >= 0xC2u && c <= 0xDFu && (u[1] & 0xC0u) == 0x80u) {
        *p += 2;
        return ((c & 0x1Fu) << 6) | (u[1] & 0x3Fu);
    }
    if (c >= 0xE0u && c <= 0xEFu && (u[1] & 0xC0u) == 0x80u && (u[2] & 0xC0u) == 0x80u) {
        v = ((c & 0x0Fu) << 12) | ((uint32_t)(u[1] & 0x3Fu) << 6) | (u[2] & 0x3Fu);
        if (v >= 0x800u && (v < 0xD800u || v > 0xDFFFu)) {
            *p += 3;
            return v;
        }
    }
    if (c >= 0xF0u && c <= 0xF4u && (u[1] & 0xC0u) == 0x80u && (u[2] & 0xC0u) == 0x80u &&
        (u[3] & 0xC0u) == 0x80u) {
        v = ((c & 0x07u) << 18) | ((uint32_t)(u[1] & 0x3Fu) << 12) |
            ((uint32_t)(u[2] & 0x3Fu) << 6) | (u[3] & 0x3Fu);
        if (v >= 0x10000u && v <= 0x10FFFFu) {
            *p += 4;
            return v;
        }
    }
    *p += 1;
    return 0x00B7u;
}

int qn_textn(qn_screen *s, int x, int y, const char *str, int maxw, uint32_t fg, uint32_t bg,
             uint16_t attr)
{
    int n = 0;

    if (y < 0 || y >= (int)s->h)
        return 0;
    while (*str && n < maxw && x + n < (int)s->w) {
        uint32_t cp = utf8_next(&str);
        qn_put(s, x + n, y, cp, fg, bg, attr);
        n++;
    }
    return n;
}

int qn_text(qn_screen *s, int x, int y, const char *str, uint32_t fg, uint32_t bg, uint16_t attr)
{
    return qn_textn(s, x, y, str, (int)s->w, fg, bg, attr);
}

int qn_printf(qn_screen *s, int x, int y, uint32_t fg, uint32_t bg, uint16_t attr, const char *fmt,
              ...)
{
    char    buf[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    return qn_text(s, x, y, buf, fg, bg, attr);
}

void qn_fill(qn_screen *s, int x, int y, int w, int h, uint32_t ch, uint32_t fg, uint32_t bg,
             uint16_t attr)
{
    for (int j = 0; j < h; j++)
        for (int i = 0; i < w; i++)
            qn_put(s, x + i, y + j, ch, fg, bg, attr);
}

void qn_hline(qn_screen *s, int x, int y, int w, uint32_t ch, uint32_t fg, uint32_t bg)
{
    for (int i = 0; i < w; i++)
        qn_put(s, x + i, y, ch, fg, bg, 0);
}

/* Adjacent changed cells need no cursor-motion escape. */
static void move_to(qn_screen *s, int x, int y)
{
    if (s->cur_y == y && s->cur_x == x)
        return;

    ob_str(s, "\033[");
    ob_uint(s, (uint32_t)(y + 1));
    ob_put(s, ";", 1);
    ob_uint(s, (uint32_t)(x + 1));
    ob_put(s, "H", 1);
    s->cur_x = x;
    s->cur_y = y;
}

bool qn_screen_flush(qn_screen *s, qn_term *t)
{
    uint32_t dirty = 0;
    uint32_t saved_fg, saved_bg;
    uint16_t saved_attr;
    int32_t saved_x, saved_y;

    if (!s || !t || !s->front || !s->back)
        return false;

    g_depth = t->depth;
    g_utf8  = t->utf8;
    s->olen = 0;
    s->build_failed = false;
    saved_fg = s->cur_fg;
    saved_bg = s->cur_bg;
    saved_attr = s->cur_attr;
    saved_x = s->cur_x;
    saved_y = s->cur_y;

    for (uint16_t y = 0; y < s->h; y++) {
        const uint32_t row = (uint32_t)y * s->w;

        for (uint16_t x = 0; x < s->w; x++) {
            qn_cell *b = &s->back[row + x];
            qn_cell *f = &s->front[row + x];

            if (b->ch == f->ch && b->fg == f->fg && b->bg == f->bg && b->attr == f->attr)
                continue;

            move_to(s, x, y);
            apply_style(s, b);
            ob_utf8(s, b->ch ? b->ch : ' ');

            /* Autowrap-off leaves the cursor at the final column. */
            s->cur_x = (x + 1 < (int)s->w) ? x + 1 : -1;
            dirty++;
        }
    }

    s->last_dirty = dirty;
    if (!s->olen && !s->build_failed)
        return true;

    ob_str(s, "\033[0m");
    s->cur_fg = s->cur_bg = QN_COL_DEFAULT;
    s->cur_attr           = 0;

    if (s->build_failed) {
        s->cur_fg = saved_fg;
        s->cur_bg = saved_bg;
        s->cur_attr = saved_attr;
        s->cur_x = saved_x;
        s->cur_y = saved_y;
        s->olen = 0;
        return false;
    }

    {
        size_t off = 0;
        while (off < s->olen) {
            ssize_t n = write(t->fd, s->obuf + off, s->olen - off);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            off += (size_t)n;
        }
        s->bytes_out += off;
        if (off != s->olen) {
            for (uint32_t i = 0; i < s->ncells; i++)
                s->front[i].ch = UINT32_MAX;
            s->cur_x = s->cur_y = -1;
            s->olen = 0;
            return false;
        }
    }
    memcpy(s->front, s->back, (size_t)s->ncells * sizeof *s->front);
    s->frames++;
    s->olen = 0;
    return true;
}
