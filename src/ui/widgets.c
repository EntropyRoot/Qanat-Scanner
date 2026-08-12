#include "qanat/ui.h"

#include <stdio.h>
#include <string.h>

static qn_theme g_theme;

void qn_theme_init(qn_color_depth depth)
{
    if (depth == QN_COLOR_NONE) {
        qn_theme *t = &g_theme;
        uint32_t  d = QN_COL_DEFAULT;

        t->bg = t->fg = t->dim = t->faint = d;
        t->accent = t->accent2 = d;
        t->good = t->warn = t->bad = t->info = d;
        t->panel = t->border = t->border_hi = d;
        t->sel_bg = t->sel_fg = d;
        t->head_bg = t->head_fg = d;
        t->bar_fill = t->bar_track = d;
        return;
    }

    g_theme.bg        = QN_RGB(0x0E, 0x11, 0x16);
    g_theme.panel     = QN_RGB(0x14, 0x18, 0x1F);
    g_theme.fg        = QN_RGB(0xD6, 0xDD, 0xE6);
    g_theme.dim       = QN_RGB(0x8A, 0x95, 0xA5);
    g_theme.faint     = QN_RGB(0x4A, 0x53, 0x61);
    g_theme.border    = QN_RGB(0x2A, 0x32, 0x3D);
    g_theme.border_hi = QN_RGB(0x3E, 0x82, 0xC4);
    g_theme.accent    = QN_RGB(0x4F, 0xA6, 0xE8);
    g_theme.accent2   = QN_RGB(0xA9, 0x7B, 0xE8);
    g_theme.good      = QN_RGB(0x54, 0xC9, 0x8A);
    g_theme.warn      = QN_RGB(0xE0, 0xB0, 0x4E);
    g_theme.bad       = QN_RGB(0xE2, 0x67, 0x67);
    g_theme.info      = QN_RGB(0x5C, 0xC8, 0xD0);
    g_theme.sel_bg    = QN_RGB(0x1E, 0x36, 0x4E);
    g_theme.sel_fg    = QN_RGB(0xEC, 0xF2, 0xF9);
    g_theme.head_bg   = QN_RGB(0x1A, 0x20, 0x29);
    g_theme.head_fg   = QN_RGB(0x9F, 0xB0, 0xC4);
    g_theme.bar_fill  = QN_RGB(0x3E, 0x82, 0xC4);
    g_theme.bar_track = QN_RGB(0x22, 0x29, 0x33);
}

const qn_theme *qn_theme_get(void)
{
    return &g_theme;
}

enum {
    BOX_H  = 0x2500,
    BOX_V  = 0x2502,
    BOX_TL = 0x256D,
    BOX_TR = 0x256E,
    BOX_BL = 0x2570,
    BOX_BR = 0x256F
};

void qn_box(qn_screen *s, qn_rect r, const char *title, bool focus)
{
    const qn_theme *t  = qn_theme_get();
    uint32_t        bc = focus ? t->border_hi : t->border;
    uint32_t        bg = t->panel;

    if (r.w < 2 || r.h < 2)
        return;

    qn_fill(s, r.x, r.y, r.w, r.h, ' ', t->fg, bg, 0);

    qn_put(s, r.x, r.y, BOX_TL, bc, bg, 0);
    qn_put(s, r.x + r.w - 1, r.y, BOX_TR, bc, bg, 0);
    qn_put(s, r.x, r.y + r.h - 1, BOX_BL, bc, bg, 0);
    qn_put(s, r.x + r.w - 1, r.y + r.h - 1, BOX_BR, bc, bg, 0);

    for (int i = 1; i < r.w - 1; i++) {
        qn_put(s, r.x + i, r.y, BOX_H, bc, bg, 0);
        qn_put(s, r.x + i, r.y + r.h - 1, BOX_H, bc, bg, 0);
    }
    for (int j = 1; j < r.h - 1; j++) {
        qn_put(s, r.x, r.y + j, BOX_V, bc, bg, 0);
        qn_put(s, r.x + r.w - 1, r.y + j, BOX_V, bc, bg, 0);
    }

    if (title && *title && r.w > 6) {
        qn_put(s, r.x + 2, r.y, ' ', bc, bg, 0);
        int n = qn_textn(s, r.x + 3, r.y, title, r.w - 6, focus ? t->sel_fg : t->head_fg, bg,
                         QN_ATTR_BOLD);
        qn_put(s, r.x + 3 + n, r.y, ' ', bc, bg, 0);
    }
}

/* Eighth-blocks provide sub-cell progress resolution. */
static const uint32_t kEighths[9] = { ' ',    0x258F, 0x258E, 0x258D, 0x258C,
                                      0x258B, 0x258A, 0x2589, 0x2588 };

void qn_gauge(qn_screen *s, qn_rect r, double frac, uint32_t fill, uint32_t track)
{
    int total, whole, rem;

    if (r.w <= 0)
        return;
    if (frac < 0.0)
        frac = 0.0;
    if (frac > 1.0)
        frac = 1.0;

    total = (int)(frac * r.w * 8.0 + 0.5);
    whole = total / 8;
    rem   = total % 8;

    for (int i = 0; i < r.w; i++) {
        if (i < whole)
            qn_put(s, r.x + i, r.y, kEighths[8], fill, track, 0);
        else if (i == whole && rem)
            qn_put(s, r.x + i, r.y, kEighths[rem], fill, track, 0);
        else
            qn_put(s, r.x + i, r.y, ' ', fill, track, 0);
    }
}

static const uint32_t kBars[9] = { ' ',    0x2581, 0x2582, 0x2583, 0x2584,
                                   0x2585, 0x2586, 0x2587, 0x2588 };

void qn_sparkline(qn_screen *s, qn_rect r, const qn_spark *sp, uint32_t col)
{
    const qn_theme *t   = qn_theme_get();
    uint32_t        max = 0;

    if (r.w <= 0)
        return;
    for (uint32_t i = 0; i < QN_SPARK_LEN; i++) {
        uint32_t v = qn_spark_at(sp, i);
        if (v > max)
            max = v;
    }
    if (!max)
        max = 1;

    for (int i = 0; i < r.w; i++) {
        uint32_t idx = (uint32_t)i * QN_SPARK_LEN / (uint32_t)r.w;
        uint32_t v   = qn_spark_at(sp, idx);
        uint32_t lvl = v * 8u / max;

        if (v && !lvl)
            lvl = 1;
        qn_put(s, r.x + i, r.y, kBars[QN_MIN(lvl, 8u)], col, t->panel, 0);
    }
}

void qn_histogram(qn_screen *s, qn_rect r, const qn_hist *h, uint32_t col)
{
    const qn_theme *t = qn_theme_get();
    int             bins;

    if (r.w <= 0 || r.h <= 0 || !h->total)
        return;
    bins = QN_MIN(r.w, (int)QN_HIST_BINS);

    for (int i = 0; i < bins; i++) {
        uint32_t v      = h->bin[i];
        uint32_t eighth = h->max_bin ? v * (uint32_t)r.h * 8u / h->max_bin : 0u;

        if (v && !eighth)
            eighth = 1;

        for (int j = 0; j < r.h; j++) {
            int      from_bottom = r.h - 1 - j;
            uint32_t lo          = (uint32_t)from_bottom * 8u;
            uint32_t lvl         = eighth > lo ? QN_MIN(eighth - lo, 8u) : 0u;

            qn_put(s, r.x + i, r.y + j, kBars[lvl], col, t->panel, 0);
        }
    }
}

void qn_kv(qn_screen *s, int x, int y, int w, const char *k, const char *v, uint32_t vcol)
{
    const qn_theme *t = qn_theme_get();
    int             kn;

    kn = qn_textn(s, x, y, k, w, t->dim, t->panel, 0);
    if (kn + 1 < w)
        qn_textn(s, x + kn + 1, y, v, w - kn - 1, vcol, t->panel, QN_ATTR_BOLD);
}

void qn_badge(qn_screen *s, int x, int y, const char *label, uint32_t fg, uint32_t bg)
{
    int n = (int)strlen(label);

    qn_put(s, x, y, ' ', fg, bg, 0);
    qn_text(s, x + 1, y, label, fg, bg, QN_ATTR_BOLD);
    qn_put(s, x + 1 + n, y, ' ', fg, bg, 0);
}
