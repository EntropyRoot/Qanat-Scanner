#ifndef QANAT_UI_H
#define QANAT_UI_H

#include "qanat/engine.h"
#include "qanat/netinfo.h"
#include "qanat/stats.h"

typedef enum {
    QN_COLOR_NONE = 0,
    QN_COLOR_16,
    QN_COLOR_256,
    QN_COLOR_TRUE
} qn_color_depth;

typedef struct {
    int            fd;
    uint16_t       w, h;
    qn_color_depth depth;
    bool           raw;
    bool           alt;
    bool           utf8;
} qn_term;

bool qn_term_open(qn_term *t, bool want_color);
void qn_term_close(qn_term *t);
bool qn_term_resized(qn_term *t); /* consumes the SIGWINCH flag */
bool qn_term_interrupted(void);

enum {
    QN_ATTR_BOLD    = 1u << 0,
    QN_ATTR_DIM     = 1u << 1,
    QN_ATTR_REVERSE = 1u << 2,
    QN_ATTR_UNDER   = 1u << 3,
    QN_ATTR_ITALIC  = 1u << 4
};

#define QN_COL_DEFAULT 0xFF000000u
#define QN_RGB(r, g, b) \
    ((uint32_t)(((uint32_t)(r) << 16) | ((uint32_t)(g) << 8) | (uint32_t)(b)))

typedef struct {
    uint32_t ch;
    uint32_t fg, bg;
    uint16_t attr;
    uint16_t _pad;
} qn_cell;

/* Damage tracking minimizes Termux pty traffic. */
typedef struct {
    qn_cell *front, *back;
    uint16_t w, h;
    uint32_t ncells;
    char    *obuf;
    size_t   ocap, olen;
    bool     build_failed;

    uint32_t cur_fg, cur_bg;
    uint16_t cur_attr;
    int32_t  cur_x, cur_y;

    uint64_t frames;
    uint64_t bytes_out;
    uint32_t last_dirty;
} qn_screen;

bool qn_screen_init(qn_screen *s, uint16_t w, uint16_t h);
bool qn_screen_resize(qn_screen *s, uint16_t w, uint16_t h);
void qn_screen_free(qn_screen *s);
void qn_screen_clear(qn_screen *s, uint32_t bg);
bool qn_screen_flush(qn_screen *s, qn_term *t);

void qn_put(qn_screen *s, int x, int y, uint32_t ch, uint32_t fg, uint32_t bg, uint16_t attr);
int  qn_text(qn_screen *s, int x, int y, const char *str, uint32_t fg, uint32_t bg, uint16_t attr);
int  qn_textn(qn_screen *s, int x, int y, const char *str, int maxw, uint32_t fg, uint32_t bg, uint16_t attr);
int  qn_printf(qn_screen *s, int x, int y, uint32_t fg, uint32_t bg, uint16_t attr, const char *fmt, ...)
    QN_FMT(7, 8);
void qn_fill(qn_screen *s, int x, int y, int w, int h, uint32_t ch, uint32_t fg, uint32_t bg, uint16_t attr);
void qn_hline(qn_screen *s, int x, int y, int w, uint32_t ch, uint32_t fg, uint32_t bg);

typedef struct {
    uint32_t bg, fg, dim, faint;
    uint32_t accent, accent2;
    uint32_t good, warn, bad, info;
    uint32_t panel, border, border_hi;
    uint32_t sel_bg, sel_fg;
    uint32_t head_bg, head_fg;
    uint32_t bar_fill, bar_track;
} qn_theme;

const qn_theme *qn_theme_get(void);
void            qn_theme_init(qn_color_depth depth);

typedef struct {
    int x, y, w, h;
} qn_rect;

void qn_box(qn_screen *s, qn_rect r, const char *title, bool focus);
void qn_gauge(qn_screen *s, qn_rect r, double frac, uint32_t fill, uint32_t track);
void qn_sparkline(qn_screen *s, qn_rect r, const qn_spark *sp, uint32_t col);
void qn_histogram(qn_screen *s, qn_rect r, const qn_hist *h, uint32_t col);
void qn_kv(qn_screen *s, int x, int y, int w, const char *k, const char *v, uint32_t vcol);
void qn_badge(qn_screen *s, int x, int y, const char *label, uint32_t fg, uint32_t bg);

typedef enum {
    QN_KEY_NONE = 0,
    QN_KEY_CHAR,
    QN_KEY_UP,
    QN_KEY_DOWN,
    QN_KEY_LEFT,
    QN_KEY_RIGHT,
    QN_KEY_PGUP,
    QN_KEY_PGDN,
    QN_KEY_HOME,
    QN_KEY_END,
    QN_KEY_ENTER,
    QN_KEY_ESC,
    QN_KEY_TAB,
    QN_KEY_BACKSPACE,
    QN_KEY_DELETE,
    QN_KEY_F1
} qn_key_kind;

typedef struct {
    qn_key_kind kind;
    uint32_t    ch;
    bool        ctrl;
    bool        paste;
} qn_key;

typedef enum {
    QN_INPUT_GROUND = 0,
    QN_INPUT_ESC,
    QN_INPUT_CSI,
    QN_INPUT_SS3,
    QN_INPUT_UTF8,
    QN_INPUT_BRACKETED_PASTE
} qn_input_state;

#define QN_INPUT_RING_CAP 8192u
#define QN_INPUT_SEQ_CAP  32u

typedef struct {
    uint8_t  ring[QN_INPUT_RING_CAP];
    uint16_t head;
    uint16_t count;
    uint8_t  state;
    uint8_t  utf8_need;
    uint8_t  seq_len;
    bool     utf8_paste;
    uint32_t utf8_value;
    uint32_t utf8_min;
    uint64_t esc_since_ms;
    uint8_t  seq[QN_INPUT_SEQ_CAP];
} qn_input;

void qn_input_init(qn_input *input);
bool qn_input_feed(qn_input *input, const uint8_t *bytes, size_t count);
bool qn_input_next(qn_input *input, uint64_t now_ms, qn_key *out);
bool qn_input_poll(qn_input *input, int fd, qn_key *out);

typedef enum {
    QN_SCAN_FIELD_PRESET = 0,
    QN_SCAN_FIELD_SCOPE,
    QN_SCAN_FIELD_COVERAGE,
    QN_SCAN_FIELD_ADDRESS_BUDGET,
    QN_SCAN_FIELD_REACHABLE_TARGET,
    QN_SCAN_FIELD_SELECTION,
    QN_SCAN_FIELD_EXPLORE,
    QN_SCAN_FIELD_CANDIDATE,
    QN_SCAN_FIELD_FINALISTS,
    QN_SCAN_FIELD_OUTPUT,
    QN_SCAN_FIELD_RANK,
    QN_SCAN_FIELD_SCAN_CONCURRENCY,
    QN_SCAN_FIELD_VERIFY_CONCURRENCY,
    QN_SCAN_FIELD_STABILITY_CONCURRENCY,
    QN_SCAN_FIELD_TUNNEL_STAGE,
    QN_SCAN_FIELD_TUNNEL_TARGET,
    QN_SCAN_FIELD_TUNNEL_CONCURRENCY,
    QN_SCAN_FIELD_TUNNEL_ATTEMPTS,
    QN_SCAN_FIELD_MEMORY,
    QN_SCAN_FIELD_REVIEW,
    QN_SCAN_FIELD__COUNT
} qn_scan_field;

typedef enum {
    QN_SCAN_EDIT_NONE = 0,
    QN_SCAN_EDIT_CHANGED,
    QN_SCAN_EDIT_REVIEW,
    QN_SCAN_EDIT_CANCELLED
} qn_scan_edit_action;

typedef struct {
    qn_scan_preset preset;
    qn_scan_field  field;
    uint16_t       scroll;
    bool           editing;
    bool           dirty;
    uint8_t        edit_length;
    char           edit[32];
} qn_scan_editor;

void qn_scan_editor_init(qn_scan_editor *editor);
const char *qn_scan_field_label(qn_scan_field field);
const char *qn_scan_field_group(qn_scan_field field);
bool qn_scan_field_active(qn_scan_field field, const qn_scan_request *request);
bool qn_scan_field_editable(qn_scan_field field);
int qn_scan_field_value(const qn_scan_editor *editor, const qn_scan_request *request,
                        qn_scan_field field, char *buffer, size_t capacity);
qn_scan_edit_action qn_scan_editor_key(qn_scan_editor *editor,
                                       qn_scan_request *request,
                                       const qn_key *key,
                                       char *message, size_t message_capacity);

typedef enum {
    QN_VIEW_DASH = 0,
    QN_VIEW_CF,
    QN_VIEW_PLAN,
    QN_VIEW_PORTS,
    QN_VIEW_HOSTS,
    QN_VIEW_NET,
    QN_VIEW_HELP,
    QN_VIEW__COUNT
} qn_view;

typedef struct qn_app qn_app;

int qn_app_run(qn_config *cfg);

#endif /* QANAT_UI_H */
