#include "qanat/ui.h"

#include "qanat/util.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#define QN_ESC_DELAY_MS 30u

static uint8_t ring_peek(const qn_input *input, uint16_t offset)
{
    return input->ring[(uint16_t)((input->head + offset) % QN_INPUT_RING_CAP)];
}

static uint8_t ring_pop(qn_input *input)
{
    uint8_t value = input->ring[input->head];

    input->head = (uint16_t)((input->head + 1u) % QN_INPUT_RING_CAP);
    input->count--;
    return value;
}

void qn_input_init(qn_input *input)
{
    if (input)
        memset(input, 0, sizeof *input);
}

bool qn_input_feed(qn_input *input, const uint8_t *bytes, size_t count)
{
    uint16_t tail;

    if (!input || (!bytes && count) || count > QN_INPUT_RING_CAP - input->count)
        return false;
    tail = (uint16_t)((input->head + input->count) % QN_INPUT_RING_CAP);
    for (size_t i = 0; i < count; i++) {
        input->ring[tail] = bytes[i];
        tail = (uint16_t)((tail + 1u) % QN_INPUT_RING_CAP);
    }
    input->count = (uint16_t)(input->count + count);
    return true;
}

static bool emit_ascii(uint8_t byte, bool paste, qn_key *out)
{
    out->paste = paste;
    switch (byte) {
    case '\r':
    case '\n': out->kind = QN_KEY_ENTER; return true;
    case '\t': out->kind = QN_KEY_TAB; return true;
    case 0x7fu:
    case 0x08u: out->kind = QN_KEY_BACKSPACE; return true;
    default: break;
    }
    out->kind = QN_KEY_CHAR;
    if (byte < 0x20u) {
        if (paste) {
            out->ch = 0xfffdu;
        } else {
            out->ctrl = true;
            out->ch = (uint32_t)(byte + 'a' - 1);
        }
    } else {
        out->ch = byte;
    }
    return true;
}

static bool begin_utf8(qn_input *input, uint8_t byte, bool paste, qn_key *out)
{
    if (byte >= 0xc2u && byte <= 0xdfu) {
        input->utf8_value = byte & 0x1fu;
        input->utf8_min = 0x80u;
        input->utf8_need = 1u;
    } else if (byte >= 0xe0u && byte <= 0xefu) {
        input->utf8_value = byte & 0x0fu;
        input->utf8_min = 0x800u;
        input->utf8_need = 2u;
    } else if (byte >= 0xf0u && byte <= 0xf4u) {
        input->utf8_value = byte & 0x07u;
        input->utf8_min = 0x10000u;
        input->utf8_need = 3u;
    } else {
        out->kind = QN_KEY_CHAR;
        out->ch = 0xfffdu;
        out->paste = paste;
        return true;
    }
    input->utf8_paste = paste;
    input->state = QN_INPUT_UTF8;
    return false;
}

static bool finish_utf8(qn_input *input, qn_key *out)
{
    uint32_t value = input->utf8_value;
    bool paste = input->utf8_paste;

    input->state = paste ? QN_INPUT_BRACKETED_PASTE : QN_INPUT_GROUND;
    input->utf8_need = 0u;
    out->kind = QN_KEY_CHAR;
    out->paste = paste;
    if (value < input->utf8_min || value > 0x10ffffu ||
        (value >= 0xd800u && value <= 0xdfffu))
        out->ch = 0xfffdu;
    else
        out->ch = value;
    return true;
}

/* CSI parameters are ';'-separated; only the first one names the key. */
static bool csi_first_param(const qn_input *input, unsigned *out_value)
{
    unsigned value = 0u;

    for (uint8_t i = 0; i + 1u < input->seq_len; i++) {
        uint8_t byte = input->seq[i];

        if (byte == ';')
            break;
        if (byte < '0' || byte > '9')
            return false; /* private markers and the like: not ours to read */
        if (value > (UINT_MAX - (unsigned)(byte - '0')) / 10u)
            return false;
        value = value * 10u + (unsigned)(byte - '0');
    }
    *out_value = value;
    return true;
}

static bool decode_csi(qn_input *input, qn_key *out)
{
    uint8_t  final = input->seq[input->seq_len - 1u];
    unsigned value = 0u;

    if (!csi_first_param(input, &value))
        return false;

    /* A modifier says how a key was pressed, never which key it was. */
    switch (final) {
    case 'A': out->kind = QN_KEY_UP; return true;
    case 'B': out->kind = QN_KEY_DOWN; return true;
    case 'C': out->kind = QN_KEY_RIGHT; return true;
    case 'D': out->kind = QN_KEY_LEFT; return true;
    case 'H': out->kind = QN_KEY_HOME; return true;
    case 'F': out->kind = QN_KEY_END; return true;
    default: break;
    }

    if (final == '~') {
        switch (value) {
        case 1u:
        case 7u: out->kind = QN_KEY_HOME; return true;
        case 3u: out->kind = QN_KEY_DELETE; return true;
        case 4u:
        case 8u: out->kind = QN_KEY_END; return true;
        case 5u: out->kind = QN_KEY_PGUP; return true;
        case 6u: out->kind = QN_KEY_PGDN; return true;
        case 200u:
            input->state = QN_INPUT_BRACKETED_PASTE;
            return false;
        default: break;
        }
    }
    /* Ignore a complete unsupported CSI instead of typing a stray character. */
    return false;
}

static bool paste_end_prefix(const qn_input *input, bool *complete)
{
    static const uint8_t end[] = { 0x1bu, '[', '2', '0', '1', '~' };
    uint16_t compare = input->count < sizeof end ? input->count : (uint16_t)sizeof end;

    *complete = false;
    for (uint16_t i = 0; i < compare; i++)
        if (ring_peek(input, i) != end[i])
            return false;
    if (input->count >= sizeof end)
        *complete = true;
    return true;
}

bool qn_input_next(qn_input *input, uint64_t now_ms, qn_key *out)
{
    if (!input || !out)
        return false;
    memset(out, 0, sizeof *out);
    for (;;) {
        if (input->state == QN_INPUT_UTF8) {
            while (input->utf8_need) {
                uint8_t byte;

                if (!input->count)
                    return false;
                byte = ring_peek(input, 0u);
                if ((byte & 0xc0u) != 0x80u) {
                    input->utf8_value = 0xfffdu;
                    input->utf8_need = 0u;
                    return finish_utf8(input, out);
                }
                ring_pop(input);
                input->utf8_value = (input->utf8_value << 6) | (byte & 0x3fu);
                input->utf8_need--;
            }
            return finish_utf8(input, out);
        }

        if (input->state == QN_INPUT_ESC) {
            uint8_t byte;

            if (!input->count) {
                if (now_ms - input->esc_since_ms < QN_ESC_DELAY_MS)
                    return false;
                input->state = QN_INPUT_GROUND;
                out->kind = QN_KEY_ESC;
                return true;
            }
            byte = ring_peek(input, 0u);
            if (byte == '[' || byte == 'O') {
                ring_pop(input);
                input->state = byte == '[' ? QN_INPUT_CSI : QN_INPUT_SS3;
                input->seq_len = 0u;
                continue;
            }
            input->state = QN_INPUT_GROUND;
            out->kind = QN_KEY_ESC;
            return true;
        }

        if (input->state == QN_INPUT_CSI || input->state == QN_INPUT_SS3) {
            uint8_t byte;

            if (!input->count)
                return false;
            byte = ring_pop(input);
            if (input->seq_len >= QN_INPUT_SEQ_CAP) {
                input->state = QN_INPUT_GROUND;
                out->kind = QN_KEY_CHAR;
                out->ch = 0xfffdu;
                return true;
            }
            input->seq[input->seq_len++] = byte;
            if (input->state == QN_INPUT_SS3) {
                input->state = QN_INPUT_GROUND;
                switch (byte) {
                case 'A': out->kind = QN_KEY_UP; return true;
                case 'B': out->kind = QN_KEY_DOWN; return true;
                case 'C': out->kind = QN_KEY_RIGHT; return true;
                case 'D': out->kind = QN_KEY_LEFT; return true;
                case 'H': out->kind = QN_KEY_HOME; return true;
                case 'F': out->kind = QN_KEY_END; return true;
                case 'P': out->kind = QN_KEY_F1; return true;
                default: out->kind = QN_KEY_CHAR; out->ch = 0xfffdu; return true;
                }
            }
            if (byte >= 0x40u && byte <= 0x7eu) {
                bool emitted;

                input->state = QN_INPUT_GROUND;
                emitted = decode_csi(input, out);
                input->seq_len = 0u;
                if (emitted)
                    return true;
            } else if (byte < 0x20u || byte > 0x3fu) {
                input->state = QN_INPUT_GROUND;
                input->seq_len = 0u;
                out->kind = QN_KEY_CHAR;
                out->ch = 0xfffdu;
                return true;
            }
            continue;
        }

        if (input->state == QN_INPUT_BRACKETED_PASTE) {
            bool complete;
            uint8_t byte;

            if (!input->count)
                return false;
            if (ring_peek(input, 0u) == 0x1bu && paste_end_prefix(input, &complete)) {
                if (!complete)
                    return false;
                for (unsigned i = 0; i < 6u; i++)
                    ring_pop(input);
                input->state = QN_INPUT_GROUND;
                continue;
            }
            byte = ring_pop(input);
            if (byte < 0x80u)
                return emit_ascii(byte == 0x1bu ? 0u : byte, true, out);
            if (begin_utf8(input, byte, true, out))
                return true;
            continue;
        }

        if (!input->count)
            return false;
        {
            uint8_t byte = ring_pop(input);

            if (byte == 0x1bu) {
                input->state = QN_INPUT_ESC;
                input->esc_since_ms = now_ms;
                continue;
            }
            if (byte < 0x80u)
                return emit_ascii(byte, false, out);
            if (begin_utf8(input, byte, false, out))
                return true;
        }
    }
}

bool qn_input_poll(qn_input *input, int fd, qn_key *out)
{
    uint8_t bytes[512];
    size_t free_space;
    ssize_t got;
    uint64_t now = qn_now_ms();

    if (qn_input_next(input, now, out))
        return true;
    if (!input || input->count >= QN_INPUT_RING_CAP)
        return false;
    free_space = QN_INPUT_RING_CAP - input->count;
    if (free_space > sizeof bytes)
        free_space = sizeof bytes;
    do {
        got = read(fd, bytes, free_space);
    } while (got < 0 && errno == EINTR);
    if (got <= 0)
        return qn_input_next(input, qn_now_ms(), out);
    if (!qn_input_feed(input, bytes, (size_t)got))
        return false;
    return qn_input_next(input, qn_now_ms(), out);
}
