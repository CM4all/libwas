/*
 * Synchronous server implementation of the Web Application Socket
 * protocol.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#include <was/simple.h>
#include <was/protocol.h>

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <glib.h>

struct was_control_packet {
    enum was_command command;
    size_t length;
    const void *payload;
};

struct was_simple {
    struct {
        int fd;

        union {
            char raw[4096];
            struct was_header header;
        } buffer;

        size_t position;

        struct was_control_packet packet;
    } control;

    struct {
        int fd;

        uint64_t received;
    } input;

    struct {
        int fd;

        uint64_t sent, announced;
        bool known_length;
        bool no_body;
    } output;

    struct {
        http_method_t method;
        char *uri;
        bool finished;
    } request;

    struct {
        enum {
            RESPONSE_STATE_NONE,
            RESPONSE_STATE_STATUS,
            RESPONSE_STATE_HEADERS,
            RESPONSE_STATE_BODY,
            RESPONSE_STATE_END,
        } state;
    } response;
};

static void
was_simple_free_request(struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    g_free(w->request.uri);
}

struct was_simple *
was_simple_new(void)
{
    struct was_simple *w = g_new(struct was_simple, 1);

    w->control.fd = 3;
    w->control.position = 0;
    w->control.packet.payload = NULL;

    w->input.fd = 0;
    w->input.received = 0;

    w->output.fd = 1;
    w->output.sent = 0;
    w->output.known_length = false;

    w->response.state = RESPONSE_STATE_NONE;

    return w;
}

void
was_simple_free(struct was_simple *w)
{
    was_simple_free_request(w);
    g_free(w);
}

static bool
was_simple_control_fill(struct was_simple *w, bool dontwait)
{
    assert(w->control.position < sizeof(w->control.buffer));

    ssize_t nbytes = recv(w->control.fd,
                          w->control.buffer.raw + w->control.position,
                          sizeof(w->control.buffer) - w->control.position,
                          dontwait * MSG_DONTWAIT);
    if (nbytes <= 0)
        return false;

    w->control.position += nbytes;
    return true;
}

static bool
was_simple_control_complete(const struct was_simple *w)
{
    return w->control.position >= sizeof(w->control.buffer.header) &&
        w->control.position >= sizeof(w->control.buffer.header) + w->control.buffer.header.length;
}

static void
was_simple_control_shift(struct was_simple *w)
{
    assert(was_simple_control_complete(w));

    unsigned full_length = sizeof(w->control.buffer.header) +
        w->control.buffer.header.length;

    w->control.position -= full_length;
    memmove(w->control.buffer.raw, w->control.buffer.raw + full_length,
            w->control.position);

    w->control.packet.payload = NULL;
}

static const struct was_control_packet *
was_simple_control_get(struct was_simple *w)
{
    if (!was_simple_control_complete(w))
        return NULL;

    w->control.packet.command = w->control.buffer.header.command;
    w->control.packet.length = w->control.buffer.header.length;

    if (w->control.packet.length > 0) {
        w->control.packet.payload = w->control.buffer.raw +
            sizeof(w->control.buffer.header);
    } else {
        w->control.packet.payload = NULL;
        was_simple_control_shift(w);
    }

    return &w->control.packet;
}

static const struct was_control_packet *
was_simple_control_read(struct was_simple *w, bool dontwait)
{
    /* clean up the previous packet */
    if (w->control.packet.payload != NULL)
        was_simple_control_shift(w);

    while (true) {
        const struct was_control_packet *packet = was_simple_control_get(w);
        if (packet != NULL)
            return packet;

        /* XXX check if buffer is full */

        if (!was_simple_control_fill(w, dontwait))
            return NULL;
    }
}

static const struct was_control_packet *
was_simple_control_expect(struct was_simple *w, enum was_command command)
{
    const struct was_control_packet *packet =
        was_simple_control_read(w, false);
    return packet != NULL && packet->command == command
        ? packet
        : NULL;
}

static bool
was_simple_control_send(struct was_simple *w, const void *data, size_t length)
{
    ssize_t nbytes = send(w->control.fd, data, length, MSG_NOSIGNAL);
    return nbytes == (ssize_t)length;
}

static bool
was_simple_control_send_header(struct was_simple *w, enum was_command command,
                               size_t length)
{
    struct was_header header = {
        .command = command,
        .length = length,
    };

    return was_simple_control_send(w, &header, sizeof(header));
}

static bool
was_simple_control_send_empty(struct was_simple *w, enum was_command command)
{
    return was_simple_control_send_header(w, command, 0);
}

static bool
was_simple_control_send_packet(struct was_simple *w, enum was_command command,
                               const void *payload, size_t length)
{
    return was_simple_control_send_header(w, command, length) &&
        was_simple_control_send(w, payload, length);
}

static void
was_simple_clear_request(struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    was_simple_free_request(w);

    w->response.state = RESPONSE_STATE_NONE;
}

static void
was_simple_finish_request(struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    // XXX
    was_simple_set_eof(w);
    was_simple_clear_request(w);
}

static bool
was_simple_apply_request_packet(struct was_simple *w,
                                const struct was_control_packet *packet)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    switch (packet->command) {
    case WAS_COMMAND_NOP:
        break;

    case WAS_COMMAND_REQUEST:
        return false;

    case WAS_COMMAND_URI:
        if (w->request.uri != NULL)
            return false;
        w->request.uri = g_strndup(packet->payload, packet->length);
        break;

    case WAS_COMMAND_SCRIPT_NAME:
    case WAS_COMMAND_PATH_INFO:
    case WAS_COMMAND_QUERY_STRING:
    case WAS_COMMAND_HEADER:
    case WAS_COMMAND_PARAMETER:
        /* XXX implement */
        break;

    case WAS_COMMAND_STATUS:
        return false;

    case WAS_COMMAND_NO_DATA:
    case WAS_COMMAND_DATA:
        /* XXX body? */
        w->request.finished = true;
        break;

    case WAS_COMMAND_LENGTH:
    case WAS_COMMAND_ABORT:
        /* XXX implement */
        return false;
    }

    return true;
}

const char *
was_simple_accept(struct was_simple *w)
{
    if (w->response.state != RESPONSE_STATE_NONE)
        was_simple_finish_request(w);

    assert(w->response.state == RESPONSE_STATE_NONE);

    const struct was_control_packet *packet;
    packet = was_simple_control_expect(w, WAS_COMMAND_REQUEST);
    if (packet == NULL)
        return NULL;

    assert(w->response.state == RESPONSE_STATE_NONE);
    w->response.state = RESPONSE_STATE_STATUS;

    memset(&w->request, 0, sizeof(w->request));
    w->request.method = HTTP_METHOD_GET;

    do {
        packet = was_simple_control_read(w, false);
        if (packet == NULL)
            return NULL;

        if (!was_simple_apply_request_packet(w, packet))
            return NULL;
    } while (!w->request.finished);

    return w->request.uri;
}

http_method_t
was_simple_get_method(const struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    return w->request.method;
}

const char *
was_simple_get_header(struct was_simple *w, const char *name)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    /* XXX */
    (void)w;
    (void)name;
    return NULL;
}

const char *
was_simple_get_parameter(struct was_simple *w, const char *name)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    /* XXX */
    (void)w;
    (void)name;
    return NULL;
}

int
was_simple_input_fd(const struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    return w->input.fd;
}

bool
was_simple_received(struct was_simple *w, size_t nbytes)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    w->input.received += nbytes;
    /* XXX */
    return true;
}

void
was_simple_input_close(struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    // XXX
    (void)w;
}

bool
was_simple_status(struct was_simple *w, http_status_t status)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    if (w->response.state != RESPONSE_STATE_STATUS)
        /* too late for sending the status */
        return false;

    if (!was_simple_control_send_packet(w, WAS_COMMAND_STATUS,
                                        &status, sizeof(status)))
        return false;

    w->response.state = RESPONSE_STATE_HEADERS;
    w->output.no_body = http_status_is_empty(status);
    return true;
}

bool
was_simple_set_header(struct was_simple *w,
                      const char *name, const char *value)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    if (w->response.state == RESPONSE_STATE_STATUS &&
        !was_simple_status(w, HTTP_STATUS_OK))
        return false;

    assert(w->response.state == RESPONSE_STATE_HEADERS);

    // XXX
    (void)name;
    (void)value;
    return true;
}

bool
was_simple_set_length(struct was_simple *w, uint64_t length)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    if (w->output.no_body)
        return false;

    assert(length >= w->output.sent);

    if (w->output.known_length) {
        assert(length == w->output.known_length);
        return true;
    }

    if (w->response.state == RESPONSE_STATE_STATUS &&
        !was_simple_status(w, HTTP_STATUS_OK))
        return false;

    if (w->response.state == RESPONSE_STATE_HEADERS) {
        if (!was_simple_control_send_empty(w, WAS_COMMAND_DATA))
            return false;

        w->response.state = RESPONSE_STATE_BODY;
    }

    assert(w->response.state == RESPONSE_STATE_BODY);

    if (!was_simple_control_send_packet(w, WAS_COMMAND_LENGTH,
                                        &length, sizeof(length)))
        return false;

    w->output.announced = length;
    w->output.known_length = true;
    return true;
}

static bool
was_simple_set_response_state_body(struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    if (w->response.state == RESPONSE_STATE_STATUS &&
        !was_simple_status(w, HTTP_STATUS_OK))
        return false;

    if (w->response.state == RESPONSE_STATE_HEADERS) {
        if (w->output.no_body) {
            w->response.state = RESPONSE_STATE_END;
            was_simple_control_send_empty(w, WAS_COMMAND_NO_DATA);
            return false;
        }

        if (!was_simple_control_send_empty(w, WAS_COMMAND_DATA))
            return false;

        w->response.state = RESPONSE_STATE_BODY;
    }

    assert(w->response.state == RESPONSE_STATE_BODY);

    return true;
}

int
was_simple_output_fd(struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    if (!was_simple_set_response_state_body(w))
        return -1;

    return w->output.fd;
}

bool
was_simple_sent(struct was_simple *w, size_t nbytes)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    if (w->output.no_body)
        return false;

    assert(!w->output.known_length || w->output.sent <= w->output.announced);
    assert(!w->output.known_length || nbytes <= w->output.announced);
    assert(!w->output.known_length ||
           w->output.sent + nbytes <= w->output.announced);

    w->output.sent += nbytes;
    return true;
}

bool
was_simple_write(struct was_simple *w, const void *data0, size_t length)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    if (!was_simple_set_response_state_body(w))
        return -1;

    const char *data = data0;

    while (length > 0) {
        ssize_t nbytes = write(w->output.fd, data, length);
        if (nbytes <= 0)
            return false;

        w->output.sent += nbytes;
        data += nbytes;
        length -= nbytes;
    }

    return true;
}

bool
was_simple_puts(struct was_simple *w, const char *s)
{
    return was_simple_write(w, s, strlen(s));
}

bool
was_simple_printf(struct was_simple *w, const char *fmt, ...)
{
    char buffer[4096];

    va_list va;
    va_start(va, fmt);
    g_vsnprintf(buffer, sizeof(buffer), fmt, va);
    va_end(va);

    return was_simple_puts(w, buffer);
}

bool
was_simple_set_eof(struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    if (w->response.state == RESPONSE_STATE_STATUS &&
        !was_simple_status(w, HTTP_STATUS_NO_CONTENT))
        return false;

    if (w->response.state == RESPONSE_STATE_HEADERS) {
        if (w->output.no_body) {
            if (!was_simple_control_send_empty(w, WAS_COMMAND_NO_DATA))
                return false;

            w->response.state = RESPONSE_STATE_END;
            return true;
        }

        w->response.state = RESPONSE_STATE_BODY;
    }

    if (w->response.state == RESPONSE_STATE_BODY) {
        if (w->output.known_length) {
            if (w->output.sent != w->output.announced)
                // XXX
                return false;
        } else {
            if (!was_simple_set_length(w, w->output.sent))
                return false;
        }
    }

    return true;
}
