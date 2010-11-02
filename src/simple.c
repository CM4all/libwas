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
#include <poll.h>
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

        uint64_t received, announced;
        bool known_length, no_body;
    } input;

    struct {
        int fd;

        uint64_t sent, announced;
        bool known_length;
        bool no_body;
    } output;

    struct {
        http_method_t method;
        char *uri, *script_name, *path_info, *query_string;

        GHashTable *headers, *parameters;

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
    g_hash_table_destroy(w->request.headers);
    g_hash_table_destroy(w->request.parameters);
}

struct was_simple *
was_simple_new(void)
{
    struct was_simple *w = g_new(struct was_simple, 1);

    w->control.fd = 3;
    w->control.position = 0;
    w->control.packet.payload = NULL;

    w->input.fd = 0;
    w->output.fd = 1;

    w->response.state = RESPONSE_STATE_NONE;

    return w;
}

void
was_simple_free(struct was_simple *w)
{
    if (w->response.state != RESPONSE_STATE_NONE)
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
was_simple_control_next(struct was_simple *w)
{
    /* clean up the previous packet */
    if (w->control.packet.payload != NULL)
        was_simple_control_shift(w);

    return was_simple_control_get(w);
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

static bool
was_simple_control_send_uint64(struct was_simple *w, enum was_command command,
                               uint64_t payload)
{
    return was_simple_control_send_packet(w, command,
                                          &payload, sizeof(payload));
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
    was_simple_end(w);
    was_simple_clear_request(w);
}

static bool
was_simple_apply_map(GHashTable *map, const char *payload, size_t length)
{
    const char *p = memchr(payload, '=', length);
    if (p == NULL || p == payload)
        return false;

    g_hash_table_insert(map, g_strndup(payload, p - payload),
                        g_strndup(p + 1, payload + length - (p + 1)));
    return true;
}

static bool
was_simple_apply_request_packet(struct was_simple *w,
                                const struct was_control_packet *packet)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    switch (packet->command) {
        http_method_t method;
        uint64_t length;

    case WAS_COMMAND_NOP:
        break;

    case WAS_COMMAND_REQUEST:
        return false;

    case WAS_COMMAND_METHOD:
        if (packet->length != sizeof(uint32_t))
            return false;

        method = (http_method_t)*(const uint32_t *)packet->payload;
        if (w->request.method != HTTP_METHOD_GET &&
            method != w->request.method)
            /* sending that packet twice is illegal */
            return false;

        if (!http_method_is_valid(method))
            return false;

        w->request.method = method;
        break;

    case WAS_COMMAND_URI:
        if (w->request.uri != NULL)
            return false;
        w->request.uri = g_strndup(packet->payload, packet->length);
        break;

    case WAS_COMMAND_SCRIPT_NAME:
        if (w->request.script_name != NULL)
            return false;
        w->request.script_name = g_strndup(packet->payload, packet->length);
        break;

    case WAS_COMMAND_PATH_INFO:
        if (w->request.path_info != NULL)
            return false;
        w->request.path_info = g_strndup(packet->payload, packet->length);
        break;

    case WAS_COMMAND_QUERY_STRING:
        if (w->request.query_string != NULL)
            return false;
        w->request.query_string = g_strndup(packet->payload, packet->length);
        break;

    case WAS_COMMAND_HEADER:
        was_simple_apply_map(w->request.headers,
                             packet->payload, packet->length);
        break;

    case WAS_COMMAND_PARAMETER:
        was_simple_apply_map(w->request.parameters,
                             packet->payload, packet->length);
        break;

    case WAS_COMMAND_STATUS:
        return false;

    case WAS_COMMAND_NO_DATA:
        w->input.announced = 0;
        w->input.known_length = true;
        w->input.no_body = true;
        w->request.finished = true;
        break;

    case WAS_COMMAND_DATA:
        /* XXX body? */
        w->input.no_body = false;
        w->request.finished = true;
        break;

    case WAS_COMMAND_LENGTH:
        if (packet->length != sizeof(length))
            return false;

        length = *(const uint64_t *)packet->payload;
        if (length < w->input.received ||
            (w->input.known_length && length != w->input.announced))
            return false;

        w->input.announced = length;
        w->input.known_length = true;
        break;

    case WAS_COMMAND_STOP:
    case WAS_COMMAND_PREMATURE:
        /* XXX implement */
        return false;
    }

    return true;
}

static bool
was_simple_control_apply_pending(struct was_simple *w)
{
    const struct was_control_packet *packet;
    while ((packet = was_simple_control_next(w)) != NULL)
        if (!was_simple_apply_request_packet(w, packet))
            return false;

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

    w->input.received = 0;
    w->input.known_length = false;

    w->output.sent = 0;
    w->output.known_length = false;

    w->response.state = RESPONSE_STATE_STATUS;

    memset(&w->request, 0, sizeof(w->request));
    w->request.method = HTTP_METHOD_GET;
    w->request.headers = g_hash_table_new_full(g_str_hash, g_str_equal,
                                               g_free, g_free);
    w->request.parameters = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                  g_free, g_free);

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
was_simple_get_script_name(const struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    return w->request.script_name;
}

const char *
was_simple_get_path_info(const struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    return w->request.path_info;
}

const char *
was_simple_get_query_string(const struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    return w->request.query_string;
}

const char *
was_simple_get_header(struct was_simple *w, const char *name)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    return g_hash_table_lookup(w->request.headers, name);
}

const char *
was_simple_get_parameter(struct was_simple *w, const char *name)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    return g_hash_table_lookup(w->request.parameters, name);
}

bool
was_simple_has_body(const struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    return !w->input.no_body;
}

static bool
was_simple_input_eof(const struct was_simple *w)
{
    return w->input.known_length && w->input.received >= w->input.announced;
}

enum was_simple_poll_result
was_simple_input_poll(struct was_simple *w, int timeout_ms)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    if (w->input.no_body || was_simple_input_eof(w))
        return WAS_SIMPLE_POLL_END;

    if (!was_simple_control_apply_pending(w))
        return WAS_SIMPLE_POLL_ERROR;

    /* check "eof" again, as it may have changed after control packets
       have been handled */
    if (was_simple_input_eof(w))
        return WAS_SIMPLE_POLL_END;

    struct pollfd fds[2] = {
        {
            .fd = w->control.fd,
            .events = POLLIN,
        },
        {
            .fd = w->input.fd,
            .events = POLLIN,
        },
    };

    while (true) {
        int ret = poll(fds, G_N_ELEMENTS(fds), timeout_ms);
        if (ret < 0)
            return WAS_SIMPLE_POLL_ERROR;

        if (ret == 0)
            return WAS_SIMPLE_POLL_TIMEOUT;

        if (fds[0].revents & POLLIN) {
            if (!was_simple_control_fill(w, true) ||
                !was_simple_control_apply_pending(w))
                return WAS_SIMPLE_POLL_ERROR;

            if (was_simple_input_eof(w))
                return WAS_SIMPLE_POLL_END;
        }

        if (fds[1].revents & POLLIN)
            return WAS_SIMPLE_POLL_SUCCESS;
    }
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

    if (w->input.known_length && w->input.received > w->input.announced) {
        // XXX handle error
        return false;
    }

    /* XXX */
    return true;
}

ssize_t
was_simple_input_read(struct was_simple *w, void *buffer, size_t length)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    if (w->input.no_body || was_simple_input_eof(w))
        return 0;

    ssize_t nbytes = read(w->input.fd, buffer, length);
    if (nbytes <= 0)
        return -1;

    if (!was_simple_received(w, nbytes))
        return -1;

    return nbytes;
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

    if (!was_simple_control_send_uint64(w, WAS_COMMAND_LENGTH, length))
        return false;

    w->output.announced = length;
    w->output.known_length = true;

    if (w->output.announced == w->output.sent)
        w->response.state = RESPONSE_STATE_END;

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
was_simple_end(struct was_simple *w)
{
    assert(w->response.state != RESPONSE_STATE_NONE);

    if (w->response.state == RESPONSE_STATE_STATUS &&
        !was_simple_status(w, HTTP_STATUS_NO_CONTENT))
        return false;

    if (w->response.state == RESPONSE_STATE_HEADERS) {
        if (!was_simple_control_send_empty(w, WAS_COMMAND_NO_DATA))
            return false;

        w->response.state = RESPONSE_STATE_END;
        return true;
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

    assert(w->response.state == RESPONSE_STATE_END);

    return true;
}
