/*
 * Synchronous server implementation of the Web Application Socket
 * protocol.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#include <was/simple.h>
#include <was/protocol.h>

#include "iterator.hxx"

#include <http/header.h>

#include <map>
#include <string>

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <fcntl.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

struct was_control_packet {
    enum was_command command;
    size_t length;
    const void *payload;
};

struct was_simple {
    /**
     * The control channel.
     */
    struct Control {
        static constexpr int fd = 3;

        union {
            char raw[4096];
            struct was_header header;
        } input_buffer;

        size_t input_position;

        struct {
            unsigned position;
            char data[4096];
        } output_buffer;

        struct was_control_packet packet;

        ssize_t DirectSend(const void *p, size_t length) {
            return send(fd, p, length, MSG_NOSIGNAL);
        }

        bool IsPacketComplete() const {
            return input_position >= sizeof(input_buffer.header) &&
                input_position >= sizeof(input_buffer.header) +
                input_buffer.header.length;
        }

        bool Fill(bool dontwait);
        void Shift();
        const struct was_control_packet *Get();
        const struct was_control_packet *Next();
        const struct was_control_packet *Read(bool dontwait);
        const struct was_control_packet *Expect(enum was_command command);
        bool Flush();
        void Append(const void *p, size_t length);
        bool Send(const void *data, size_t length);
        bool SendHeader(enum was_command command, size_t length);

        bool SendEmpty(enum was_command command) {
            return SendHeader(command, 0);
        }

        bool SendPacket(enum was_command command,
                        const void *payload, size_t length) {
            return SendHeader(command, length) && Send(payload, length);
        }

        bool SendUint64(enum was_command command, uint64_t payload) {
            return SendPacket(command, &payload, sizeof(payload));
        }
    } control;

    /**
     * The request body.
     */
    struct Input {
        static constexpr int fd = 0;

        /**
         * Number of bytes received on the pipe.
         */
        uint64_t received;

        /**
         * Number of bytes announced by the peer via
         * #WAS_COMMAND_LENGTH.  Only valid if #known_length is true.
         */
        uint64_t announced;

        /**
         * Is #announced valid?
         */
        bool known_length;

        /**
         * Did we send #WAS_COMMAND_STOP?
         */
        bool stopped;

        /**
         * True if #WAS_COMMAND_PREMATURE has been received.
         */
        bool premature;

        /**
         * True if reading from the input shall ignore the #premature
         * flag.  This is used to disable the checks while discarding
         * remaining input.
         */
        bool ignore_premature;

        /**
         * True if #WAS_COMMAND_NO_DATA has been received.
         */
        bool no_body;

        bool HasBody() const {
            return !no_body;
        }

        bool IsEOF() const {
            return known_length && received >= announced;
        }
    } input;

    /**
     * The response body.
     */
    struct Output {
        static constexpr int fd = 1;

        /**
         * Number of bytes sent to the pipe.
         */
        uint64_t sent;

        /**
         * Number of bytes announced to the peer via
         * #WAS_COMMAND_LENGTH, generated by was_simple_set_length().
         * Only valid if #known_length is true.
         */
        uint64_t announced;

        /**
         * Is #announced valid?
         */
        bool known_length;

        /**
         * Was this stream aborted prematurely by the peer?
         */
        bool premature;

        /**
         * True if a HTTP status was used that has no response body by
         * definition (e.g. 204 No Content).
         */
        bool no_body;

        /**
         * Did we send all data?
         */
        bool IsFull() const {
            return known_length && sent >= announced;
        }

        void Sent(size_t nbytes) {
            assert(!known_length || sent <= announced);
            assert(!known_length || nbytes <= announced);
            assert(!known_length || sent + nbytes <= announced);

            sent += nbytes;
        }
    } output;

    /**
     * Request metadata received from the control channel.
     */
    struct {
        http_method_t method;
        char *uri, *script_name, *path_info, *query_string;

        std::multimap<std::string, std::string> headers, parameters;

        /**
         * True when all request metadata has been received.
         */
        bool finished;
    } request;

    struct Response {
        enum class State {
            NONE,
            STATUS,
            HEADERS,
            BODY,
            END,
        } state;
    } response;

    bool HasRequestBody() const {
        assert(response.state != Response::State::NONE);

        return input.HasBody();
    }
};

static void
was_simple_init_request(struct was_simple *w)
{
    w->request.method = HTTP_METHOD_GET;

    w->request.uri = nullptr;
    w->request.script_name = nullptr;
    w->request.path_info = nullptr;
    w->request.query_string = nullptr;

    w->request.finished = false;
}

static void
was_simple_free_request(struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    free(w->request.uri);
    free(w->request.script_name);
    free(w->request.path_info);
    free(w->request.query_string);

    w->request.headers.clear();
    w->request.parameters.clear();
}

/**
 * Enables non-blocking mode for the specified file descriptor.
 */
static void
fd_set_nonblock(int fd)
{
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

struct was_simple *
was_simple_new(void)
{
    auto *w = new was_simple();

    w->control.input_position = 0;
    w->control.output_buffer.position = 0;
    w->control.packet.payload = nullptr;

    w->response.state = was_simple::Response::State::NONE;

    fd_set_nonblock(w->input.fd);
    fd_set_nonblock(w->output.fd);

    return w;
}

void
was_simple_free(struct was_simple *w)
{
    if (w->response.state != was_simple::Response::State::NONE)
        was_simple_free_request(w);

    delete w;
}

bool
was_simple::Control::Fill(bool dontwait)
{
    assert(input_position < sizeof(input_buffer));

    ssize_t nbytes = recv(fd,
                          input_buffer.raw + input_position,
                          sizeof(input_buffer) - input_position,
                          dontwait * MSG_DONTWAIT);
    if (nbytes <= 0)
        return false;

    input_position += nbytes;
    return true;
}

void
was_simple::Control::Shift()
{
    assert(IsPacketComplete());

    unsigned full_length = sizeof(input_buffer.header) +
        input_buffer.header.length;

    input_position -= full_length;
    memmove(input_buffer.raw, input_buffer.raw + full_length, input_position);

    packet.payload = nullptr;
}

const struct was_control_packet *
was_simple::Control::Get()
{
    if (!IsPacketComplete())
        return nullptr;

    packet.command = (enum was_command)input_buffer.header.command;
    packet.length = input_buffer.header.length;

    if (packet.length > 0) {
        packet.payload = input_buffer.raw +
            sizeof(input_buffer.header);
    } else {
        packet.payload = nullptr;
        Shift();
    }

    return &packet;
}

const struct was_control_packet *
was_simple::Control::Next()
{
    /* clean up the previous packet */
    if (packet.payload != nullptr)
        Shift();

    return Get();
}

const struct was_control_packet *
was_simple::Control::Read(bool dontwait)
{
    /* clean up the previous packet */
    if (packet.payload != nullptr)
        Shift();

    while (true) {
        const auto *p = Get();
        if (p != nullptr)
            return p;

        /* XXX check if buffer is full */

        if (!Fill(dontwait))
            return nullptr;
    }
}

const struct was_control_packet *
was_simple::Control::Expect(enum was_command command)
{
    const auto *p = Read(false);
    return p != nullptr && p->command == command
        ? p
        : nullptr;
}

bool
was_simple::Control::Flush()
{
    assert(output_buffer.position <= sizeof(output_buffer.data));

    if (output_buffer.position == 0)
        /* buffer is empty */
        return true;

    ssize_t nbytes = DirectSend(output_buffer.data, output_buffer.position);
    if (nbytes <= 0)
        return false;

    output_buffer.position -= nbytes;
    memmove(output_buffer.data + nbytes,
            output_buffer.data,
            output_buffer.position);
    return true;
}

void
was_simple::Control::Append(const void *p, size_t length)
{
    assert(output_buffer.position <= sizeof(output_buffer.data));
    assert(output_buffer.position + length <= sizeof(output_buffer.data));

    memcpy(output_buffer.data + output_buffer.position, p, length);
    output_buffer.position += length;
}

bool
was_simple::Control::Send(const void *data, size_t length)
{
    while (output_buffer.position + length > sizeof(output_buffer.data)) {
        if (output_buffer.position == 0) {
            /* too large for the buffer */
            ssize_t nbytes = DirectSend(data, length);
            return nbytes == (ssize_t)length;
        }

        if (!Flush())
            return false;
    }

    Append(data, length);
    return true;
}

bool
was_simple::Control::SendHeader(enum was_command command, size_t length)
{
    struct was_header header = {
        .command = uint16_t(command),
        .length = uint16_t(length),
    };

    return Send(&header, sizeof(header));
}

static void
was_simple_clear_request(struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    was_simple_free_request(w);

    w->response.state = was_simple::Response::State::NONE;
}

/**
 * @return true if the connection can be reused
 */
static bool
was_simple_finish_request(struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    // XXX
    bool result = was_simple_end(w);
    was_simple_clear_request(w);
    return result;
}

static bool
was_simple_apply_string(char **value_r,
                        const void *payload, size_t length)
{
    if (*value_r != nullptr)
        return false;

    *value_r = strndup((const char *)payload, length);
    return true;
}

static bool
was_simple_apply_map(std::multimap<std::string, std::string> &map,
                     const void *_payload, size_t length)
{
    const char *payload = (const char *)_payload;

    const char *p = (const char *)memchr(payload, '=', length);
    if (p == nullptr || p == payload)
        return false;

    map.emplace(std::string(payload, p),
                std::string(p + 1, payload + length));
    return true;
}

static bool
was_simple_apply_request_packet(struct was_simple *w,
                                const struct was_control_packet *packet)
{
    assert(w->response.state != was_simple::Response::State::NONE);

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
        return was_simple_apply_string(&w->request.uri,
                                       packet->payload, packet->length);

    case WAS_COMMAND_SCRIPT_NAME:
        return was_simple_apply_string(&w->request.script_name,
                                       packet->payload, packet->length);

    case WAS_COMMAND_PATH_INFO:
        return was_simple_apply_string(&w->request.path_info,
                                       packet->payload, packet->length);

    case WAS_COMMAND_QUERY_STRING:
        return was_simple_apply_string(&w->request.query_string,
                                       packet->payload, packet->length);

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
        w->output.premature = true;

        if (w->response.state <= was_simple::Response::State::BODY &&
            !w->control.SendUint64(WAS_COMMAND_PREMATURE, w->output.sent))
            return false;

        if (w->response.state == was_simple::Response::State::BODY)
            w->response.state = was_simple::Response::State::END;

        break;

    case WAS_COMMAND_PREMATURE:
        if (packet->length != sizeof(length))
            return false;

        length = *(const uint64_t *)packet->payload;
        if (length < w->input.received ||
            (w->input.known_length && length > w->input.announced))
            return false;

        w->input.announced = length;
        w->input.known_length = true;
        w->input.premature = true;
        return false;
    }

    return true;
}

static bool
was_simple_control_apply_pending(struct was_simple *w)
{
    const struct was_control_packet *packet;
    while ((packet = w->control.Next()) != nullptr)
        if (!was_simple_apply_request_packet(w, packet))
            return false;

    return true;
}

static bool
was_simple_control_read_and_apply(struct was_simple *w)
{
    const auto *packet = w->control.Read(false);
    return packet != nullptr &&
        was_simple_apply_request_packet(w, packet);
}

const char *
was_simple_accept(struct was_simple *w)
{
    if (w->response.state != was_simple::Response::State::NONE &&
        !was_simple_finish_request(w))
        return nullptr;

    assert(w->response.state == was_simple::Response::State::NONE);

    const auto *packet = w->control.Expect(WAS_COMMAND_REQUEST);
    if (packet == nullptr)
        return nullptr;

    assert(w->response.state == was_simple::Response::State::NONE);

    w->input.received = 0;
    w->input.known_length = false;
    w->input.premature = false;
    w->input.ignore_premature = false;

    w->output.sent = 0;
    w->output.known_length = false;
    w->output.premature = false;

    w->response.state = was_simple::Response::State::STATUS;

    was_simple_init_request(w);

    do {
        if (!was_simple_control_read_and_apply(w))
            return nullptr;
    } while (!w->request.finished);

    return w->request.uri;
}

http_method_t
was_simple_get_method(const struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    return w->request.method;
}

const char *
was_simple_get_script_name(const struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    return w->request.script_name;
}

const char *
was_simple_get_path_info(const struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    return w->request.path_info;
}

const char *
was_simple_get_query_string(const struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    return w->request.query_string;
}

const char *
was_simple_get_header(struct was_simple *w, const char *name)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    auto i = w->request.headers.find(name);
    return i != w->request.headers.end()
        ? i->second.c_str()
        : nullptr;
}

struct was_simple_iterator *
was_simple_get_multi_header(struct was_simple *w, const char *name)
{
    auto x = w->request.headers.equal_range(name);
    return was_simple_iterator_new(x.first, x.second);
}

struct was_simple_iterator *
was_simple_get_header_iterator(struct was_simple *w)
{
    return was_simple_iterator_new(w->request.headers.begin(),
                                   w->request.headers.end());
}

const char *
was_simple_get_parameter(struct was_simple *w, const char *name)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    auto i = w->request.parameters.find(name);
    return i != w->request.parameters.end()
        ? i->second.c_str()
        : nullptr;
}

struct was_simple_iterator *
was_simple_get_parameter_iterator(struct was_simple *w)
{
    return was_simple_iterator_new(w->request.parameters.begin(),
                                   w->request.parameters.end());
}

bool
was_simple_has_body(const struct was_simple *w)
{
    return w->HasRequestBody();
}

enum was_simple_poll_result
was_simple_input_poll(struct was_simple *w, int timeout_ms)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (w->input.no_body || w->input.IsEOF())
        return WAS_SIMPLE_POLL_END;

    if (w->input.premature && !w->input.ignore_premature)
        return WAS_SIMPLE_POLL_ERROR;

    if (!w->control.Flush() || !was_simple_control_apply_pending(w) ||
        !w->control.Flush())
        return WAS_SIMPLE_POLL_ERROR;

    /* check "eof" again, as it may have changed after control packets
       have been handled */
    if (w->input.IsEOF())
        return WAS_SIMPLE_POLL_END;

    struct pollfd fds[] = {
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
        int ret = poll(fds, ARRAY_SIZE(fds), timeout_ms);
        if (ret < 0)
            return WAS_SIMPLE_POLL_ERROR;

        if (ret == 0)
            return WAS_SIMPLE_POLL_TIMEOUT;

        if (fds[0].revents & POLLIN) {
            if (!w->control.Fill(true) ||
                !was_simple_control_apply_pending(w))
                return WAS_SIMPLE_POLL_ERROR;

            if (w->input.IsEOF())
                return WAS_SIMPLE_POLL_END;
        }

        if (fds[1].revents & POLLIN)
            return WAS_SIMPLE_POLL_SUCCESS;
    }
}

int
was_simple_input_fd(const struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    return w->input.fd;
}

bool
was_simple_received(struct was_simple *w, size_t nbytes)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (w->input.premature && !w->input.ignore_premature)
        return false;

    w->input.received += nbytes;

    if (w->input.known_length && w->input.received > w->input.announced) {
        // XXX handle error
        return false;
    }

    /* XXX */
    return true;
}

ssize_t
was_simple_read(struct was_simple *w, void *buffer, size_t length)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (w->input.no_body || w->input.IsEOF())
        return 0;

    if (w->input.premature && !w->input.ignore_premature)
        return -2;

    ssize_t nbytes = read(w->input.fd, buffer, length);
    if (nbytes < 0 && errno == EAGAIN) {
        /* reading blocks: poll for data (or for control commands and
           handle them) */
        switch (was_simple_input_poll(w, -1)) {
        case WAS_SIMPLE_POLL_SUCCESS:
            /* time to try again */
            nbytes = read(w->input.fd, buffer, length);
            break;

        case WAS_SIMPLE_POLL_ERROR:
            return -1;

        case WAS_SIMPLE_POLL_TIMEOUT:
        case WAS_SIMPLE_POLL_CLOSED:
            return -2;

        case WAS_SIMPLE_POLL_END:
            return 0;
        }
    }

    if (nbytes <= 0)
        return nbytes < 0 ? -1 : -2;

    if (!was_simple_received(w, nbytes))
        return -2;

    return nbytes;
}

bool
was_simple_input_close(struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (w->input.no_body || w->input.stopped || w->input.premature ||
        w->input.IsEOF())
        return true;

    if (!w->control.SendEmpty(WAS_COMMAND_STOP))
        return false;

    w->input.stopped = true;
    return true;
}

bool
was_simple_status(struct was_simple *w, http_status_t status)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (w->response.state != was_simple::Response::State::STATUS)
        /* too late for sending the status */
        return false;

    if (!w->control.SendPacket(WAS_COMMAND_STATUS, &status, sizeof(status)))
        return false;

    w->response.state = was_simple::Response::State::HEADERS;
    w->output.no_body = http_status_is_empty(status);
    return true;
}

bool
was_simple_set_header(struct was_simple *w,
                      const char *name, const char *value)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (w->response.state == was_simple::Response::State::STATUS &&
        !was_simple_status(w, HTTP_STATUS_OK))
        return false;

    assert(w->response.state == was_simple::Response::State::HEADERS);

    const size_t name_length = strlen(name), value_length = strlen(value);
    char *p = (char *)malloc(name_length + 1 + value_length);
    char *q = (char *)mempcpy(p, name, name_length);
    *q++ = '=';
    q = (char *)mempcpy(q, value, value_length);

    bool success = w->control.SendPacket(WAS_COMMAND_HEADER, p, q - p);
    free(p);
    return success;
}

bool
was_simple_copy_all_headers(struct was_simple *w)
{
    for (const auto &i : w->request.headers)
        if (!http_header_is_hop_by_hop(i.first.c_str()))
            if (!was_simple_set_header(w, i.first.c_str(), i.second.c_str()))
                return false;

    return true;
}

bool
was_simple_set_length(struct was_simple *w, uint64_t length)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (w->output.no_body)
        return false;

    assert(length >= w->output.sent);

    if (w->output.known_length) {
        assert(length == w->output.known_length);
        return true;
    }

    if (w->response.state == was_simple::Response::State::STATUS &&
        !was_simple_status(w, HTTP_STATUS_OK))
        return false;

    if (w->response.state == was_simple::Response::State::HEADERS) {
        if (!w->control.SendEmpty(WAS_COMMAND_DATA))
            return false;

        w->response.state = was_simple::Response::State::BODY;
    }

    assert(w->response.state == was_simple::Response::State::BODY);

    if (!w->control.SendUint64(WAS_COMMAND_LENGTH, length))
        return false;

    w->output.announced = length;
    w->output.known_length = true;

    if (w->output.announced == w->output.sent)
        w->response.state = was_simple::Response::State::END;

    return true;
}

static bool
was_simple_set_response_state_body(struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (w->response.state == was_simple::Response::State::STATUS &&
        !was_simple_status(w, HTTP_STATUS_OK))
        return false;

    if (w->response.state == was_simple::Response::State::HEADERS) {
        if (w->output.no_body) {
            w->response.state = was_simple::Response::State::END;
            w->control.SendEmpty(WAS_COMMAND_NO_DATA);
            return false;
        }

        if (!w->control.SendEmpty(WAS_COMMAND_DATA))
            return false;

        w->response.state = was_simple::Response::State::BODY;
    }

    assert(w->response.state == was_simple::Response::State::BODY);

    if (w->output.premature) {
        w->response.state = was_simple::Response::State::END;
        return false;
    }

    return true;
}

enum was_simple_poll_result
was_simple_output_poll(struct was_simple *w, int timeout_ms)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (w->output.IsFull())
        return WAS_SIMPLE_POLL_END;

    if (!w->control.Flush() || !was_simple_control_apply_pending(w) ||
        !w->control.Flush() ||
        w->response.state > was_simple::Response::State::BODY)
        return WAS_SIMPLE_POLL_ERROR;

    assert(!w->output.premature);

    struct pollfd fds[] = {
        {
            .fd = w->control.fd,
            .events = POLLIN,
        },
        {
            .fd = w->output.fd,
            .events = POLLOUT,
        },
    };

    while (true) {
        int ret = poll(fds, ARRAY_SIZE(fds), timeout_ms);
        if (ret < 0)
            return WAS_SIMPLE_POLL_ERROR;

        if (ret == 0)
            return WAS_SIMPLE_POLL_TIMEOUT;

        if (fds[0].revents & POLLIN) {
            if (!w->control.Fill(true) ||
                !was_simple_control_apply_pending(w) ||
                w->response.state > was_simple::Response::State::BODY)
                return WAS_SIMPLE_POLL_ERROR;
        }

        if (fds[1].revents & POLLOUT)
            return WAS_SIMPLE_POLL_SUCCESS;
    }
}

int
was_simple_output_fd(struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (!was_simple_set_response_state_body(w))
        return -1;

    return w->output.fd;
}

bool
was_simple_sent(struct was_simple *w, size_t nbytes)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (w->output.no_body)
        return false;

    if (!w->control.Flush())
        return false;

    w->output.Sent(nbytes);
    return true;
}

bool
was_simple_write(struct was_simple *w, const void *data0, size_t length)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (!was_simple_set_response_state_body(w) ||
        !w->control.Flush())
        return false;

    const char *data = (const char *)data0;

    while (length > 0) {
        ssize_t nbytes = write(w->output.fd, data, length);
        if (nbytes < 0 && errno == EAGAIN) {
            /* writing blocks: poll for the pipe to become writable
               again (or for control commands and handle them) */
            switch (was_simple_output_poll(w, -1)) {
            case WAS_SIMPLE_POLL_SUCCESS:
                /* time to try again */
                continue;

            case WAS_SIMPLE_POLL_ERROR:
            case WAS_SIMPLE_POLL_TIMEOUT:
            case WAS_SIMPLE_POLL_CLOSED:
            case WAS_SIMPLE_POLL_END:
                return false;
            }
        }

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
    vsnprintf(buffer, sizeof(buffer), fmt, va);
    va_end(va);

    return was_simple_puts(w, buffer);
}

static bool
discard_all_input(struct was_simple *w)
{
    while (true) {
        char buffer[4096];
        ssize_t nbytes = was_simple_read(w, buffer, sizeof(buffer));
        if (nbytes <= 0)
            return nbytes == 0;
    }
}

bool
was_simple_end(struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    w->input.ignore_premature = true;

    if (!was_simple_input_close(w))
        return false;

    /* generate a status code? */
    if (w->response.state == was_simple::Response::State::STATUS &&
        !was_simple_status(w, HTTP_STATUS_NO_CONTENT))
        return false;

    /* no response body? */
    if (w->response.state == was_simple::Response::State::HEADERS) {
        if (!w->control.SendEmpty(WAS_COMMAND_NO_DATA) ||
            !w->control.Flush())
            return false;

        w->response.state = was_simple::Response::State::END;
    }

    /* finish the response body? */
    if (w->response.state == was_simple::Response::State::BODY) {
        if (w->output.premature) {
            w->response.state = was_simple::Response::State::END;
        } else if (w->output.known_length) {
            if (w->output.sent != w->output.announced)
                // XXX
                return false;

            w->response.state = was_simple::Response::State::END;
        } else {
            if (!was_simple_set_length(w, w->output.sent))
                return false;
        }
    }

    /* finish the control channel? */
    if (!w->control.Flush())
        return false;

    assert(w->response.state == was_simple::Response::State::END);

    /* discard the request body? */
    if (!discard_all_input(w))
        return false;

    /* wait for PREMATURE? */
    if (w->input.stopped && !w->input.IsEOF())
        while (!w->input.premature)
            if (!was_simple_control_read_and_apply(w))
                return false;

    /* connection is ready to be reused */
    return true;
}
