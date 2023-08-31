// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

/*
 * Synchronous server implementation of the Web Application Socket
 * protocol.
 */

#include <was/simple.h>
#include <was/protocol.h>

#include "iterator.hxx"

#include <http/header.h>

#include <cassert>
#include <cerrno>
#include <climits>
#include <cstring>
#include <map>
#include <string>
#include <string_view>

#include <unistd.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <fcntl.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

/**
 * Enables non-blocking mode for the specified file descriptor.
 */
static void
fd_set_nonblock(int fd)
{
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

struct was_control_packet {
    enum was_command command;
    size_t length;
    const void *payload;

    constexpr std::string_view GetPayloadString() const noexcept {
        return {static_cast<const char *>(payload), length};
    }
};

struct was_simple {
    /**
     * The control channel.
     */
    struct Control {
        union {
            char raw[8192];
            struct was_header header;
        } input_buffer;

        size_t input_position = 0;

        /**
         * The number of bytes to ignore from the input pipe.  This is
         * used to recover from packets that are too large.  If this
         * is non-zero, then #input_position must be zero, and the
         * #input_buffer will be used to discard data.
         */
        size_t discard_input = 0;

        struct {
            unsigned position = 0;
            char data[4096];
        } output_buffer;

        struct was_control_packet packet;

        const int fd;

        explicit Control(int _fd) noexcept
            :fd(_fd)
        {
            packet.payload = nullptr;
        }

        ~Control() noexcept {
            close(fd);
        }

        ssize_t DirectSend(const void *p, size_t length) {
            return send(fd, p, length, MSG_NOSIGNAL);
        }

        bool IsInputBufferFull() const {
            return input_position >= sizeof(input_buffer);
        }

        bool IsPacketComplete() const {
            return input_position >= sizeof(input_buffer.header) &&
                input_position >= sizeof(input_buffer.header) +
                input_buffer.header.length;
        }

        /**
         * Fill the #input_buffer.
         *
         * @param dontwait if true, then MSG_DONTWAIT is used to avoid
         * blocking (fails with EAGAIN/EWOULDBLOCK if it would block)
         *
         * @return true on success, false on error (end-of-socket or
         * I/O error, including EAGAIN/EWOULDBLOCK)
         */
        bool Fill(bool dontwait);

        /**
         * Shift the input buffer, removing the current WAS control
         * packet.
         */
        void Shift();

        /**
         * Determine the command of the current packet whose header
         * has been received.  This can be used to peek at a packet
         * which will be discarded, e.g. if Read() returns nullptr
         * with errno=E2BIG.
         */
        enum was_command PeekCommand() const noexcept {
            return (enum was_command)input_buffer.header.command;
        }

        /**
         * @return the current WAS control packet or nullptr if no
         * complete packet (header + payload) has been received yet
         */
        const struct was_control_packet *Get();

        /**
         * @return the next WAS control packet (discarding the current
         * control packet, if one was fully received) or nullptr if
         * another complete packet has not been received yet
         */
        const struct was_control_packet *Next();

        /**
         * Read the next WAS control packet (discarding the current
         * control packet, if one was fully received)
         *
         * @return the next complete WAS control packet or nullptr on
         * error (end-of-socket or I/O error) with errno set; E2BIG
         * means the packet payload is too large for the #input_buffer
         */
        const struct was_control_packet *Read(bool dontwait);

        /**
         * Send the #output_buffer to the control socket.
         *
         * @return true on success, false on I/O error
         */
        bool Flush();

        /**
         * Append data to the #output_buffer (but does not yet send
         * it).  The caller must ensure that there is enough space in
         * the #output_buffer.
         */
        void Append(const void *p, size_t length);

        /**
         * Append data to the #output_buffer if there is enough room,
         * possibly flushing it and possibly sending the data directly
         * to the socket.
         *
         * @return true on success, false on I/O error
         */
        bool Send(const void *data, size_t length);

        /**
         * Assemble a WAS control header and send it.
         *
         * @return true on success, false on I/O error
         */
        bool SendHeader(enum was_command command, size_t length);

        /**
         * Send a WAS control packet without a payload.
         *
         * @return true on success, false on I/O error
         */
        bool SendEmpty(enum was_command command) {
            return SendHeader(command, 0);
        }

        /**
         * Send a WAS control packet with a payload.
         *
         * @return true on success, false on I/O error
         */
        bool SendPacket(enum was_command command,
                        const void *payload, size_t length) {
            return SendHeader(command, length) && Send(payload, length);
        }

        /**
         * Send a WAS control packet with a uint64_t payload.
         *
         * @return true on success, false on I/O error
         */
        bool SendUint64(enum was_command command, uint64_t payload) {
            return SendPacket(command, &payload, sizeof(payload));
        }
    } control;

    /**
     * The request body.
     */
    struct Input {
        /**
         * Number of bytes received on the pipe.
         */
        uint64_t received;

        /**
         * Number of bytes announced by the peer via
         * #WAS_COMMAND_LENGTH.  Only valid if #known_length is true.
         */
        uint64_t announced;

        const int fd;

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

        explicit Input(int _fd) noexcept
            :fd(_fd)
        {
            fd_set_nonblock(fd);
        }

        ~Input() noexcept {
            if (fd != STDIN_FILENO)
                close(fd);
        }

        bool HasBody() const {
            return !no_body;
        }

        bool IsEOF() const {
            return known_length && received >= announced;
        }

        int64_t GetRemaining() const {
            assert(!stopped);

            return known_length
                ? int64_t(announced - received)
                : -1;
        }

        /**
         * Clamp the given size to the number of remaining bytes, if
         * that is known.
         */
        size_t ClampRemaining(size_t size) const {
            if (known_length) {
                uint64_t remaining = announced - received;
                if (size > remaining)
                    return remaining;
            }

            return size;
        }
    } input;

    /**
     * The response body.
     */
    struct Output {
        /**
         * Number of bytes sent to the pipe.
         */
        uint64_t sent;

        /**
         * Number of bytes announced to the peer via
         * #WAS_COMMAND_LENGTH, generated by SetLength().
         * Only valid if #known_length is true.
         */
        uint64_t announced;

        const int fd;

        /**
         * Is #announced valid?
         */
        bool known_length;

        /**
         * True if a HTTP status was used that has no response body by
         * definition (e.g. 204 No Content).
         */
        bool no_body;

        explicit Output(int _fd) noexcept
            :fd(_fd)
        {
            fd_set_nonblock(fd);
        }

        ~Output() noexcept {
            if (fd != STDOUT_FILENO)
                close(fd);
        }

        /**
         * Did we send all data?
         */
        bool IsFull() const {
            return known_length && sent >= announced;
        }

        /**
         * Can this much data be sent?
         */
        bool CanSend(size_t nbytes) const {
            return !no_body && (!known_length || sent + nbytes <= announced);
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
    struct Request {
        http_method_t method;
        char *uri, *script_name, *path_info, *query_string;

        char *remote_host;

        std::multimap<std::string, std::string, std::less<>> headers, parameters;

        /**
         * True if #WAS_COMMAND_METRIC has been received.
         */
        bool want_metrics;

        /**
         * True when all request metadata has been received.
         */
        bool finished;

        void Init() {
            method = HTTP_METHOD_GET;

            uri = nullptr;
            script_name = nullptr;
            path_info = nullptr;
            query_string = nullptr;

            remote_host = nullptr;

            want_metrics = false;
            finished = false;
        }

        void Deinit() {
            free(uri);
            free(script_name);
            free(path_info);
            free(query_string);

            free(remote_host);

            headers.clear();
            parameters.clear();
        }
    } request;

    struct Response {
        enum class State {
            /**
             * No request (yet) in progress.  This will turn into
             * #STATUS as soon as the next request begins by calling
             * Accept().
             */
            NONE,

            /**
             * The response status is about to be sent.
             */
            STATUS,

            /**
             * The response headers are being sent.
             */
            HEADERS,

            /**
             * The response body is being sent.
             */
            BODY,

            /**
             * The response (body) has ended.  This will turn into
             * #NONE and then #STATUS in the next Accept() call.
             */
            END,

            /**
             * Received #WAS_COMMAND_STOP.  All further calls for the
             * current request shall be denied.  This will turn into
             * #NONE and then #STATUS in the next Accept() call.
             */
            STOP,

            /**
             * An unrecoverable error has occurred, and the WAS
             * connection cannot be reused.
             */
            ERROR,
        } state = State::NONE;
    } response;

    /**
     * This variable keeps track of a micro-optimization: after the
     * first partial read, poll the control channel to see if the peer
     * has sent #WAS_COMMAND_LENGTH or #WAS_COMMAND_STOP meanwhile.
     */
    enum class PartialReadState {
        INITIAL,

        /**
         * The last read was partial.  Before trying again, poll the
         * control channel.
         */
        PARTIAL,

        FINISHED,
    } partial_read_state = PartialReadState::INITIAL;

    /**
     * If this is non-zero, the this library rejects the request with
     * this HTTP status instead of letting the caller handle it.
     */
    http_status_t error_status;

    was_simple(int control_fd, int input_fd, int output_fd) noexcept
        :control(control_fd), input(input_fd), output(output_fd)
    {
    }

    ~was_simple() {
        if (response.state != Response::State::NONE)
            request.Deinit();
    }

    bool HasRequestBody() const {
        assert(response.state != Response::State::NONE);

        return input.HasBody();
    }

    void DeinitRequest() {
        assert(response.state != Response::State::NONE);

        request.Deinit();
    }

    void ClearRequest() {
        assert(response.state != Response::State::NONE);

        request.Deinit();
        response.state = Response::State::NONE;
        partial_read_state = PartialReadState::INITIAL;
    }

    /**
     * @return true if the connection can be reused
     */
    bool FinishRequest();

    /**
     * @return true if no more control packets can be sent for the
     * current request
     */
    bool IsControlFinished() const {
        return response.state == Response::State::END ||
            response.state == Response::State::STOP;
    }

    bool ApplyRequestPacket(const struct was_control_packet &packet);
    bool ApplyPendingControl();
    bool ReadAndApplyControl();

    const char *Accept(const char *would_block=nullptr);
    enum was_simple_poll_result PollInput(int timeout_ms);

    bool Received(size_t nbytes);
    ssize_t Read(void *buffer, size_t length);

    int64_t GetInputRemaining() const {
        if (input.premature)
            return -1;

        return input.GetRemaining();
    }

    bool CloseInput();
    bool SetStatus(http_status_t status);
    bool SetHeader(std::string_view name, std::string_view value) noexcept;
    bool SetLength(uint64_t length);

    enum was_simple_poll_result PollOutput(int timeout_ms);
    bool Write(const void *data, size_t length);

    ssize_t Splice(size_t max_length) noexcept;
    bool SpliceAll(bool end) noexcept;

    bool SetResponseStateBody();

    bool DiscardAllInput();

    bool WantMetrics() const noexcept {
        assert(response.state != Response::State::NONE);

        return request.want_metrics;
    }

    bool SendMetric(std::string_view name, float value) noexcept;

    bool End();
    bool Abort();
};

bool
was_simple::Control::Fill(bool dontwait)
{
    assert(input_position < sizeof(input_buffer));

    size_t max_read = sizeof(input_buffer) - input_position;
    if (discard_input > 0 && discard_input < max_read)
        max_read = discard_input;

    ssize_t nbytes = recv(fd,
                          input_buffer.raw + input_position,
                          max_read,
                          dontwait * MSG_DONTWAIT);
    if (nbytes <= 0) {
        if (nbytes == 0)
            /* the WAS client closed the control socket; recv()==0
               doesn't set errno, but our caller checks errno if we
               return false; to avoid leaving a random errno value,
               set one that fits best */
            errno = ECONNRESET;
        return false;
    }

    if (discard_input > 0)
        discard_input -= nbytes;
    else
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

inline const struct was_control_packet *
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

        if (IsInputBufferFull()) {
            /* input buffer is full: discard the packet and return an
               error to the caller */

            const size_t total_size = sizeof(input_buffer.header) +
                input_buffer.header.length;
            discard_input = total_size - input_position;
            input_position = 0;

            errno = E2BIG;
            return nullptr;
        }

        if (!Fill(dontwait))
            return nullptr;
    }
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

inline void
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

static constexpr struct was_header
MakeHeader(enum was_command command, size_t length) noexcept
{
    struct was_header h{};
    h.length = uint16_t(length);
    h.command = uint16_t(command);
    return h;
}

bool
was_simple::Control::SendHeader(enum was_command command, size_t length)
{
    const auto header = MakeHeader(command, length);
    return Send(&header, sizeof(header));
}

inline bool
was_simple::FinishRequest()
{
    assert(response.state != Response::State::NONE);

    if (response.state == Response::State::ERROR)
        /* cannot reuse this WAS connection */
        return false;

    // TODO??
    bool result = End();
    ClearRequest();
    return result;
}

static bool
was_simple_apply_string(char **value_r, std::string_view payload)
{
    if (*value_r != nullptr)
        return false;

    *value_r = strndup(payload.data(), payload.size());
    return true;
}

static bool
was_simple_apply_map(std::multimap<std::string, std::string, std::less<>> &map,
                     std::string_view payload)
{
    const auto eq = payload.find('=');
    if (eq == 0 || eq == payload.npos)
        return false;

    map.emplace(payload.substr(0, eq), payload.substr(eq + 1));
    return true;
}

bool
was_simple::ApplyRequestPacket(const struct was_control_packet &packet)
{
    assert(response.state != Response::State::NONE);

    http_method_t method;
    uint64_t length;

    switch (packet.command) {
    case WAS_COMMAND_NOP:
        break;

    case WAS_COMMAND_REQUEST:
        return false;

    case WAS_COMMAND_METHOD:
        if (request.finished)
            return false;

        if (packet.length != sizeof(uint32_t))
            return false;

        method = (http_method_t)*(const uint32_t *)packet.payload;
        if (request.method != HTTP_METHOD_GET &&
            method != request.method)
            /* sending that packet twice is illegal */
            return false;

        if (!http_method_is_valid(method))
            return false;

        request.method = method;
        break;

    case WAS_COMMAND_URI:
        if (request.finished)
            return false;

        return was_simple_apply_string(&request.uri,
                                       packet.GetPayloadString());

    case WAS_COMMAND_SCRIPT_NAME:
        if (request.finished)
            return false;

        return was_simple_apply_string(&request.script_name,
                                       packet.GetPayloadString());

    case WAS_COMMAND_PATH_INFO:
        if (request.finished)
            return false;

        return was_simple_apply_string(&request.path_info,
                                       packet.GetPayloadString());

    case WAS_COMMAND_QUERY_STRING:
        if (request.finished)
            return false;

        return was_simple_apply_string(&request.query_string,
                                       packet.GetPayloadString());

    case WAS_COMMAND_HEADER:
        if (request.finished)
            return false;

        was_simple_apply_map(request.headers, packet.GetPayloadString());
        break;

    case WAS_COMMAND_PARAMETER:
        if (request.finished)
            return false;

        was_simple_apply_map(request.parameters, packet.GetPayloadString());
        break;

    case WAS_COMMAND_STATUS:
        return false;

    case WAS_COMMAND_NO_DATA:
        if (request.finished)
            return false;

        input.announced = 0;
        input.known_length = true;
        input.no_body = true;
        request.finished = true;
        break;

    case WAS_COMMAND_DATA:
        if (request.finished)
            return false;

        /* TODO: body? */
        input.no_body = false;
        request.finished = true;
        break;

    case WAS_COMMAND_LENGTH:
        if (!request.finished || input.no_body || input.premature)
            return false;

        if (packet.length != sizeof(length))
            return false;

        length = *(const uint64_t *)packet.payload;
        if (length < input.received ||
            (input.known_length && length != input.announced))
            return false;

        input.announced = length;
        input.known_length = true;
        break;

    case WAS_COMMAND_STOP:
        if (!request.finished)
            return false;

        if (response.state == Response::State::STOP) {
            /* if we're already at this state, then probably because
               was_simple_abort() was called - and
               WAS_COMMAND_PREMATURE has already been sent, so we can
               silently ignore this control packet */
            assert(output.no_body);
            return true;
        }

        output.no_body = true;

        if (!control.SendUint64(WAS_COMMAND_PREMATURE, output.sent) ||
            !control.Flush())
            return false;

        response.state = Response::State::STOP;
        break;

    case WAS_COMMAND_PREMATURE:
        if (!request.finished)
            return false;

        if (packet.length != sizeof(length))
            return false;

        length = *(const uint64_t *)packet.payload;
        if (length < input.received ||
            (input.known_length && length > input.announced))
            return false;

        input.announced = length;
        input.known_length = true;
        input.premature = true;
        return true;

    case WAS_COMMAND_REMOTE_HOST:
        if (request.finished)
            return false;

        return was_simple_apply_string(&request.remote_host,
                                       packet.GetPayloadString());

    case WAS_COMMAND_METRIC:
        request.want_metrics = true;
        return true;
    }

    return true;
}

bool
was_simple::ApplyPendingControl()
{
    const struct was_control_packet *packet;
    while ((packet = control.Next()) != nullptr)
        if (!ApplyRequestPacket(*packet))
            return false;

    return true;
}

bool
was_simple::ReadAndApplyControl()
{
    const auto *packet = control.Read(false);
    if (packet == nullptr) {
        if (errno == E2BIG) {
            /* the payload is too large for our control input buffer;
               check the command to see whether to fail the request
               with a HTTP error status or abort the WAS connection */
            switch (control.PeekCommand()) {
            case WAS_COMMAND_URI:
            case WAS_COMMAND_SCRIPT_NAME:
            case WAS_COMMAND_PATH_INFO:
            case WAS_COMMAND_QUERY_STRING:
                error_status = HTTP_STATUS_REQUEST_URI_TOO_LONG;
                return true;

            case WAS_COMMAND_HEADER:
            case WAS_COMMAND_PARAMETER:
                if (error_status == http_status_t{})
                    error_status = HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE;
                return true;

            default:
                /* there's no good way to handle this gracefully;
                   abort the WAS connection */
                break;
            }
        }

        response.state = Response::State::ERROR;
        return false;
    }

    return ApplyRequestPacket(*packet);
}

const char *
was_simple::Accept(const char *would_block)
{
    if (response.state != Response::State::NONE &&
        !FinishRequest())
        return nullptr;

    assert(response.state == Response::State::NONE);

    while (true) {
        const auto *packet = control.Read(would_block != nullptr);
        if (packet == nullptr)
            return errno == EAGAIN ? would_block : nullptr;

        if (packet->command == WAS_COMMAND_REQUEST)
            /* we got another request: break out of this "while" loop
               and handle it */
            break;
        else if (packet->command == WAS_COMMAND_STOP) {
            /* this is late, we're already finished sending the
               response body, but we're doing our best to handle it
               gracefully */
            if (!control.SendUint64(WAS_COMMAND_PREMATURE, output.sent) ||
                !control.Flush()) {
                response.state = Response::State::ERROR;

                /* need to clear request's attributes or else our
                   destructor will call Deinit() which will
                   double-free obsolete string pointers */
                request.Init();

                return nullptr;
            }
        } else if (packet->command != WAS_COMMAND_NOP)
            /* unexpected packet */
            return nullptr;
    }

    assert(response.state == Response::State::NONE);

    error_status = http_status_t{};

    input.received = 0;
    input.known_length = false;
    input.stopped = false;
    input.premature = false;
    input.ignore_premature = false;

    output.sent = 0;
    output.known_length = false;

    response.state = Response::State::STATUS;

    request.Init();

    do {
        if (!ReadAndApplyControl()) {
            response.state = Response::State::ERROR;
            return nullptr;
        }
    } while (!request.finished);

    /* after we have received DATA or NO_DATA which allows us to start
       handling the request, consume all other control packets that
       may have been received already, just in case it contains
       helpful data such as LENGTH */
    if (!ApplyPendingControl()) {
        response.state = Response::State::ERROR;
        return nullptr;
    }

    if (error_status != http_status_t{}) {
        /* a recoverable error has occurred - generate an empty
           response without returning this request to the caller */
        SetStatus(error_status);

        /* TODO let's hope the compiler optimizes this to a JMP or
           else we risk stack overflow; but I don't want to use "goto"
           here, and wrapping the whole method in a loop is ugly,
           too */
        return Accept(would_block);
    }

    return request.uri;
}

static constexpr struct pollfd
MakePollfd(int fd, short events) noexcept
{
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = events;
    return pfd;
}

enum was_simple_poll_result
was_simple::PollInput(int timeout_ms)
{
    assert(response.state != Response::State::NONE);

    if (input.premature && !input.ignore_premature)
        return WAS_SIMPLE_POLL_CLOSED;

    if (input.no_body || input.IsEOF())
        return WAS_SIMPLE_POLL_END;

    if (!control.Flush() || !ApplyPendingControl() ||
        !control.Flush()) {
        response.state = Response::State::ERROR;
        return WAS_SIMPLE_POLL_ERROR;
    }

    if (response.state == Response::State::STOP)
        /* this may have been caused by STOP */
        return WAS_SIMPLE_POLL_ERROR;

    /* check "eof" again, as it may have changed after control packets
       have been handled */
    if (input.IsEOF())
        return WAS_SIMPLE_POLL_END;

    struct pollfd fds[] = {
        MakePollfd(control.fd, POLLIN),
        MakePollfd(input.fd, POLLIN),
    };

    while (true) {
        int ret = poll(fds, ARRAY_SIZE(fds), timeout_ms);
        if (ret < 0) {
            response.state = Response::State::ERROR;
            return WAS_SIMPLE_POLL_ERROR;
        }

        if (ret == 0)
            return WAS_SIMPLE_POLL_TIMEOUT;

        if (fds[0].revents & POLLIN) {
            if (!control.Fill(true) ||
                !ApplyPendingControl()) {
                response.state = Response::State::ERROR;
                return WAS_SIMPLE_POLL_ERROR;
            }

            if (input.premature && !input.ignore_premature)
                return WAS_SIMPLE_POLL_CLOSED;

            if (response.state == Response::State::STOP)
                /* this may have been caused by STOP */
                return WAS_SIMPLE_POLL_ERROR;

            if (input.IsEOF())
                return WAS_SIMPLE_POLL_END;
        }

        if (fds[1].revents & POLLIN)
            return WAS_SIMPLE_POLL_SUCCESS;
    }
}

bool
was_simple::Received(size_t nbytes)
{
    assert(response.state != Response::State::NONE);

    if (input.premature && !input.ignore_premature)
        return false;

    input.received += nbytes;

    if (input.known_length && input.received > input.announced) {
        response.state = Response::State::ERROR;
        return false;
    }

    /* TODO??? */
    return true;
}

ssize_t
was_simple::Read(void *buffer, size_t length)
{
    assert(response.state != Response::State::NONE);

    if (response.state == Response::State::ERROR)
        return -2;

    if (input.premature && !input.ignore_premature)
        return -2;

    if (input.no_body || input.IsEOF())
        return 0;

    length = input.ClampRemaining(length);
    if (length == 0)
        return 0;

    if (partial_read_state == PartialReadState::PARTIAL) {
        partial_read_state = PartialReadState::FINISHED;

        switch (PollInput(-1)) {
        case WAS_SIMPLE_POLL_SUCCESS:
            break;

        case WAS_SIMPLE_POLL_ERROR:
        case WAS_SIMPLE_POLL_TIMEOUT:
        case WAS_SIMPLE_POLL_CLOSED:
            return -2;

        case WAS_SIMPLE_POLL_END:
            return 0;
        }
    }

    ssize_t nbytes = read(input.fd, buffer, length);
    if (nbytes < 0 && errno == EAGAIN) {
        /* reading blocks: poll for data (or for control commands and
           handle them) */
        switch (PollInput(-1)) {
        case WAS_SIMPLE_POLL_SUCCESS:
            /* time to try again */

            length = input.ClampRemaining(length);
            assert(length > 0);

            nbytes = read(input.fd, buffer, length);
            break;

        case WAS_SIMPLE_POLL_ERROR:
        case WAS_SIMPLE_POLL_TIMEOUT:
        case WAS_SIMPLE_POLL_CLOSED:
            return -2;

        case WAS_SIMPLE_POLL_END:
            return 0;
        }
    }

    if (nbytes <= 0) {
        response.state = Response::State::ERROR;
        return nbytes < 0 ? -1 : -2;
    }

    if (!Received(nbytes))
        return -2;

    if (size_t(nbytes) < length &&
        partial_read_state == PartialReadState::INITIAL)
        partial_read_state = PartialReadState::PARTIAL;

    return nbytes;
}

bool
was_simple::CloseInput()
{
    assert(response.state != Response::State::NONE);

    if (response.state == Response::State::ERROR)
        return false;

    /* kludge: send STOP for request body only if another control
       packet will be sent in this function, because otherwise
       beng-proxy's was_stock may be confused by a control packet on
       an idle WAS control connection */
    if (IsControlFinished())
        return true;

    if (input.no_body || input.stopped || input.premature ||
        input.IsEOF())
        return true;

    if (!control.SendEmpty(WAS_COMMAND_STOP)) {
        response.state = Response::State::ERROR;
        return false;
    }

    input.stopped = true;
    return true;
}

bool
was_simple::SetStatus(http_status_t status)
{
    assert(response.state != Response::State::NONE);

    if (response.state != Response::State::STATUS)
        /* too late for sending the status */
        return false;

    if (!control.SendPacket(WAS_COMMAND_STATUS, &status, sizeof(status))) {
        response.state = Response::State::ERROR;
        return false;
    }

    response.state = Response::State::HEADERS;
    output.no_body = http_status_is_empty(status);
    return true;
}

inline bool
was_simple::SetHeader(std::string_view name,
                      std::string_view value) noexcept
{
    assert(response.state != Response::State::NONE);

    if (response.state == Response::State::STATUS &&
        !SetStatus(HTTP_STATUS_OK))
        return false;

    if (response.state != Response::State::HEADERS)
        /* too late for sending headers */
        return false;

    bool success = control.SendHeader(WAS_COMMAND_HEADER,
                                      name.size() + 1 + value.size()) &&
        control.Send(name.data(), name.size()) &&
        control.Send("=", 1) &&
        control.Send(value.data(), value.size());

    if (!success)
        response.state = Response::State::ERROR;

    return success;
}

bool
was_simple::SetLength(uint64_t length)
{
    assert(response.state != Response::State::NONE);

    if (output.no_body)
        return false;

    assert(length >= output.sent);

    if (output.known_length) {
        assert(length == output.known_length);
        return true;
    }

    if (response.state == Response::State::STATUS &&
        !SetStatus(HTTP_STATUS_OK))
        return false;

    if (response.state == Response::State::HEADERS) {
        if (!control.SendEmpty(WAS_COMMAND_DATA)) {
            response.state = Response::State::ERROR;
            return false;
        }

        response.state = Response::State::BODY;
    }

    assert(response.state == Response::State::BODY);

    if (!control.SendUint64(WAS_COMMAND_LENGTH, length) ||
        !control.Flush()) {
        response.state = Response::State::ERROR;
        return false;
    }

    output.announced = length;
    output.known_length = true;

    if (output.IsFull())
        response.state = Response::State::END;

    return true;
}

bool
was_simple::SetResponseStateBody()
{
    assert(response.state != Response::State::NONE);

    if (response.state == Response::State::ERROR)
        return false;

    if (response.state == Response::State::STATUS &&
        !SetStatus(HTTP_STATUS_OK))
        return false;

    if (response.state == Response::State::HEADERS) {
        if (output.no_body) {
            response.state = Response::State::END;
            if (!control.SendEmpty(WAS_COMMAND_NO_DATA))
                response.state = Response::State::ERROR;
            return false;
        }

        if (!control.SendEmpty(WAS_COMMAND_DATA)) {
            response.state = Response::State::ERROR;
            return false;
        }

        if (output.IsFull()) {
            response.state = Response::State::END;
            return false;
        }

        response.state = Response::State::BODY;
    }

    return response.state == Response::State::BODY;
}

enum was_simple_poll_result
was_simple::PollOutput(int timeout_ms)
{
    assert(response.state != Response::State::NONE);

    if (response.state == Response::State::STOP)
        return WAS_SIMPLE_POLL_ERROR;

    if (output.IsFull())
        return WAS_SIMPLE_POLL_END;

    if (!control.Flush() || !ApplyPendingControl() ||
        !control.Flush()) {
        response.state = Response::State::ERROR;
        return WAS_SIMPLE_POLL_ERROR;
    }

    if (response.state > Response::State::BODY)
        /* throw WAS_SIMPLE_POLL_ERROR even if state==END, which may
           have been caused by STOP; in that case, the current request
           must be aborted by the application, but this object may be
           reused, so don't set state=ERROR */
        return WAS_SIMPLE_POLL_ERROR;

    struct pollfd fds[] = {
        MakePollfd(control.fd, POLLIN),
        MakePollfd(output.fd, POLLOUT),
    };

    while (true) {
        int ret = poll(fds, ARRAY_SIZE(fds), timeout_ms);
        if (ret < 0) {
            response.state = Response::State::ERROR;
            return WAS_SIMPLE_POLL_ERROR;
        }

        if (ret == 0)
            return WAS_SIMPLE_POLL_TIMEOUT;

        if (fds[0].revents & POLLIN) {
            if (!control.Fill(true) ||
                !ApplyPendingControl()) {
                response.state = Response::State::ERROR;
                return WAS_SIMPLE_POLL_ERROR;
            }

            if (response.state > Response::State::BODY)
                /* throw WAS_SIMPLE_POLL_ERROR even if state==END,
                   which may have been caused by STOP; in that case,
                   the current request must be aborted by the
                   application, but this object may be reused, so
                   don't set state=ERROR */
                return WAS_SIMPLE_POLL_ERROR;
        }

        if (fds[1].revents & POLLOUT)
            return WAS_SIMPLE_POLL_SUCCESS;
    }
}

inline bool
was_simple::Write(const void *data0, size_t length)
{
    assert(response.state != Response::State::NONE);

    if (!SetResponseStateBody() ||
        !output.CanSend(length))
        return false;

    if (!control.Flush()) {
        response.state = Response::State::ERROR;
        return false;
    }

    const char *data = (const char *)data0;

    while (length > 0) {
        ssize_t nbytes = write(output.fd, data, length);
        if (nbytes < 0 && errno == EAGAIN) {
            /* writing blocks: poll for the pipe to become writable
               again (or for control commands and handle them) */
            switch (PollOutput(-1)) {
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

        if (nbytes <= 0) {
            response.state = Response::State::ERROR;
            return false;
        }

        output.Sent(nbytes);
        data += nbytes;
        length -= nbytes;

        if (output.IsFull()) {
            response.state = Response::State::END;
            if (length > 0)
                return false;
        }
    }

    return true;
}

inline ssize_t
was_simple::Splice(size_t max_length) noexcept
{
    assert(response.state != Response::State::NONE);

    if (response.state == Response::State::ERROR)
        return -2;

    if (input.premature && !input.ignore_premature)
        return -2;

    if (input.no_body || input.IsEOF())
        return 0;

    max_length = input.ClampRemaining(max_length);
    if (max_length == 0)
        return 0;

    if (!SetResponseStateBody() ||
        !output.CanSend(max_length))
        return -2;

    if (!control.Flush()) {
        response.state = Response::State::ERROR;
        return -2;
    }

    if (partial_read_state == PartialReadState::PARTIAL) {
        partial_read_state = PartialReadState::FINISHED;

        switch (PollInput(-1)) {
        case WAS_SIMPLE_POLL_SUCCESS:
            break;

        case WAS_SIMPLE_POLL_ERROR:
        case WAS_SIMPLE_POLL_TIMEOUT:
        case WAS_SIMPLE_POLL_CLOSED:
            return -2;

        case WAS_SIMPLE_POLL_END:
            return 0;
        }
    }

    ssize_t nbytes = splice(input.fd, nullptr,
                            output.fd, nullptr, max_length,
                            SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
    if (nbytes < 0 && errno == EAGAIN) {
        switch (PollInput(-1)) {
        case WAS_SIMPLE_POLL_SUCCESS:
            break;

        case WAS_SIMPLE_POLL_ERROR:
        case WAS_SIMPLE_POLL_TIMEOUT:
        case WAS_SIMPLE_POLL_CLOSED:
            return -2;

        case WAS_SIMPLE_POLL_END:
            return 0;
        }

        switch (PollOutput(-1)) {
        case WAS_SIMPLE_POLL_SUCCESS:
            break;

        case WAS_SIMPLE_POLL_ERROR:
        case WAS_SIMPLE_POLL_TIMEOUT:
        case WAS_SIMPLE_POLL_CLOSED:
        case WAS_SIMPLE_POLL_END:
            return -2;
        }

        nbytes = splice(input.fd, nullptr,
                        output.fd, nullptr, max_length,
                        SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
    }

    if (nbytes < 0)
        return -1;

    if (nbytes == 0)
        /* the pipe was closed - this shouldn't happen */
        return -2;

    if (!Received(nbytes))
        return -2;

    output.Sent(nbytes);
    if (output.IsFull())
        response.state = Response::State::END;

    return nbytes;
}

inline bool
was_simple::SpliceAll(bool end) noexcept
{
    while (true) {
        if (end && !output.known_length && input.known_length &&
            !SetLength(input.announced - input.received + output.sent))
            return false;

        ssize_t nbytes = Splice(INT_MAX);
        if (nbytes < 0)
            return false;

        if (nbytes == 0)
            return !end || End();
    }
}

inline bool
was_simple::DiscardAllInput()
{
    /* since we're discarding everything, receiving PREMATURE is okay,
       just stop there and report success */
    input.ignore_premature = true;

    while (true) {
        char buffer[4096];
        ssize_t nbytes = Read(buffer, sizeof(buffer));
        if (nbytes <= 0)
            return nbytes == 0;
    }
}

bool
was_simple::End()
{
    assert(response.state != Response::State::NONE);

    if (!CloseInput())
        return false;

    /* generate a status code? */
    if (response.state == Response::State::STATUS &&
        !SetStatus(HTTP_STATUS_NO_CONTENT))
        return false;

    /* no response body? */
    if (response.state == Response::State::HEADERS) {
        if (!control.SendEmpty(WAS_COMMAND_NO_DATA)) {
            response.state = Response::State::ERROR;
            return false;
        }

        response.state = Response::State::END;
    }

    /* finish the response body? */
    if (response.state == Response::State::BODY) {
        assert(!output.no_body);

        if (output.known_length) {
            assert(output.sent < output.announced);

            if (!control.SendUint64(WAS_COMMAND_PREMATURE, output.sent)) {
                response.state = Response::State::ERROR;
                return false;
            }

            response.state = Response::State::END;
        } else {
            if (!SetLength(output.sent))
                return false;
        }
    }

    /* finish the control channel? */
    if (!control.Flush()) {
        response.state = Response::State::ERROR;
        return false;
    }

    assert(response.state == Response::State::END ||
           response.state == Response::State::STOP);

    /* discard the request body? */
    if (!DiscardAllInput())
        return false;

    /* wait for PREMATURE? */
    if (input.stopped && !input.IsEOF()) {
        while (!input.premature) {
            if (!ReadAndApplyControl()) {
                response.state = Response::State::ERROR;
                return false;
            }
        }
    }

    /* connection is ready to be reused */
    return true;
}

inline bool
was_simple::Abort()
{
    switch (response.state) {
    case Response::State::NONE:
    case Response::State::STOP:
    case Response::State::END:
        return true;

    case Response::State::STATUS:
        return SetStatus(HTTP_STATUS_INTERNAL_SERVER_ERROR) && End();

    case Response::State::HEADERS:
        response.state = Response::State::BODY;
        /* fall through */

    case Response::State::BODY:
        if (!output.no_body && !output.IsFull()) {
            output.no_body = true;

            if (!control.SendUint64(WAS_COMMAND_PREMATURE, output.sent) ||
                !control.Flush()) {
                response.state = Response::State::ERROR;
                return false;
            }

            response.state = Response::State::STOP;
        }

        return true;

    case Response::State::ERROR:
        return false;
    }

    assert(false);
    was_gcc_unreachable();
}

inline bool
was_simple::SendMetric(std::string_view name, float value) noexcept
{
    assert(response.state != Response::State::NONE);

    if (!WantMetrics())
        return true;

    bool success = control.SendHeader(WAS_COMMAND_METRIC,
                                      sizeof(value) + name.size()) &&
        control.Send(&value, sizeof(value)) &&
        control.Send(name.data(), name.size());

    if (!success)
        response.state = Response::State::ERROR;

    return success;
}

struct was_simple *
was_simple_new(void)
{
    return new was_simple{3, 0, 1};
}

struct was_simple *
was_simple_new_fds(int control_fd, int input_fd, int output_fd)
{
    return new was_simple{control_fd, input_fd, output_fd};
}

void
was_simple_free(struct was_simple *w)
{
    delete w;
}

const char *
was_simple_accept(struct was_simple *w)
{
    return w->Accept();
}

const char *
was_simple_accept_non_block(struct was_simple *w, const char *would_block)
{
    return w->Accept(would_block);
}

int
was_simple_control_fd(struct was_simple *w)
{
    return w->control.fd;
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
was_simple_get_header(const struct was_simple *w, const char *name)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    auto i = w->request.headers.find(name);
    return i != w->request.headers.end()
        ? i->second.c_str()
        : nullptr;
}

struct was_simple_iterator *
was_simple_get_multi_header(const struct was_simple *w, const char *name)
{
    auto x = w->request.headers.equal_range(name);
    return was_simple_iterator_new(x.first, x.second);
}

struct was_simple_iterator *
was_simple_get_header_iterator(const struct was_simple *w)
{
    return was_simple_iterator_new(w->request.headers.begin(),
                                   w->request.headers.end());
}

const char *
was_simple_get_remote_host(const struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    return w->request.remote_host;
}

const char *
was_simple_get_parameter(const struct was_simple *w, const char *name)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    auto i = w->request.parameters.find(name);
    return i != w->request.parameters.end()
        ? i->second.c_str()
        : nullptr;
}

struct was_simple_iterator *
was_simple_get_parameter_iterator(const struct was_simple *w)
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
    return w->PollInput(timeout_ms);
}

int
was_simple_input_fd(const struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (w->input.premature && !w->input.ignore_premature)
        return -1;

    if (w->response.state == was_simple::Response::State::ERROR)
        return -1;

    return w->input.fd;
}

bool
was_simple_received(struct was_simple *w, size_t nbytes)
{
    return w->Received(nbytes);
}

ssize_t
was_simple_read(struct was_simple *w, void *buffer, size_t length)
{
    return w->Read(buffer, length);
}

int64_t
was_simple_input_remaining(const struct was_simple *w)
{
    return w->GetInputRemaining();
}

bool
was_simple_input_close(struct was_simple *w)
{
    return w->CloseInput();
}

bool
was_simple_status(struct was_simple *w, http_status_t status)
{
    return w->SetStatus(status);
}

bool
was_simple_set_header(struct was_simple *w,
                      const char *name, const char *value)
{
    return w->SetHeader(name,  value);
}

bool
was_simple_set_header_n(struct was_simple *w,
                        const char *name, size_t name_length,
                        const char *value, size_t value_length)
{
    return w->SetHeader({name, name_length}, {value, value_length});
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
    return w->SetLength(length);
}

bool
was_simple_output_begin(struct was_simple *w)
{
    return w->SetResponseStateBody();
}

enum was_simple_poll_result
was_simple_output_poll(struct was_simple *w, int timeout_ms)
{
    return w->PollOutput(timeout_ms);
}

int
was_simple_output_fd(struct was_simple *w)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (!w->SetResponseStateBody())
        return -1;

    return w->output.fd;
}

bool
was_simple_sent(struct was_simple *w, size_t nbytes)
{
    assert(w->response.state != was_simple::Response::State::NONE);

    if (w->response.state > was_simple::Response::State::BODY)
        return false;

    if (!w->output.CanSend(nbytes)) {
        w->response.state = was_simple::Response::State::ERROR;
        return false;
    }

    if (!w->control.Flush()) {
        w->response.state = was_simple::Response::State::ERROR;
        return false;
    }

    w->output.Sent(nbytes);

    if (w->output.IsFull()) {
        assert(w->response.state == was_simple::Response::State::BODY);
        w->response.state = was_simple::Response::State::END;
    }

    return true;
}

bool
was_simple_write(struct was_simple *w, const void *data, size_t length)
{
    return w->Write(data, length);
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

ssize_t
was_simple_splice(struct was_simple *w, size_t max_length)
{
    return w->Splice(max_length);
}

bool
was_simple_splice_all(struct was_simple *w, bool end)
{
    return w->SpliceAll(end);
}

bool
was_simple_want_metrics(const struct was_simple *w)
{
    return w->WantMetrics();
}

bool
was_simple_metric(struct was_simple *w, const char *name, float value)
{
    return w->SendMetric(name, value);
}

bool
was_simple_end(struct was_simple *w)
{
    return w->End();
}

bool
was_simple_abort(struct was_simple *w)
{
    return w->Abort();
}
