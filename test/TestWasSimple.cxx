// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include <was/simple.h>
#include <was/multi.h>
#include <was/protocol.h>

#include <algorithm>
#include <string>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void
SetNonBlocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

struct FakeWasClient {
    int control_fd = -1, input_fd = -1, output_fd = -1;

public:
    FakeWasClient();
    ~FakeWasClient() noexcept;

    void SendControlRaw(const void *data, size_t size) {
        if (send(control_fd, data, size, 0) != ssize_t(size))
            abort();
    }

    void SendControlHeader(enum was_command cmd, size_t size) {
        struct was_header header;
        header.length = uint16_t(size);
        header.command = uint16_t(cmd);
        SendControlRaw(&header, sizeof(header));
    }

    void SendControl(enum was_command cmd) {
        SendControlHeader(cmd, 0);
    }

    void SendControl(enum was_command cmd, const char *payload) {
        size_t length = strlen(payload);
        SendControlHeader(cmd, length);
        SendControlRaw(payload, length);
    }

    template<typename T>
    void SendControlT(enum was_command cmd, const T &payload) {
        SendControlHeader(cmd, sizeof(payload));
        SendControlRaw(&payload, sizeof(payload));
    }

    void SendLength(uint64_t length) {
        SendControlT(WAS_COMMAND_LENGTH, length);
    }

    void SendPremature(uint64_t length) {
        SendControlT(WAS_COMMAND_PREMATURE, length);
    }

    void SendOutput(const void *data, size_t size) {
        if (write(output_fd, data, size) != ssize_t(size))
            abort();
    }

    void SendOutput(const char *s) {
        SendOutput(s, strlen(s));
    }

    size_t ReceiveControlRaw(void *data, size_t size) {
        ssize_t nbytes = recv(control_fd, data, size, 0);
        if (nbytes < 0)
            abort();
        return nbytes;
    }

    void ExpectControlRaw(void *data, size_t size) {
        if (ReceiveControlRaw(data, size) != size)
            abort();
    }

    void ExpectControlEmpty() {
        uint8_t buffer[64];
        ssize_t nbytes = recv(control_fd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (nbytes >= 0 || errno != EAGAIN)
            abort();
    }

    template<typename T>
    void ReceiveControlT(T &value) {
        ExpectControlRaw(&value, sizeof(value));
    }

    struct was_header ReceiveControlHeader() {
        struct was_header header;
        ExpectControlRaw(&header, sizeof(header));
        return header;
    }

    void ExpectControlHeader(enum was_command cmd, size_t size) {
        const auto header = ReceiveControlHeader();
        if (header.command != cmd)
            abort();
        if (header.length != size)
            abort();
    }

    void ExpectControl(enum was_command cmd) {
        ExpectControlHeader(cmd, 0);
    }

    template<typename T>
    void ExpectControlT(enum was_command cmd, const T &expected_value) {
        ExpectControlHeader(cmd, sizeof(T));

        T value;
        ReceiveControlT(value);

        if (value != expected_value)
            abort();
    }

    void ExpectStatus(http_status_t status) {
        ExpectControlT(WAS_COMMAND_STATUS, uint32_t(status));
    }

    void ExpectLength(uint64_t length) {
        ExpectControlT(WAS_COMMAND_LENGTH, length);
    }

    void ExpectPremature(uint64_t length) {
        ExpectControlT(WAS_COMMAND_PREMATURE, length);
    }

    void DiscardAllInput(size_t length) {
        uint8_t buffer[1024];

        while (length > 0) {
            size_t n = std::min(length, sizeof(buffer));
            ssize_t nbytes = read(input_fd, buffer, n);
            if (nbytes != ssize_t(n))
                abort();

            length -= nbytes;
        }

        ssize_t nbytes = read(input_fd, buffer, sizeof(buffer));
        if (nbytes != -1 || errno != EAGAIN)
            abort();
    }
};

FakeWasClient::FakeWasClient()
{
    int fds[2];

    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) < 0)
        abort();

    control_fd = fds[0];
    if (control_fd == 3)
        control_fd = dup(control_fd);

    if (fds[1] != 3) {
        dup2(fds[1], 3);
        close(fds[1]);
    }

    if (pipe(fds) < 0)
        abort();

    if (fcntl(fds[1], F_SETPIPE_SZ, 4096) < 0)
        abort();

    input_fd = fds[0];
    SetNonBlocking(input_fd);

    dup2(fds[1], 1);
    close(fds[1]);

    if (pipe(fds) < 0)
        abort();

    output_fd = fds[1];
    dup2(fds[0], 0);
    close(fds[0]);

    SetNonBlocking(0);
    SetNonBlocking(1);
    SetNonBlocking(3);
}

FakeWasClient::~FakeWasClient()
{
    close(control_fd);
    close(input_fd);
    close(output_fd);
}

static void
TestEmpty(FakeWasClient &client, struct was_simple *s)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_NO_DATA);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (was_simple_has_body(s))
        abort();

    was_simple_end(s);

    client.ExpectStatus(HTTP_STATUS_NO_CONTENT);
    client.ExpectControl(WAS_COMMAND_NO_DATA);
    client.ExpectControlEmpty();
    client.DiscardAllInput(0);
}

static void
TestSimple(FakeWasClient &client, struct was_simple *s)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_NO_DATA);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (was_simple_has_body(s))
        abort();

    was_simple_puts(s, "foo");
    was_simple_end(s);

    client.ExpectStatus(HTTP_STATUS_OK);
    client.ExpectControl(WAS_COMMAND_DATA);
    client.ExpectLength(3);
    client.ExpectControlEmpty();
    client.DiscardAllInput(3);
}

static void
TestDiscardedRequestBody(FakeWasClient &client, struct was_simple *s)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (!was_simple_has_body(s))
        abort();

    if (was_simple_input_fd(s) != 0)
        abort();

    if (was_simple_input_remaining(s) != -1)
        abort();

    if (was_simple_input_poll(s, 0) != WAS_SIMPLE_POLL_TIMEOUT)
        abort();

    client.SendLength(5);
    client.SendOutput("hello");

    if (was_simple_input_poll(s, 0) != WAS_SIMPLE_POLL_SUCCESS)
        abort();

    if (was_simple_input_remaining(s) != 5)
        abort();

    was_simple_end(s);

    client.ExpectControl(WAS_COMMAND_STOP);
    // TODO: do we need to send WAS_COMMAND_PREMATURE now?
    client.ExpectStatus(HTTP_STATUS_NO_CONTENT);
    client.ExpectControl(WAS_COMMAND_NO_DATA);
    client.ExpectControlEmpty();
}

static void
TestPrematureDiscardedRequestBody(FakeWasClient &client, struct was_simple *s,
                                  bool poll)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (!was_simple_has_body(s))
        abort();

    client.SendLength(100);
    client.SendOutput("hello");
    client.SendPremature(5);

    if (poll) {
        auto poll_result = was_simple_input_poll(s, 0);
        if (poll_result != WAS_SIMPLE_POLL_CLOSED)
            abort();
    }

    was_simple_end(s);

    if (!poll) {
        /* the library sent WAS_COMMAND_STOP because it didn't yet
           process the client's WAS_COMMAND_PREMATURE */
        client.ExpectControl(WAS_COMMAND_STOP);
    }

    client.ExpectStatus(HTTP_STATUS_NO_CONTENT);
    client.ExpectControl(WAS_COMMAND_NO_DATA);
    client.ExpectControlEmpty();
}

static void
TestPrematureConsumedRequestBody(FakeWasClient &client, struct was_simple *s,
                                 bool poll)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (!was_simple_has_body(s))
        abort();

    client.SendLength(100);
    client.SendOutput("hello");

    if (was_simple_input_fd(s) != 0)
        abort();

    if (was_simple_input_remaining(s) != -1)
        abort();

    auto poll_result = was_simple_input_poll(s, 0);
    if (poll_result != WAS_SIMPLE_POLL_SUCCESS)
        abort();

    if (was_simple_input_remaining(s) != 100)
        abort();

    char buffer[64];
    ssize_t nbytes = was_simple_read(s, buffer, sizeof(buffer));
    if (nbytes != 5 || memcmp(buffer, "hello", 5) != 0)
        abort();

    if (was_simple_input_remaining(s) != 95)
        abort();

    client.SendPremature(5);

    if (poll) {
        poll_result = was_simple_input_poll(s, 0);
        if (poll_result != WAS_SIMPLE_POLL_CLOSED)
            abort();

        if (was_simple_input_fd(s) != -1)
            abort();
    }

    nbytes = was_simple_read(s, buffer, sizeof(buffer));
    if (nbytes != -2)
        abort();

    if (was_simple_input_fd(s) != -1)
        abort();

    if (was_simple_input_remaining(s) != -1)
        abort();

    was_simple_end(s);

    client.ExpectStatus(HTTP_STATUS_NO_CONTENT);
    client.ExpectControl(WAS_COMMAND_NO_DATA);
    client.ExpectControlEmpty();
}

static void
TestStopEarly(FakeWasClient &client, struct was_simple *s)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_NO_DATA);
    client.SendControl(WAS_COMMAND_STOP);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (was_simple_has_body(s))
        abort();

    was_simple_end(s);

    client.ExpectPremature(0);
    client.ExpectControlEmpty();
}

static void
TestStopLate(FakeWasClient &client, struct was_simple *s, bool poll)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_HEADER, "foo=bar");
    client.SendControl(WAS_COMMAND_NO_DATA);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (was_simple_has_body(s))
        abort();

    client.ExpectControlEmpty();

    bool success = was_simple_puts(s, "foo");
    if (!success)
        abort();

    client.ExpectStatus(HTTP_STATUS_OK);
    client.ExpectControl(WAS_COMMAND_DATA);
    client.ExpectControlEmpty();

    client.SendControl(WAS_COMMAND_STOP);

    if (poll) {
        auto poll_result = was_simple_output_poll(s, 0);
        if (poll_result != WAS_SIMPLE_POLL_ERROR)
            abort();
    } else {
        char buffer[4096];
        memset(buffer, '0', sizeof(buffer));

        success = was_simple_write(s, buffer, 4090);
        if (!success)
            abort();

        success = was_simple_write(s, buffer, 8);
        if (success)
            abort();
    }

    /* after receiving STOP, all method calls for this request must fail */

    if (was_simple_status(s, HTTP_STATUS_NOT_FOUND))
        abort();

    if (was_simple_set_header(s, "foo", "bar"))
        abort();

    if (was_simple_copy_all_headers(s))
        abort();

    if (was_simple_set_length(s, 42))
        abort();

    if (was_simple_output_begin(s))
        abort();

    if (was_simple_output_poll(s, 0) != WAS_SIMPLE_POLL_ERROR)
        abort();

    if (was_simple_output_fd(s) != -1)
        abort();

    if (was_simple_set_length(s, 1))
        abort();

    if (was_simple_puts(s, "foo"))
        abort();

    was_simple_end(s);

    client.ExpectPremature(poll ? 3 : 4093);
    client.ExpectControlEmpty();
    client.DiscardAllInput(poll ? 3 : 4093);
}

static void
TestAbort(FakeWasClient &client, struct was_simple *s, bool length)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_NO_DATA);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (was_simple_has_body(s))
        abort();

    client.ExpectControlEmpty();

    bool success = was_simple_puts(s, "foo");
    if (!success)
        abort();

    if (length && !was_simple_set_length(s, 1024))
        abort();

    client.ExpectStatus(HTTP_STATUS_OK);
    client.ExpectControl(WAS_COMMAND_DATA);

    if (length)
        client.ExpectLength(1024);

    client.ExpectControlEmpty();

    was_simple_abort(s);

    client.ExpectPremature(3);
    client.ExpectControlEmpty();
    client.DiscardAllInput(3);
}

/**
 * Stop the response (by the client or by was_simple_abort()) while
 * the request body is still being received.  was_simple_end() must
 * discard the rest of the request body and allow reusing the
 * connection.
 */
static void
TestStopDiscardRequestBody(FakeWasClient &client, struct was_simple *s,
                           bool use_abort)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);
    client.SendLength(10);
    client.SendOutput("hello");

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (!was_simple_has_body(s))
        abort();

    bool success = was_simple_puts(s, "foo");
    if (!success)
        abort();

    client.ExpectStatus(HTTP_STATUS_OK);
    client.ExpectControl(WAS_COMMAND_DATA);
    client.ExpectControlEmpty();

    if (use_abort) {
        if (!was_simple_abort(s))
            abort();
    } else {
        client.SendControl(WAS_COMMAND_STOP);

        if (was_simple_output_poll(s, 0) != WAS_SIMPLE_POLL_ERROR)
            abort();
    }

    client.ExpectPremature(3);
    client.ExpectControlEmpty();

    /* the application must still see the STOP */
    if (was_simple_input_poll(s, 0) != WAS_SIMPLE_POLL_ERROR)
        abort();

    client.SendOutput("world");

    if (!was_simple_end(s))
        abort();

    client.ExpectControlEmpty();
    client.DiscardAllInput(3);
}

/**
 * Receive STOP while the final write (or was_simple_set_length())
 * discards the request body.  No response data and no LENGTH may be
 * sent after PREMATURE.
 */
static void
TestStopWhileDiscarding(FakeWasClient &client, struct was_simple *s,
                        bool set_length)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);
    client.SendLength(10);
    client.SendOutput("helloworld");

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (set_length) {
        if (!was_simple_puts(s, "foo"))
            abort();

        client.ExpectStatus(HTTP_STATUS_OK);
        client.ExpectControl(WAS_COMMAND_DATA);
    } else {
        if (!was_simple_set_length(s, 3))
            abort();

        client.ExpectStatus(HTTP_STATUS_OK);
        client.ExpectControl(WAS_COMMAND_DATA);
        client.ExpectLength(3);
    }

    client.ExpectControlEmpty();

    /* this STOP will be received while the library discards the
       request body */
    client.SendControl(WAS_COMMAND_STOP);

    if (set_length) {
        if (was_simple_set_length(s, 3))
            abort();
    } else {
        if (was_simple_puts(s, "foo"))
            abort();
    }

    client.ExpectControl(WAS_COMMAND_STOP);
    client.ExpectPremature(set_length ? 3 : 0);
    client.ExpectControlEmpty();

    if (!was_simple_end(s))
        abort();

    client.ExpectControlEmpty();
    client.DiscardAllInput(set_length ? 3 : 0);
}

/**
 * The request body is consumed completely; was_simple_end() must not
 * send STOP.
 */
static void
TestConsumedRequestBody(FakeWasClient &client, struct was_simple *s)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);
    client.SendLength(5);
    client.SendOutput("hello");

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    char buffer[64];
    ssize_t nbytes = was_simple_read(s, buffer, sizeof(buffer));
    if (nbytes != 5 || memcmp(buffer, "hello", 5) != 0)
        abort();

    if (was_simple_input_remaining(s) != 0)
        abort();

    if (was_simple_read(s, buffer, sizeof(buffer)) != 0)
        abort();

    if (was_simple_input_poll(s, 0) != WAS_SIMPLE_POLL_END)
        abort();

    if (!was_simple_end(s))
        abort();

    client.ExpectStatus(HTTP_STATUS_NO_CONTENT);
    client.ExpectControl(WAS_COMMAND_NO_DATA);
    client.ExpectControlEmpty();
}

/**
 * DATA with LENGTH 0.
 */
static void
TestEmptyRequestBody(FakeWasClient &client, struct was_simple *s)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);
    client.SendLength(0);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (!was_simple_has_body(s))
        abort();

    if (was_simple_input_remaining(s) != 0)
        abort();

    char buffer[64];
    if (was_simple_read(s, buffer, sizeof(buffer)) != 0)
        abort();

    if (!was_simple_end(s))
        abort();

    client.ExpectStatus(HTTP_STATUS_NO_CONTENT);
    client.ExpectControl(WAS_COMMAND_NO_DATA);
    client.ExpectControlEmpty();
}

/**
 * LENGTH arrives after all of the request body has been read.
 */
static void
TestLateLength(FakeWasClient &client, struct was_simple *s)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);
    client.SendOutput("hello");

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    char buffer[64];
    ssize_t nbytes = was_simple_read(s, buffer, sizeof(buffer));
    if (nbytes != 5 || memcmp(buffer, "hello", 5) != 0)
        abort();

    if (was_simple_input_remaining(s) != -1)
        abort();

    client.SendLength(5);

    if (was_simple_read(s, buffer, sizeof(buffer)) != 0)
        abort();

    if (was_simple_input_remaining(s) != 0)
        abort();

    if (!was_simple_end(s))
        abort();

    client.ExpectStatus(HTTP_STATUS_NO_CONTENT);
    client.ExpectControl(WAS_COMMAND_NO_DATA);
    client.ExpectControlEmpty();
}

/**
 * PREMATURE arrives right after DATA, before any request body data.
 */
static void
TestImmediatePremature(FakeWasClient &client, struct was_simple *s)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);
    client.SendPremature(0);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    char buffer[64];
    if (was_simple_read(s, buffer, sizeof(buffer)) != -2)
        abort();

    if (!was_simple_end(s))
        abort();

    client.ExpectStatus(HTTP_STATUS_NO_CONTENT);
    client.ExpectControl(WAS_COMMAND_NO_DATA);
    client.ExpectControlEmpty();
}

/**
 * STOP arrives while was_simple_end() discards the request body.
 *
 * @param body true if the response body has already begun
 */
static void
TestStopDuringEnd(FakeWasClient &client, struct was_simple *s, bool body)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);
    client.SendLength(10);
    client.SendOutput("hello");

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (body) {
        if (!was_simple_puts(s, "foo"))
            abort();

        client.ExpectStatus(HTTP_STATUS_OK);
        client.ExpectControl(WAS_COMMAND_DATA);
    } else {
        /* this is only queued, and will be flushed by
           was_simple_end() */
        if (!was_simple_status(s, HTTP_STATUS_OK))
            abort();
    }

    client.ExpectControlEmpty();

    client.SendControl(WAS_COMMAND_STOP);
    client.SendOutput("world");

    if (!was_simple_end(s))
        abort();

    if (!body)
        client.ExpectStatus(HTTP_STATUS_OK);
    client.ExpectControl(WAS_COMMAND_STOP);
    client.ExpectPremature(body ? 3 : 0);
    client.ExpectControlEmpty();
    client.DiscardAllInput(body ? 3 : 0);
}

/**
 * A request packet which is too large for the control input buffer
 * must be answered with an error status, and the connection must
 * remain usable.
 */
static void
TestOversizedRequestPacket(FakeWasClient &client, struct was_simple *s,
                           enum was_command command, http_status_t status)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);

    const std::string payload(9000, 'x');
    client.SendControl(command, payload.c_str());
    client.SendControl(WAS_COMMAND_NO_DATA);

    /* the library responds with an error status by itself and then
       waits for the next request */
    static const char would_block[] = "would_block";
    const char *uri = was_simple_accept_non_block(s, would_block);
    if (uri != would_block)
        abort();

    client.ExpectStatus(status);
    client.ExpectControl(WAS_COMMAND_NO_DATA);
    client.ExpectControlEmpty();

    /* the next request must be handled normally */
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, "next");
    client.SendControl(WAS_COMMAND_NO_DATA);

    uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, "next") != 0)
        abort();

    if (!was_simple_end(s))
        abort();

    client.ExpectStatus(HTTP_STATUS_NO_CONTENT);
    client.ExpectControl(WAS_COMMAND_NO_DATA);
    client.ExpectControlEmpty();
}

static void
TestAbortNoBodyStatus(FakeWasClient &client, struct was_simple *s)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_NO_DATA);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (!was_simple_status(s, HTTP_STATUS_NO_CONTENT))
        abort();

    /* this aborts a response that has no body; can't send
       PREMATURE */
    if (!was_simple_abort(s))
        abort();

    client.ExpectStatus(HTTP_STATUS_NO_CONTENT);
    client.ExpectControl(WAS_COMMAND_NO_DATA);
}

static void
TestMalformedMapPacket(enum was_command command)
{
    FakeWasClient client;
    auto *s = was_simple_new();

    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(command, "foo");
    client.SendControl(WAS_COMMAND_NO_DATA);

    /* must be rejected by was_simple_accept() */
    if (was_simple_accept(s) != nullptr)
        abort();

    client.ExpectControlEmpty();

    was_simple_free(s);
}

static void
TestStopTooLate(FakeWasClient &client, struct was_simple *s)
{
    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_NO_DATA);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (was_simple_has_body(s))
        abort();

    client.ExpectControlEmpty();

    bool success = was_simple_puts(s, "foo");
    if (!success)
        abort();

    if (!was_simple_set_length(s, 3))
        abort();

    client.ExpectStatus(HTTP_STATUS_OK);
    client.ExpectControl(WAS_COMMAND_DATA);
    client.ExpectLength(3);

    client.ExpectControlEmpty();
    client.DiscardAllInput(3);

    client.SendControl(WAS_COMMAND_STOP);

    /* send another request and see if we receive the
       WAS_COMMAND_PREMATURE from inside was_simple_accept() */

    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_NO_DATA);

    uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    client.ExpectPremature(3);
    client.ExpectControlEmpty();

    was_simple_end(s);

    client.ExpectStatus(HTTP_STATUS_NO_CONTENT);
    client.ExpectControl(WAS_COMMAND_NO_DATA);
    client.ExpectControlEmpty();
    client.DiscardAllInput(0);
}

/**
 * The peer closes the request body pipe before the announced LENGTH
 * has been delivered.  The library must fail instead of looping
 * forever.
 */
static void
TestInputPipeHangup(bool read_first)
{
    FakeWasClient client;
    auto *s = was_simple_new();

    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);
    client.SendLength(10);
    client.SendOutput("hello");

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    if (read_first) {
        char buffer[64];
        ssize_t nbytes = was_simple_read(s, buffer, sizeof(buffer));
        if (nbytes != 5 || memcmp(buffer, "hello", 5) != 0)
            abort();

        close(client.output_fd);
        client.output_fd = -1;

        if (was_simple_read(s, buffer, sizeof(buffer)) != -2)
            abort();
    } else {
        close(client.output_fd);
        client.output_fd = -1;
    }

    if (was_simple_end(s))
        abort();

    if (was_simple_accept(s) != nullptr)
        abort();

    was_simple_free(s);
}

/**
 * A control packet which is too large for the control input buffer
 * arrives while the request body is being received.  This cannot be
 * handled gracefully, but it must not crash.
 */
static void
TestOversizedPacketDuringBody()
{
    FakeWasClient client;
    auto *s = was_simple_new();

    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    const std::string payload(20000, 'x');
    client.SendControlHeader(WAS_COMMAND_HEADER, 0xffff);
    client.SendControlRaw(payload.data(), payload.size());

    if (was_simple_input_poll(s, -1) != WAS_SIMPLE_POLL_ERROR)
        abort();

    if (was_simple_end(s))
        abort();

    was_simple_free(s);
}

/**
 * LENGTH arrives together with more request body data after a
 * partial read; the library must not read beyond the announced
 * length.
 */
static void
TestLengthAfterPartialRead()
{
    FakeWasClient client;
    auto *s = was_simple_new();

    client.SendControl(WAS_COMMAND_REQUEST);
    client.SendControl(WAS_COMMAND_URI, __func__);
    client.SendControl(WAS_COMMAND_DATA);
    client.SendOutput("hello");

    const char *uri = was_simple_accept(s);
    if (uri == nullptr || strcmp(uri, __func__) != 0)
        abort();

    char buffer[64];
    ssize_t nbytes = was_simple_read(s, buffer, sizeof(buffer));
    if (nbytes != 5 || memcmp(buffer, "hello", 5) != 0)
        abort();

    /* the peer violates the protocol by sending more data than
       announced */
    client.SendOutput("world!!");
    client.SendLength(8);

    nbytes = was_simple_read(s, buffer, sizeof(buffer));
    if (nbytes != 3 || memcmp(buffer, "wor", 3) != 0)
        abort();

    if (was_simple_read(s, buffer, sizeof(buffer)) != 0)
        abort();

    was_simple_free(s);
}

static void
SendMultiDatagram(int fd, uint16_t command, const int *fds, size_t n_fds)
{
    struct was_header header;
    header.length = 0;
    header.command = command;

    struct iovec v{&header, sizeof(header)};

    alignas(struct cmsghdr) char cmsg_buffer[CMSG_SPACE(4 * sizeof(int))]{};

    struct msghdr msg{};
    msg.msg_iov = &v;
    msg.msg_iovlen = 1;

    if (n_fds > 0) {
        msg.msg_control = cmsg_buffer;
        msg.msg_controllen = CMSG_SPACE(n_fds * sizeof(int));

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(n_fds * sizeof(int));
        memcpy(CMSG_DATA(cmsg), fds, n_fds * sizeof(int));
    }

    if (sendmsg(fd, &msg, 0) != ssize_t(sizeof(header)))
        abort();
}

/**
 * Was the write end of this pipe closed everywhere?
 */
static bool
IsPipeClosed(int read_fd)
{
    char buffer[1];
    return read(read_fd, buffer, sizeof(buffer)) == 0;
}

/**
 * Multi-WAS datagrams which are ignored or rejected must not leak
 * the file descriptors attached to them.
 */
static void
TestMultiRejectedFds(uint16_t command, size_t n_fds)
{
    int sv[2];
    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sv) < 0)
        abort();

    dup2(sv[1], 0);
    close(sv[1]);

    int pipe_fds[2];
    if (pipe(pipe_fds) < 0)
        abort();

    SetNonBlocking(pipe_fds[0]);

    int fds[4];
    for (size_t i = 0; i < n_fds; ++i)
        fds[i] = pipe_fds[1];

    SendMultiDatagram(sv[0], command, fds, n_fds);
    close(pipe_fds[1]);

    /* closing the socket makes was_multi_accept_simple() return
       nullptr if it ignores the datagram */
    close(sv[0]);

    auto *m = was_multi_new();
    if (was_multi_accept_simple(m) != nullptr)
        abort();
    was_multi_free(m);

    if (!IsPipeClosed(pipe_fds[0]))
        abort();

    close(pipe_fds[0]);
}

static void
TestAllOnOneConnection()
{
    FakeWasClient client;

    auto *s = was_simple_new();

    TestEmpty(client, s);
    TestSimple(client, s);
    TestDiscardedRequestBody(client, s);
    TestPrematureDiscardedRequestBody(client, s, false);
    TestPrematureDiscardedRequestBody(client, s, true);
    TestPrematureConsumedRequestBody(client, s, false);
    TestPrematureConsumedRequestBody(client, s, true);
    TestStopEarly(client, s);
    TestStopLate(client, s, false);
    TestStopLate(client, s, true);
    TestAbort(client, s, false);
    TestAbort(client, s, true);
    TestStopDiscardRequestBody(client, s, false);
    TestStopDiscardRequestBody(client, s, true);
    TestStopWhileDiscarding(client, s, false);
    TestStopWhileDiscarding(client, s, true);
    TestConsumedRequestBody(client, s);
    TestEmptyRequestBody(client, s);
    TestLateLength(client, s);
    TestImmediatePremature(client, s);
    TestStopDuringEnd(client, s, false);
    TestStopDuringEnd(client, s, true);
    TestOversizedRequestPacket(client, s, WAS_COMMAND_URI,
                               HTTP_STATUS_REQUEST_URI_TOO_LONG);
    TestOversizedRequestPacket(client, s, WAS_COMMAND_HEADER,
                               HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE);
    TestAbortNoBodyStatus(client, s);
    TestStopTooLate(client, s);

    /* invoke TestEmpty() again just to be sure the WAS connection is
       still alive */
    TestEmpty(client, s);

    was_simple_free(s);
}

static void
TestAll()
{
    TestAllOnOneConnection();

    TestMalformedMapPacket(WAS_COMMAND_HEADER);
    TestMalformedMapPacket(WAS_COMMAND_PARAMETER);

    TestInputPipeHangup(false);
    TestInputPipeHangup(true);
    TestOversizedPacketDuringBody();
    TestLengthAfterPartialRead();

    TestMultiRejectedFds(MULTI_WAS_COMMAND_NOP, 1);
    TestMultiRejectedFds(2, 1);
    TestMultiRejectedFds(0xffff, 4);
    TestMultiRejectedFds(MULTI_WAS_COMMAND_NEW, 1);
    TestMultiRejectedFds(MULTI_WAS_COMMAND_NEW, 4);
}

int
main(int, char **)
{
    TestAll();
    return EXIT_SUCCESS;
}
