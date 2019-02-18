/*
 * Copyright 2010-2019 Content Management AG
 * All rights reserved.
 *
 * author: Max Kellermann <mk@cm4all.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * FOUNDATION OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <was/simple.h>
#include <was/protocol.h>

#include <algorithm>

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
TestPrematureDiscardedRequestBody(FakeWasClient &client, struct was_simple *s)
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

    was_simple_end(s);

    client.ExpectControl(WAS_COMMAND_STOP); // TODO: remove
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

static void
TestAll()
{
    FakeWasClient client;

    auto *s = was_simple_new();

    TestEmpty(client, s);
    TestSimple(client, s);
    TestDiscardedRequestBody(client, s);
    TestPrematureDiscardedRequestBody(client, s);
    TestPrematureConsumedRequestBody(client, s, false);
    TestPrematureConsumedRequestBody(client, s, true);
    TestStopEarly(client, s);
    TestStopLate(client, s, false);
    TestStopLate(client, s, true);
    TestAbort(client, s, false);
    TestAbort(client, s, true);
    TestStopTooLate(client, s);

    /* invoke TestEmpty() again just to be sure the WAS connection is
       still alive */
    TestEmpty(client, s);

    was_simple_free(s);
}

int
main(int, char **)
{
    TestAll();
    return EXIT_SUCCESS;
}
