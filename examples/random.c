/*
 * Copyright 2010-2021 CM4all GmbH
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

/*
 * A WAS application which emits random binary data.
 */

#include <was/simple.h>

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int
main(int argc, const char *const*argv)
{
    (void)argc;
    (void)argv;

    const int urandom_fd = open("/dev/urandom", O_RDONLY|O_NOCTTY|O_CLOEXEC);
    if (urandom_fd < 0) {
        perror("Failed to open /dev/urandom");
        return EXIT_FAILURE;
    }

    struct was_simple *was = was_simple_new();

    while (was_simple_accept(was) != NULL) {
        was_simple_set_header(was, "content-type", "application/octet-stream");

        const int output_fd = was_simple_output_fd(was);

        while (true) {
            ssize_t nbytes = splice(urandom_fd, NULL, output_fd, NULL,
                                    1 << 30,
                                    SPLICE_F_MOVE|SPLICE_F_NONBLOCK|SPLICE_F_MORE);
            if (nbytes > 0) {
                if (!was_simple_sent(was, nbytes))
                    break;
            } else if (nbytes < 0) {
                if (errno != EAGAIN ||
                    was_simple_output_poll(was, -1) != WAS_SIMPLE_POLL_SUCCESS)
                    break;
            }
        }
    }

    was_simple_free(was);
    close(urandom_fd);

    return EXIT_SUCCESS;
}
