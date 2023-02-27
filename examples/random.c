// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

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
