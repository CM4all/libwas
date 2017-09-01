/*
 * Copyright 2010-2017 Content Management AG
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
 * A WAS application which copies the request into the response.
 */

#include <was/simple.h>

#include <stdlib.h>

int
main(int argc, const char *const*argv)
{
    (void)argc;
    (void)argv;

    struct was_simple *was = was_simple_new();

    while (was_simple_accept(was) != NULL) {
        if (was_simple_has_body(was)) {
            was_simple_copy_all_headers(was);

            int64_t remaining = was_simple_input_remaining(was);
            if (remaining >= 0)
                was_simple_set_length(was, remaining);

            while (true) {
                // TODO: use splice()
                char buffer[8192];
                ssize_t nbytes = was_simple_read(was, buffer, sizeof(buffer));
                if (nbytes <= 0)
                    break;

                if (!was_simple_write(was, buffer, nbytes))
                    break;
            }
        } else
            was_simple_status(was, HTTP_STATUS_NO_CONTENT);
    }

    was_simple_free(was);

    return EXIT_SUCCESS;
}
