// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

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
            was_simple_splice_all(was, true);
        } else
            was_simple_status(was, HTTP_STATUS_NO_CONTENT);
    }

    was_simple_free(was);

    return EXIT_SUCCESS;
}
