// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

/*
 * A simple "Hello world" WAS application.
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
        was_simple_set_header(was, "content-type", "text/plain");
        was_simple_puts(was, "Hello, world!\n");
    }

    was_simple_free(was);

    return EXIT_SUCCESS;
}
