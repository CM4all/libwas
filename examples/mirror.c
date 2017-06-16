/*
 * A WAS application which copies the request into the response.
 *
 * author: Max Kellermann <mk@cm4all.com>
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
