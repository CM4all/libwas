/*
 * Synchronous server implementation of the Web Application Socket
 * protocol.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#ifndef WAS_SIMPLE_H
#define WAS_SIMPLE_H

#include <http/status.h>
#include <http/method.h>

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/**
 * Creates a default #was_simple object for this process.
 */
struct was_simple *
was_simple_new(void);

/**
 * Frees the #was_simple object.
 */
void
was_simple_free(struct was_simple *w);

/**
 * Wait for a request to arrive.  If an older request is pending, it
 * is cleaned up.
 *
 * @return the request URI, or NULL if this process shall be
 * terminated
 */
const char *
was_simple_accept(struct was_simple *w);

/**
 * Returns the method of the current request.
 */
http_method_t
was_simple_get_method(const struct was_simple *w);

/**
 * Returns the value of a request header.  In this library, each
 * header name can not have more than one value.
 */
const char *
was_simple_get_header(struct was_simple *w, const char *name);

/**
 * Returns the value of a WAS parameter.
 */
const char *
was_simple_get_parameter(struct was_simple *w, const char *name);

/**
 * Is a request body present?  (May be empty, though)
 */
bool
was_simple_has_body(const struct was_simple *w);

int
was_simple_input_fd(const struct was_simple *w);

bool
was_simple_received(struct was_simple *w, size_t nbytes);

/**
 * Read data from the request body.
 *
 * @return the number of bytes read, 0 if the end of the request body
 * has been reached, -1 on error
 */
ssize_t
was_simple_input_read(struct was_simple *w, void *buffer, size_t length);

void
was_simple_input_close(struct was_simple *w);

bool
was_simple_status(struct was_simple *w, http_status_t status);

bool
was_simple_set_header(struct was_simple *w,
                      const char *name, const char *value);

bool
was_simple_set_length(struct was_simple *w, uint64_t length);

int
was_simple_output_fd(struct was_simple *w);

bool
was_simple_sent(struct was_simple *w, size_t nbytes);

bool
was_simple_write(struct was_simple *w, const void *data, size_t length);

bool
was_simple_puts(struct was_simple *w, const char *s);

bool
was_simple_printf(struct was_simple *w, const char *s, ...)
__attribute__((format(printf, 2, 3)));

/**
 * Mark the end of the current request.  If no status has been set,
 * then "204 No Content" is used.  If no request body has been
 * announced, then NO_DATA is sent.
 */
bool
was_simple_end(struct was_simple *w);

#endif
