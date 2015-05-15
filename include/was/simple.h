/*
 * Synchronous server implementation of the Web Application Socket
 * protocol.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#ifndef WAS_SIMPLE_H
#define WAS_SIMPLE_H

#include <inline/compiler.h>
#include <http/status.h>
#include <http/method.h>

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

enum was_simple_poll_result {
    /**
     * The pipe is ready for I/O.
     */
    WAS_SIMPLE_POLL_SUCCESS,

    /**
     * An error has occurred, and this request shall be aborted.
     */
    WAS_SIMPLE_POLL_ERROR,

    /**
     * The timeout has expired before the pipe has become ready.
     */
    WAS_SIMPLE_POLL_TIMEOUT,

    /**
     * At the end of the entity.  The caller must not attempt to do
     * further I/O on the pipe.
     */
    WAS_SIMPLE_POLL_END,

    /**
     * The entity has been closed, but the application may continue to
     * handle the request.
     */
    WAS_SIMPLE_POLL_CLOSED,
};

struct was_simple_pair {
    const char *name, *value;
};

struct was_simple_iterator;

#ifdef __cplusplus
extern "C" {
#endif

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
gcc_pure
http_method_t
was_simple_get_method(const struct was_simple *w);

/**
 * Returns the SCRIPT_NAME attribute.
 */
gcc_pure
const char *
was_simple_get_script_name(const struct was_simple *w);

/**
 * Returns the PATH_INFO attribute.
 */
gcc_pure
const char *
was_simple_get_path_info(const struct was_simple *w);

/**
 * Returns the query string.
 */
gcc_pure
const char *
was_simple_get_query_string(const struct was_simple *w);

/**
 * Returns the value of a request header.
 *
 * If there are multiple headers with that name, any one of those is
 * returned.  To get all values, call
 * was_simple_get_multi_header() instead.
 */
gcc_pure
const char *
was_simple_get_header(struct was_simple *w, const char *name);

/**
 * Returns an object that can iterate all request headers with the
 * given name.  It must be freed with was_simple_iterator_free().
 *
 * If you need only one value, call was_simple_get_header() instead.
 */
struct was_simple_iterator *
was_simple_get_multi_header(struct was_simple *w, const char *name);

/**
 * Returns an object that can iterate all request headers.  It must be
 * freed with was_simple_iterator_free().
 */
struct was_simple_iterator *
was_simple_get_header_iterator(struct was_simple *w);

/**
 * Returns the value of a WAS parameter.
 */
gcc_pure
const char *
was_simple_get_parameter(struct was_simple *w, const char *name);

/**
 * Returns an object that can iterate all request parameters.  It must
 * be freed with was_simple_iterator_free().
 */
struct was_simple_iterator *
was_simple_get_parameter_iterator(struct was_simple *w);

/**
 * Is a request body present?  (May be empty, though)
 */
gcc_pure
bool
was_simple_has_body(const struct was_simple *w);

/**
 * Wait for request body data.  Handles pending control channel
 * commands before returning.
 *
 * @param timeout_ms the timeout in milliseconds; 0 means do not block
 * at all; -1 means wait forever
 */
enum was_simple_poll_result
was_simple_input_poll(struct was_simple *w, int timeout_ms);

/**
 * Obtains the file descriptor for reading the request body.  It is in
 * non-blocking mode.  If an operation returns EAGAIN,
 * was_simple_input_poll() can be called to wait for more data.
 *
 * After something has been read successfully, call
 * was_simple_received().
 */
gcc_pure
int
was_simple_input_fd(const struct was_simple *w);

/**
 * The caller announces that he has read something from the input file
 * descriptor given by was_simple_input_fd().
 *
 * This function must not be called after was_simple_read().
 */
bool
was_simple_received(struct was_simple *w, size_t nbytes);

/**
 * Read data from the request body.
 *
 * @return the number of bytes read, 0 if the end of the request body
 * has been reached, -1 on I/O error (with errno set), -2 on other
 * error
 */
ssize_t
was_simple_read(struct was_simple *w, void *buffer, size_t length);

/**
 * The caller announces that he is not interested in any more data
 * from the request body.  The function will tell the web server to
 * stop sending any more, and will discard all data that is still
 * pending.  This needs to be called only if more data is available.
 */
bool
was_simple_input_close(struct was_simple *w);

/**
 * Set the response status code.  This must be called before sending
 * headers and response body (or not at all, which results in "200 OK"
 * or "204 No Content").
 */
bool
was_simple_status(struct was_simple *w, http_status_t status);

/**
 * Set a response header.
 *
 * This function must not be used to set hop-by-hop headers (RFC 2616
 * 13.5.1) or "Content-Length".  To set the "Content-Length" header,
 * call was_simple_set_length() instead.
 */
bool
was_simple_set_header(struct was_simple *w,
                      const char *name, const char *value);

/**
 * Copies all request headers to the response.
 */
bool
was_simple_copy_all_headers(struct was_simple *w);

/**
 * Declare the response body length (in bytes).  Calling this function
 * is optional, but calling it as early as possible may help the web
 * server reduce overhead.
 */
bool
was_simple_set_length(struct was_simple *w, uint64_t length);

/**
 * Wait for the response body pipe to become writable.  Handles
 * pending control channel commands before returning.
 *
 * @param timeout_ms the timeout in milliseconds; 0 means do not block
 * at all; -1 means wait forever
 */
enum was_simple_poll_result
was_simple_output_poll(struct was_simple *w, int timeout_ms);

/**
 * Obtains the file descriptor for reading the request body.  It is in
 * non-blocking mode.
 *
 * After something has been written successfully, call
 * was_simple_sent().
 */
gcc_pure
int
was_simple_output_fd(struct was_simple *w);

/**
 * The caller announces that he has written something from the output
 * file descriptor given by was_simple_output_fd().
 *
 * This function must not be called after was_simple_write() or its
 * siblings.
 */
bool
was_simple_sent(struct was_simple *w, size_t nbytes);

bool
was_simple_write(struct was_simple *w, const void *data, size_t length);

bool
was_simple_puts(struct was_simple *w, const char *s);

gcc_printf(2, 3)
bool
was_simple_printf(struct was_simple *w, const char *s, ...);

/**
 * Mark the end of the current request.  If no status has been set,
 * then "204 No Content" is used.  If no request body has been
 * announced, then NO_DATA is sent.
 */
bool
was_simple_end(struct was_simple *w);

void
was_simple_iterator_free(struct was_simple_iterator *i);

const struct was_simple_pair *
was_simple_iterator_next(struct was_simple_iterator *i);

#ifdef __cplusplus
}
#endif

#endif
