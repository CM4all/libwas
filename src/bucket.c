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
 * apr_bucket adapter for a was_simple.
 */

/* workaround for libapr compiler warning */
#define APR_NOT_DONE_YET 0

#include "bucket.h"

#include <was/simple.h>

#include <assert.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>

struct was_bucket {
    struct was_simple *was;
};

static void
wbucket_destroy(void *data)
{
    struct was_bucket *fb = data;

    was_simple_input_close(fb->was);
}

static apr_status_t
wbucket_read(apr_bucket *b, const char **data_r, apr_size_t *length_r,
             apr_read_type_e block)
{
    struct was_bucket *fb = b->data;

    if (block == APR_NONBLOCK_READ) {
        switch (was_simple_input_poll(fb->was, 0)) {
        case WAS_SIMPLE_POLL_SUCCESS:
            break;

        case WAS_SIMPLE_POLL_ERROR:
            return APR_FROM_OS_ERROR(errno);

        case WAS_SIMPLE_POLL_TIMEOUT:
            return APR_EAGAIN;

        case WAS_SIMPLE_POLL_CLOSED:
            return APR_EGENERAL;

        case WAS_SIMPLE_POLL_END:
            b = apr_bucket_immortal_make(b, "", 0);
            *data_r = b->data;
            *length_r = 0;
            return APR_SUCCESS;
        }
    }

    char *buffer = apr_bucket_alloc(APR_BUCKET_BUFF_SIZE, b->list); /* XXX: check for failure? */

    ssize_t nbytes = was_simple_read(fb->was, buffer, APR_BUCKET_BUFF_SIZE);
    if (nbytes < 0) {
        apr_status_t status = nbytes == -1
            ? APR_FROM_OS_ERROR(errno)
            : APR_EGENERAL;
        apr_bucket_free(buffer);
        return status;
    }

    if (nbytes == 0) {
        apr_bucket_free(buffer);

        b = apr_bucket_immortal_make(b, "", 0);
        *data_r = b->data;
        *length_r = 0;
        return APR_SUCCESS;
    }

    /* Change the current bucket to refer to what we read */
    b = apr_bucket_heap_make(b, buffer, nbytes, apr_bucket_free);
    apr_bucket_heap *h = b->data;
    h->alloc_len = APR_BUCKET_BUFF_SIZE; /* note the real buffer size */

    APR_BUCKET_INSERT_AFTER(b, apr_bucket_was_create(fb->was, b->list));

    *data_r = buffer;
    *length_r = nbytes;

    return APR_SUCCESS;
}

static const apr_bucket_type_t apr_bucket_type_was = {
    "WAS", 5, APR_BUCKET_DATA,
    wbucket_destroy,
    wbucket_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_copy_notimpl
};

static apr_bucket *
apr_bucket_was_make(apr_bucket *b, struct was_simple *was)
{
    struct was_bucket *fb = apr_bucket_alloc(sizeof(*fb), b->list);

    assert(b != NULL);
    assert(was != NULL);

    fb->was = was;

    b->type = &apr_bucket_type_was;
    b->length = (apr_size_t)(-1);
    b->start = -1;
    b->data = fb;

    return b;
}

apr_bucket *
apr_bucket_was_create(struct was_simple *was, apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    assert(was != NULL);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return apr_bucket_was_make(b, was);
}
