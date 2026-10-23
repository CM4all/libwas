// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

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

static apr_status_t
wbucket_read(apr_bucket *b, const char **data_r, apr_size_t *length_r,
             apr_read_type_e block)
{
    struct was_simple *was = b->data;

    if (block == APR_NONBLOCK_READ) {
        switch (was_simple_input_poll(was, 0)) {
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

    /* in blocking mode, fill the whole buffer to avoid wasting
       memory on many small heap buckets */
    ssize_t nbytes = block == APR_BLOCK_READ
        ? was_simple_read_most(was, buffer, APR_BUCKET_BUFF_SIZE)
        : was_simple_read(was, buffer, APR_BUCKET_BUFF_SIZE);
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

    APR_BUCKET_INSERT_AFTER(b, apr_bucket_was_create(was, b->list));

    *data_r = buffer;
    *length_r = nbytes;

    return APR_SUCCESS;
}

static const apr_bucket_type_t apr_bucket_type_was = {
    "WAS", 5, APR_BUCKET_DATA,
    apr_bucket_destroy_noop,
    wbucket_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_copy_notimpl
};

static apr_bucket *
apr_bucket_was_make(apr_bucket *b, struct was_simple *was)
{
    assert(b != NULL);
    assert(was != NULL);

    b->type = &apr_bucket_type_was;
    b->length = (apr_size_t)(-1);
    b->start = -1;
    b->data = was;

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
