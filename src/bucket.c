/*
 * apr_bucket adapter for a was_simple.
 *
 * author: Max Kellermann <mk@cm4all.com>
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

    int fd = was_simple_input_fd(fb->was);
    if (fd < 0)
        return APR_EGENERAL;

    char *buffer;
    int nbytes;
    apr_bucket_heap *h;

    if (block == APR_NONBLOCK_READ) {
        struct pollfd pfd = {
            .fd = fd,
            .events = POLLIN,
        };

        int ret = poll(&pfd, 1, 0);
        if (ret < 0)
            return APR_EGENERAL;

        if (ret == 0)
            return APR_EAGAIN;
    }

    buffer = apr_bucket_alloc(*length_r, b->list); /* XXX: check for failure? */

    nbytes = read(fd, buffer, APR_BUCKET_BUFF_SIZE);
    if (nbytes < 0) {
        apr_bucket_free(buffer);
        return APR_EGENERAL; /* XXX which status code? */
    }

    if (nbytes == 0) {
        apr_bucket_free(buffer);

        b = apr_bucket_immortal_make(b, "", 0);
        *data_r = b->data;
        *length_r = 0;
        return APR_SUCCESS;
    }

    if (!was_simple_received(fb->was, nbytes))
        return APR_EGENERAL;

    /* Change the current bucket to refer to what we read */
    b = apr_bucket_heap_make(b, buffer, nbytes, apr_bucket_free);
    h = b->data;
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
