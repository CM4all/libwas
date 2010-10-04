/*
 * apr_bucket adapter for a was_simple.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#ifndef WAS_BUCKET_H
#define WAS_BUCKET_H

#include <apr_buckets.h>

struct was_simple;

apr_bucket *
apr_bucket_was_create(struct was_simple *was, apr_bucket_alloc_t *list);

#endif
