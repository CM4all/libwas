/*
 * A libapreq2 module for libwas_simple.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#ifndef WAS_APREQ_H
#define WAS_APREQ_H

#include <apreq_module.h>

struct was_simple;

#ifdef __cplusplus
extern "C" {
#endif

APREQ_DECLARE(apreq_handle_t*)
apreq_handle_was(apr_pool_t *pool, struct was_simple *was, const char *uri);

#ifdef __cplusplus
}
#endif

#endif
