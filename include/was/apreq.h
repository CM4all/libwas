// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

/*
 * A libapreq2 module for libwas_simple.
 */

#ifndef WAS_APREQ_H
#define WAS_APREQ_H

struct apr_pool_t;
struct apreq_handle_t;
struct was_simple;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a libapreq2 handle for the current request of the given
 * #was_simple object (or return the existing one attached to the
 * pool).
 *
 * The handle must not be used after the request has been finished
 * (by was_simple_end(), was_simple_accept() or was_simple_free()).
 */
struct apreq_handle_t *
apreq_handle_was(struct apr_pool_t *pool,
                 struct was_simple *was, const char *uri);

#ifdef __cplusplus
}
#endif

#endif
