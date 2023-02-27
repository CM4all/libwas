// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

/*
 * Synchronous server implementation of the Multi Web Application
 * Socket protocol.
 */

#ifndef WAS_MULTI_H
#define WAS_MULTI_H

#include "compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates a default #was_multi object for this process.
 */
struct was_multi *
was_multi_new(void);

/**
 * Frees the #was_multi object.
 */
void
was_multi_free(struct was_multi *m);

/**
 * Obtains the socket descriptor of the Multi-WAS connection.  It can be
 * used for poll().
 */
was_gcc_pure
int
was_multi_fd(struct was_multi *m);

/**
 * Wait for a new connection to arrive.
 *
 * @return the new WAS connection (to be freed using
 * was_simple_free()), or NULL if this process shall be terminated
 */
struct was_simple *
was_multi_accept_simple(struct was_multi *m);

#ifdef __cplusplus
}
#endif

#endif
