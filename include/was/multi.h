/*
 * Copyright 2010-2021 CM4all GmbH
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
