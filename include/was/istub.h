// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

/*
 * libcm4all-core-xios driver for the WAS request body.
 */

#ifndef WAS_ISTUB_H
#define WAS_ISTUB_H

#include <sysx/types.h>
#include <xios/types.h>

struct was_simple;

#ifdef __cplusplus
extern "C" {
#endif

xresult
xios_was_input_create(xmemctx *mctx, struct was_simple *was,
                      xiostub **stub_r);

#ifdef __cplusplus
}
#endif

#endif
