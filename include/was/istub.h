/*
 * libcm4all-core-xios driver for the WAS request body.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#ifndef WAS_ISTUB_H
#define WAS_ISTUB_H

#include <sysx/memory.h>
#include <xios/iostub.h>

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
