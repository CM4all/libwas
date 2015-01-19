/*
 * libcm4all-core-xios driver for the WAS response body.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#ifndef WAS_OSTUB_H
#define WAS_OSTUB_H

#include <sysx/memory.h>
#include <xios/iostub.h>

struct was_simple;

#ifdef __cplusplus
extern "C" {
#endif

xresult
xios_was_output_create(xmemctx *mctx, struct was_simple *was,
                       xiostub **stub_r);

#ifdef __cplusplus
}
#endif

#endif
