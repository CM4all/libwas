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
 * libcm4all-core-xios driver for the WAS request body.
 */

#include <was/istub.h>
#include <was/simple.h>
#include <was/compiler.h>

#include <xios/iostub.h>
#include <sysx/result.h>

#include <assert.h>
#include <unistd.h>

struct xios_was_input {
    struct was_simple *was;

    uint64_t received;
};

static xoffs
xios_was_input_readn(xiostub *stub, was_gcc_unused xioexec *exec, void *ctxt,
                     char *buff, xoffs size)
{
    struct was_simple *w = ctxt;

    ssize_t nbytes = was_simple_read(w, buff, size);

    if (nbytes <= 0) {
        if (nbytes == 0)
            /* end of request body */
            return -1;

        xios_iostub_seterror(stub,
                             nbytes == -1
                             ? sysx_result_geterrno()
                             : SYSX_R_FAILURE);
        return -2;
    }

    return nbytes;
}

static int
xios_was_input_read(xiostub *stub, xioexec *exec, void *ctxt)
{
    uint8_t value;
    xoffs nbytes = xios_was_input_readn(stub, exec, ctxt,
                                        (char *)&value, sizeof(value));
    if (nbytes < 0)
        return (int)nbytes;

    if (nbytes != sizeof(value)) {
        xios_iostub_seterror(stub, SYSX_R_ILLEGALSTATE);
        return -2;
    }

    return (int)value;
}

static int
xios_was_input_close(xiostub *stub, was_gcc_unused xioexec *exec, void *ctxt)
{
    struct was_simple *w = ctxt;

    if (!was_simple_input_close(w)) {
        xios_iostub_seterror(stub, SYSX_R_ILLEGALSTATE);
        return -2;
    }

    return 0;
}

static const xiodriver xios_was_input_driver = {
    .in = {
        .read = xios_was_input_read,
        .readn = xios_was_input_readn,
    },
    .close = xios_was_input_close,
};

xresult
xios_was_input_create(xmemctx *mctx, struct was_simple *was,
                      xiostub **stub_r)
{
    xiodriver driver = xios_was_input_driver;

    assert(mctx != NULL);
    assert(was != NULL);
    assert(stub_r != NULL);
    assert(*stub_r == NULL);

    driver.ctxt = was;

    return xios_iostub_create(mctx, &driver, stub_r);
}
