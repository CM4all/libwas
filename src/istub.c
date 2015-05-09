/*
 * libcm4all-core-xios driver for the WAS request body.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#include <was/istub.h>
#include <was/simple.h>

#include <inline/compiler.h>

#include <xios/iostub.h>
#include <sysx/result.h>

#include <assert.h>
#include <unistd.h>

struct xios_was_input {
    struct was_simple *was;

    uint64_t received;
};

static xoffs
xios_was_input_readn(xiostub *stub, gcc_unused xioexec *exec, void *ctxt,
                     char *buff, xoffs size)
{
    struct was_simple *w = ctxt;
    int fd = was_simple_input_fd(w);
    if (fd < 0) {
        xios_iostub_seterror(stub, SYSX_R_ILLEGALSTATE);
        return -2;
    }

    ssize_t nbytes = read(fd, buff, size);
    if (nbytes < 0) {
        xios_iostub_seterror(stub, sysx_result_geterrno());
        return -2;
    }

    if (nbytes == 0) {
        xios_iostub_seterror(stub, SYSX_R_UNEXPECTEDEND);
        return -2;
    }

    if (!was_simple_received(w, nbytes)) {
        xios_iostub_seterror(stub, SYSX_R_FAILURE);
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

static const xiodriver xios_was_input_driver = {
    .in = {
        .read = xios_was_input_read,
        .readn = xios_was_input_readn,
    },
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
