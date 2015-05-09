/*
 * libcm4all-core-xios driver for the WAS response body.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#include <was/ostub.h>
#include <was/simple.h>

#include <inline/compiler.h>

#include <xios/iostub.h>
#include <sysx/result.h>

#include <assert.h>
#include <unistd.h>

static int
xios_was_output_write_internal(xiostub *stub, gcc_unused xioexec *exec,
                               struct was_simple *w, int fd,
                               const void *buff, size_t size)
{
    ssize_t nbytes = write(fd, buff, size);
    if (nbytes < 0) {
        xios_iostub_seterror(stub, sysx_result_geterrno());
        return -2;
    }

    if (nbytes == 0) {
        xios_iostub_seterror(stub, SYSX_R_NOSPACE);
        return -2;
    }

    if (!was_simple_sent(w, nbytes)) {
        xios_iostub_seterror(stub, SYSX_R_FAILURE);
        return -2;
    }

    return nbytes;
}

static int
xios_was_output_write(xiostub *stub, gcc_unused xioexec *exec, void *ctxt,
                      int byte)
{
    struct was_simple *w = ctxt;
    int fd = was_simple_output_fd(w);
    if (fd < 0) {
        xios_iostub_seterror(stub, SYSX_R_ILLEGALSTATE);
        return -2;
    }

    const uint8_t value = byte;
    ssize_t nbytes = xios_was_output_write_internal(stub, exec, w, fd,
                                                    &value, sizeof(value));
    if (nbytes < 0)
        return nbytes;

    assert(nbytes == sizeof(value));

    return byte;
}

static int
xios_was_output_writen(xiostub *stub, gcc_unused xioexec *exec, void *ctxt,
                       const char *buff, xoffs size)
{
    struct was_simple *w = ctxt;
    int fd = was_simple_output_fd(w);
    if (fd < 0) {
        xios_iostub_seterror(stub, SYSX_R_ILLEGALSTATE);
        return -2;
    }

    while (size > 0) {
        ssize_t nbytes = xios_was_output_write_internal(stub, exec, w, fd,
                                                        buff, size);
        if (nbytes < 0)
            return nbytes;

        assert(nbytes > 0);

        buff += nbytes;
        size -= nbytes;
    }

    return 0;
}

static const xiodriver xios_was_output_driver = {
    .out = {
        .write = xios_was_output_write,
        .writen = xios_was_output_writen,
    },
};

xresult
xios_was_output_create(xmemctx *mctx, struct was_simple *was,
                       xiostub **stub_r)
{
    xiodriver driver = xios_was_output_driver;

    assert(mctx != NULL);
    assert(was != NULL);
    assert(stub_r != NULL);
    assert(*stub_r == NULL);

    driver.ctxt = was;

    return xios_iostub_create(mctx, &driver, stub_r);
}
