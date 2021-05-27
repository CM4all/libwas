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
 * Definitions for the Web Application Socket protocol.
 */

#ifndef WAS_PROTOCOL_H
#define WAS_PROTOCOL_H

#include <stdint.h>

enum was_command {
    WAS_COMMAND_NOP = 0,
    WAS_COMMAND_REQUEST = 1,
    WAS_COMMAND_METHOD = 2,
    WAS_COMMAND_URI = 3,
    WAS_COMMAND_SCRIPT_NAME = 4,
    WAS_COMMAND_PATH_INFO = 5,
    WAS_COMMAND_QUERY_STRING = 6,
    WAS_COMMAND_HEADER = 7,
    WAS_COMMAND_PARAMETER = 8,
    WAS_COMMAND_STATUS = 9,

    /**
     * The sender announces that it will not send any body data on the
     * pipe.  This packet finishes request/response metadata.
     *
     * Payload: empty.
     */
    WAS_COMMAND_NO_DATA = 10,

    /**
     * The sender announces that it will send body data on the pipe.
     * May be followed by #WAS_COMMAND_LENGTH.
     *
     * The recipient may reply with #WAS_COMMAND_STOP.
     *
     * Payload: empty.
     */
    WAS_COMMAND_DATA = 11,

    /**
     * Follows #WAS_COMMAND_DATA.  This is sent as soon as the sender
     * knows the total length.  It may be sent after the final byte
     * has already been written to the pipe, to mark the end of the
     * response.
     *
     * Payload: a 64 bit integer specifying the total body length.
     */
    WAS_COMMAND_LENGTH = 12,

    /**
     * The recipient is asked to stop sending data on the pipe.  The
     * recipient will reply with a #WAS_COMMAND_PREMATURE.
     */
    WAS_COMMAND_STOP = 13,

    /**
     * Reply to #WAS_COMMAND_STOP or generated when an error has
     * occurred.  The sender confirms that it has stopped sending body
     * data prematurely.
     *
     * Payload: a 64 bit integer specifying the total number of bytes
     * that has been written to the pipe.  The recipient may use this
     * number to recover, to empty the pipe.
     */
    WAS_COMMAND_PREMATURE = 14,
};

struct was_header {
    uint16_t length;
    uint16_t command;
};

#endif
