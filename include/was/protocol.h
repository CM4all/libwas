// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

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

    /**
     * The client's address (canonical string representation of the IP
     * address, no port number and no square braces).
     */
    WAS_COMMAND_REMOTE_HOST = 15,

    /**
     * Request: collect metrics for this request (no payload).
     *
     * Response: provide one metric value.  Payload is a 32 bit
     * floating point counter value followed by a symbolic name (ASCII
     * letters, digits, underscore; without null-terminator).
     */
    WAS_COMMAND_METRIC = 16,
};

enum multi_was_command {
    MULTI_WAS_COMMAND_NOP = 0,

    /**
     * The container submits a new connection to the WAS process.  The
     * payload is empty, but three file descriptors are part of the
     * datagram: control, input and output of the new WAS connection.
     */
    MULTI_WAS_COMMAND_NEW = 1,
};

struct was_header {
    uint16_t length;
    uint16_t command;
};

#endif
