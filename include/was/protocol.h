/*
 * Definitions for the Web Application Socket protocol.
 *
 * author: Max Kellermann <mk@cm4all.com>
 */

#ifndef WAS_PROTOCOL_H
#define WAS_PROTOCOL_H

#include <stdint.h>

enum was_command {
    WAS_COMMAND_NOP = 0,
    WAS_COMMAND_REQUEST,
    WAS_COMMAND_METHOD,
    WAS_COMMAND_URI,
    WAS_COMMAND_SCRIPT_NAME,
    WAS_COMMAND_PATH_INFO,
    WAS_COMMAND_QUERY_STRING,
    WAS_COMMAND_HEADER,
    WAS_COMMAND_PARAMETER,
    WAS_COMMAND_STATUS,

    /**
     * The sender announces that it will not send any body data on the
     * pipe.  This packet finishes request/response metadata.
     *
     * Payload: empty.
     */
    WAS_COMMAND_NO_DATA,

    /**
     * The sender announces that it will send body data on the pipe.
     * May be followed by #WAS_COMMAND_LENGTH.
     *
     * The recipient may reply with #WAS_COMMAND_STOP.
     *
     * Payload: empty.
     */
    WAS_COMMAND_DATA,

    /**
     * Follows #WAS_COMMAND_DATA.  This is sent as soon as the sender
     * knows the total length.  It may be sent after the final byte
     * has already been written to the pipe, to mark the end of the
     * response.
     *
     * Payload: a 64 bit integer specifying the total body length.
     */
    WAS_COMMAND_LENGTH,

    /**
     * The recipient is asked to stop sending data on the pipe.  The
     * recipient will reply with a #WAS_COMMAND_PREMATURE.
     */
    WAS_COMMAND_STOP,

    /**
     * Reply to #WAS_COMMAND_STOP or generated when an error has
     * occurred.  The sender confirms that it has stopped sending body
     * data prematurely.
     *
     * Payload: a 64 bit integer specifying the total number of bytes
     * that has been written to the pipe.  The recipient may use this
     * number to recover, to empty the pipe.
     */
    WAS_COMMAND_PREMATURE,
};

struct was_header {
    uint16_t length;
    uint16_t command;
};

#endif
