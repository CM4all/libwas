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
    WAS_COMMAND_NO_DATA,
    WAS_COMMAND_DATA,
    WAS_COMMAND_LENGTH,
    WAS_COMMAND_ABORT,
};

struct was_header {
    uint16_t length;
    uint16_t command;
};

struct was_packet_data {
    uint64_t length;
};

struct was_packet_request {
    uint32_t id;
    uint8_t method;
    uint8_t reserved[3];
};

struct was_packet_response {
    uint32_t id;
    uint16_t status;
    uint8_t reserved[2];
};

#endif
