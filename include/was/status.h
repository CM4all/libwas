// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <assert.h>

typedef enum {
	HTTP_STATUS_CONTINUE = 100,
	HTTP_STATUS_SWITCHING_PROTOCOLS = 101,

	// added in RFC 2518, removed in RFC 4918 (WebDAV)
	HTTP_STATUS_PROCESSING = 102,

	// RFC 8297, HTTP/2 only
	HTTP_STATUS_EARLY_HINTS = 103,

	HTTP_STATUS_OK = 200,
	HTTP_STATUS_CREATED = 201,
	HTTP_STATUS_ACCEPTED = 202,
	HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION = 203,
	HTTP_STATUS_NO_CONTENT = 204,
	HTTP_STATUS_RESET_CONTENT = 205,
	HTTP_STATUS_PARTIAL_CONTENT = 206,

	/**
	 * @see RFC 4918 (WebDAV)
	 */
	HTTP_STATUS_MULTI_STATUS = 207,

	/**
	 * @see RFC 5842 (Binding Extensiosn to WebDAV)
	 */
	HTTP_STATUS_ALREADY_REPORTED = 208,

	/**
	 * @see RFC 3229 (Delta Encoding in HTTP)
	 */
	HTTP_STATUS_IM_USED = 226,

	HTTP_STATUS_MULTIPLE_CHOICES = 300,
	HTTP_STATUS_MOVED_PERMANENTLY = 301,
	HTTP_STATUS_FOUND = 302,
	HTTP_STATUS_SEE_OTHER = 303,
	HTTP_STATUS_NOT_MODIFIED = 304,
	HTTP_STATUS_USE_PROXY = 305, // deprecated in RFC 7231
	HTTP_STATUS_TEMPORARY_REDIRECT = 307,
	HTTP_STATUS_PERMANENT_REDIRECT = 308, // RFC 9110 (HTTP Semantics)
	HTTP_STATUS_BAD_REQUEST = 400,
	HTTP_STATUS_UNAUTHORIZED = 401,
	HTTP_STATUS_PAYMENT_REQUIRED = 402,
	HTTP_STATUS_FORBIDDEN = 403,
	HTTP_STATUS_NOT_FOUND = 404,
	HTTP_STATUS_METHOD_NOT_ALLOWED = 405,
	HTTP_STATUS_NOT_ACCEPTABLE = 406,
	HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407,
	HTTP_STATUS_REQUEST_TIMEOUT = 408,
	HTTP_STATUS_CONFLICT = 409,
	HTTP_STATUS_GONE = 410,
	HTTP_STATUS_LENGTH_REQUIRED = 411,
	HTTP_STATUS_PRECONDITION_FAILED = 412,
	HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE = 413,
	HTTP_STATUS_REQUEST_URI_TOO_LONG = 414,
	HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,
	HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
	HTTP_STATUS_EXPECTATION_FAILED = 417,

	/**
	 * @see RFC 2324
	 */
	HTTP_STATUS_I_M_A_TEAPOT = 418,

	/**
	 * @see RFC 9110 (HTTP Semantics)
	 */
	HTTP_STATUS_MISDIRECTED_REQUEST = 421,

	/**
	 * @see RFC 4918 (WebDAV)
	 */
	HTTP_STATUS_UNPROCESSABLE_ENTITY = 422,

	/**
	 * @see RFC 4918 (WebDAV)
	 */
	HTTP_STATUS_LOCKED = 423,

	/**
	 * @see RFC 4918 (WebDAV)
	 */
	HTTP_STATUS_FAILED_DEPENDENCY = 424,

	/**
	 * @see RFC 8470 (Using Early Data in HTTP)
	 */
	HTTP_STATUS_TOO_EARLY = 425,

	/**
	 * @see RFC 7231 (HTTP 1.1)
	 */
	HTTP_STATUS_UPGRADE_REQUIRED = 426,

	/**
	 * @see RFC 6585 (Additional HTTP Status Codes)
	 */
	HTTP_STATUS_PRECONDITION_REQUIRED = 428,

	/**
	 * @see RFC 6585 (Additional HTTP Status Codes)
	 */
	HTTP_STATUS_TOO_MANY_REQUESTS = 429,

	/**
	 * @see RFC 6585 (Additional HTTP Status Codes)
	 */
	HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,

	/**
	 * @see https://datatracker.ietf.org/doc/draft-ietf-httpbis-legally-restricted-status/
	 */
	HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS = 451,

	HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
	HTTP_STATUS_NOT_IMPLEMENTED = 501,
	HTTP_STATUS_BAD_GATEWAY = 502,
	HTTP_STATUS_SERVICE_UNAVAILABLE = 503,
	HTTP_STATUS_GATEWAY_TIMEOUT = 504,
	HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505,

	/**
	 * @see RFC 2295 (Transparent Content Negotiation in HTTP)
	 */
	HTTP_STATUS_VARIANT_ALSO_NEGOTIATES = 506,

	/**
	 * @see RFC 4918 (WebDAV)
	 */
	HTTP_STATUS_INSUFFICIENT_STORAGE = 507,

	/**
	 * @see RFC 5842 (Binding Extensions to WebDAV)
	 */
	HTTP_STATUS_LOOP_DETECTED = 508,

	/**
	 * @see RFC 2774 (An HTTP Extension Framework)
	 */
	HTTP_STATUS_NOT_EXTENDED = 510,

	/**
	 * @see RFC 6585 (Additional HTTP Status Codes)
	 */
	HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED = 511,
} http_status_t;

extern const char *http_status_to_string_data_6_60[6][60];

static inline bool
http_status_is_success(http_status_t _status)
{
	const unsigned status = (unsigned)_status;
	return status >= 200 && status < 300;
}

static inline bool
http_status_is_redirect(http_status_t _status)
{
	const unsigned status = (unsigned)_status;
	return status >= 300 && status < 400;
}

static inline bool
http_status_is_client_error(http_status_t _status)
{
	const unsigned status = (unsigned)_status;
	return status >= 400 && status < 500;
}

static inline bool
http_status_is_server_error(http_status_t _status)
{
	const unsigned status = (unsigned)_status;
	return status >= 500 && status < 600;
}

static inline bool
http_status_is_error(http_status_t _status)
{
	const unsigned status = (unsigned)_status;
	return status >= 400 && status < 600;
}

static inline bool
http_status_is_empty(http_status_t status)
{
	return status == HTTP_STATUS_CONTINUE ||
               status == HTTP_STATUS_NO_CONTENT ||
               status == HTTP_STATUS_RESET_CONTENT ||
               status == HTTP_STATUS_NOT_MODIFIED;
}
