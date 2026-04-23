/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <openclaw_trusted_backend_ta.h>

#define TA_UUID TA_OPENCLAW_TRUSTED_BACKEND_UUID

#define TA_FLAGS 0
/* Authorize still keeps medium-sized request/response structs on the TA stack. */
#define TA_STACK_SIZE (16 * 1024)
#define TA_DATA_SIZE (32 * 1024)

#define TA_VERSION "1.0"
#define TA_DESCRIPTION "OpenClaw trusted backend OP-TEE example TA"

#endif
