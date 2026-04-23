// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <stddef.h>

#include "../include/openclaw_trusted_backend_keystone.h"

#ifdef __cplusplus
extern "C" {
#endif

int oc_keystone_enclave_authorize(const struct oc_ta_authorize_request *request,
				  struct oc_ta_authorize_response *response,
				  char *error_message, size_t error_message_len);

int oc_keystone_enclave_confirm(
	const struct oc_keystone_confirm_enclave_request *request,
	struct oc_ta_confirm_response *response, char *error_message,
	size_t error_message_len);

int oc_keystone_enclave_complete(const struct oc_ta_complete_request *request,
				 struct oc_ta_complete_response *response,
				 char *error_message, size_t error_message_len);

#ifdef __cplusplus
}
#endif
