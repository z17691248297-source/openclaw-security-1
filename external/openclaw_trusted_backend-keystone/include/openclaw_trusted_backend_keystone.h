/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef OPENCLAW_TRUSTED_BACKEND_KEYSTONE_H
#define OPENCLAW_TRUSTED_BACKEND_KEYSTONE_H

#include <stdint.h>

#define OC_TA_MAX_ID 64
#define OC_TA_MAX_TOOL_NAME 32
#define OC_TA_MAX_ACTION 24
#define OC_TA_MAX_OBJECT 256
#define OC_TA_MAX_LEVEL 8
#define OC_TA_MAX_REASON 128
#define OC_TA_MAX_RULE_ID 64
#define OC_TA_MAX_TOKEN 96
#define OC_TA_MAX_STATUS 24
#define OC_TA_MAX_WORLD_ID 64
#define OC_TA_MAX_DIGEST 80
#define OC_TA_MAX_UUID 48
#define OC_TA_MAX_SERVICE_NAME 64
#define OC_TA_MAX_MODE 32
#define OC_TA_MAX_PATH 48
#define OC_TA_MAX_TEE_CALL 48
#define OC_TA_MAX_SCOPE_JSON 4096
#define OC_TA_MAX_ATTEST_NONCE 128

#define OC_TA_MEASUREMENT_SHA256 \
	"sha256:1d6413a1d4a2947307b598c5308825cd3e84a54d65fd87b91f0b6d2196eb7d4f"

struct oc_ta_authorize_request {
	char req_id[OC_TA_MAX_ID];
	char sid[OC_TA_MAX_ID];
	char tool_name[OC_TA_MAX_TOOL_NAME];
	char action[OC_TA_MAX_ACTION];
	char object[OC_TA_MAX_OBJECT];
	char requested_level[OC_TA_MAX_LEVEL];
	char normalized_scope_digest[OC_TA_MAX_DIGEST];
	char scope_raw[OC_TA_MAX_SCOPE_JSON];
	char workspace_root[OC_TA_MAX_OBJECT];
	char session_binding[OC_TA_MAX_ID];
	uint32_t seq;
	uint32_t ttl_ms;
};

struct oc_ta_authorize_response {
	uint32_t allow;
	uint32_t requires_confirmation;
	uint32_t nonce_bound;
	char decision[OC_TA_MAX_ACTION];
	char level[OC_TA_MAX_LEVEL];
	char execution_mode[OC_TA_MAX_STATUS];
	char reason[OC_TA_MAX_REASON];
	char matched_rule_id[OC_TA_MAX_RULE_ID];
	char scope_token[OC_TA_MAX_TOKEN];
	char confirmation_request_id[OC_TA_MAX_ID];
	char challenge_token[OC_TA_MAX_TOKEN];
	char proof_path[OC_TA_MAX_PATH];
	char tee_call[OC_TA_MAX_TEE_CALL];
	char world_id[OC_TA_MAX_WORLD_ID];
	char measurement_sha256[OC_TA_MAX_DIGEST];
	char action_risk_level[OC_TA_MAX_LEVEL];
	char action_risk_reason[OC_TA_MAX_REASON];
	char object_risk_level[OC_TA_MAX_LEVEL];
	char object_risk_reason[OC_TA_MAX_REASON];
	char context_risk_level[OC_TA_MAX_LEVEL];
	char context_risk_reason[OC_TA_MAX_REASON];
	char effect_risk_level[OC_TA_MAX_LEVEL];
	char effect_risk_reason[OC_TA_MAX_REASON];
};

struct oc_ta_confirm_request {
	char confirmation_request_id[OC_TA_MAX_ID];
	char challenge_token[OC_TA_MAX_TOKEN];
	char operator_id[OC_TA_MAX_ID];
	char decision[OC_TA_MAX_ACTION];
};

struct oc_ta_confirm_response {
	uint32_t ok;
	char confirmation_request_id[OC_TA_MAX_ID];
	char status[OC_TA_MAX_STATUS];
	char decision[OC_TA_MAX_ACTION];
	char level[OC_TA_MAX_LEVEL];
	char execution_mode[OC_TA_MAX_STATUS];
	char reason[OC_TA_MAX_REASON];
	char matched_rule_id[OC_TA_MAX_RULE_ID];
	char req_id[OC_TA_MAX_ID];
	char sid[OC_TA_MAX_ID];
	char tool_name[OC_TA_MAX_TOOL_NAME];
	char action[OC_TA_MAX_ACTION];
	char object[OC_TA_MAX_OBJECT];
	char operator_id[OC_TA_MAX_ID];
	char scope_token[OC_TA_MAX_TOKEN];
};

struct oc_ta_complete_request {
	char req_id[OC_TA_MAX_ID];
	char sid[OC_TA_MAX_ID];
	char tool_name[OC_TA_MAX_TOOL_NAME];
	char action[OC_TA_MAX_ACTION];
	char object[OC_TA_MAX_OBJECT];
	char status[OC_TA_MAX_STATUS];
	char result_digest[OC_TA_MAX_DIGEST];
};

struct oc_ta_complete_response {
	char req_id[OC_TA_MAX_ID];
	char proof_path[OC_TA_MAX_PATH];
	char tee_call[OC_TA_MAX_TEE_CALL];
	char world_id[OC_TA_MAX_WORLD_ID];
	char measurement_sha256[OC_TA_MAX_DIGEST];
};

enum oc_keystone_enclave_command {
	OC_KEYSTONE_CMD_PROBE = 1,
	OC_KEYSTONE_CMD_AUTHORIZE = 2,
	OC_KEYSTONE_CMD_CONFIRM = 3,
	OC_KEYSTONE_CMD_COMPLETE = 4,
};

struct oc_keystone_confirm_enclave_request {
	struct oc_ta_confirm_request confirm;
	struct oc_ta_authorize_request pending_authorize;
};

struct oc_keystone_enclave_request {
	uint32_t command;
	char attestation_nonce[OC_TA_MAX_ATTEST_NONCE];
	union {
		struct oc_ta_authorize_request authorize;
		struct oc_keystone_confirm_enclave_request confirm;
		struct oc_ta_complete_request complete;
	} payload;
};

struct oc_keystone_enclave_response {
	uint32_t ok;
	uint32_t command;
	union {
		struct oc_ta_authorize_response authorize;
		struct oc_ta_confirm_response confirm;
		struct oc_ta_complete_response complete;
	} payload;
};

struct oc_ta_health_response {
	char mode[OC_TA_MAX_MODE];
	char adaptor[OC_TA_MAX_STATUS];
	char platform[OC_TA_MAX_ACTION];
	char world_id[OC_TA_MAX_WORLD_ID];
	char ta_uuid[OC_TA_MAX_UUID];
	char measurement_sha256[OC_TA_MAX_DIGEST];
};

struct oc_ta_guest_response {
	char adaptor[OC_TA_MAX_STATUS];
	char platform[OC_TA_MAX_ACTION];
	char guest_id[OC_TA_MAX_ID];
	char service_name[OC_TA_MAX_SERVICE_NAME];
	char attestation_mode[OC_TA_MAX_MODE];
	uint32_t attestation_ready;
	char world_id[OC_TA_MAX_WORLD_ID];
	char ta_uuid[OC_TA_MAX_UUID];
	char measurement_sha256[OC_TA_MAX_DIGEST];
};

#endif
