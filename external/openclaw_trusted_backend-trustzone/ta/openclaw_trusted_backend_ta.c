// SPDX-License-Identifier: BSD-2-Clause

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <openclaw_trusted_backend_ta.h>

#define OC_POLICY_ALLOC_EXEC_CONTEXT(name)                                        \
	struct oc_policy_exec_context *name =                                      \
		TEE_Malloc(sizeof(struct oc_policy_exec_context),                  \
			   TEE_MALLOC_FILL_ZERO)
#define OC_POLICY_FREE_EXEC_CONTEXT(name) \
	do {                              \
		if (name)                 \
			TEE_Free(name);   \
	} while (0)

#include "../../openclaw_trusted_backend-common/tdx_compatible_exec_policy.h"

struct pending_confirmation_state {
	bool active;
	char confirmation_request_id[OC_TA_MAX_ID];
	char challenge_token[OC_TA_MAX_TOKEN];
	char req_id[OC_TA_MAX_ID];
	char sid[OC_TA_MAX_ID];
	char tool_name[OC_TA_MAX_TOOL_NAME];
	char action[OC_TA_MAX_ACTION];
	char object[OC_TA_MAX_OBJECT];
	char level[OC_TA_MAX_LEVEL];
	char execution_mode[OC_TA_MAX_STATUS];
	char reason[OC_TA_MAX_REASON];
	char matched_rule_id[OC_TA_MAX_RULE_ID];
};

#define MAX_PENDING_CONFIRMATIONS 8

static struct pending_confirmation_state
	g_pending_confirmations[MAX_PENDING_CONFIRMATIONS];

static void copy_text(char *dst, size_t dst_len, const char *src)
{
	if (!dst || !dst_len)
		return;
	if (!src) {
		dst[0] = '\0';
		return;
	}
	snprintf(dst, dst_len, "%s", src);
}

static void random_hex(char *dst, size_t dst_len)
{
	static const char hex[] = "0123456789abcdef";
	uint8_t raw[(OC_TA_MAX_TOKEN - 1) / 2];
	size_t byte_count = 0;
	size_t index = 0;

	if (!dst || dst_len < 3)
		return;
	byte_count = (dst_len - 1) / 2;
	if (byte_count > sizeof(raw))
		byte_count = sizeof(raw);
	TEE_GenerateRandom(raw, byte_count);
	for (index = 0; index < byte_count; index++) {
		dst[index * 2] = hex[(raw[index] >> 4) & 0xf];
		dst[index * 2 + 1] = hex[raw[index] & 0xf];
	}
	dst[byte_count * 2] = '\0';
}

static void mint_token(const char *prefix, char *dst, size_t dst_len)
{
	char hex[65];

	random_hex(hex, sizeof(hex));
	snprintf(dst, dst_len, "%s%s", prefix ? prefix : "", hex);
}

static void fill_proof_fields(struct oc_ta_authorize_response *response)
{
	copy_text(response->proof_path, sizeof(response->proof_path), "ree-proxy");
	copy_text(response->tee_call, sizeof(response->tee_call), "TEEC_InvokeCommand");
	copy_text(response->world_id, sizeof(response->world_id), "optee-secure-world");
	copy_text(response->measurement_sha256, sizeof(response->measurement_sha256),
		  OC_TA_MEASUREMENT_SHA256);
	response->nonce_bound = 1;
}

static void fill_classification_fields(struct oc_ta_authorize_response *response,
				       const char *action_level,
				       const char *action_reason,
				       const char *object_level,
				       const char *object_reason,
				       const char *effect_level,
				       const char *effect_reason)
{
	copy_text(response->action_risk_level,
		  sizeof(response->action_risk_level), action_level);
	copy_text(response->action_risk_reason,
		  sizeof(response->action_risk_reason), action_reason);
	copy_text(response->object_risk_level,
		  sizeof(response->object_risk_level), object_level);
	copy_text(response->object_risk_reason,
		  sizeof(response->object_risk_reason), object_reason);
	copy_text(response->context_risk_level,
		  sizeof(response->context_risk_level), "L0");
	copy_text(response->context_risk_reason,
		  sizeof(response->context_risk_reason), "OP-TEE REE proxy example");
	copy_text(response->effect_risk_level,
		  sizeof(response->effect_risk_level), effect_level);
	copy_text(response->effect_risk_reason,
		  sizeof(response->effect_risk_reason), effect_reason);
}

static TEE_Result read_struct_input(TEE_Param params[4], uint32_t index,
				    void *dst, size_t dst_len)
{
	if (!params[index].memref.buffer || params[index].memref.size < dst_len)
		return TEE_ERROR_BAD_PARAMETERS;
	TEE_MemFill(dst, 0, dst_len);
	TEE_MemMove(dst, params[index].memref.buffer, dst_len);
	return TEE_SUCCESS;
}

static TEE_Result write_struct_output(TEE_Param params[4], uint32_t index,
				      const void *src, size_t src_len)
{
	if (!params[index].memref.buffer || params[index].memref.size < src_len)
		return TEE_ERROR_SHORT_BUFFER;
	TEE_MemMove(params[index].memref.buffer, src, src_len);
	params[index].memref.size = src_len;
	return TEE_SUCCESS;
}

static struct pending_confirmation_state *allocate_pending_confirmation_slot(void)
{
	size_t index = 0;

	for (index = 0; index < MAX_PENDING_CONFIRMATIONS; index++) {
		if (!g_pending_confirmations[index].active)
			return &g_pending_confirmations[index];
	}

	/* Example behavior: recycle the oldest slot once the ring is full. */
	return &g_pending_confirmations[0];
}

static struct pending_confirmation_state *find_pending_confirmation_slot(
	const char *confirmation_request_id)
{
	size_t index = 0;

	for (index = 0; index < MAX_PENDING_CONFIRMATIONS; index++) {
		if (!g_pending_confirmations[index].active)
			continue;
		if (strcmp(g_pending_confirmations[index].confirmation_request_id,
			   confirmation_request_id) == 0)
			return &g_pending_confirmations[index];
	}

	return NULL;
}

static void remember_confirmation(const struct oc_ta_authorize_request *request,
				  const struct oc_ta_authorize_response *response)
{
	struct pending_confirmation_state *slot = allocate_pending_confirmation_slot();

	TEE_MemFill(slot, 0, sizeof(*slot));
	slot->active = true;
	copy_text(slot->confirmation_request_id,
		  sizeof(slot->confirmation_request_id),
		  response->confirmation_request_id);
	copy_text(slot->challenge_token,
		  sizeof(slot->challenge_token),
		  response->challenge_token);
	copy_text(slot->req_id,
		  sizeof(slot->req_id), request->req_id);
	copy_text(slot->sid,
		  sizeof(slot->sid), request->sid);
	copy_text(slot->tool_name,
		  sizeof(slot->tool_name), request->tool_name);
	copy_text(slot->action,
		  sizeof(slot->action), request->action);
	copy_text(slot->object,
		  sizeof(slot->object), request->object);
	copy_text(slot->level,
		  sizeof(slot->level), response->level);
	copy_text(slot->execution_mode,
		  sizeof(slot->execution_mode),
		  response->execution_mode);
	copy_text(slot->reason,
		  sizeof(slot->reason), response->reason);
	copy_text(slot->matched_rule_id,
		  sizeof(slot->matched_rule_id),
		  response->matched_rule_id);
}

static void fill_authorize_response(const struct oc_ta_authorize_request *request,
				    struct oc_ta_authorize_response *response)
{
	struct oc_policy_request_view policy_request;
	struct oc_policy_result policy_result;

	TEE_MemFill(response, 0, sizeof(*response));
	fill_proof_fields(response);

	policy_request.sid = request->sid;
	policy_request.action = request->action;
	policy_request.object = request->object;
	policy_request.requested_level = request->requested_level;
	policy_request.scope_raw = request->scope_raw;
	policy_request.workspace_root = request->workspace_root;
	policy_request.session_binding = request->session_binding;
	oc_tdx_policy_evaluate(&policy_request, &policy_result);

	response->allow = policy_result.allow ? 1U : 0U;
	response->requires_confirmation =
		policy_result.requires_confirmation ? 1U : 0U;
	response->nonce_bound = policy_result.nonce_bound ? 1U : 0U;
	copy_text(response->decision, sizeof(response->decision),
		  policy_result.decision);
	copy_text(response->level, sizeof(response->level), policy_result.level);
	copy_text(response->execution_mode, sizeof(response->execution_mode),
		  policy_result.execution_mode);
	copy_text(response->reason, sizeof(response->reason), policy_result.reason);
	copy_text(response->matched_rule_id,
		  sizeof(response->matched_rule_id),
		  policy_result.matched_rule_id);
	copy_text(response->action_risk_level,
		  sizeof(response->action_risk_level),
		  policy_result.action_risk_level);
	copy_text(response->action_risk_reason,
		  sizeof(response->action_risk_reason),
		  policy_result.action_risk_reason);
	copy_text(response->object_risk_level,
		  sizeof(response->object_risk_level),
		  policy_result.object_risk_level);
	copy_text(response->object_risk_reason,
		  sizeof(response->object_risk_reason),
		  policy_result.object_risk_reason);
	copy_text(response->context_risk_level,
		  sizeof(response->context_risk_level),
		  policy_result.context_risk_level);
	copy_text(response->context_risk_reason,
		  sizeof(response->context_risk_reason),
		  policy_result.context_risk_reason);
	copy_text(response->effect_risk_level,
		  sizeof(response->effect_risk_level),
		  policy_result.effect_risk_level);
	copy_text(response->effect_risk_reason,
		  sizeof(response->effect_risk_reason),
		  policy_result.effect_risk_reason);

	if (response->requires_confirmation) {
		mint_token("confirm:", response->confirmation_request_id,
			   sizeof(response->confirmation_request_id));
		mint_token("challenge:", response->challenge_token,
			   sizeof(response->challenge_token));
		remember_confirmation(request, response);
	}
}

static TEE_Result handle_healthz(uint32_t param_types, TEE_Param params[4])
{
	struct oc_ta_health_response response;
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_MemFill(&response, 0, sizeof(response));
	copy_text(response.mode, sizeof(response.mode), "optee-example");
	copy_text(response.adaptor, sizeof(response.adaptor), "optee-ree-backend");
	copy_text(response.platform, sizeof(response.platform), "trustzone");
	copy_text(response.world_id, sizeof(response.world_id), "optee-secure-world");
	copy_text(response.ta_uuid, sizeof(response.ta_uuid),
		  TA_OPENCLAW_TRUSTED_BACKEND_UUID_STRING);
	copy_text(response.measurement_sha256, sizeof(response.measurement_sha256),
		  OC_TA_MEASUREMENT_SHA256);
	return write_struct_output(params, 0, &response, sizeof(response));
}

static TEE_Result handle_guest_info(uint32_t param_types, TEE_Param params[4])
{
	struct oc_ta_guest_response response;
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_MemFill(&response, 0, sizeof(response));
	copy_text(response.adaptor, sizeof(response.adaptor), "optee-ree-backend");
	copy_text(response.platform, sizeof(response.platform), "trustzone");
	copy_text(response.guest_id, sizeof(response.guest_id),
		  "trustzone:optee-example");
	copy_text(response.service_name, sizeof(response.service_name),
		  "openclaw-trusted-backend-ta");
	copy_text(response.attestation_mode, sizeof(response.attestation_mode),
		  "optee-example");
	response.attestation_ready = 1;
	copy_text(response.world_id, sizeof(response.world_id), "optee-secure-world");
	copy_text(response.ta_uuid, sizeof(response.ta_uuid),
		  TA_OPENCLAW_TRUSTED_BACKEND_UUID_STRING);
	copy_text(response.measurement_sha256, sizeof(response.measurement_sha256),
		  OC_TA_MEASUREMENT_SHA256);
	return write_struct_output(params, 0, &response, sizeof(response));
}

static TEE_Result handle_authorize(uint32_t param_types, TEE_Param params[4])
{
	struct oc_ta_authorize_request request;
	struct oc_ta_authorize_response response;
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);
	TEE_Result result = TEE_SUCCESS;

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	result = read_struct_input(params, 0, &request, sizeof(request));
	if (result != TEE_SUCCESS)
		return result;

	fill_authorize_response(&request, &response);
	return write_struct_output(params, 1, &response, sizeof(response));
}

static TEE_Result handle_confirm(uint32_t param_types, TEE_Param params[4])
{
	struct oc_ta_confirm_request request;
	struct oc_ta_confirm_response response;
	struct pending_confirmation_state *pending = NULL;
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);
	TEE_Result result = TEE_SUCCESS;
	bool approve = false;

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	result = read_struct_input(params, 0, &request, sizeof(request));
	if (result != TEE_SUCCESS)
		return result;

	TEE_MemFill(&response, 0, sizeof(response));
	copy_text(response.confirmation_request_id,
		  sizeof(response.confirmation_request_id),
		  request.confirmation_request_id);
	copy_text(response.operator_id, sizeof(response.operator_id),
		  request.operator_id[0] ? request.operator_id : "optee-operator");

	pending = find_pending_confirmation_slot(request.confirmation_request_id);
	if (!pending) {
		copy_text(response.status, sizeof(response.status), "expired");
		copy_text(response.decision, sizeof(response.decision), "ddeny");
		copy_text(response.level, sizeof(response.level), "L3");
		copy_text(response.execution_mode, sizeof(response.execution_mode),
			  "ree-constrained");
		copy_text(response.reason, sizeof(response.reason),
			  "no matching pending confirmation");
		copy_text(response.matched_rule_id, sizeof(response.matched_rule_id),
			  "confirm.missing");
		return write_struct_output(params, 1, &response, sizeof(response));
	}

	copy_text(response.req_id, sizeof(response.req_id),
		  pending->req_id);
	copy_text(response.sid, sizeof(response.sid),
		  pending->sid);
	copy_text(response.tool_name, sizeof(response.tool_name),
		  pending->tool_name);
	copy_text(response.action, sizeof(response.action),
		  pending->action);
	copy_text(response.object, sizeof(response.object),
		  pending->object);
	copy_text(response.level, sizeof(response.level),
		  pending->level);
	copy_text(response.execution_mode, sizeof(response.execution_mode),
		  pending->execution_mode);
	copy_text(response.matched_rule_id, sizeof(response.matched_rule_id),
		  pending->matched_rule_id);

	if (strcmp(pending->challenge_token,
		   request.challenge_token) != 0) {
		copy_text(response.status, sizeof(response.status), "denied");
		copy_text(response.decision, sizeof(response.decision), "ddeny");
		copy_text(response.reason, sizeof(response.reason),
			  "confirmation challenge mismatch");
		copy_text(response.matched_rule_id, sizeof(response.matched_rule_id),
			  "confirm.challenge-mismatch");
		return write_struct_output(params, 1, &response, sizeof(response));
	}

	approve = strcmp(request.decision, "approve") == 0;
	if (!approve) {
		copy_text(response.status, sizeof(response.status), "denied");
		copy_text(response.decision, sizeof(response.decision), "ddeny");
		copy_text(response.reason, sizeof(response.reason),
			  "operator denied confirmation");
		copy_text(response.matched_rule_id, sizeof(response.matched_rule_id),
			  "confirm.operator-deny");
		pending->active = false;
		return write_struct_output(params, 1, &response, sizeof(response));
	}

	response.ok = 1;
	copy_text(response.status, sizeof(response.status), "approved");
	copy_text(response.decision, sizeof(response.decision), "dia");
	copy_text(response.reason, sizeof(response.reason),
		  pending->reason);
	mint_token("scope:", response.scope_token, sizeof(response.scope_token));
	pending->active = false;
	return write_struct_output(params, 1, &response, sizeof(response));
}

static TEE_Result handle_complete(uint32_t param_types, TEE_Param params[4])
{
	struct oc_ta_complete_request request;
	struct oc_ta_complete_response response;
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);
	TEE_Result result = TEE_SUCCESS;

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	result = read_struct_input(params, 0, &request, sizeof(request));
	if (result != TEE_SUCCESS)
		return result;

	TEE_MemFill(&response, 0, sizeof(response));
	copy_text(response.req_id, sizeof(response.req_id), request.req_id);
	copy_text(response.proof_path, sizeof(response.proof_path), "ree-proxy");
	copy_text(response.tee_call, sizeof(response.tee_call),
		  "TEEC_InvokeCommand(complete)");
	copy_text(response.world_id, sizeof(response.world_id),
		  "optee-secure-world");
	copy_text(response.measurement_sha256, sizeof(response.measurement_sha256),
		  OC_TA_MEASUREMENT_SHA256);
	return write_struct_output(params, 1, &response, sizeof(response));
}

TEE_Result TA_CreateEntryPoint(void)
{
	IMSG("OpenClaw trusted backend example TA created");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	IMSG("OpenClaw trusted backend example TA destroyed");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("OpenClaw trusted backend example session opened");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
	IMSG("OpenClaw trusted backend example session closed");
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_OPENCLAW_TRUSTED_BACKEND_CMD_HEALTHZ:
		return handle_healthz(param_types, params);
	case TA_OPENCLAW_TRUSTED_BACKEND_CMD_GUEST_INFO:
		return handle_guest_info(param_types, params);
	case TA_OPENCLAW_TRUSTED_BACKEND_CMD_AUTHORIZE:
		return handle_authorize(param_types, params);
	case TA_OPENCLAW_TRUSTED_BACKEND_CMD_CONFIRM:
		return handle_confirm(param_types, params);
	case TA_OPENCLAW_TRUSTED_BACKEND_CMD_COMPLETE:
		return handle_complete(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
