//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "app/eapp_utils.h"
#include "app/syscall.h"
#include "edge/edge_common.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../include/openclaw_trusted_backend_keystone.h"
#include "../../openclaw_trusted_backend-common/tdx_compatible_exec_policy.h"

#define OCALL_COPY_REPORT 3
#define OCALL_GET_REQUEST 4
#define OCALL_COPY_RESPONSE 5

#define KEYSTONE_PROOF_PATH "openclaw -> ree proxy -> enclave call"
#define KEYSTONE_AUTHORIZE_TEE_CALL "keystone enclave authorize"
#define KEYSTONE_CONFIRM_TEE_CALL "keystone enclave confirm"
#define KEYSTONE_COMPLETE_TEE_CALL "keystone enclave complete"
#define KEYSTONE_WORLD_ID "keystone-enclave"

static void copy_text(char *dst, size_t dst_len, const char *src)
{
	size_t index = 0;

	if (!dst || !dst_len)
		return;
	if (!src) {
		dst[0] = '\0';
		return;
	}

	while (src[index] && index + 1 < dst_len) {
		dst[index] = src[index];
		index++;
	}
	dst[index] = '\0';
}

static void zero_bytes(void *ptr, size_t len)
{
	size_t index = 0;
	unsigned char *cursor = (unsigned char *)ptr;

	if (!cursor)
		return;
	for (index = 0; index < len; index++)
		cursor[index] = 0;
}

static size_t text_length(const char *text)
{
	size_t len = 0;

	while (text && text[len])
		len++;
	return len;
}

static bool text_equal(const char *left, const char *right)
{
	size_t index = 0;

	if (!left || !right)
		return false;
	while (left[index] && right[index]) {
		if (left[index] != right[index])
			return false;
		index++;
	}
	return left[index] == '\0' && right[index] == '\0';
}

static int ascii_tolower(int ch)
{
	if (ch >= 'A' && ch <= 'Z')
		return ch - 'A' + 'a';
	return ch;
}

static bool equals_ci(const char *left, const char *right)
{
	while (left && right && *left && *right) {
		if (ascii_tolower(*left) != ascii_tolower(*right))
			return false;
		left++;
		right++;
	}

	return left && right && *left == '\0' && *right == '\0';
}

static unsigned long hash_text(const char *text)
{
	unsigned long hash = 5381;
	const unsigned char *cursor =
		(const unsigned char *)(text ? text : "");

	while (*cursor)
		hash = ((hash << 5) + hash) + *cursor++;
	return hash;
}

static void append_hex8(char *dst, size_t dst_len, size_t *offset,
			unsigned long value)
{
	static const char hex[] = "0123456789abcdef";
	int shift = 0;

	if (!dst || !offset || *offset >= dst_len)
		return;
	for (shift = 28; shift >= 0 && *offset + 1 < dst_len; shift -= 4)
		dst[(*offset)++] = hex[(value >> shift) & 0x0f];
	dst[*offset] = '\0';
}

static void format_token_pair(char *dst, size_t dst_len, const char *prefix,
			      unsigned long left, unsigned long right)
{
	size_t offset = 0;
	size_t index = 0;

	if (!dst || !dst_len)
		return;
	while (prefix && prefix[index] && offset + 1 < dst_len)
		dst[offset++] = prefix[index++];
	if (offset + 1 < dst_len)
		dst[offset++] = '-';
	append_hex8(dst, dst_len, &offset, left);
	if (offset + 1 < dst_len)
		dst[offset++] = '-';
	append_hex8(dst, dst_len, &offset, right);
	dst[offset < dst_len ? offset : dst_len - 1] = '\0';
}

static void fill_common_identity(char *world_id, size_t world_id_len,
				 char *measurement_sha256,
				 size_t measurement_sha256_len)
{
	copy_text(world_id, world_id_len, KEYSTONE_WORLD_ID);
	copy_text(measurement_sha256, measurement_sha256_len,
		  OC_TA_MEASUREMENT_SHA256);
}

static void mint_confirmation_values(const struct oc_ta_authorize_request *request,
				     char *confirmation_request_id,
				     size_t confirmation_request_id_len,
				     char *challenge_token,
				     size_t challenge_token_len)
{
	unsigned long confirm_hash = hash_text(request->req_id);
	unsigned long challenge_hash =
		hash_text(request->sid) ^ hash_text(request->object) ^
		hash_text(request->normalized_scope_digest);

	format_token_pair(confirmation_request_id, confirmation_request_id_len,
			  "confirm", confirm_hash,
			  hash_text(request->normalized_scope_digest));
	format_token_pair(challenge_token, challenge_token_len, "challenge",
			  challenge_hash, hash_text(request->action));
}

static void fill_authorize_response(const struct oc_ta_authorize_request *request,
				    struct oc_ta_authorize_response *response)
{
	struct oc_policy_request_view policy_request;
	struct oc_policy_result policy_result;

	zero_bytes(response, sizeof(*response));
	fill_common_identity(response->world_id, sizeof(response->world_id),
			     response->measurement_sha256,
			     sizeof(response->measurement_sha256));
	copy_text(response->proof_path, sizeof(response->proof_path),
		  KEYSTONE_PROOF_PATH);
	copy_text(response->tee_call, sizeof(response->tee_call),
		  KEYSTONE_AUTHORIZE_TEE_CALL);

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
		mint_confirmation_values(request, response->confirmation_request_id,
					 sizeof(response->confirmation_request_id),
					 response->challenge_token,
					 sizeof(response->challenge_token));
	}
}

static void fill_confirm_response(
	const struct oc_keystone_confirm_enclave_request *request,
	struct oc_ta_confirm_response *response)
{
	struct oc_ta_authorize_response authorize_response;
	char expected_confirmation_request_id[OC_TA_MAX_ID];
	char expected_challenge_token[OC_TA_MAX_TOKEN];
	bool approved = equals_ci(request->confirm.decision, "approve");

	zero_bytes(response, sizeof(*response));
	fill_authorize_response(&request->pending_authorize, &authorize_response);
	mint_confirmation_values(&request->pending_authorize,
				 expected_confirmation_request_id,
				 sizeof(expected_confirmation_request_id),
				 expected_challenge_token,
				 sizeof(expected_challenge_token));

	copy_text(response->confirmation_request_id,
		  sizeof(response->confirmation_request_id),
		  request->confirm.confirmation_request_id);
	copy_text(response->operator_id, sizeof(response->operator_id),
		  request->confirm.operator_id[0] ? request->confirm.operator_id :
						   "keystone-operator");
	copy_text(response->req_id, sizeof(response->req_id),
		  request->pending_authorize.req_id);
	copy_text(response->sid, sizeof(response->sid),
		  request->pending_authorize.sid);
	copy_text(response->tool_name, sizeof(response->tool_name),
		  request->pending_authorize.tool_name);
	copy_text(response->action, sizeof(response->action),
		  request->pending_authorize.action);
	copy_text(response->object, sizeof(response->object),
		  request->pending_authorize.object);
	copy_text(response->level, sizeof(response->level), authorize_response.level);
	copy_text(response->execution_mode, sizeof(response->execution_mode),
		  authorize_response.execution_mode);

	if (!authorize_response.requires_confirmation ||
	    !text_equal(request->confirm.confirmation_request_id,
			expected_confirmation_request_id) ||
	    !text_equal(request->confirm.challenge_token,
			expected_challenge_token)) {
		copy_text(response->status, sizeof(response->status), "denied");
		copy_text(response->decision, sizeof(response->decision), "ddeny");
		copy_text(response->reason, sizeof(response->reason),
			  "trusted confirmation challenge mismatch");
		copy_text(response->matched_rule_id,
			  sizeof(response->matched_rule_id),
			  "keystone.confirm.challenge-mismatch");
		response->ok = 0U;
		return;
	}

	copy_text(response->matched_rule_id, sizeof(response->matched_rule_id),
		  approved ? authorize_response.matched_rule_id :
			     "confirm.operator-deny");
	copy_text(response->status, sizeof(response->status),
		  approved ? "approved" : "denied");
	copy_text(response->decision, sizeof(response->decision),
		  approved ? "dia" : "ddeny");
	copy_text(response->reason, sizeof(response->reason),
		  approved ? authorize_response.reason :
			     "trusted confirmation denied");
	response->ok = approved ? 1U : 0U;
}

static void fill_complete_response(const struct oc_ta_complete_request *request,
				   struct oc_ta_complete_response *response)
{
	zero_bytes(response, sizeof(*response));
	copy_text(response->req_id, sizeof(response->req_id), request->req_id);
	copy_text(response->proof_path, sizeof(response->proof_path),
		  KEYSTONE_PROOF_PATH);
	copy_text(response->tee_call, sizeof(response->tee_call),
		  KEYSTONE_COMPLETE_TEE_CALL);
	fill_common_identity(response->world_id, sizeof(response->world_id),
			     response->measurement_sha256,
			     sizeof(response->measurement_sha256));
}

static void copy_request_from_host(struct oc_keystone_enclave_request *request)
{
	struct edge_data retdata;

	zero_bytes(&retdata, sizeof(retdata));
	ocall(OCALL_GET_REQUEST, NULL, 0, &retdata, sizeof(retdata));
	if (retdata.size > sizeof(*request))
		retdata.size = sizeof(*request);
	copy_from_shared(request, retdata.offset, retdata.size);
}

static void copy_response_to_host(const struct oc_keystone_enclave_response *response)
{
	ocall(OCALL_COPY_RESPONSE, (void *)response, sizeof(*response), 0, 0);
}

static void copy_report_to_host(const char *nonce)
{
	char report_buffer[2048];
	size_t nonce_len = nonce && nonce[0] ? text_length(nonce) + 1 : 1;

	attest_enclave((void *)report_buffer, (void *)(nonce ? nonce : ""),
		       nonce_len);
	ocall(OCALL_COPY_REPORT, report_buffer, sizeof(report_buffer), 0, 0);
}

int main(void)
{
	struct oc_keystone_enclave_request request;
	struct oc_keystone_enclave_response response;

	zero_bytes(&request, sizeof(request));
	zero_bytes(&response, sizeof(response));
	copy_request_from_host(&request);

	response.ok = 1U;
	response.command = request.command;

	switch (request.command) {
	case OC_KEYSTONE_CMD_PROBE:
		break;
	case OC_KEYSTONE_CMD_AUTHORIZE:
		fill_authorize_response(&request.payload.authorize,
					&response.payload.authorize);
		break;
	case OC_KEYSTONE_CMD_CONFIRM:
		fill_confirm_response(&request.payload.confirm,
				      &response.payload.confirm);
		break;
	case OC_KEYSTONE_CMD_COMPLETE:
		fill_complete_response(&request.payload.complete,
				       &response.payload.complete);
		break;
	default:
		response.ok = 0U;
		break;
	}

	copy_response_to_host(&response);
	copy_report_to_host(request.attestation_nonce);
	EAPP_RETURN(0);
}
