// SPDX-License-Identifier: BSD-2-Clause

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <tee_client_api.h>

#include <openclaw_trusted_backend_ta.h>

static const char *bool_json(bool value)
{
	return value ? "true" : "false";
}

static void print_json_escaped(const char *value)
{
	const unsigned char *cursor = (const unsigned char *)(value ? value : "");

	putchar('"');
	while (*cursor) {
		switch (*cursor) {
		case '\\':
			fputs("\\\\", stdout);
			break;
		case '"':
			fputs("\\\"", stdout);
			break;
		case '\n':
			fputs("\\n", stdout);
			break;
		case '\r':
			fputs("\\r", stdout);
			break;
		case '\t':
			fputs("\\t", stdout);
			break;
		default:
			if (*cursor < 0x20)
				printf("\\u%04x", *cursor);
			else
				putchar(*cursor);
			break;
		}
		cursor++;
	}
	putchar('"');
}

static void print_json_field(const char *name, const char *value, bool trailing_comma)
{
	printf("  \"%s\": ", name);
	print_json_escaped(value);
	printf("%s\n", trailing_comma ? "," : "");
}

static const char *find_option(int argc, char *argv[], const char *name, const char *fallback)
{
	int index = 0;

	for (index = 2; index + 1 < argc; index++) {
		if (strcmp(argv[index], name) == 0)
			return argv[index + 1];
	}
	return fallback;
}

static uint32_t find_option_u32(int argc, char *argv[], const char *name, uint32_t fallback)
{
	const char *raw = find_option(argc, argv, name, NULL);
	char *end = NULL;
	unsigned long parsed = 0;

	if (!raw || !raw[0])
		return fallback;
	parsed = strtoul(raw, &end, 10);
	if (!end || *end != '\0')
		errx(1, "invalid integer for %s: %s", name, raw);
	return (uint32_t)parsed;
}

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

static void compute_request_digest(const struct oc_ta_authorize_request *request,
				   char *out, size_t out_len)
{
	EVP_MD_CTX *ctx = NULL;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = 0;
	size_t offset = 0;
	bool ok = false;

	if (!out || out_len < 72) {
		if (out && out_len)
			out[0] = '\0';
		return;
	}

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		goto out;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) <= 0)
		goto out;
	if (EVP_DigestUpdate(ctx, request, sizeof(*request)) <= 0)
		goto out;
	if (EVP_DigestFinal_ex(ctx, digest, &digest_len) <= 0)
		goto out;

	offset = (size_t)snprintf(out, out_len, "sha256:");
	for (unsigned int index = 0; index < digest_len && offset + 2 < out_len;
	     index++) {
		offset += (size_t)snprintf(out + offset, out_len - offset, "%02x",
					   digest[index]);
	}
	ok = true;
out:
	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (!ok)
		copy_text(out, out_len, "sha256:optee-request-digest-error");
}

static void print_json_value_or_empty_object(const char *raw)
{
	const char *value = raw && raw[0] ? raw : "{}";

	fputs(value, stdout);
}

static void open_context_and_session(TEEC_Context *ctx, TEEC_Session *sess)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_UUID uuid = TA_OPENCLAW_TRUSTED_BACKEND_UUID;
	uint32_t err_origin = 0;

	res = TEEC_InitializeContext(NULL, ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(ctx, sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
			       &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x",
		     res, err_origin);
}

static void close_context_and_session(TEEC_Context *ctx, TEEC_Session *sess)
{
	TEEC_CloseSession(sess);
	TEEC_FinalizeContext(ctx);
}

static void invoke_or_die(TEEC_Session *sess, uint32_t command_id, TEEC_Operation *op)
{
	TEEC_Result res = TEEC_SUCCESS;
	uint32_t err_origin = 0;

	res = TEEC_InvokeCommand(sess, command_id, op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(%u) failed with code 0x%x origin 0x%x",
		     command_id, res, err_origin);
}

static void print_normalized_request(const struct oc_ta_authorize_request *request)
{
	char request_digest[80];

	compute_request_digest(request, request_digest, sizeof(request_digest));
	printf("  \"normalizedRequest\": {\n");
	printf("    \"version\": 1,\n");
	printf("    \"reqId\": ");
	print_json_escaped(request->req_id);
	printf(",\n");
	printf("    \"sid\": ");
	print_json_escaped(request->sid);
	printf(",\n");
	printf("    \"seq\": %u,\n", request->seq);
	printf("    \"ttlMs\": %u,\n", request->ttl_ms);
	printf("    \"toolName\": ");
	print_json_escaped(request->tool_name);
	printf(",\n");
	printf("    \"action\": ");
	print_json_escaped(request->action);
	printf(",\n");
	printf("    \"object\": ");
	print_json_escaped(request->object);
	printf(",\n");
	printf("    \"scope\": ");
	print_json_value_or_empty_object(request->scope_raw);
	printf(",\n");
	printf("    \"context\": {\n");
	printf("      \"sessionId\": ");
	print_json_escaped(request->sid);
	printf(",\n");
	printf("      \"workspaceRoot\": ");
	print_json_escaped(request->workspace_root[0] ? request->workspace_root :
					       "/workspace");
	printf("\n");
	printf("    },\n");
	printf("    \"level\": ");
	print_json_escaped(request->requested_level[0] ? request->requested_level : "L2");
	printf(",\n");
	printf("    \"normalizedScopeDigest\": ");
	print_json_escaped(request->normalized_scope_digest[0] ?
				       request->normalized_scope_digest :
				       "sha256:missing-normalized-scope-digest");
	printf(",\n");
	printf("    \"requestDigest\": ");
	print_json_escaped(request_digest);
	printf("\n");
	printf("  },\n");
}

static void print_classification(const struct oc_ta_authorize_response *response)
{
	bool destructive = strcmp(response->decision, "ddeny") == 0;

	printf("  \"classification\": {\n");
	printf("    \"actionRisk\": {\n");
	printf("      \"level\": ");
	print_json_escaped(response->action_risk_level);
	printf(",\n");
	printf("      \"reason\": ");
	print_json_escaped(response->action_risk_reason);
	printf("\n");
	printf("    },\n");
	printf("    \"objectRisk\": {\n");
	printf("      \"level\": ");
	print_json_escaped(response->object_risk_level);
	printf(",\n");
	printf("      \"reason\": ");
	print_json_escaped(response->object_risk_reason);
	printf("\n");
	printf("    },\n");
	printf("    \"contextRisk\": {\n");
	printf("      \"level\": ");
	print_json_escaped(response->context_risk_level);
	printf(",\n");
	printf("      \"reason\": ");
	print_json_escaped(response->context_risk_reason);
	printf("\n");
	printf("    },\n");
	printf("    \"effectRisk\": {\n");
	printf("      \"level\": ");
	print_json_escaped(response->effect_risk_level);
	printf(",\n");
	printf("      \"reason\": ");
	print_json_escaped(response->effect_risk_reason);
	printf("\n");
	printf("    },\n");
	printf("    \"contextFlags\": {\n");
	printf("      \"destructive\": %s,\n", bool_json(destructive));
	printf("      \"export\": %s,\n",
	       bool_json(strcmp(response->decision, "duc") == 0));
	printf("      \"multi_step\": false,\n");
	printf("      \"outside_workspace\": false,\n");
	printf("      \"protected_path\": %s,\n", bool_json(destructive));
	printf("      \"remote_target\": false,\n");
	printf("      \"shell_wrapper\": false,\n");
	printf("      \"task_mismatch\": false,\n");
	printf("      \"user_absent\": false\n");
	printf("    },\n");
	printf("    \"effectFlags\": {\n");
	printf("      \"destructive\": %s,\n", bool_json(destructive));
	printf("      \"export\": %s,\n",
	       bool_json(strcmp(response->decision, "duc") == 0));
	printf("      \"multi_step\": false,\n");
	printf("      \"outside_workspace\": false,\n");
	printf("      \"protected_path\": %s,\n", bool_json(destructive));
	printf("      \"remote_target\": false,\n");
	printf("      \"shell_wrapper\": false,\n");
	printf("      \"task_mismatch\": false,\n");
	printf("      \"user_absent\": false\n");
	printf("    }\n");
	printf("  },\n");
}

static void print_authorize_json(const struct oc_ta_authorize_request *request,
				 const struct oc_ta_authorize_response *response)
{
	printf("{\n");
	printf("  \"allow\": %s,\n", bool_json(response->allow != 0));
	printf("  \"decision\": ");
	print_json_escaped(response->decision);
	printf(",\n");
	printf("  \"level\": ");
	print_json_escaped(response->level);
	printf(",\n");
	printf("  \"executionMode\": ");
	print_json_escaped(response->execution_mode);
	printf(",\n");
	printf("  \"reason\": ");
	print_json_escaped(response->reason);
	printf(",\n");
	printf("  \"matchedRuleId\": ");
	print_json_escaped(response->matched_rule_id);
	printf(",\n");
	print_normalized_request(request);
	print_classification(response);
	printf("  \"scopeToken\": ");
	if (response->scope_token[0])
		print_json_escaped(response->scope_token);
	else
		printf("null");
	printf(",\n");
	printf("  \"confirmation\": ");
	if (response->requires_confirmation) {
		printf("{\n");
		printf("    \"confirmationRequestId\": ");
		print_json_escaped(response->confirmation_request_id);
		printf(",\n");
		printf("    \"challengeToken\": ");
		print_json_escaped(response->challenge_token);
		printf(",\n");
		printf("    \"prompt\": ");
		print_json_escaped("OP-TEE example approval required");
		printf(",\n");
		printf("    \"summary\": ");
		print_json_escaped(response->reason);
		printf(",\n");
		printf("    \"expiresAtMs\": 0,\n");
		printf("    \"executionMode\": ");
		print_json_escaped(response->execution_mode);
		printf("\n");
		printf("  }");
	} else {
		printf("null");
	}
	printf(",\n");
	printf("  \"evidence\": {\n");
	printf("    \"backend\": ");
	print_json_escaped("optee-openclaw-trusted-backend-example");
	printf(",\n");
	printf("    \"adaptor\": ");
	print_json_escaped("optee-ree-backend");
	printf(",\n");
	printf("    \"platform\": ");
	print_json_escaped("trustzone");
	printf(",\n");
	printf("    \"proofPath\": ");
	print_json_escaped(response->proof_path);
	printf(",\n");
	printf("    \"proof\": {\n");
	printf("      \"platform\": ");
	print_json_escaped("trustzone");
	printf(",\n");
	printf("      \"adaptor\": ");
	print_json_escaped("optee-ree-backend");
	printf(",\n");
	printf("      \"proofPath\": ");
	print_json_escaped(response->proof_path);
	printf(",\n");
	printf("      \"teeCall\": ");
	print_json_escaped(response->tee_call);
	printf(",\n");
	printf("      \"matchedRuleId\": ");
	print_json_escaped(response->matched_rule_id);
	printf(",\n");
	printf("      \"worldId\": ");
	print_json_escaped(response->world_id);
	printf(",\n");
	printf("      \"measurementSha256\": ");
	print_json_escaped(response->measurement_sha256);
	printf(",\n");
	printf("      \"nonceBound\": %s\n", bool_json(response->nonce_bound != 0));
	printf("    }\n");
	printf("  }\n");
	printf("}\n");
}

static void print_confirm_json(const struct oc_ta_confirm_response *response)
{
	printf("{\n");
	printf("  \"ok\": %s,\n", bool_json(response->ok != 0));
	printf("  \"confirmationRequestId\": ");
	print_json_escaped(response->confirmation_request_id);
	printf(",\n");
	printf("  \"status\": ");
	print_json_escaped(response->status);
	printf(",\n");
	printf("  \"decision\": ");
	print_json_escaped(response->decision);
	printf(",\n");
	printf("  \"level\": ");
	print_json_escaped(response->level);
	printf(",\n");
	printf("  \"executionMode\": ");
	print_json_escaped(response->execution_mode);
	printf(",\n");
	printf("  \"reason\": ");
	print_json_escaped(response->reason);
	printf(",\n");
	printf("  \"matchedRuleId\": ");
	print_json_escaped(response->matched_rule_id);
	printf(",\n");
	printf("  \"normalizedRequest\": {\n");
	printf("    \"version\": 1,\n");
	printf("    \"reqId\": ");
	print_json_escaped(response->req_id);
	printf(",\n");
	printf("    \"sid\": ");
	print_json_escaped(response->sid);
	printf(",\n");
	printf("    \"toolName\": ");
	print_json_escaped(response->tool_name);
	printf(",\n");
	printf("    \"action\": ");
	print_json_escaped(response->action);
	printf(",\n");
	printf("    \"object\": ");
	print_json_escaped(response->object);
	printf(",\n");
	printf("    \"normalizedScopeDigest\": ");
	print_json_escaped("sha256:missing-normalized-scope-digest");
	printf(",\n");
	printf("    \"requestDigest\": ");
	print_json_escaped("sha256:missing-request-digest");
	printf("\n");
	printf("  },\n");
	printf("  \"confirmedAtMs\": 0,\n");
	printf("  \"operatorId\": ");
	print_json_escaped(response->operator_id);
	printf(",\n");
	printf("  \"scopeToken\": ");
	if (response->scope_token[0])
		print_json_escaped(response->scope_token);
	else
		printf("null");
	printf(",\n");
	printf("  \"evidence\": {\n");
	printf("    \"backend\": ");
	print_json_escaped("optee-openclaw-trusted-backend-example");
	printf(",\n");
	printf("    \"adaptor\": ");
	print_json_escaped("optee-ree-backend");
	printf(",\n");
	printf("    \"platform\": ");
	print_json_escaped("trustzone");
	printf(",\n");
	printf("    \"proofPath\": ");
	print_json_escaped("ree-proxy");
	printf(",\n");
	printf("    \"proof\": {\n");
	printf("      \"platform\": ");
	print_json_escaped("trustzone");
	printf(",\n");
	printf("      \"adaptor\": ");
	print_json_escaped("optee-ree-backend");
	printf(",\n");
	printf("      \"teeCall\": ");
	print_json_escaped("TEEC_InvokeCommand(confirm)");
	printf(",\n");
	printf("      \"worldId\": ");
	print_json_escaped("optee-secure-world");
	printf(",\n");
	printf("      \"measurementSha256\": ");
	print_json_escaped(OC_TA_MEASUREMENT_SHA256);
	printf(",\n");
	printf("      \"nonceBound\": true\n");
	printf("    }\n");
	printf("  }\n");
	printf("}\n");
}

static void print_complete_json(const struct oc_ta_complete_response *response)
{
	printf("{\n");
	printf("  \"ok\": true,\n");
	printf("  \"adaptor\": ");
	print_json_escaped("optee-ree-backend");
	printf(",\n");
	printf("  \"platform\": ");
	print_json_escaped("trustzone");
	printf(",\n");
	printf("  \"proof\": {\n");
	printf("    \"platform\": ");
	print_json_escaped("trustzone");
	printf(",\n");
	printf("    \"adaptor\": ");
	print_json_escaped("optee-ree-backend");
	printf(",\n");
	printf("    \"phase\": ");
	print_json_escaped("complete");
	printf(",\n");
	printf("    \"reqId\": ");
	print_json_escaped(response->req_id);
	printf(",\n");
	printf("    \"proofPath\": ");
	print_json_escaped(response->proof_path);
	printf(",\n");
	printf("    \"teeCall\": ");
	print_json_escaped(response->tee_call);
	printf(",\n");
	printf("    \"worldId\": ");
	print_json_escaped(response->world_id);
	printf(",\n");
	printf("    \"measurementSha256\": ");
	print_json_escaped(response->measurement_sha256);
	printf("\n");
	printf("  }\n");
	printf("}\n");
}

static void print_healthz_json(const struct oc_ta_health_response *response)
{
	printf("{\n");
	printf("  \"ok\": true,\n");
	print_json_field("mode", response->mode, true);
	print_json_field("adaptor", response->adaptor, true);
	print_json_field("platform", response->platform, true);
	printf("  \"guest\": {\n");
	printf("    \"platform\": ");
	print_json_escaped(response->platform);
	printf(",\n");
	printf("    \"worldId\": ");
	print_json_escaped(response->world_id);
	printf(",\n");
	printf("    \"taUuid\": ");
	print_json_escaped(response->ta_uuid);
	printf(",\n");
	printf("    \"measurementSha256\": ");
	print_json_escaped(response->measurement_sha256);
	printf(",\n");
	printf("    \"attestationMode\": ");
	print_json_escaped("optee-example");
	printf(",\n");
	printf("    \"attestationReady\": true\n");
	printf("  }\n");
	printf("}\n");
}

static void print_guest_json(const struct oc_ta_guest_response *response)
{
	printf("{\n");
	printf("  \"ok\": true,\n");
	print_json_field("adaptor", response->adaptor, true);
	print_json_field("platform", response->platform, true);
	printf("  \"guest\": {\n");
	printf("    \"guestId\": ");
	print_json_escaped(response->guest_id);
	printf(",\n");
	printf("    \"serviceName\": ");
	print_json_escaped(response->service_name);
	printf(",\n");
	printf("    \"attestationMode\": ");
	print_json_escaped(response->attestation_mode);
	printf(",\n");
	printf("    \"attestationReady\": %s,\n",
	       bool_json(response->attestation_ready != 0));
	printf("    \"worldId\": ");
	print_json_escaped(response->world_id);
	printf(",\n");
	printf("    \"taUuid\": ");
	print_json_escaped(response->ta_uuid);
	printf(",\n");
	printf("    \"measurementSha256\": ");
	print_json_escaped(response->measurement_sha256);
	printf("\n");
	printf("  },\n");
	printf("  \"attestation\": {\n");
	printf("    \"platform\": ");
	print_json_escaped(response->platform);
	printf(",\n");
	printf("    \"worldId\": ");
	print_json_escaped(response->world_id);
	printf(",\n");
	printf("    \"measurementSha256\": ");
	print_json_escaped(response->measurement_sha256);
	printf(",\n");
	printf("    \"nonceBound\": true\n");
	printf("  }\n");
	printf("}\n");
}

static void run_healthz(TEEC_Session *sess)
{
	struct oc_ta_health_response response;
	TEEC_Operation op;

	memset(&response, 0, sizeof(response));
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = &response;
	op.params[0].tmpref.size = sizeof(response);
	invoke_or_die(sess, TA_OPENCLAW_TRUSTED_BACKEND_CMD_HEALTHZ, &op);
	print_healthz_json(&response);
}

static void run_guest(TEEC_Session *sess)
{
	struct oc_ta_guest_response response;
	TEEC_Operation op;

	memset(&response, 0, sizeof(response));
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = &response;
	op.params[0].tmpref.size = sizeof(response);
	invoke_or_die(sess, TA_OPENCLAW_TRUSTED_BACKEND_CMD_GUEST_INFO, &op);
	print_guest_json(&response);
}

static void run_authorize(TEEC_Session *sess, int argc, char *argv[])
{
	struct oc_ta_authorize_request request;
	struct oc_ta_authorize_response response;
	TEEC_Operation op;

	memset(&request, 0, sizeof(request));
	memset(&response, 0, sizeof(response));
	memset(&op, 0, sizeof(op));

	copy_text(request.req_id, sizeof(request.req_id),
		  find_option(argc, argv, "--req-id", "req-optee-example"));
	copy_text(request.sid, sizeof(request.sid),
		  find_option(argc, argv, "--sid", "sid-optee-example"));
	copy_text(request.tool_name, sizeof(request.tool_name),
		  find_option(argc, argv, "--tool-name", "exec"));
	copy_text(request.action, sizeof(request.action),
		  find_option(argc, argv, "--action", "exec"));
	copy_text(request.object, sizeof(request.object),
		  find_option(argc, argv, "--object", "echo hello from optee"));
	copy_text(request.requested_level, sizeof(request.requested_level),
		  find_option(argc, argv, "--level", "L2"));
	copy_text(request.normalized_scope_digest,
		  sizeof(request.normalized_scope_digest),
		  find_option(argc, argv, "--normalized-scope-digest",
			      "sha256:missing-normalized-scope-digest"));
	copy_text(request.scope_raw, sizeof(request.scope_raw),
		  find_option(argc, argv, "--scope-json", "{}"));
	copy_text(request.workspace_root, sizeof(request.workspace_root),
		  find_option(argc, argv, "--workspace-root", ""));
	copy_text(request.session_binding, sizeof(request.session_binding),
		  find_option(argc, argv, "--session-binding", ""));
	request.seq = find_option_u32(argc, argv, "--seq", 1);
	request.ttl_ms = find_option_u32(argc, argv, "--ttl-ms", 15000);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE);
	op.params[0].tmpref.buffer = &request;
	op.params[0].tmpref.size = sizeof(request);
	op.params[1].tmpref.buffer = &response;
	op.params[1].tmpref.size = sizeof(response);
	invoke_or_die(sess, TA_OPENCLAW_TRUSTED_BACKEND_CMD_AUTHORIZE, &op);
	print_authorize_json(&request, &response);
}

static void run_confirm(TEEC_Session *sess, int argc, char *argv[])
{
	struct oc_ta_confirm_request request;
	struct oc_ta_confirm_response response;
	TEEC_Operation op;

	memset(&request, 0, sizeof(request));
	memset(&response, 0, sizeof(response));
	memset(&op, 0, sizeof(op));

	copy_text(request.confirmation_request_id,
		  sizeof(request.confirmation_request_id),
		  find_option(argc, argv, "--confirmation-request-id",
			      "missing-confirmation-id"));
	copy_text(request.challenge_token, sizeof(request.challenge_token),
		  find_option(argc, argv, "--challenge-token",
			      "missing-challenge-token"));
	copy_text(request.operator_id, sizeof(request.operator_id),
		  find_option(argc, argv, "--operator-id", "optee-operator"));
	copy_text(request.decision, sizeof(request.decision),
		  find_option(argc, argv, "--decision", "approve"));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE);
	op.params[0].tmpref.buffer = &request;
	op.params[0].tmpref.size = sizeof(request);
	op.params[1].tmpref.buffer = &response;
	op.params[1].tmpref.size = sizeof(response);
	invoke_or_die(sess, TA_OPENCLAW_TRUSTED_BACKEND_CMD_CONFIRM, &op);
	print_confirm_json(&response);
}

static void run_complete(TEEC_Session *sess, int argc, char *argv[])
{
	struct oc_ta_complete_request request;
	struct oc_ta_complete_response response;
	TEEC_Operation op;

	memset(&request, 0, sizeof(request));
	memset(&response, 0, sizeof(response));
	memset(&op, 0, sizeof(op));

	copy_text(request.req_id, sizeof(request.req_id),
		  find_option(argc, argv, "--req-id", "req-optee-example"));
	copy_text(request.sid, sizeof(request.sid),
		  find_option(argc, argv, "--sid", "sid-optee-example"));
	copy_text(request.tool_name, sizeof(request.tool_name),
		  find_option(argc, argv, "--tool-name", "exec"));
	copy_text(request.action, sizeof(request.action),
		  find_option(argc, argv, "--action", "exec"));
	copy_text(request.object, sizeof(request.object),
		  find_option(argc, argv, "--object", "echo hello from optee"));
	copy_text(request.status, sizeof(request.status),
		  find_option(argc, argv, "--status", "ok"));
	copy_text(request.result_digest, sizeof(request.result_digest),
		  find_option(argc, argv, "--result-digest",
			      "sha256:optee-example-result"));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE);
	op.params[0].tmpref.buffer = &request;
	op.params[0].tmpref.size = sizeof(request);
	op.params[1].tmpref.buffer = &response;
	op.params[1].tmpref.size = sizeof(response);
	invoke_or_die(sess, TA_OPENCLAW_TRUSTED_BACKEND_CMD_COMPLETE, &op);
	print_complete_json(&response);
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s healthz\n"
		"  %s guest\n"
		"  %s authorize [--req-id ID] [--sid SID] [--tool-name NAME]\n"
		"               [--action ACTION] [--object TEXT] [--level L2]\n"
		"               [--normalized-scope-digest DIGEST]\n"
		"               [--scope-json JSON] [--workspace-root PATH]\n"
		"               [--session-binding ID] [--seq 1] [--ttl-ms 15000]\n"
		"  %s confirm --confirmation-request-id ID --challenge-token TOKEN\n"
		"             [--operator-id ID] [--decision approve|deny]\n"
		"  %s complete [--req-id ID] [--sid SID] [--tool-name NAME]\n"
		"              [--action ACTION] [--object TEXT] [--status ok]\n"
		"              [--result-digest DIGEST]\n",
		argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char *argv[])
{
	TEEC_Context ctx;
	TEEC_Session sess;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	open_context_and_session(&ctx, &sess);

	if (strcmp(argv[1], "healthz") == 0 || strcmp(argv[1], "health") == 0) {
		run_healthz(&sess);
	} else if (strcmp(argv[1], "guest") == 0) {
		run_guest(&sess);
	} else if (strcmp(argv[1], "authorize") == 0) {
		run_authorize(&sess, argc, argv);
	} else if (strcmp(argv[1], "confirm") == 0) {
		run_confirm(&sess, argc, argv);
	} else if (strcmp(argv[1], "complete") == 0) {
		run_complete(&sess, argc, argv);
	} else {
		close_context_and_session(&ctx, &sess);
		usage(argv[0]);
		return 1;
	}

	close_context_and_session(&ctx, &sess);
	return 0;
}
