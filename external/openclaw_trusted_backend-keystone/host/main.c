// SPDX-License-Identifier: BSD-2-Clause

#include <ctype.h>
#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "openclaw_trusted_backend_keystone.h"
#include "keystone_enclave_bridge.h"

#define KEYSTONE_BACKEND_NAME "keystone-openclaw-trusted-backend-example"
#define KEYSTONE_ADAPTOR "keystone-remote-backend"
#define KEYSTONE_PLATFORM "keystone"
#define KEYSTONE_PROOF_PATH "openclaw -> ree proxy -> enclave call"
#define KEYSTONE_CONFIRM_TEE_CALL "keystone enclave confirm"
#define KEYSTONE_WORLD_ID "keystone-enclave"
#define KEYSTONE_GUEST_ID "keystone-guest:openclaw-keystone-01"
#define KEYSTONE_SERVICE_NAME "openclaw-keystone-trusted-backend"
#define KEYSTONE_ATTESTATION_MODE "command"
#define KEYSTONE_SCOPE_DIGEST "sha256:missing-normalized-scope-digest"
#define KEYSTONE_REQUEST_DIGEST "sha256:missing-request-digest"

static const char *bool_json(bool value)
{
	return value ? "true" : "false";
}

static const char *env_or_default(const char *name, const char *fallback)
{
	const char *value = getenv(name);

	return (value && value[0]) ? value : fallback;
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

static bool file_readable(const char *path)
{
	return path && path[0] && access(path, R_OK) == 0;
}

static int ascii_tolower(int ch)
{
	return tolower((unsigned char)ch);
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

static bool contains_ci(const char *haystack, const char *needle)
{
	size_t needle_len = needle ? strlen(needle) : 0;
	size_t offset = 0;

	if (!haystack || !needle_len)
		return false;

	for (offset = 0; haystack[offset]; offset++) {
		size_t index = 0;

		while (haystack[offset + index] &&
		       ascii_tolower(haystack[offset + index]) ==
			       ascii_tolower(needle[index])) {
			index++;
			if (index == needle_len)
				return true;
		}
	}

	return false;
}

static bool compute_sha256_file(const char *path, char *out, size_t out_len)
{
	EVP_MD_CTX *ctx = NULL;
	FILE *file = NULL;
	unsigned char buffer[4096];
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = 0;
	size_t read_bytes = 0;
	size_t offset = 0;
	bool ok = false;

	if (!path || !out || out_len < 72)
		return false;

	file = fopen(path, "rb");
	if (!file)
		goto out;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		goto out;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) <= 0)
		goto out;

	while ((read_bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
		if (EVP_DigestUpdate(ctx, buffer, read_bytes) <= 0)
			goto out;
	}
	if (ferror(file))
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
	if (file)
		fclose(file);
	return ok;
}

static void resolve_measurement_sha256(char *out, size_t out_len)
{
	const char *candidates[] = {
		getenv("KEYSTONE_MEASUREMENT_FILE"),
		getenv("KEYSTONE_PACKAGE_FILE"),
		getenv("KEYSTONE_EAPP_FILE"),
		NULL,
	};
	size_t index = 0;

	for (index = 0; index < sizeof(candidates) / sizeof(candidates[0]); index++) {
		if (file_readable(candidates[index]) &&
		    compute_sha256_file(candidates[index], out, out_len))
			return;
	}

	copy_text(out, out_len, OC_TA_MEASUREMENT_SHA256);
}

static bool parse_attestation_ready_file(const char *path, bool *ready_out)
{
	FILE *file = NULL;
	char line[256];

	if (!path || !ready_out)
		return false;

	file = fopen(path, "r");
	if (!file)
		return false;

	while (fgets(line, sizeof(line), file)) {
		char *value = NULL;
		size_t length = 0;

		if (strncmp(line, "attestation_ready=", 18) != 0)
			continue;

		value = line + 18;
		length = strlen(value);
		while (length > 0 &&
		       (value[length - 1] == '\n' || value[length - 1] == '\r')) {
			value[length - 1] = '\0';
			length--;
		}
		*ready_out = strcmp(value, "1") == 0 ||
			     strcasecmp(value, "true") == 0;
		fclose(file);
		return true;
	}

	fclose(file);
	return false;
}

static bool resolve_attestation_ready(void)
{
	const char *status_file = getenv("KEYSTONE_ATTESTATION_STATUS_FILE");
	const char *runner = getenv("KEYSTONE_ATTESTOR_RUNNER");
	const char *package_file = getenv("KEYSTONE_PACKAGE_FILE");
	const char *eapp_file = getenv("KEYSTONE_EAPP_FILE");
	const char *runtime_file = getenv("KEYSTONE_RUNTIME_FILE");
	const char *loader_file = getenv("KEYSTONE_LOADER_FILE");
	bool ready = false;

	if (file_readable(status_file) &&
	    parse_attestation_ready_file(status_file, &ready))
		return ready;

	return file_readable(runner) &&
	       (file_readable(package_file) ||
		(file_readable(eapp_file) && file_readable(runtime_file) &&
		 file_readable(loader_file)));
}

static void fill_common_identity(char *world_id, size_t world_id_len,
				 char *measurement_sha256,
				 size_t measurement_sha256_len)
{
	copy_text(world_id, world_id_len,
		  env_or_default("KEYSTONE_WORLD_ID", KEYSTONE_WORLD_ID));
	resolve_measurement_sha256(measurement_sha256, measurement_sha256_len);
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
		copy_text(out, out_len, "sha256:keystone-request-digest-error");
}

static void print_json_value_or_empty_object(const char *raw)
{
	const char *value = raw && raw[0] ? raw : "{}";

	fputs(value, stdout);
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
	bool confirmable = strcmp(response->decision, "duc") == 0;
	bool protected_path = contains_ci(response->reason, "critical") ||
			      contains_ci(response->reason, "protected");

	printf("  \"classification\": {\n");
	printf("    \"actionRisk\": {\n");
	printf("      \"level\": ");
	print_json_escaped(response->action_risk_level);
	printf(",\n");
	printf("      \"reason\": ");
	print_json_escaped(response->action_risk_reason);
	printf(",\n");
	printf("      \"matchedRuleId\": ");
	print_json_escaped(response->matched_rule_id);
	printf("\n");
	printf("    },\n");
	printf("    \"objectRisk\": {\n");
	printf("      \"level\": ");
	print_json_escaped(response->object_risk_level);
	printf(",\n");
	printf("      \"reason\": ");
	print_json_escaped(response->object_risk_reason);
	printf(",\n");
	printf("      \"matchedRuleId\": ");
	print_json_escaped(response->matched_rule_id);
	printf(",\n");
	printf("      \"classification\": ");
	print_json_escaped(destructive ? "critical" :
			       (confirmable ? "sensitive" : "ordinary"));
	printf("\n");
	printf("    },\n");
	printf("    \"contextRisk\": {\n");
	printf("      \"level\": ");
	print_json_escaped(response->context_risk_level);
	printf(",\n");
	printf("      \"reason\": ");
	print_json_escaped(response->context_risk_reason);
	printf(",\n");
	printf("      \"matchedRuleId\": ");
	print_json_escaped(response->matched_rule_id);
	printf(",\n");
	printf("      \"factors\": {\n");
	printf("        \"outsideWorkspace\": false,\n");
	printf("        \"userAbsent\": false\n");
	printf("      }\n");
	printf("    },\n");
	printf("    \"effectRisk\": {\n");
	printf("      \"level\": ");
	print_json_escaped(response->effect_risk_level);
	printf(",\n");
	printf("      \"reason\": ");
	print_json_escaped(response->effect_risk_reason);
	printf(",\n");
	printf("      \"matchedRuleId\": ");
	print_json_escaped(response->matched_rule_id);
	printf(",\n");
	printf("      \"factors\": {\n");
	printf("        \"destructive\": %s,\n", bool_json(destructive));
	printf("        \"export\": %s\n", bool_json(confirmable));
	printf("      }\n");
	printf("    },\n");
	printf("    \"contextFlags\": {\n");
	printf("      \"destructive\": %s,\n", bool_json(destructive));
	printf("      \"export\": %s,\n", bool_json(confirmable));
	printf("      \"multi_step\": false,\n");
	printf("      \"outside_workspace\": false,\n");
	printf("      \"protected_path\": %s,\n", bool_json(protected_path));
	printf("      \"remote_target\": %s,\n", bool_json(confirmable));
	printf("      \"shell_wrapper\": false,\n");
	printf("      \"task_mismatch\": false,\n");
	printf("      \"user_absent\": false\n");
	printf("    },\n");
	printf("    \"effectFlags\": {\n");
	printf("      \"destructive\": %s,\n", bool_json(destructive));
	printf("      \"export\": %s,\n", bool_json(confirmable));
	printf("      \"multi_step\": false,\n");
	printf("      \"outside_workspace\": false,\n");
	printf("      \"protected_path\": %s,\n", bool_json(protected_path));
	printf("      \"remote_target\": %s,\n", bool_json(confirmable));
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
		print_json_escaped("Keystone trusted confirmation required");
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
	print_json_escaped(KEYSTONE_BACKEND_NAME);
	printf(",\n");
	printf("    \"adaptor\": ");
	print_json_escaped(KEYSTONE_ADAPTOR);
	printf(",\n");
	printf("    \"platform\": ");
	print_json_escaped(KEYSTONE_PLATFORM);
	printf(",\n");
	printf("    \"proofPath\": ");
	print_json_escaped(response->proof_path);
	printf(",\n");
	printf("    \"proof\": {\n");
	printf("      \"platform\": ");
	print_json_escaped(KEYSTONE_PLATFORM);
	printf(",\n");
	printf("      \"adaptor\": ");
	print_json_escaped(KEYSTONE_ADAPTOR);
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
	char measurement_sha256[OC_TA_MAX_DIGEST];

	resolve_measurement_sha256(measurement_sha256,
				      sizeof(measurement_sha256));
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
	print_json_escaped(KEYSTONE_SCOPE_DIGEST);
	printf(",\n");
	printf("    \"requestDigest\": ");
	print_json_escaped(KEYSTONE_REQUEST_DIGEST);
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
	print_json_escaped(KEYSTONE_BACKEND_NAME);
	printf(",\n");
	printf("    \"adaptor\": ");
	print_json_escaped(KEYSTONE_ADAPTOR);
	printf(",\n");
	printf("    \"platform\": ");
	print_json_escaped(KEYSTONE_PLATFORM);
	printf(",\n");
	printf("    \"proofPath\": ");
	print_json_escaped(KEYSTONE_PROOF_PATH);
	printf(",\n");
	printf("    \"proof\": {\n");
	printf("      \"platform\": ");
	print_json_escaped(KEYSTONE_PLATFORM);
	printf(",\n");
	printf("      \"adaptor\": ");
	print_json_escaped(KEYSTONE_ADAPTOR);
	printf(",\n");
	printf("      \"teeCall\": ");
	print_json_escaped(KEYSTONE_CONFIRM_TEE_CALL);
	printf(",\n");
	printf("      \"worldId\": ");
	print_json_escaped(KEYSTONE_WORLD_ID);
	printf(",\n");
	printf("      \"measurementSha256\": ");
	print_json_escaped(measurement_sha256);
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
	print_json_escaped(KEYSTONE_ADAPTOR);
	printf(",\n");
	printf("  \"platform\": ");
	print_json_escaped(KEYSTONE_PLATFORM);
	printf(",\n");
	printf("  \"proof\": {\n");
	printf("    \"platform\": ");
	print_json_escaped(KEYSTONE_PLATFORM);
	printf(",\n");
	printf("    \"adaptor\": ");
	print_json_escaped(KEYSTONE_ADAPTOR);
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
	print_json_escaped(KEYSTONE_ATTESTATION_MODE);
	printf(",\n");
	printf("    \"attestationReady\": %s\n",
	       bool_json(resolve_attestation_ready()));
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

static void fill_authorize_response(const struct oc_ta_authorize_request *request,
				    struct oc_ta_authorize_response *response)
{
	memset(response, 0, sizeof(*response));
	if (!oc_keystone_enclave_authorize(request, response, response->reason,
					   sizeof(response->reason)))
		errx(1, "Keystone enclave authorize failed: %s",
		     response->reason[0] ? response->reason : "unknown error");
	resolve_measurement_sha256(response->measurement_sha256,
				   sizeof(response->measurement_sha256));
}

static void fill_confirm_response(int argc, char *argv[],
				  struct oc_ta_confirm_response *response)
{
	struct oc_keystone_confirm_enclave_request request;
	char error_message[256];

	memset(&request, 0, sizeof(request));
	memset(response, 0, sizeof(*response));
	memset(error_message, 0, sizeof(error_message));
	copy_text(request.confirm.confirmation_request_id,
		  sizeof(request.confirm.confirmation_request_id),
		  find_option(argc, argv, "--confirmation-request-id",
			      "missing-confirmation-id"));
	copy_text(request.confirm.challenge_token,
		  sizeof(request.confirm.challenge_token),
		  find_option(argc, argv, "--challenge-token", ""));
	copy_text(request.confirm.operator_id, sizeof(request.confirm.operator_id),
		  find_option(argc, argv, "--operator-id", "keystone-operator"));
	copy_text(request.confirm.decision, sizeof(request.confirm.decision),
		  find_option(argc, argv, "--decision", "approve"));
	copy_text(request.pending_authorize.req_id,
		  sizeof(request.pending_authorize.req_id),
		  find_option(argc, argv, "--req-id", "req-keystone-confirm"));
	copy_text(request.pending_authorize.sid,
		  sizeof(request.pending_authorize.sid),
		  find_option(argc, argv, "--sid", "sid-keystone-confirm"));
	copy_text(request.pending_authorize.tool_name,
		  sizeof(request.pending_authorize.tool_name),
		  find_option(argc, argv, "--tool-name", "exec"));
	copy_text(request.pending_authorize.action,
		  sizeof(request.pending_authorize.action),
		  find_option(argc, argv, "--action", "exec"));
	copy_text(request.pending_authorize.object,
		  sizeof(request.pending_authorize.object),
		  find_option(argc, argv, "--object",
			      "keystone-confirmed-command"));
	copy_text(request.pending_authorize.requested_level,
		  sizeof(request.pending_authorize.requested_level),
		  find_option(argc, argv, "--level", "L2"));
	copy_text(request.pending_authorize.normalized_scope_digest,
		  sizeof(request.pending_authorize.normalized_scope_digest),
		  find_option(argc, argv, "--normalized-scope-digest",
			      "sha256:missing-normalized-scope-digest"));
	copy_text(request.pending_authorize.scope_raw,
		  sizeof(request.pending_authorize.scope_raw),
		  find_option(argc, argv, "--scope-json", "{}"));
	copy_text(request.pending_authorize.workspace_root,
		  sizeof(request.pending_authorize.workspace_root),
		  find_option(argc, argv, "--workspace-root", ""));
	copy_text(request.pending_authorize.session_binding,
		  sizeof(request.pending_authorize.session_binding),
		  find_option(argc, argv, "--session-binding", ""));
	request.pending_authorize.seq = find_option_u32(argc, argv, "--seq", 1);
	request.pending_authorize.ttl_ms =
		find_option_u32(argc, argv, "--ttl-ms", 15000);

	if (!oc_keystone_enclave_confirm(&request, response, error_message,
					 sizeof(error_message)))
		errx(1, "Keystone enclave confirm failed: %s",
		     error_message[0] ? error_message : "unknown error");
}

static void fill_complete_response(int argc, char *argv[],
				   struct oc_ta_complete_response *response)
{
	struct oc_ta_complete_request request;
	char error_message[256];

	memset(&request, 0, sizeof(request));
	memset(response, 0, sizeof(*response));
	memset(error_message, 0, sizeof(error_message));
	copy_text(request.req_id, sizeof(request.req_id),
		  find_option(argc, argv, "--req-id", "req-keystone-complete"));
	copy_text(request.sid, sizeof(request.sid),
		  find_option(argc, argv, "--sid", "sid-keystone-complete"));
	copy_text(request.tool_name, sizeof(request.tool_name),
		  find_option(argc, argv, "--tool-name", "exec"));
	copy_text(request.action, sizeof(request.action),
		  find_option(argc, argv, "--action", "exec"));
	copy_text(request.object, sizeof(request.object),
		  find_option(argc, argv, "--object",
			      "echo hello from keystone"));
	copy_text(request.status, sizeof(request.status),
		  find_option(argc, argv, "--status", "ok"));
	copy_text(request.result_digest, sizeof(request.result_digest),
		  find_option(argc, argv, "--result-digest",
			      "sha256:keystone-result-digest"));

	if (!oc_keystone_enclave_complete(&request, response, error_message,
					  sizeof(error_message)))
		errx(1, "Keystone enclave complete failed: %s",
		     error_message[0] ? error_message : "unknown error");
	resolve_measurement_sha256(response->measurement_sha256,
				   sizeof(response->measurement_sha256));
}

static void fill_healthz_response(struct oc_ta_health_response *response)
{
	memset(response, 0, sizeof(*response));
	copy_text(response->mode, sizeof(response->mode),
		  env_or_default("KEYSTONE_TRUSTED_VERIFY_MODE", "ed25519"));
	copy_text(response->adaptor, sizeof(response->adaptor), KEYSTONE_ADAPTOR);
	copy_text(response->platform, sizeof(response->platform), KEYSTONE_PLATFORM);
	copy_text(response->ta_uuid, sizeof(response->ta_uuid),
		  "not-applicable");
	fill_common_identity(response->world_id, sizeof(response->world_id),
			     response->measurement_sha256,
			     sizeof(response->measurement_sha256));
}

static void fill_guest_response(struct oc_ta_guest_response *response)
{
	memset(response, 0, sizeof(*response));
	copy_text(response->adaptor, sizeof(response->adaptor), KEYSTONE_ADAPTOR);
	copy_text(response->platform, sizeof(response->platform), KEYSTONE_PLATFORM);
	copy_text(response->guest_id, sizeof(response->guest_id),
		  env_or_default("KEYSTONE_GUEST_ID", KEYSTONE_GUEST_ID));
	copy_text(response->service_name, sizeof(response->service_name),
		  env_or_default("KEYSTONE_SERVICE_NAME",
				 KEYSTONE_SERVICE_NAME));
	copy_text(response->attestation_mode,
		  sizeof(response->attestation_mode),
		  env_or_default("KEYSTONE_ATTESTATION_MODE",
				 KEYSTONE_ATTESTATION_MODE));
	copy_text(response->ta_uuid, sizeof(response->ta_uuid),
		  "not-applicable");
	response->attestation_ready = resolve_attestation_ready() ? 1 : 0;
	fill_common_identity(response->world_id, sizeof(response->world_id),
			     response->measurement_sha256,
			     sizeof(response->measurement_sha256));
}

static void run_healthz(void)
{
	struct oc_ta_health_response response;

	fill_healthz_response(&response);
	print_healthz_json(&response);
}

static void run_guest(void)
{
	struct oc_ta_guest_response response;

	fill_guest_response(&response);
	print_guest_json(&response);
}

static void run_authorize(int argc, char *argv[])
{
	struct oc_ta_authorize_request request;
	struct oc_ta_authorize_response response;

	memset(&request, 0, sizeof(request));
	copy_text(request.req_id, sizeof(request.req_id),
		  find_option(argc, argv, "--req-id", "req-keystone-example"));
	copy_text(request.sid, sizeof(request.sid),
		  find_option(argc, argv, "--sid", "sid-keystone-example"));
	copy_text(request.tool_name, sizeof(request.tool_name),
		  find_option(argc, argv, "--tool-name", "exec"));
	copy_text(request.action, sizeof(request.action),
		  find_option(argc, argv, "--action", "exec"));
	copy_text(request.object, sizeof(request.object),
		  find_option(argc, argv, "--object",
			      "echo hello from keystone"));
	copy_text(request.requested_level, sizeof(request.requested_level),
		  find_option(argc, argv, "--level", "L2"));
	copy_text(request.normalized_scope_digest,
		  sizeof(request.normalized_scope_digest),
		  find_option(argc, argv, "--normalized-scope-digest",
			      "sha256:keystone-example-scope"));
	copy_text(request.scope_raw, sizeof(request.scope_raw),
		  find_option(argc, argv, "--scope-json", "{}"));
	copy_text(request.workspace_root, sizeof(request.workspace_root),
		  find_option(argc, argv, "--workspace-root", ""));
	copy_text(request.session_binding, sizeof(request.session_binding),
		  find_option(argc, argv, "--session-binding", ""));
	request.seq = find_option_u32(argc, argv, "--seq", 1);
	request.ttl_ms = find_option_u32(argc, argv, "--ttl-ms", 15000);

	fill_authorize_response(&request, &response);
	print_authorize_json(&request, &response);
}

static void run_confirm(int argc, char *argv[])
{
	struct oc_ta_confirm_response response;

	fill_confirm_response(argc, argv, &response);
	print_confirm_json(&response);
}

static void run_complete(int argc, char *argv[])
{
	struct oc_ta_complete_response response;

	fill_complete_response(argc, argv, &response);
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
		"             [--req-id ID] [--sid SID] [--tool-name NAME]\n"
		"             [--action ACTION] [--object TEXT] [--level L2]\n"
		"             [--normalized-scope-digest DIGEST]\n"
		"             [--scope-json JSON] [--workspace-root PATH]\n"
		"             [--session-binding ID] [--seq 1] [--ttl-ms 15000]\n"
		"  %s complete [--req-id ID] [--sid SID] [--tool-name NAME]\n"
		"              [--action ACTION] [--object TEXT] [--status ok]\n"
		"              [--result-digest DIGEST]\n",
		argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "healthz") == 0 || strcmp(argv[1], "health") == 0) {
		run_healthz();
	} else if (strcmp(argv[1], "guest") == 0) {
		run_guest();
	} else if (strcmp(argv[1], "authorize") == 0) {
		run_authorize(argc, argv);
	} else if (strcmp(argv[1], "confirm") == 0) {
		run_confirm(argc, argv);
	} else if (strcmp(argv[1], "complete") == 0) {
		run_complete(argc, argv);
	} else {
		usage(argv[0]);
		return 1;
	}

	return 0;
}
