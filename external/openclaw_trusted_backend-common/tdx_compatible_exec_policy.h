/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef OPENCLAW_TDX_COMPATIBLE_EXEC_POLICY_H
#define OPENCLAW_TDX_COMPATIBLE_EXEC_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef OC_POLICY_MAX_TOKEN_COUNT
#define OC_POLICY_MAX_TOKEN_COUNT 32
#endif

#ifndef OC_POLICY_MAX_TOKEN_LEN
#define OC_POLICY_MAX_TOKEN_LEN 256
#endif

#ifndef OC_POLICY_MAX_TARGET_COUNT
#define OC_POLICY_MAX_TARGET_COUNT 32
#endif

#ifndef OC_POLICY_MAX_PATH_LEN
#define OC_POLICY_MAX_PATH_LEN 256
#endif

#ifndef OC_POLICY_MAX_SCOPE_VALUE
#define OC_POLICY_MAX_SCOPE_VALUE 64
#endif

enum oc_policy_risk_level {
	OC_POLICY_RISK_L0 = 0,
	OC_POLICY_RISK_L1 = 1,
	OC_POLICY_RISK_L2 = 2,
	OC_POLICY_RISK_L3 = 3,
};

enum oc_policy_command_class {
	OC_POLICY_COMMAND_NONE = 0,
	OC_POLICY_COMMAND_LOW_RISK = 1,
	OC_POLICY_COMMAND_MEDIUM_READ = 2,
	OC_POLICY_COMMAND_MEDIUM_MODIFY = 3,
	OC_POLICY_COMMAND_HIGH_RISK = 4,
	OC_POLICY_COMMAND_UNKNOWN = 5,
	OC_POLICY_COMMAND_SHELL_COMPOUND = 6,
};

enum oc_policy_object_classification {
	OC_POLICY_OBJECT_ORDINARY = 0,
	OC_POLICY_OBJECT_SENSITIVE = 1,
	OC_POLICY_OBJECT_CRITICAL = 2,
};

struct oc_policy_request_view {
	const char *sid;
	const char *action;
	const char *object;
	const char *requested_level;
	const char *scope_raw;
	const char *workspace_root;
	const char *session_binding;
};

struct oc_policy_result {
	bool allow;
	bool requires_confirmation;
	bool nonce_bound;
	const char *decision;
	const char *level;
	const char *execution_mode;
	const char *reason;
	const char *matched_rule_id;
	const char *action_risk_level;
	const char *action_risk_reason;
	const char *object_risk_level;
	const char *object_risk_reason;
	const char *context_risk_level;
	const char *context_risk_reason;
	const char *effect_risk_level;
	const char *effect_risk_reason;
};

struct oc_policy_assessment {
	enum oc_policy_risk_level level;
	const char *reason;
	const char *matched_rule_id;
};

struct oc_policy_action_assessment {
	struct oc_policy_assessment base;
	enum oc_policy_command_class command_class;
};

struct oc_policy_object_assessment {
	struct oc_policy_assessment base;
	enum oc_policy_object_classification classification;
};

struct oc_policy_context_assessment {
	struct oc_policy_assessment base;
	bool multi_step;
	bool outside_workspace;
	bool remote_target;
	bool shell_wrapper;
	bool user_absent;
	size_t target_count;
};

struct oc_policy_effect_assessment {
	struct oc_policy_assessment base;
	bool destructive;
	bool export_like;
	bool persistence;
	bool privilege_mutation;
};

struct oc_policy_pattern_match {
	bool matched;
	enum oc_policy_risk_level level;
	const char *decision;
	const char *reason;
	const char *matched_rule_id;
};

struct oc_policy_confirmation_requirement {
	bool required;
	const char *reason;
	const char *matched_rule_id;
	const char *execution_mode;
};

struct oc_policy_exec_context {
	char raw_command[OC_POLICY_MAX_TOKEN_LEN];
	char cwd[OC_POLICY_MAX_PATH_LEN];
	char workspace_root[OC_POLICY_MAX_PATH_LEN];
	char match_mode[OC_POLICY_MAX_SCOPE_VALUE];
	char base_command[OC_POLICY_MAX_SCOPE_VALUE];
	char tokens[OC_POLICY_MAX_TOKEN_COUNT][OC_POLICY_MAX_TOKEN_LEN];
	size_t token_count;
	char targets[OC_POLICY_MAX_TARGET_COUNT][OC_POLICY_MAX_PATH_LEN];
	size_t target_count;
	bool shell_exact;
	bool has_session;
};

#ifndef OC_POLICY_ALLOC_EXEC_CONTEXT
#define OC_POLICY_ALLOC_EXEC_CONTEXT(name)                                \
	struct oc_policy_exec_context name##_storage;                     \
	struct oc_policy_exec_context *name = &name##_storage
#endif

#ifndef OC_POLICY_FREE_EXEC_CONTEXT
#define OC_POLICY_FREE_EXEC_CONTEXT(name) \
	do {                              \
		(void)(name);             \
	} while (0)
#endif

static const char *oc_policy_level_name(enum oc_policy_risk_level level)
{
	switch (level) {
	case OC_POLICY_RISK_L0:
		return "L0";
	case OC_POLICY_RISK_L1:
		return "L1";
	case OC_POLICY_RISK_L2:
		return "L2";
	case OC_POLICY_RISK_L3:
	default:
		return "L3";
	}
}

static enum oc_policy_risk_level
oc_policy_max_level(enum oc_policy_risk_level left,
			 enum oc_policy_risk_level right)
{
	return left > right ? left : right;
}

static size_t oc_policy_text_length(const char *text)
{
	size_t length = 0;

	if (!text)
		return 0;
	while (text[length])
		length++;
	return length;
}

static bool oc_policy_prefix_equals(const char *left, const char *right,
					 size_t length)
{
	size_t index = 0;

	if (!left || !right)
		return false;
	for (index = 0; index < length; index++) {
		if (left[index] != right[index])
			return false;
	}
	return true;
}

static const char *oc_policy_find_char(const char *text, char needle)
{
	size_t index = 0;

	if (!text)
		return NULL;
	while (text[index]) {
		if (text[index] == needle)
			return text + index;
		index++;
	}
	return NULL;
}

static const char *oc_policy_find_last_char(const char *text, char needle)
{
	const char *match = NULL;
	size_t index = 0;

	if (!text)
		return NULL;
	while (text[index]) {
		if (text[index] == needle)
			match = text + index;
		index++;
	}
	return match;
}

static const char *oc_policy_find_substring(const char *text,
						 const char *needle)
{
	size_t offset = 0;
	size_t needle_len = 0;

	if (!text || !needle || !needle[0])
		return NULL;
	needle_len = oc_policy_text_length(needle);
	for (offset = 0; text[offset]; offset++) {
		size_t index = 0;

		for (index = 0; index < needle_len; index++) {
			if (!text[offset + index] || text[offset + index] != needle[index])
				break;
		}
		if (index == needle_len)
			return text + offset;
	}
	return NULL;
}

static bool oc_policy_equals(const char *left, const char *right)
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

static int oc_policy_ascii_tolower(int value)
{
	if (value >= 'A' && value <= 'Z')
		return value - 'A' + 'a';
	return value;
}

static bool oc_policy_equals_ci(const char *left, const char *right)
{
	size_t index = 0;

	if (!left || !right)
		return false;
	while (left[index] && right[index]) {
		if (oc_policy_ascii_tolower(left[index]) !=
		    oc_policy_ascii_tolower(right[index]))
			return false;
		index++;
	}
	return left[index] == '\0' && right[index] == '\0';
}

static bool oc_policy_starts_with_ci(const char *text, const char *prefix)
{
	size_t index = 0;

	if (!text || !prefix)
		return false;
	while (prefix[index]) {
		if (!text[index] ||
		    oc_policy_ascii_tolower(text[index]) !=
			    oc_policy_ascii_tolower(prefix[index]))
			return false;
		index++;
	}
	return true;
}

static bool oc_policy_contains_ci(const char *haystack, const char *needle)
{
	size_t offset = 0;
	size_t index = 0;

	if (!haystack || !needle || !needle[0])
		return false;
	for (offset = 0; haystack[offset]; offset++) {
		for (index = 0; needle[index]; index++) {
			if (!haystack[offset + index] ||
			    oc_policy_ascii_tolower(haystack[offset + index]) !=
				    oc_policy_ascii_tolower(needle[index]))
				break;
		}
		if (!needle[index])
			return true;
	}
	return false;
}

static bool oc_policy_is_boundary_char(int value)
{
	if ((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z'))
		return false;
	if (value >= '0' && value <= '9')
		return false;
	return value != '_' && value != '.' && value != '/' && value != '~' &&
	       value != '-';
}

static bool oc_policy_has_word_token_ci(const char *text, const char *token)
{
	size_t token_len = 0;
	size_t offset = 0;

	if (!text || !token || !token[0])
		return false;
	token_len = oc_policy_text_length(token);
	for (offset = 0; text[offset]; offset++) {
		size_t index = 0;
		int before = offset > 0 ? text[offset - 1] : '\0';
		int after = '\0';

		if (offset > 0 && !oc_policy_is_boundary_char(before))
			continue;
		for (index = 0; index < token_len; index++) {
			if (!text[offset + index] ||
			    oc_policy_ascii_tolower(text[offset + index]) !=
				    oc_policy_ascii_tolower(token[index]))
				break;
		}
		if (index != token_len)
			continue;
		after = text[offset + token_len];
		if (!after || oc_policy_is_boundary_char(after))
			return true;
	}
	return false;
}

static bool oc_policy_command_contains_any_token(
	const char *text, const char *const *tokens, size_t count)
{
	size_t index = 0;

	for (index = 0; index < count; index++) {
		if (oc_policy_has_word_token_ci(text, tokens[index]))
			return true;
	}
	return false;
}

static bool oc_policy_in_list_ci(const char *value, const char *const *list,
				  size_t count)
{
	size_t index = 0;

	if (!value || !value[0])
		return false;
	for (index = 0; index < count; index++) {
		if (oc_policy_equals_ci(value, list[index]))
			return true;
	}
	return false;
}

static void oc_policy_copy_text(char *dst, size_t dst_len, const char *src)
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

static void oc_policy_normalize_slashes(char *text)
{
	size_t index = 0;

	if (!text)
		return;
	for (index = 0; text[index]; index++) {
		if (text[index] == '\\')
			text[index] = '/';
	}
}

static void oc_policy_trim_in_place(char *text)
{
	size_t start = 0;
	size_t end = 0;

	if (!text)
		return;
	end = oc_policy_text_length(text);
	while (text[start] == ' ' || text[start] == '\t' || text[start] == '\n' ||
	       text[start] == '\r')
		start++;
	while (end > start && (text[end - 1] == ' ' || text[end - 1] == '\t' ||
			       text[end - 1] == '\n' || text[end - 1] == '\r'))
		end--;
	if (start > 0)
		memmove(text, text + start, end - start);
	text[end - start] = '\0';
}

static bool oc_policy_extract_json_string(const char *json, const char *field,
					      char *out, size_t out_len)
{
	char needle[64];
	const char *cursor = NULL;

	if (!out || !out_len) {
		return false;
	}
	out[0] = '\0';
	if (!json || !field)
		return false;

	needle[0] = '"';
	oc_policy_copy_text(needle + 1, sizeof(needle) - 2, field);
	{
		size_t needle_len = oc_policy_text_length(needle);

		if (needle_len + 1 >= sizeof(needle))
			return false;
		needle[needle_len] = '"';
		needle[needle_len + 1] = '\0';
	}
	cursor = oc_policy_find_substring(json, needle);
	while (cursor) {
		const char *value = cursor + oc_policy_text_length(needle);
		size_t offset = 0;
		bool escaped = false;

		while (*value == ' ' || *value == '\t' || *value == '\n' ||
		       *value == '\r')
			value++;
		if (*value != ':') {
			cursor = oc_policy_find_substring(cursor + 1, needle);
			continue;
		}
		value++;
		while (*value == ' ' || *value == '\t' || *value == '\n' ||
		       *value == '\r')
			value++;
		if (*value != '"')
			return false;
		value++;
		while (*value) {
			char ch = *value++;

			if (escaped) {
				if (offset + 1 < out_len)
					out[offset++] = ch;
				escaped = false;
				continue;
			}
			if (ch == '\\') {
				escaped = true;
				continue;
			}
			if (ch == '"')
				break;
			if (offset + 1 < out_len)
				out[offset++] = ch;
		}
		out[offset] = '\0';
		return true;
	}

	return false;
}

static bool oc_policy_is_url(const char *value)
{
	return oc_policy_starts_with_ci(value, "http://") ||
	       oc_policy_starts_with_ci(value, "https://");
}

static bool oc_policy_is_remote_spec(const char *value)
{
	const char *at = NULL;
	const char *colon = NULL;
	const char *slash = NULL;

	if (!value || !value[0])
		return false;
	at = oc_policy_find_char(value, '@');
	colon = oc_policy_find_char(value, ':');
	slash = oc_policy_find_char(value, '/');
	if (!at || !colon || at >= colon)
		return false;
	return !slash || slash > colon;
}

static bool oc_policy_is_redirection_token(const char *value)
{
	return oc_policy_equals(value, ">") || oc_policy_equals(value, ">>") ||
	       oc_policy_equals(value, "1>") || oc_policy_equals(value, "1>>") ||
	       oc_policy_equals(value, "2>") || oc_policy_equals(value, "2>>") ||
	       oc_policy_equals(value, "<") || oc_policy_equals(value, "0<");
}

static bool oc_policy_has_inline_redirection_target(const char *value)
{
	const char *cursor = value;

	if (!value || !value[0])
		return false;

	while (*cursor >= '0' && *cursor <= '9')
		cursor++;
	if (*cursor != '<' && *cursor != '>')
		return false;
	cursor++;
	if (*(cursor - 1) == '>' && *cursor == '>')
		cursor++;
	if (!*cursor || *cursor == '<' || *cursor == '>')
		return false;
	return true;
}

static bool oc_policy_extract_inline_redirection_target(const char *value,
						 char *out, size_t out_len)
{
	const char *cursor = value;
	size_t offset = 0;

	if (!value || !value[0] || !out || !out_len)
		return false;
	out[0] = '\0';

	while (*cursor >= '0' && *cursor <= '9')
		cursor++;
	if (*cursor != '<' && *cursor != '>')
		return false;
	cursor++;
	if (*(cursor - 1) == '>' && *cursor == '>')
		cursor++;
	if (!*cursor || *cursor == '<' || *cursor == '>')
		return false;
	while (*cursor && offset + 1 < out_len)
		out[offset++] = *cursor++;
	out[offset] = '\0';
	oc_policy_trim_in_place(out);
	return out[0] != '\0';
}

static bool oc_policy_resolve_path_target(const char *target, const char *cwd,
					      char *out, size_t out_len)
{
	if (!target || !target[0] || !out || !out_len)
		return false;
	if (target[0] == '-' || oc_policy_is_url(target) ||
	    oc_policy_is_remote_spec(target))
		return false;
	if (oc_policy_starts_with_ci(target, "~/")) {
		oc_policy_copy_text(out, out_len, target);
		oc_policy_normalize_slashes(out);
		return true;
	}
	if (target[0] == '/') {
		oc_policy_copy_text(out, out_len, target);
		oc_policy_normalize_slashes(out);
		return true;
	}
	if (cwd && cwd[0]) {
		size_t cwd_len = 0;
		size_t target_len = 0;

		oc_policy_copy_text(out, out_len, cwd);
		cwd_len = oc_policy_text_length(out);
		if (cwd_len + 1 >= out_len)
			return false;
		out[cwd_len++] = '/';
		out[cwd_len] = '\0';
		target_len = oc_policy_text_length(target);
		if (cwd_len + target_len + 1 > out_len)
			return false;
		oc_policy_copy_text(out + cwd_len, out_len - cwd_len, target);
		oc_policy_normalize_slashes(out);
		return true;
	}
	oc_policy_copy_text(out, out_len, target);
	oc_policy_normalize_slashes(out);
	return true;
}

static const char *oc_policy_basename(const char *value)
{
	const char *slash = NULL;

	if (!value || !value[0])
		return "";
	slash = oc_policy_find_last_char(value, '/');
	return slash ? slash + 1 : value;
}

static bool oc_policy_has_hidden_segment(const char *value)
{
	const char *segment = value;
	const char *cursor = value;

	if (!value)
		return false;
	while (1) {
		if (*cursor == '/' || *cursor == '\0') {
			if (cursor > segment && segment[0] == '.' &&
			    !(cursor - segment == 1))
				return true;
			if (*cursor == '\0')
				return false;
			segment = cursor + 1;
		}
		cursor++;
	}
}

static bool oc_policy_is_within_workspace(const char *target,
					      const char *workspace_root)
{
	size_t root_len = 0;

	if (!target || !target[0] || !workspace_root || !workspace_root[0] ||
	    oc_policy_starts_with_ci(target, "~/"))
		return false;
	root_len = oc_policy_text_length(workspace_root);
	if (!oc_policy_prefix_equals(target, workspace_root, root_len))
		return false;
	return target[root_len] == '\0' || target[root_len] == '/';
}

static size_t oc_policy_tokenize_command(const char *command,
					     char tokens[][OC_POLICY_MAX_TOKEN_LEN],
					     size_t max_tokens)
{
	bool in_single = false;
	bool in_double = false;
	bool escaped = false;
	size_t count = 0;
	size_t offset = 0;
	size_t index = 0;

	if (!command || !command[0] || !tokens || max_tokens == 0)
		return 0;
	for (index = 0; command[index]; index++) {
		char ch = command[index];

		if (escaped) {
			if (count < max_tokens && offset + 1 < OC_POLICY_MAX_TOKEN_LEN)
				tokens[count][offset++] = ch;
			escaped = false;
			continue;
		}
		if (!in_single && ch == '\\') {
			escaped = true;
			continue;
		}
		if (!in_double && ch == '\'') {
			in_single = !in_single;
			continue;
		}
		if (!in_single && ch == '"') {
			in_double = !in_double;
			continue;
		}
		if (!in_single && !in_double &&
		    (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r')) {
			if (offset > 0 && count < max_tokens) {
				tokens[count][offset] = '\0';
				count++;
				offset = 0;
			}
			continue;
		}
		if (count < max_tokens && offset + 1 < OC_POLICY_MAX_TOKEN_LEN)
			tokens[count][offset++] = ch;
	}
	if (offset > 0 && count < max_tokens) {
		tokens[count][offset] = '\0';
		count++;
	}
	return count;
}

static bool oc_policy_is_shell_compound(const char *raw_command)
{
	bool in_single = false;
	bool in_double = false;
	bool escaped = false;
	size_t index = 0;
	char head[32];
	size_t head_len = 0;
	const char *keywords[] = { "(",  ":",      "case", "for", "function",
				   "if", "select", "time", "until", "while",
				   "{" };

	if (!raw_command || !raw_command[0])
		return false;

	while (raw_command[index] == ' ' || raw_command[index] == '\t' ||
	       raw_command[index] == '\n' || raw_command[index] == '\r' ||
	       raw_command[index] == '(' || raw_command[index] == '{')
		index++;
	while (raw_command[index] && raw_command[index] != ' ' &&
	       raw_command[index] != '\t' && raw_command[index] != '\n' &&
	       raw_command[index] != '\r' && raw_command[index] != ';' &&
	       raw_command[index] != ')' && raw_command[index] != '}' &&
	       head_len + 1 < sizeof(head)) {
		head[head_len++] = raw_command[index++];
	}
	head[head_len] = '\0';
	if (oc_policy_in_list_ci(head, keywords,
				 sizeof(keywords) / sizeof(keywords[0])))
		return true;

	for (index = 0; raw_command[index]; index++) {
		char ch = raw_command[index];
		char next = raw_command[index + 1];

		if (escaped) {
			escaped = false;
			continue;
		}
		if (!in_single && ch == '\\') {
			escaped = true;
			continue;
		}
		if (!in_double && ch == '\'') {
			in_single = !in_single;
			continue;
		}
		if (!in_single && ch == '"') {
			in_double = !in_double;
			continue;
		}
		if (in_single || in_double)
			continue;
		if (ch == ';' || ch == '\n' || ch == '\r')
			return true;
		if (ch == '|' || ch == '&') {
			if (next == ch || ch == '|')
				return true;
		}
	}
	return false;
}

static bool oc_policy_add_unique_target(char targets[][OC_POLICY_MAX_PATH_LEN],
					    size_t *count, const char *value)
{
	size_t index = 0;

	if (!targets || !count || !value || !value[0])
		return false;
	for (index = 0; index < *count; index++) {
		if (oc_policy_equals(targets[index], value))
			return true;
	}
	if (*count >= OC_POLICY_MAX_TARGET_COUNT)
		return false;
	oc_policy_copy_text(targets[*count], OC_POLICY_MAX_PATH_LEN, value);
	(*count)++;
	return true;
}

static void oc_policy_collect_targets(struct oc_policy_exec_context *context)
{
	static const char *const redirection_only_commands[] = {
		"echo", "false", "printf", "pwd", "true",
	};
	const char *positional[OC_POLICY_MAX_TOKEN_COUNT];
	size_t positional_count = 0;
	size_t index = 0;
	int skip_leading_operands = 0;
	bool after_double_dash = false;

	if (!context)
		return;
	context->target_count = 0;
	if (context->shell_exact || context->token_count == 0)
		return;

	if (oc_policy_equals_ci(context->base_command, "awk") ||
	    oc_policy_equals_ci(context->base_command, "chmod") ||
	    oc_policy_equals_ci(context->base_command, "chown") ||
	    oc_policy_equals_ci(context->base_command, "grep") ||
	    oc_policy_equals_ci(context->base_command, "sed")) {
		skip_leading_operands = 1;
	}

	for (index = 1; index < context->token_count; index++) {
		const char *value = context->tokens[index];
		char target[OC_POLICY_MAX_PATH_LEN];
		char inline_target[OC_POLICY_MAX_PATH_LEN];

		if (!value[0])
			continue;
		if (oc_policy_is_redirection_token(value)) {
			if (index + 1 < context->token_count &&
			    oc_policy_resolve_path_target(
				    context->tokens[index + 1], context->cwd,
				    target, sizeof(target)))
				oc_policy_add_unique_target(context->targets,
							    &context->target_count,
							    target);
			index++;
			continue;
		}
		if (oc_policy_extract_inline_redirection_target(
			    value, inline_target, sizeof(inline_target))) {
			if (oc_policy_resolve_path_target(inline_target, context->cwd,
						 target, sizeof(target)))
				oc_policy_add_unique_target(context->targets,
							    &context->target_count,
							    target);
			continue;
		}
	}

	if (!oc_policy_in_list_ci(context->base_command, redirection_only_commands,
				   sizeof(redirection_only_commands) /
					   sizeof(redirection_only_commands[0]))) {
		for (index = 1; index < context->token_count; index++) {
			const char *value = context->tokens[index];

			if (!value[0])
				continue;
			if (oc_policy_is_redirection_token(value)) {
				index++;
				continue;
			}
			if (oc_policy_has_inline_redirection_target(value))
				continue;
			if (!after_double_dash && oc_policy_equals(value, "--")) {
				after_double_dash = true;
				continue;
			}
			if (!after_double_dash && value[0] == '-')
				continue;
			positional[positional_count++] = value;
		}
	}

	for (index = 0; index < positional_count; index++) {
		char target[OC_POLICY_MAX_PATH_LEN];

		if ((int)index < skip_leading_operands)
			continue;
		if (oc_policy_resolve_path_target(positional[index], context->cwd,
					      target, sizeof(target)))
			oc_policy_add_unique_target(context->targets,
						    &context->target_count,
						    target);
	}

	if (context->target_count == 0 && context->cwd[0])
		oc_policy_add_unique_target(context->targets,
					    &context->target_count,
					    context->cwd);
}

static void oc_policy_init_exec_context(const struct oc_policy_request_view *request,
					      struct oc_policy_exec_context *context)
{
	memset(context, 0, sizeof(*context));
	if (!request)
		return;

	oc_policy_copy_text(context->raw_command, sizeof(context->raw_command),
			    request->object);
	oc_policy_copy_text(context->workspace_root,
			    sizeof(context->workspace_root), "");
	if (request->scope_raw && request->scope_raw[0]) {
		oc_policy_extract_json_string(request->scope_raw, "cwd",
					      context->cwd, sizeof(context->cwd));
		oc_policy_extract_json_string(request->scope_raw, "matchMode",
					      context->match_mode,
					      sizeof(context->match_mode));
	}
	if (request->workspace_root && request->workspace_root[0]) {
		oc_policy_copy_text(context->workspace_root,
				    sizeof(context->workspace_root),
				    request->workspace_root);
	} else if (context->cwd[0]) {
		oc_policy_copy_text(context->workspace_root,
				    sizeof(context->workspace_root),
				    context->cwd);
	}

	context->has_session =
		(request->session_binding && request->session_binding[0]) ||
		(request->sid && request->sid[0] &&
		 !oc_policy_equals_ci(request->sid, "anonymous"));
	context->shell_exact =
		oc_policy_equals(context->match_mode, "shell-exact") ||
		oc_policy_is_shell_compound(context->raw_command);
	if (context->shell_exact) {
		oc_policy_copy_text(context->base_command,
				    sizeof(context->base_command),
				    "shell-compound");
		return;
	}

	context->token_count = oc_policy_tokenize_command(
		context->raw_command, context->tokens,
		sizeof(context->tokens) / sizeof(context->tokens[0]));
	if (context->token_count > 0)
		oc_policy_copy_text(context->base_command,
				    sizeof(context->base_command),
				    context->tokens[0]);
	oc_policy_collect_targets(context);
}

static struct oc_policy_action_assessment
oc_policy_classify_action(const struct oc_policy_request_view *request,
			      const struct oc_policy_exec_context *context)
{
	static const char *const low_risk_commands[] = {
		"cut",   "echo", "false", "head", "ls",   "printf",
		"pwd",   "sort", "tail",  "tr",   "true", "uniq",
		"wc",
	};
	static const char *const medium_read_commands[] = {
		"cat", "find", "grep",
	};
	static const char *const medium_modify_commands[] = {
		"awk", "chmod", "cp",  "mkdir", "mv",  "sed", "tar",
		"zip",
	};
	static const char *const high_risk_commands[] = {
		"bash", "curl", "dd",   "iptables", "mount", "nc",
		"ncat", "node", "perl", "python",   "rm",    "rsync",
		"scp",  "service", "sh", "ssh",      "su",    "sudo",
		"systemctl", "ufw", "umount", "wget", "zsh",
	};
	struct oc_policy_action_assessment result;

	(void)request;
	memset(&result, 0, sizeof(result));

	if (context->shell_exact) {
		result.base.level = OC_POLICY_RISK_L2;
		result.base.reason =
			"compound shell command requires isolated execution";
		result.base.matched_rule_id = "exec.action.shell-compound";
		result.command_class = OC_POLICY_COMMAND_SHELL_COMPOUND;
		return result;
	}
	if (oc_policy_in_list_ci(context->base_command, low_risk_commands,
				   sizeof(low_risk_commands) /
					   sizeof(low_risk_commands[0]))) {
		result.base.level = OC_POLICY_RISK_L1;
		result.base.reason = "low-risk exec command";
		result.base.matched_rule_id = "exec.action.low-risk";
		result.command_class = OC_POLICY_COMMAND_LOW_RISK;
		return result;
	}
	if (oc_policy_in_list_ci(context->base_command, medium_read_commands,
				   sizeof(medium_read_commands) /
					   sizeof(medium_read_commands[0]))) {
		result.base.level = OC_POLICY_RISK_L1;
		result.base.reason = "read-like exec command";
		result.base.matched_rule_id = "exec.action.medium-read";
		result.command_class = OC_POLICY_COMMAND_MEDIUM_READ;
		return result;
	}
	if (oc_policy_in_list_ci(context->base_command, medium_modify_commands,
				   sizeof(medium_modify_commands) /
					   sizeof(medium_modify_commands[0]))) {
		result.base.level = OC_POLICY_RISK_L2;
		result.base.reason = "state-modifying exec command";
		result.base.matched_rule_id = "exec.action.medium-modify";
		result.command_class = OC_POLICY_COMMAND_MEDIUM_MODIFY;
		return result;
	}
	if (oc_policy_in_list_ci(context->base_command, high_risk_commands,
				   sizeof(high_risk_commands) /
					   sizeof(high_risk_commands[0]))) {
		result.base.level = OC_POLICY_RISK_L3;
		result.base.reason = "high-risk exec command";
		result.base.matched_rule_id = "exec.action.high-risk";
		result.command_class = OC_POLICY_COMMAND_HIGH_RISK;
		return result;
	}

	result.base.level = OC_POLICY_RISK_L2;
	result.base.reason = "unclassified exec command";
	result.base.matched_rule_id = "exec.action.unknown";
	result.command_class = OC_POLICY_COMMAND_UNKNOWN;
	return result;
}

static struct oc_policy_object_assessment
oc_policy_classify_object(const struct oc_policy_exec_context *context)
{
	static const char *const critical_prefixes[] = {
		"/etc", "/var/lib", "~/.aws", "~/.config/gcloud", "~/.ssh",
	};
	static const char *const sensitive_prefixes[] = {
		"/home", "/root", "~/.config",
	};
	static const char *const protected_keywords[] = {
		"credential", "private_key", "secret", "token",
		"auth",       "private",     "ssh",
	};
	static const char *const sensitive_filenames[] = {
		".env", "config.json", "config.yaml", "settings.json",
	};
	struct oc_policy_object_assessment result;
	size_t index = 0;

	memset(&result, 0, sizeof(result));

	if (context->shell_exact) {
		size_t prefix_index = 0;
		size_t keyword_index = 0;
		bool critical_prefix = false;
		bool protected_keyword = false;
		size_t sensitive_index = 0;
		bool sensitive_prefix = false;
		bool sensitive_filename = false;

		for (prefix_index = 0;
		     prefix_index <
		     sizeof(critical_prefixes) / sizeof(critical_prefixes[0]);
		     prefix_index++) {
			if (oc_policy_contains_ci(context->raw_command,
						  critical_prefixes[prefix_index])) {
				critical_prefix = true;
				break;
			}
		}
		for (keyword_index = 0;
		     keyword_index < sizeof(protected_keywords) /
					  sizeof(protected_keywords[0]);
		     keyword_index++) {
			if (oc_policy_contains_ci(context->raw_command,
						  protected_keywords[keyword_index])) {
				protected_keyword = true;
				break;
			}
		}
		if (critical_prefix || protected_keyword) {
			result.base.level = OC_POLICY_RISK_L3;
			result.base.reason =
				"critical object referenced from shell compound";
			result.base.matched_rule_id =
				"object.critical.shell-compound";
			result.classification = OC_POLICY_OBJECT_CRITICAL;
			return result;
		}
		for (sensitive_index = 0;
		     sensitive_index < sizeof(sensitive_prefixes) /
					  sizeof(sensitive_prefixes[0]);
		     sensitive_index++) {
			if (oc_policy_contains_ci(context->raw_command,
						  sensitive_prefixes[sensitive_index])) {
				sensitive_prefix = true;
				break;
			}
		}
		for (sensitive_index = 0;
		     sensitive_index < sizeof(sensitive_filenames) /
					  sizeof(sensitive_filenames[0]);
		     sensitive_index++) {
			if (oc_policy_has_word_token_ci(context->raw_command,
							sensitive_filenames[sensitive_index])) {
				sensitive_filename = true;
				break;
			}
		}
		if (sensitive_prefix || sensitive_filename) {
			result.base.level = OC_POLICY_RISK_L2;
			result.base.reason =
				"sensitive object referenced from shell compound";
			result.base.matched_rule_id =
				"object.sensitive.shell-compound";
			result.classification = OC_POLICY_OBJECT_SENSITIVE;
			return result;
		}
		result.base.level = OC_POLICY_RISK_L0;
		result.base.reason = "ordinary workspace object target";
		result.base.matched_rule_id = "object.ordinary.workspace";
		result.classification = OC_POLICY_OBJECT_ORDINARY;
		return result;
	}

	for (index = 0; index < context->target_count; index++) {
		const char *target = context->targets[index];
		size_t prefix_index = 0;
		size_t keyword_index = 0;
		bool critical_prefix = false;
		bool protected_keyword = false;

		for (prefix_index = 0;
		     prefix_index <
		     sizeof(critical_prefixes) / sizeof(critical_prefixes[0]);
		     prefix_index++) {
			if (oc_policy_starts_with_ci(target,
						     critical_prefixes[prefix_index])) {
				critical_prefix = true;
				break;
			}
		}
		for (keyword_index = 0;
		     keyword_index < sizeof(protected_keywords) /
					  sizeof(protected_keywords[0]);
		     keyword_index++) {
			if (oc_policy_contains_ci(target,
						  protected_keywords[keyword_index])) {
				protected_keyword = true;
				break;
			}
		}
		if (critical_prefix || protected_keyword) {
			result.base.level = OC_POLICY_RISK_L3;
			result.base.reason = "critical object target";
			result.base.matched_rule_id =
				"object.critical.protected-path";
			result.classification = OC_POLICY_OBJECT_CRITICAL;
			return result;
		}
	}

	for (index = 0; index < context->target_count; index++) {
		const char *target = context->targets[index];
		const char *base = oc_policy_basename(target);
		bool inside_workspace =
			oc_policy_is_within_workspace(target,
						      context->workspace_root);
		bool outside_workspace =
			context->workspace_root[0] && !inside_workspace;
		bool sensitive_prefix = false;
		bool sensitive_filename = false;
		size_t prefix_index = 0;
		size_t file_index = 0;

		for (prefix_index = 0;
		     prefix_index <
		     sizeof(sensitive_prefixes) / sizeof(sensitive_prefixes[0]);
		     prefix_index++) {
			if ((!context->workspace_root[0] || outside_workspace) &&
			    oc_policy_starts_with_ci(target,
						     sensitive_prefixes[prefix_index])) {
				sensitive_prefix = true;
				break;
			}
		}
		for (file_index = 0;
		     file_index < sizeof(sensitive_filenames) /
					  sizeof(sensitive_filenames[0]);
		     file_index++) {
			if (oc_policy_equals_ci(base, sensitive_filenames[file_index])) {
				sensitive_filename = true;
				break;
			}
		}
		if (oc_policy_has_hidden_segment(target) || outside_workspace ||
		    sensitive_prefix || sensitive_filename) {
			result.base.level = OC_POLICY_RISK_L2;
			result.base.reason = "sensitive object target";
			if (oc_policy_has_hidden_segment(target))
				result.base.matched_rule_id =
					"object.sensitive.hidden-path";
			else if (sensitive_filename)
				result.base.matched_rule_id =
					"object.sensitive.filename";
			else if (outside_workspace)
				result.base.matched_rule_id =
					"object.sensitive.non-workspace";
			else
				result.base.matched_rule_id =
					"object.sensitive.user-path";
			result.classification = OC_POLICY_OBJECT_SENSITIVE;
			return result;
		}
	}

	result.base.level = OC_POLICY_RISK_L0;
	result.base.reason = "ordinary workspace object target";
	result.base.matched_rule_id = "object.ordinary.workspace";
	result.classification = OC_POLICY_OBJECT_ORDINARY;
	return result;
}

static bool oc_policy_contains_multistep_operator(const char *raw_command)
{
	size_t index = 0;
	bool in_single = false;
	bool in_double = false;
	bool escaped = false;

	if (!raw_command)
		return false;
	for (index = 0; raw_command[index]; index++) {
		char ch = raw_command[index];
		char next = raw_command[index + 1];

		if (escaped) {
			escaped = false;
			continue;
		}
		if (!in_single && ch == '\\') {
			escaped = true;
			continue;
		}
		if (!in_double && ch == '\'') {
			in_single = !in_single;
			continue;
		}
		if (!in_single && ch == '"') {
			in_double = !in_double;
			continue;
		}
		if (in_single || in_double)
			continue;
		if (ch == ';' || ch == '\n' || ch == '\r')
			return true;
		if ((ch == '&' || ch == '|') && next == ch)
			return true;
	}
	return false;
}

static struct oc_policy_context_assessment
oc_policy_classify_context(const struct oc_policy_exec_context *context,
			       const struct oc_policy_object_assessment *object_risk)
{
	static const char *const remote_commands[] = {
		"curl", "nc", "ncat", "rsync", "scp", "ssh", "wget",
	};
	struct oc_policy_context_assessment result;
	size_t index = 1;
	bool inline_code = false;
	bool remote_target = false;
	bool outside_workspace = false;

	(void)object_risk;
	memset(&result, 0, sizeof(result));
	result.multi_step = context->shell_exact ||
			    oc_policy_contains_multistep_operator(
				    context->raw_command);
	if ((oc_policy_equals_ci(context->base_command, "bash") ||
	     oc_policy_equals_ci(context->base_command, "sh") ||
	     oc_policy_equals_ci(context->base_command, "zsh"))) {
		result.shell_wrapper = true;
	}
	for (index = 1; index < context->token_count; index++) {
		const char *token = context->tokens[index];

		if ((oc_policy_equals_ci(context->base_command, "bash") ||
		     oc_policy_equals_ci(context->base_command, "sh") ||
		     oc_policy_equals_ci(context->base_command, "zsh")) &&
		    oc_policy_equals(token, "-c"))
			inline_code = true;
		if (oc_policy_equals_ci(context->base_command, "python") &&
		    oc_policy_equals(token, "-c"))
			inline_code = true;
		if ((oc_policy_equals_ci(context->base_command, "node") ||
		     oc_policy_equals_ci(context->base_command, "perl")) &&
		    oc_policy_equals(token, "-e"))
			inline_code = true;
		if (oc_policy_is_url(token) || oc_policy_is_remote_spec(token))
			remote_target = true;
	}
	result.shell_wrapper = result.shell_wrapper || inline_code;
	remote_target = remote_target ||
			oc_policy_in_list_ci(context->base_command, remote_commands,
					    sizeof(remote_commands) /
						    sizeof(remote_commands[0])) ||
			oc_policy_command_contains_any_token(
				context->raw_command, remote_commands,
				sizeof(remote_commands) /
					sizeof(remote_commands[0]));
	for (index = 0; index < context->target_count; index++) {
		if (context->workspace_root[0] &&
		    !oc_policy_is_within_workspace(context->targets[index],
						     context->workspace_root)) {
			outside_workspace = true;
			break;
		}
	}
	result.outside_workspace = outside_workspace;
	result.remote_target = remote_target;
	result.user_absent = !context->has_session;
	result.target_count = context->target_count;

	if (result.remote_target) {
		result.base.level = OC_POLICY_RISK_L3;
		result.base.reason = "remote target or remote transfer context";
		result.base.matched_rule_id = "context.remote-target";
		return result;
	}
	if (result.shell_wrapper) {
		result.base.level = OC_POLICY_RISK_L3;
		result.base.reason = "shell wrapper or inline interpreter context";
		result.base.matched_rule_id = "context.shell-wrapper";
		return result;
	}
	if (result.multi_step && result.outside_workspace) {
		result.base.level = OC_POLICY_RISK_L3;
		result.base.reason =
			"multi-step command spans outside the workspace";
		result.base.matched_rule_id =
			"context.multi-step.non-workspace";
		return result;
	}
	if (result.multi_step) {
		result.base.level = OC_POLICY_RISK_L2;
		result.base.reason = "multi-step command context";
		result.base.matched_rule_id = "context.multi-step";
		return result;
	}
	if (result.outside_workspace) {
		result.base.level = OC_POLICY_RISK_L2;
		result.base.reason = "non-workspace execution context";
		result.base.matched_rule_id = "context.non-workspace";
		return result;
	}
	if (result.user_absent || result.target_count > 1) {
		result.base.level = OC_POLICY_RISK_L1;
		result.base.reason =
			"reduced operator context or multi-target command";
		result.base.matched_rule_id = "context.reduced-operator";
		return result;
	}

	result.base.level = OC_POLICY_RISK_L0;
	result.base.reason = "ordinary workspace execution context";
	result.base.matched_rule_id = "context.workspace.ordinary";
	return result;
}

static struct oc_policy_effect_assessment
oc_policy_classify_effect(const struct oc_policy_exec_context *context,
			      const struct oc_policy_action_assessment *action_risk,
			      const struct oc_policy_object_assessment *object_risk,
			      const struct oc_policy_context_assessment *context_risk)
{
	static const char *const destructive_commands[] = {
		"chown", "dd",   "iptables", "mount",  "rm",
		"service", "sudo", "systemctl", "ufw", "umount",
	};
	static const char *const archive_commands[] = {
		"tar", "zip",
	};
	static const char *const persistence_commands[] = {
		"chmod", "cp", "mkdir", "mv", "sed", "tar", "zip",
	};
	static const char *const privilege_mutation_commands[] = {
		"chmod", "chown", "iptables", "mount", "service",
		"systemctl", "ufw",
	};
	static const char *const remote_commands[] = {
		"curl", "nc", "ncat", "rsync", "scp", "ssh", "wget",
	};
	struct oc_policy_effect_assessment result;
	bool destructive = false;
	bool export_like = false;
	bool privilege_mutation = false;
	bool persistence = false;

	memset(&result, 0, sizeof(result));

	destructive =
		oc_policy_in_list_ci(context->base_command, destructive_commands,
				     sizeof(destructive_commands) /
					     sizeof(destructive_commands[0])) ||
		oc_policy_command_contains_any_token(
			context->raw_command, destructive_commands,
			sizeof(destructive_commands) /
				sizeof(destructive_commands[0])) ||
		oc_policy_contains_ci(context->raw_command, "rm -rf");
	export_like =
		oc_policy_in_list_ci(context->base_command, remote_commands,
				     sizeof(remote_commands) /
					     sizeof(remote_commands[0])) ||
		oc_policy_in_list_ci(context->base_command, archive_commands,
				     sizeof(archive_commands) /
					     sizeof(archive_commands[0])) ||
		oc_policy_command_contains_any_token(
			context->raw_command, remote_commands,
			sizeof(remote_commands) /
				sizeof(remote_commands[0]));
	privilege_mutation =
		oc_policy_in_list_ci(context->base_command,
				     privilege_mutation_commands,
				     sizeof(privilege_mutation_commands) /
					     sizeof(privilege_mutation_commands[0])) ||
		(object_risk->classification == OC_POLICY_OBJECT_CRITICAL &&
		 (oc_policy_equals_ci(context->base_command, "chmod") ||
		  oc_policy_equals_ci(context->base_command, "chown")));
	persistence =
		oc_policy_in_list_ci(context->base_command, persistence_commands,
				     sizeof(persistence_commands) /
					     sizeof(persistence_commands[0])) ||
		(action_risk->command_class ==
			 OC_POLICY_COMMAND_MEDIUM_MODIFY &&
		 object_risk->classification != OC_POLICY_OBJECT_ORDINARY);

	result.destructive = destructive;
	result.export_like = export_like;
	result.persistence = persistence;
	result.privilege_mutation = privilege_mutation;

	if (destructive &&
	    object_risk->classification != OC_POLICY_OBJECT_ORDINARY) {
		result.base.level = OC_POLICY_RISK_L3;
		result.base.reason =
			"destructive effect against a sensitive or critical target";
		result.base.matched_rule_id =
			"effect.destructive.sensitive-target";
		return result;
	}
	if (export_like) {
		result.base.level = OC_POLICY_RISK_L3;
		result.base.reason =
			"data packaging, export, or remote transfer effect";
		result.base.matched_rule_id = "effect.export-or-archive";
		return result;
	}
	if (privilege_mutation) {
		result.base.level = OC_POLICY_RISK_L3;
		result.base.reason =
			"privilege or system-state mutation effect";
		result.base.matched_rule_id = "effect.privilege-mutation";
		return result;
	}
	if (destructive) {
		result.base.level = OC_POLICY_RISK_L2;
		result.base.reason = "destructive local effect";
		result.base.matched_rule_id = "effect.destructive.local";
		return result;
	}
	if (persistence) {
		result.base.level = OC_POLICY_RISK_L2;
		result.base.reason =
			"persistent filesystem or state mutation effect";
		result.base.matched_rule_id = "effect.persistence";
		return result;
	}
	if (action_risk->command_class == OC_POLICY_COMMAND_MEDIUM_READ) {
		result.base.level = OC_POLICY_RISK_L1;
		result.base.reason = "bounded read effect";
		result.base.matched_rule_id = "effect.read-bounded";
		return result;
	}

	(void)context_risk;
	result.base.level = OC_POLICY_RISK_L0;
	result.base.reason = "transient or low-impact effect";
	result.base.matched_rule_id = "effect.transient.low";
	return result;
}

static struct oc_policy_pattern_match
oc_policy_match_pattern(const struct oc_policy_exec_context *context,
			    const struct oc_policy_object_assessment *object_risk)
{
	struct oc_policy_pattern_match result;
	size_t index = 1;
	bool has_dash_c = false;
	bool has_dash_e = false;

	memset(&result, 0, sizeof(result));

	if ((oc_policy_contains_ci(context->raw_command, "curl") ||
	     oc_policy_contains_ci(context->raw_command, "wget")) &&
	    (oc_policy_contains_ci(context->raw_command, "| bash") ||
	     oc_policy_contains_ci(context->raw_command, "| sh") ||
	     oc_policy_contains_ci(context->raw_command, "| zsh"))) {
		result.matched = true;
		result.level = OC_POLICY_RISK_L3;
		result.decision = "ddeny";
		result.reason = "remote fetch execution is denied";
		result.matched_rule_id = "exec.pattern.remote-fetch-shell";
		return result;
	}

	for (index = 1; index < context->token_count; index++) {
		if (oc_policy_equals(context->tokens[index], "-c"))
			has_dash_c = true;
		if (oc_policy_equals(context->tokens[index], "-e"))
			has_dash_e = true;
	}

	if ((oc_policy_equals_ci(context->base_command, "bash") ||
	     oc_policy_equals_ci(context->base_command, "sh") ||
	     oc_policy_equals_ci(context->base_command, "zsh")) &&
	    has_dash_c) {
		result.matched = true;
		result.level = OC_POLICY_RISK_L3;
		result.decision = "ddeny";
		result.reason = "shell wrapper inline execution is denied";
		result.matched_rule_id = "exec.pattern.shell-inline";
		return result;
	}
	if ((oc_policy_equals_ci(context->base_command, "python") && has_dash_c) ||
	    (oc_policy_equals_ci(context->base_command, "node") && has_dash_e) ||
	    (oc_policy_equals_ci(context->base_command, "perl") && has_dash_e)) {
		result.matched = true;
		result.level = OC_POLICY_RISK_L3;
		result.decision = "ddeny";
		result.reason = "inline code execution is denied";
		result.matched_rule_id = "exec.pattern.inline-code";
		return result;
	}
	if (oc_policy_contains_ci(context->raw_command, "rm -rf")) {
		result.matched = true;
		result.level = OC_POLICY_RISK_L3;
		result.decision = "ddeny";
		result.reason = "destructive recursive removal is denied";
		result.matched_rule_id = "exec.pattern.rm-rf";
		return result;
	}
	if (object_risk->classification == OC_POLICY_OBJECT_CRITICAL &&
	    (oc_policy_equals_ci(context->base_command, "chmod") ||
	     oc_policy_equals_ci(context->base_command, "chown"))) {
		result.matched = true;
		result.level = OC_POLICY_RISK_L3;
		result.decision = "ddeny";
		result.reason = "system-path permission mutation is denied";
		result.matched_rule_id =
			"exec.pattern.system-permission-mutation";
	}
	return result;
}

static struct oc_policy_confirmation_requirement
oc_policy_confirmation_requirement_for(
	enum oc_policy_risk_level final_level,
	const struct oc_policy_exec_context *context,
	const struct oc_policy_object_assessment *object_risk,
	const struct oc_policy_effect_assessment *effect_risk)
{
	static const char *const confirmable_commands[] = {
		"rsync", "scp", "tar", "zip",
	};
	struct oc_policy_confirmation_requirement result;
	bool archive_command = false;

	memset(&result, 0, sizeof(result));
	archive_command = oc_policy_equals_ci(context->base_command, "tar") ||
			  oc_policy_equals_ci(context->base_command, "zip");
	if (final_level == OC_POLICY_RISK_L3 &&
	    !effect_risk->destructive &&
	    object_risk->classification != OC_POLICY_OBJECT_CRITICAL &&
	    (archive_command ||
	     (oc_policy_in_list_ci(context->base_command, confirmable_commands,
				     sizeof(confirmable_commands) /
					     sizeof(confirmable_commands[0])) &&
	      effect_risk->export_like))) {
		result.required = true;
		result.reason =
			"trusted user confirmation required for high-impact export or archival effect";
		result.matched_rule_id = "exec.confirm.high-impact-export";
		result.execution_mode = "ree-constrained";
	}
	return result;
}

static const struct oc_policy_assessment *
oc_policy_select_dominant_assessment(
	enum oc_policy_risk_level final_level,
	const struct oc_policy_effect_assessment *effect_risk,
	const struct oc_policy_context_assessment *context_risk,
	const struct oc_policy_object_assessment *object_risk,
	const struct oc_policy_action_assessment *action_risk)
{
	if (effect_risk->base.level == final_level)
		return &effect_risk->base;
	if (context_risk->base.level == final_level)
		return &context_risk->base;
	if (object_risk->base.level == final_level)
		return &object_risk->base;
	if (action_risk->base.level == final_level)
		return &action_risk->base;
	return &effect_risk->base;
}

static const char *oc_policy_execution_mode_for_decision(const char *decision)
{
	if (oc_policy_equals(decision, "dree"))
		return "ree-direct";
	if (oc_policy_equals(decision, "dia"))
		return "ree-constrained";
	if (oc_policy_equals(decision, "die"))
		return "isolated";
	return "ree-constrained";
}

static void oc_tdx_policy_evaluate(const struct oc_policy_request_view *request,
				       struct oc_policy_result *result)
{
	OC_POLICY_ALLOC_EXEC_CONTEXT(context);
	struct oc_policy_action_assessment action_risk;
	struct oc_policy_object_assessment object_risk;
	struct oc_policy_context_assessment context_risk;
	struct oc_policy_effect_assessment effect_risk;
	struct oc_policy_pattern_match pattern_match;
	struct oc_policy_confirmation_requirement confirmation;
	const struct oc_policy_assessment *dominant = NULL;
	enum oc_policy_risk_level final_level = OC_POLICY_RISK_L0;
	const char *final_decision = "dree";
	const char *final_reason = "ordinary workspace execution context";
	const char *matched_rule_id = "context.workspace.ordinary";
	const char *execution_mode = "ree-direct";

	memset(result, 0, sizeof(*result));
	if (!context) {
		result->decision = "ddeny";
		result->level = "L3";
		result->execution_mode = "isolated";
		result->reason = "policy evaluation context allocation failed";
		result->matched_rule_id = "context.alloc.failure";
		result->action_risk_level = "L3";
		result->action_risk_reason = result->reason;
		result->object_risk_level = "L3";
		result->object_risk_reason = result->reason;
		result->context_risk_level = "L3";
		result->context_risk_reason = result->reason;
		result->effect_risk_level = "L3";
		result->effect_risk_reason = result->reason;
		return;
	}

	oc_policy_init_exec_context(request, context);
	action_risk = oc_policy_classify_action(request, context);
	object_risk = oc_policy_classify_object(context);
	context_risk = oc_policy_classify_context(context, &object_risk);
	effect_risk = oc_policy_classify_effect(context, &action_risk,
						 &object_risk, &context_risk);
	pattern_match = oc_policy_match_pattern(context, &object_risk);

	final_level = oc_policy_max_level(action_risk.base.level,
					      object_risk.base.level);
	final_level = oc_policy_max_level(final_level, context_risk.base.level);
	final_level = oc_policy_max_level(final_level, effect_risk.base.level);
	if (pattern_match.matched)
		final_level = oc_policy_max_level(final_level, pattern_match.level);

	confirmation = oc_policy_confirmation_requirement_for(
		final_level, context, &object_risk, &effect_risk);
	dominant = oc_policy_select_dominant_assessment(
		final_level, &effect_risk, &context_risk, &object_risk,
		&action_risk);

	if (pattern_match.matched) {
		final_decision = pattern_match.decision;
		final_reason = pattern_match.reason;
		matched_rule_id = pattern_match.matched_rule_id;
		if (oc_policy_equals(final_decision, "ddeny")) {
			execution_mode =
				final_level == OC_POLICY_RISK_L0
					? "ree-direct"
					: final_level == OC_POLICY_RISK_L1
						  ? "ree-constrained"
						  : "isolated";
		} else {
			execution_mode =
				oc_policy_execution_mode_for_decision(final_decision);
		}
	} else if (confirmation.required) {
		final_decision = "duc";
		final_reason = confirmation.reason;
		matched_rule_id = confirmation.matched_rule_id;
		execution_mode = confirmation.execution_mode;
	} else {
		if (final_level == OC_POLICY_RISK_L0)
			final_decision = "dree";
		else if (final_level == OC_POLICY_RISK_L1)
			final_decision = "dia";
		else if (final_level == OC_POLICY_RISK_L2)
			final_decision = "die";
		else
			final_decision = "ddeny";
		final_reason = dominant->reason;
		matched_rule_id = dominant->matched_rule_id;
		if (oc_policy_equals(final_decision, "ddeny")) {
			execution_mode =
				final_level == OC_POLICY_RISK_L0
					? "ree-direct"
					: final_level == OC_POLICY_RISK_L1
						  ? "ree-constrained"
						  : "isolated";
		} else {
			execution_mode =
				oc_policy_execution_mode_for_decision(final_decision);
		}
	}

	result->allow = oc_policy_equals(final_decision, "dree") ||
			oc_policy_equals(final_decision, "dia") ||
			oc_policy_equals(final_decision, "die");
	result->requires_confirmation = oc_policy_equals(final_decision, "duc");
	result->nonce_bound = result->allow &&
			      request->action && oc_policy_equals_ci(request->action, "exec");
	result->decision = final_decision;
	result->level = oc_policy_level_name(final_level);
	result->execution_mode = execution_mode;
	result->reason = final_reason;
	result->matched_rule_id = matched_rule_id;
	result->action_risk_level = oc_policy_level_name(action_risk.base.level);
	result->action_risk_reason = action_risk.base.reason;
	result->object_risk_level = oc_policy_level_name(object_risk.base.level);
	result->object_risk_reason = object_risk.base.reason;
	result->context_risk_level = oc_policy_level_name(context_risk.base.level);
	result->context_risk_reason = context_risk.base.reason;
	result->effect_risk_level = oc_policy_level_name(effect_risk.base.level);
	result->effect_risk_reason = effect_risk.base.reason;
	OC_POLICY_FREE_EXEC_CONTEXT(context);
}

#endif
