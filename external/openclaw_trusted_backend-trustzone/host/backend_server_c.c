// SPDX-License-Identifier: BSD-2-Clause

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openclaw_trusted_backend_ta.h>

#define DEFAULT_BIND "0.0.0.0"
#define DEFAULT_PORT 19090
#define DEFAULT_SCOPE_TOKEN_TTL_MS 15000
#define DEFAULT_CONFIRMATION_TTL_MS (5 * 60 * 1000)
#define DEFAULT_CA_BINARY "/usr/bin/optee_example_openclaw_trusted_backend"
#define DEFAULT_VERIFY_MODE "ed25519"
#define DEFAULT_SIGNING_PRIVATE_KEY_FILE \
	"/etc/openclaw-trusted-backend-optee/ed25519-private.pem"

#define MAX_HTTP_REQUEST (64 * 1024)
#define MAX_HTTP_PATH 256
#define MAX_BIND_ADDR 64
#define MAX_CA_BINARY 512
#define MAX_VERIFY_MODE 32
#define MAX_HMAC_KEY 256
#define MAX_PRIVATE_KEY_FILE 512
#define MAX_PUBLIC_KEY_FILE 512
#define MAX_SCOPE_JSON 4096
#define MAX_JSON_TOKEN 1024
#define MAX_REQUEST_JSON 16384
#define MAX_PENDING_CONFIRMATIONS 32
#define MAX_EXEC_ARGS 32
#define MAX_EXEC_ARG_LEN 256
#define MAX_EXEC_COMMAND 512
#define MAX_EXEC_RAW_COMMAND 2048

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct server_config {
	char bind[MAX_BIND_ADDR];
	int port;
	char ca_binary[MAX_CA_BINARY];
	char verify_mode[MAX_VERIFY_MODE];
	char hmac_key[MAX_HMAC_KEY];
	char signing_private_key_file[MAX_PRIVATE_KEY_FILE];
	char upstream_tdx_public_key_file[MAX_PUBLIC_KEY_FILE];
	int scope_token_ttl_ms;
	int confirmation_ttl_ms;
};

struct scope_request {
	char req_id[OC_TA_MAX_ID];
	char sid[OC_TA_MAX_ID];
	char tool_name[OC_TA_MAX_TOOL_NAME];
	char action[OC_TA_MAX_ACTION];
	char object[OC_TA_MAX_OBJECT];
	char level[OC_TA_MAX_LEVEL];
	char normalized_scope_digest[OC_TA_MAX_DIGEST];
	char scope_raw[MAX_SCOPE_JSON];
	char workspace_root[OC_TA_MAX_OBJECT];
	char session_binding[OC_TA_MAX_ID];
	char request_json[MAX_REQUEST_JSON];
	long long issued_at_ms;
	int seq;
	int ttl_ms;
};

struct pending_confirmation {
	bool active;
	char confirmation_request_id[OC_TA_MAX_ID];
	long long expires_at_ms;
	struct scope_request request;
};

struct server_state {
	struct server_config config;
	struct pending_confirmation pending[MAX_PENDING_CONFIRMATIONS];
};

struct exec_spec {
	char match_mode[32];
	char raw_command[MAX_EXEC_RAW_COMMAND];
	char command[MAX_EXEC_COMMAND];
	char cwd[OC_TA_MAX_OBJECT];
	char args[MAX_EXEC_ARGS][MAX_EXEC_ARG_LEN];
	size_t arg_count;
};

struct approved_exec_binding {
	char raw_command[MAX_EXEC_RAW_COMMAND];
	char command[MAX_EXEC_COMMAND];
	char cwd[OC_TA_MAX_OBJECT];
	char workspace_root[OC_TA_MAX_OBJECT];
	char remote_platform[64];
	char args[MAX_EXEC_ARGS][MAX_EXEC_ARG_LEN];
	size_t arg_count;
};

struct http_request {
	char method[8];
	char path[MAX_HTTP_PATH];
	char *body;
	size_t body_len;
};

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static void copy_text(char *dst, size_t dst_len, const char *src)
{
	size_t n = 0;

	if (!dst || !dst_len)
		return;
	if (!src) {
		dst[0] = '\0';
		return;
	}

	n = strlen(src);
	if (n >= dst_len)
		n = dst_len - 1;

	memcpy(dst, src, n);
	dst[n] = '\0';
}

static int coerce_int(const char *raw, int fallback)
{
	char *end = NULL;
	long parsed = 0;

	if (!raw || !raw[0])
		return fallback;

	parsed = strtol(raw, &end, 10);
	if (!end || *end != '\0')
		return fallback;
	if (parsed < INT_MIN || parsed > INT_MAX)
		return fallback;
	return (int)parsed;
}

static const char *bool_json(bool value)
{
	return value ? "true" : "false";
}

static const char *skip_ws(const char *cursor)
{
	while (cursor && *cursor && isspace((unsigned char)*cursor))
		cursor++;
	return cursor;
}

static const char *json_string_end(const char *cursor)
{
	if (!cursor || *cursor != '"')
		return NULL;

	cursor++;
	while (*cursor) {
		if (*cursor == '\\') {
			if (!cursor[1])
				return NULL;
			cursor += 2;
			continue;
		}
		if (*cursor == '"')
			return cursor;
		cursor++;
	}

	return NULL;
}

static const char *json_compound_end(const char *cursor, char open_c,
				      char close_c)
{
	int depth = 0;

	if (!cursor || *cursor != open_c)
		return NULL;

	while (*cursor) {
		if (*cursor == '"') {
			cursor = json_string_end(cursor);
			if (!cursor)
				return NULL;
			cursor++;
			continue;
		}
		if (*cursor == open_c)
			depth++;
		else if (*cursor == close_c) {
			depth--;
			if (!depth)
				return cursor;
		}
		cursor++;
	}

	return NULL;
}

static const char *json_value_end(const char *cursor)
{
	if (!cursor || !*cursor)
		return NULL;

	if (*cursor == '"')
		return json_string_end(cursor);
	if (*cursor == '{')
		return json_compound_end(cursor, '{', '}');
	if (*cursor == '[')
		return json_compound_end(cursor, '[', ']');

	while (*cursor && *cursor != ',' && *cursor != '}' && *cursor != ']' &&
	       !isspace((unsigned char)*cursor))
		cursor++;

	return cursor - 1;
}

static bool json_key_matches(const char *start, const char *end,
			     const char *key)
{
	size_t key_len = 0;

	if (!start || !end || end < start)
		return false;

	key_len = strlen(key);
	return (size_t)(end - start + 1) == key_len &&
	       strncmp(start, key, key_len) == 0;
}

static bool json_find_key(const char *json, const char *key,
			  const char **value_start, const char **value_end)
{
	const char *cursor = json;

	if (!json || !key || !value_start || !value_end)
		return false;

	while (*cursor) {
		const char *key_end = NULL;
		const char *after_key = NULL;

		if (*cursor != '"') {
			cursor++;
			continue;
		}

		key_end = json_string_end(cursor);
		if (!key_end)
			return false;

		after_key = skip_ws(key_end + 1);
		if (*after_key == ':' &&
		    json_key_matches(cursor + 1, key_end - 1, key)) {
			const char *value = skip_ws(after_key + 1);
			const char *end = json_value_end(value);

			if (!end)
				return false;

			*value_start = value;
			*value_end = end;
			return true;
		}

		cursor = key_end + 1;
	}

	return false;
}

static bool json_find_top_level_key(const char *json, const char *key,
				    const char **value_start,
				    const char **value_end)
{
	const char *cursor = NULL;

	if (!json || !key || !value_start || !value_end)
		return false;

	cursor = skip_ws(json);
	if (*cursor != '{')
		return false;
	cursor++;

	while (*cursor) {
		const char *key_end = NULL;
		const char *after_key = NULL;
		const char *value = NULL;
		const char *end = NULL;

		cursor = skip_ws(cursor);
		if (*cursor == '}')
			return false;
		if (*cursor != '"')
			return false;

		key_end = json_string_end(cursor);
		if (!key_end)
			return false;

		after_key = skip_ws(key_end + 1);
		if (*after_key != ':')
			return false;

		value = skip_ws(after_key + 1);
		end = json_value_end(value);
		if (!end)
			return false;

		if (json_key_matches(cursor + 1, key_end - 1, key)) {
			*value_start = value;
			*value_end = end;
			return true;
		}

		cursor = skip_ws(end + 1);
		if (*cursor == ',') {
			cursor++;
			continue;
		}
		if (*cursor == '}')
			return false;
	}

	return false;
}

static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + c - 'a';
	if (c >= 'A' && c <= 'F')
		return 10 + c - 'A';
	return -1;
}

static size_t utf8_encode(uint32_t codepoint, char *out)
{
	if (codepoint <= 0x7f) {
		out[0] = (char)codepoint;
		return 1;
	}
	if (codepoint <= 0x7ff) {
		out[0] = (char)(0xc0 | ((codepoint >> 6) & 0x1f));
		out[1] = (char)(0x80 | (codepoint & 0x3f));
		return 2;
	}
	if (codepoint <= 0xffff) {
		out[0] = (char)(0xe0 | ((codepoint >> 12) & 0x0f));
		out[1] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
		out[2] = (char)(0x80 | (codepoint & 0x3f));
		return 3;
	}

	out[0] = (char)(0xf0 | ((codepoint >> 18) & 0x07));
	out[1] = (char)(0x80 | ((codepoint >> 12) & 0x3f));
	out[2] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
	out[3] = (char)(0x80 | (codepoint & 0x3f));
	return 4;
}

static bool json_decode_string(const char *start, const char *end, char *out,
			       size_t out_len)
{
	const char *cursor = start;
	char *writer = out;
	char *limit = out + out_len - 1;

	if (!start || !end || start >= end || *start != '"' || *end != '"' ||
	    !out || !out_len)
		return false;

	cursor++;
	while (cursor < end) {
		if (writer >= limit)
			return false;

		if (*cursor != '\\') {
			*writer++ = *cursor++;
			continue;
		}

		cursor++;
		if (cursor >= end)
			return false;

		switch (*cursor) {
		case '"':
		case '\\':
		case '/':
			*writer++ = *cursor++;
			break;
		case 'b':
			*writer++ = '\b';
			cursor++;
			break;
		case 'f':
			*writer++ = '\f';
			cursor++;
			break;
		case 'n':
			*writer++ = '\n';
			cursor++;
			break;
		case 'r':
			*writer++ = '\r';
			cursor++;
			break;
		case 't':
			*writer++ = '\t';
			cursor++;
			break;
		case 'u': {
			uint32_t codepoint = 0;
			char encoded[4];
			size_t encoded_len = 0;
			size_t index = 0;

			if (cursor + 4 >= end)
				return false;

			cursor++;
			for (index = 0; index < 4; index++) {
				int value = hex_value(cursor[index]);

				if (value < 0)
					return false;
				codepoint = (codepoint << 4) | (uint32_t)value;
			}
			cursor += 4;

			encoded_len = utf8_encode(codepoint, encoded);
			if ((size_t)(limit - writer) < encoded_len)
				return false;
			memcpy(writer, encoded, encoded_len);
			writer += encoded_len;
			break;
		}
		default:
			return false;
		}
	}

	*writer = '\0';
	return true;
}

static bool json_get_string(const char *json, const char *key, char *out,
			    size_t out_len)
{
	const char *value_start = NULL;
	const char *value_end = NULL;

	if (!json_find_key(json, key, &value_start, &value_end))
		return false;
	if (!value_start || !value_end || *value_start != '"' ||
	    *value_end != '"')
		return false;

	return json_decode_string(value_start, value_end, out, out_len);
}

static bool json_get_string_top_level(const char *json, const char *key,
				      char *out, size_t out_len)
{
	const char *value_start = NULL;
	const char *value_end = NULL;

	if (!json_find_top_level_key(json, key, &value_start, &value_end))
		return false;
	if (!value_start || !value_end || *value_start != '"' ||
	    *value_end != '"')
		return false;

	return json_decode_string(value_start, value_end, out, out_len);
}

static bool json_get_raw_value(const char *json, const char *key, char *out,
			       size_t out_len)
{
	const char *value_start = NULL;
	const char *value_end = NULL;
	size_t n = 0;

	if (!json_find_key(json, key, &value_start, &value_end))
		return false;

	n = (size_t)(value_end - value_start + 1);
	if (n >= out_len)
		return false;

	memcpy(out, value_start, n);
	out[n] = '\0';
	return true;
}

static bool json_get_raw_value_top_level(const char *json, const char *key,
					 char *out, size_t out_len)
{
	const char *value_start = NULL;
	const char *value_end = NULL;
	size_t n = 0;

	if (!json_find_top_level_key(json, key, &value_start, &value_end))
		return false;

	n = (size_t)(value_end - value_start + 1);
	if (n >= out_len)
		return false;

	memcpy(out, value_start, n);
	out[n] = '\0';
	return true;
}

static bool json_get_bool(const char *json, const char *key, bool *out)
{
	const char *value_start = NULL;
	const char *value_end = NULL;
	size_t n = 0;

	if (!out || !json_find_key(json, key, &value_start, &value_end))
		return false;

	n = (size_t)(value_end - value_start + 1);
	if (n == 4 && strncmp(value_start, "true", 4) == 0) {
		*out = true;
		return true;
	}
	if (n == 5 && strncmp(value_start, "false", 5) == 0) {
		*out = false;
		return true;
	}

	return false;
}

static bool json_get_bool_top_level(const char *json, const char *key,
				    bool *out)
{
	const char *value_start = NULL;
	const char *value_end = NULL;
	size_t n = 0;

	if (!out || !json_find_top_level_key(json, key, &value_start, &value_end))
		return false;

	n = (size_t)(value_end - value_start + 1);
	if (n == 4 && strncmp(value_start, "true", 4) == 0) {
		*out = true;
		return true;
	}
	if (n == 5 && strncmp(value_start, "false", 5) == 0) {
		*out = false;
		return true;
	}

	return false;
}

static bool json_get_int64(const char *json, const char *key, long long *out)
{
	const char *value_start = NULL;
	const char *value_end = NULL;
	char raw[32];
	char *end = NULL;
	long long parsed = 0;
	size_t n = 0;

	if (!out || !json_find_key(json, key, &value_start, &value_end))
		return false;

	n = (size_t)(value_end - value_start + 1);
	if (!n || n >= sizeof(raw))
		return false;

	memcpy(raw, value_start, n);
	raw[n] = '\0';

	parsed = strtoll(raw, &end, 10);
	if (!end || *end != '\0')
		return false;

	*out = parsed;
	return true;
}

static bool json_get_int64_top_level(const char *json, const char *key,
				     long long *out)
{
	const char *value_start = NULL;
	const char *value_end = NULL;
	char raw[32];
	char *end = NULL;
	long long parsed = 0;
	size_t n = 0;

	if (!out || !json_find_top_level_key(json, key, &value_start, &value_end))
		return false;

	n = (size_t)(value_end - value_start + 1);
	if (!n || n >= sizeof(raw))
		return false;

	memcpy(raw, value_start, n);
	raw[n] = '\0';

	parsed = strtoll(raw, &end, 10);
	if (!end || *end != '\0')
		return false;

	*out = parsed;
	return true;
}

static bool json_parse_string_array(const char *json, char values[][MAX_EXEC_ARG_LEN],
				    size_t max_values, size_t *out_count)
{
	const char *cursor = skip_ws(json);
	size_t count = 0;

	if (!cursor || !values || !out_count || *cursor != '[')
		return false;

	cursor = skip_ws(cursor + 1);
	if (*cursor == ']') {
		*out_count = 0;
		return true;
	}

	while (*cursor) {
		const char *value_end = NULL;

		if (count >= max_values || *cursor != '"')
			return false;

		value_end = json_string_end(cursor);
		if (!value_end ||
		    !json_decode_string(cursor, value_end, values[count],
					MAX_EXEC_ARG_LEN))
			return false;
		count++;

		cursor = skip_ws(value_end + 1);
		if (*cursor == ',') {
			cursor = skip_ws(cursor + 1);
			continue;
		}
		if (*cursor == ']') {
			*out_count = count;
			return true;
		}
		return false;
	}

	return false;
}

static char *json_escape_string(const char *input)
{
	size_t needed = 3;
	const unsigned char *cursor = (const unsigned char *)input;
	char *escaped = NULL;
	char *writer = NULL;

	while (cursor && *cursor) {
		switch (*cursor) {
		case '\\':
		case '"':
		case '\n':
		case '\r':
		case '\t':
			needed += 2;
			break;
		default:
			if (*cursor < 0x20)
				needed += 6;
			else
				needed += 1;
			break;
		}
		cursor++;
	}

	escaped = calloc(1, needed);
	if (!escaped)
		return NULL;

	writer = escaped;
	*writer++ = '"';
	cursor = (const unsigned char *)input;
	while (cursor && *cursor) {
		switch (*cursor) {
		case '\\':
			*writer++ = '\\';
			*writer++ = '\\';
			break;
		case '"':
			*writer++ = '\\';
			*writer++ = '"';
			break;
		case '\n':
			*writer++ = '\\';
			*writer++ = 'n';
			break;
		case '\r':
			*writer++ = '\\';
			*writer++ = 'r';
			break;
		case '\t':
			*writer++ = '\\';
			*writer++ = 't';
			break;
		default:
			if (*cursor < 0x20) {
				snprintf(writer, 7, "\\u%04x", *cursor);
				writer += 6;
			} else {
				*writer++ = (char)*cursor;
			}
			break;
		}
		cursor++;
	}
	*writer++ = '"';
	*writer = '\0';

	return escaped;
}

static bool json_replace_value(char **json_ptr, const char *key,
			       const char *replacement)
{
	char *json = NULL;
	const char *value_start = NULL;
	const char *value_end = NULL;
	size_t prefix_len = 0;
	size_t replacement_len = 0;
	size_t suffix_len = 0;
	char *updated = NULL;

	if (!json_ptr || !*json_ptr || !replacement)
		return false;

	json = *json_ptr;
	if (!json_find_key(json, key, &value_start, &value_end))
		return false;

	prefix_len = (size_t)(value_start - json);
	replacement_len = strlen(replacement);
	suffix_len = strlen(value_end + 1);

	updated = malloc(prefix_len + replacement_len + suffix_len + 1);
	if (!updated)
		return false;

	memcpy(updated, json, prefix_len);
	memcpy(updated + prefix_len, replacement, replacement_len);
	memcpy(updated + prefix_len + replacement_len, value_end + 1, suffix_len);
	updated[prefix_len + replacement_len + suffix_len] = '\0';

	free(*json_ptr);
	*json_ptr = updated;
	return true;
}

static bool json_replace_string(char **json_ptr, const char *key,
				const char *value)
{
	char *escaped = json_escape_string(value ? value : "");
	bool ok = false;

	if (!escaped)
		return false;

	ok = json_replace_value(json_ptr, key, escaped);
	free(escaped);
	return ok;
}

static bool json_replace_number(char **json_ptr, const char *key, long long value)
{
	char raw[32];

	snprintf(raw, sizeof(raw), "%lld", value);
	return json_replace_value(json_ptr, key, raw);
}

static const char *status_text(int status)
{
	switch (status) {
	case 200:
		return "OK";
	case 400:
		return "Bad Request";
	case 404:
		return "Not Found";
	case 500:
		return "Internal Server Error";
	default:
		return "OK";
	}
}

static char *build_error_json(const char *error, const char *message)
{
	char *escaped_error = json_escape_string(error ? error : "error");
	char *escaped_message = json_escape_string(message ? message : "");
	char *json = NULL;
	int written = 0;

	if (!escaped_error || !escaped_message)
		goto out;

	written = snprintf(NULL, 0,
			   "{\"error\":%s,\"message\":%s}",
			   escaped_error, escaped_message);
	if (written < 0)
		goto out;

	json = malloc((size_t)written + 1);
	if (!json)
		goto out;

	snprintf(json, (size_t)written + 1,
		 "{\"error\":%s,\"message\":%s}",
		 escaped_error, escaped_message);
out:
	free(escaped_error);
	free(escaped_message);
	return json;
}

static char *ca_failure_json(char *output, const char *fallback)
{
	char *json = NULL;

	if (output && output[0] == '{')
		return output;

	json = build_error_json("ca_invocation_failed",
				output && output[0] ? output : fallback);
	free(output);
	return json;
}

static bool send_all(int fd, const char *buffer, size_t len)
{
	size_t total = 0;

	while (total < len) {
		ssize_t written = send(fd, buffer + total, len - total, 0);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			return false;
		}
		if (!written)
			return false;
		total += (size_t)written;
	}

	return true;
}

static void send_json_response(int fd, int status, const char *body)
{
	char header[256];
	size_t body_len = body ? strlen(body) : 0;
	int header_len = 0;

	header_len = snprintf(header, sizeof(header),
			      "HTTP/1.1 %d %s\r\n"
			      "Content-Type: application/json\r\n"
			      "Content-Length: %zu\r\n"
			      "Connection: close\r\n"
			      "\r\n",
			      status, status_text(status), body_len);
	if (header_len < 0)
		return;

	send_all(fd, header, (size_t)header_len);
	if (body_len)
		send_all(fd, body, body_len);
}

static const char *find_header_end(const char *buffer, size_t len,
				   size_t *delimiter_len)
{
	size_t index = 0;

	for (index = 0; index + 3 < len; index++) {
		if (buffer[index] == '\r' && buffer[index + 1] == '\n' &&
		    buffer[index + 2] == '\r' && buffer[index + 3] == '\n') {
			*delimiter_len = 4;
			return buffer + index;
		}
	}
	for (index = 0; index + 1 < len; index++) {
		if (buffer[index] == '\n' && buffer[index + 1] == '\n') {
			*delimiter_len = 2;
			return buffer + index;
		}
	}

	return NULL;
}

static void http_request_cleanup(struct http_request *request)
{
	free(request->body);
	request->body = NULL;
	request->body_len = 0;
}

static bool parse_headers(const char *headers, struct http_request *request,
			  size_t *content_length)
{
	char *copy = NULL;
	char *saveptr = NULL;
	char *line = NULL;
	bool first_line = true;

	*content_length = 0;
	copy = strdup(headers);
	if (!copy)
		return false;

	for (line = strtok_r(copy, "\r\n", &saveptr); line;
	     line = strtok_r(NULL, "\r\n", &saveptr)) {
		if (!*line)
			continue;
		if (first_line) {
			char version[16];

			first_line = false;
			if (sscanf(line, "%7s %255s %15s",
				   request->method, request->path, version) < 2) {
				free(copy);
				return false;
			}
			continue;
		}
		if (strncasecmp(line, "Content-Length:", 15) == 0) {
			const char *raw = skip_ws(line + 15);
			long parsed = strtol(raw, NULL, 10);

			if (parsed < 0) {
				free(copy);
				return false;
			}
			*content_length = (size_t)parsed;
		}
	}

	free(copy);
	return true;
}

static bool read_http_request(int fd, struct http_request *request)
{
	char *buffer = calloc(1, MAX_HTTP_REQUEST + 1);
	size_t total = 0;
	size_t content_length = 0;
	size_t header_len = 0;
	size_t delimiter_len = 0;
	size_t required = 0;
	bool parsed_headers = false;

	if (!buffer)
		return false;

	memset(request, 0, sizeof(*request));

	while (total < MAX_HTTP_REQUEST) {
		ssize_t count = recv(fd, buffer + total, MAX_HTTP_REQUEST - total, 0);

		if (count < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (!count)
			break;

		total += (size_t)count;
		buffer[total] = '\0';

		if (!parsed_headers) {
			const char *header_end =
				find_header_end(buffer, total, &delimiter_len);

			if (!header_end)
				continue;

			header_len = (size_t)(header_end - buffer);
			buffer[header_len] = '\0';

			if (!parse_headers(buffer, request, &content_length))
				goto err;

			required = header_len + delimiter_len + content_length;
			if (required > MAX_HTTP_REQUEST)
				goto err;

			memmove(buffer, header_end + delimiter_len,
				total - header_len - delimiter_len);
			total -= header_len + delimiter_len;
			buffer[total] = '\0';
			parsed_headers = true;

			if (!content_length)
				break;
		}

		if (parsed_headers && total >= content_length)
			break;
	}

	if (!parsed_headers)
		goto err;
	if (total < content_length)
		goto err;

	request->body = calloc(1, content_length + 1);
	if (!request->body)
		goto err;

	if (content_length)
		memcpy(request->body, buffer, content_length);
	request->body[content_length] = '\0';
	request->body_len = content_length;

	free(buffer);
	return true;
err:
	free(buffer);
	http_request_cleanup(request);
	return false;
}

static bool read_pipe_output(int fd, char **output)
{
	char chunk[1024];
	char *buffer = NULL;
	size_t used = 0;
	size_t capacity = 0;

	while (1) {
		ssize_t count = read(fd, chunk, sizeof(chunk));

		if (count < 0) {
			if (errno == EINTR)
				continue;
			free(buffer);
			return false;
		}
		if (!count)
			break;

		if (used + (size_t)count + 1 > capacity) {
			size_t new_capacity = capacity ? capacity * 2 : 2048;
			char *resized = NULL;

			while (new_capacity < used + (size_t)count + 1)
				new_capacity *= 2;

			resized = realloc(buffer, new_capacity);
			if (!resized) {
				free(buffer);
				return false;
			}
			buffer = resized;
			capacity = new_capacity;
		}

		memcpy(buffer + used, chunk, (size_t)count);
		used += (size_t)count;
	}

	if (!buffer) {
		buffer = calloc(1, 1);
		if (!buffer)
			return false;
	}
	buffer[used] = '\0';
	*output = buffer;
	return true;
}

static void trim_output(char *text)
{
	size_t len = 0;

	if (!text)
		return;

	len = strlen(text);
	while (len && isspace((unsigned char)text[len - 1])) {
		text[len - 1] = '\0';
		len--;
	}
}

static bool run_ca_command(char *const argv[], char **output, int *exit_code)
{
	int pipefd[2];
	pid_t pid = 0;
	int status = 0;

	*output = NULL;
	*exit_code = -1;

	if (pipe(pipefd) < 0)
		return false;

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return false;
	}

	if (!pid) {
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		execvp(argv[0], argv);
		_exit(127);
	}

	close(pipefd[1]);
	if (!read_pipe_output(pipefd[0], output)) {
		close(pipefd[0]);
		waitpid(pid, NULL, 0);
		return false;
	}
	close(pipefd[0]);

	if (waitpid(pid, &status, 0) < 0) {
		free(*output);
		*output = NULL;
		return false;
	}

	if (WIFEXITED(status))
		*exit_code = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		*exit_code = 128 + WTERMSIG(status);
	else
		*exit_code = -1;

	trim_output(*output);
	return true;
}

static bool parse_exec_spec(const struct scope_request *request,
			    struct exec_spec *spec, char **error_json)
{
	char raw_args[MAX_SCOPE_JSON];

	memset(spec, 0, sizeof(*spec));
	if (!json_get_string(request->scope_raw, "rawCommand", spec->raw_command,
			     sizeof(spec->raw_command))) {
		*error_json = build_error_json("invalid_remote_scope",
					      "missing exec.rawCommand");
		return false;
	}
	if (!json_get_string(request->scope_raw, "matchMode", spec->match_mode,
			     sizeof(spec->match_mode)))
		copy_text(spec->match_mode, sizeof(spec->match_mode), "shell-exact");
	json_get_string(request->scope_raw, "command", spec->command,
			sizeof(spec->command));
	json_get_string(request->scope_raw, "cwd", spec->cwd, sizeof(spec->cwd));

	if (json_get_raw_value(request->scope_raw, "args", raw_args,
			       sizeof(raw_args)) &&
	    !json_parse_string_array(raw_args, spec->args, ARRAY_SIZE(spec->args),
				     &spec->arg_count)) {
		*error_json = build_error_json("invalid_remote_scope",
					      "invalid exec.args");
		return false;
	}

	if (strcmp(spec->match_mode, "exact") == 0 && !spec->command[0]) {
		*error_json = build_error_json("invalid_remote_scope",
					      "exact exec scope missing command");
		return false;
	}

	return true;
}

static bool run_exec_spec(const struct exec_spec *spec, char **stdout_text,
			  char **stderr_text, int *exit_code)
{
	int stdout_pipe[2];
	int stderr_pipe[2];
	pid_t pid = 0;
	int status = 0;

	*stdout_text = NULL;
	*stderr_text = NULL;
	*exit_code = -1;

	if (pipe(stdout_pipe) < 0)
		return false;
	if (pipe(stderr_pipe) < 0) {
		close(stdout_pipe[0]);
		close(stdout_pipe[1]);
		return false;
	}

	pid = fork();
	if (pid < 0) {
		close(stdout_pipe[0]);
		close(stdout_pipe[1]);
		close(stderr_pipe[0]);
		close(stderr_pipe[1]);
		return false;
	}

	if (!pid) {
		size_t index = 0;
		char *argv[MAX_EXEC_ARGS + 2];

		dup2(stdout_pipe[1], STDOUT_FILENO);
		dup2(stderr_pipe[1], STDERR_FILENO);
		close(stdout_pipe[0]);
		close(stdout_pipe[1]);
		close(stderr_pipe[0]);
		close(stderr_pipe[1]);

		if (spec->cwd[0] && chdir(spec->cwd) != 0) {
			fprintf(stderr, "failed to chdir to %s: %s\n", spec->cwd,
				strerror(errno));
			_exit(127);
		}

		if (strcmp(spec->match_mode, "exact") == 0 && spec->command[0]) {
			argv[0] = (char *)spec->command;
			for (index = 0; index < spec->arg_count &&
					     index < ARRAY_SIZE(spec->args);
			     index++)
				argv[index + 1] = (char *)spec->args[index];
			argv[index + 1] = NULL;
			execvp(spec->command, argv);
			fprintf(stderr, "failed to exec %s: %s\n", spec->command,
				strerror(errno));
			_exit(127);
		}

		execl("/bin/sh", "sh", "-lc", spec->raw_command, (char *)NULL);
		fprintf(stderr, "failed to exec shell command: %s\n",
			strerror(errno));
		_exit(127);
	}

	close(stdout_pipe[1]);
	close(stderr_pipe[1]);

	if (!read_pipe_output(stdout_pipe[0], stdout_text)) {
		close(stdout_pipe[0]);
		close(stderr_pipe[0]);
		waitpid(pid, NULL, 0);
		return false;
	}
	close(stdout_pipe[0]);

	if (!read_pipe_output(stderr_pipe[0], stderr_text)) {
		close(stderr_pipe[0]);
		waitpid(pid, NULL, 0);
		free(*stdout_text);
		*stdout_text = NULL;
		return false;
	}
	close(stderr_pipe[0]);

	if (waitpid(pid, &status, 0) < 0) {
		free(*stdout_text);
		free(*stderr_text);
		*stdout_text = NULL;
		*stderr_text = NULL;
		return false;
	}

	if (WIFEXITED(status))
		*exit_code = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		*exit_code = 128 + WTERMSIG(status);
	else
		*exit_code = -1;

	trim_output(*stdout_text);
	trim_output(*stderr_text);
	return true;
}

static bool compute_exec_result_digest(int exit_code, const char *stdout_text,
				       const char *stderr_text,
				       char out_hex[OC_TA_MAX_DIGEST])
{
	EVP_MD_CTX *ctx = NULL;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = 0;
	char exit_raw[32];
	const char *status = exit_code == 0 ? "ok" : "error";
	size_t index = 0;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return false;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) <= 0)
		goto err;

	snprintf(exit_raw, sizeof(exit_raw), "%d", exit_code);
	if (EVP_DigestUpdate(ctx, status, strlen(status)) <= 0 ||
	    EVP_DigestUpdate(ctx, "\n", 1) <= 0 ||
	    EVP_DigestUpdate(ctx, exit_raw, strlen(exit_raw)) <= 0 ||
	    EVP_DigestUpdate(ctx, "\n", 1) <= 0 ||
	    EVP_DigestUpdate(ctx, stdout_text ? stdout_text : "",
			     strlen(stdout_text ? stdout_text : "")) <= 0 ||
	    EVP_DigestUpdate(ctx, "\n", 1) <= 0 ||
	    EVP_DigestUpdate(ctx, stderr_text ? stderr_text : "",
			     strlen(stderr_text ? stderr_text : "")) <= 0)
		goto err;

	if (EVP_DigestFinal_ex(ctx, digest, &digest_len) <= 0)
		goto err;
	if (digest_len * 2 + 1 > OC_TA_MAX_DIGEST)
		goto err;

	for (index = 0; index < digest_len; index++)
		snprintf(out_hex + index * 2, 3, "%02x", digest[index]);
	out_hex[digest_len * 2] = '\0';
	EVP_MD_CTX_free(ctx);
	return true;
err:
	EVP_MD_CTX_free(ctx);
	return false;
}

static char *build_remote_exec_complete_body(const struct scope_request *request,
					     const char *status_text_value,
					     const char *result_digest)
{
	char *escaped_req_id = NULL;
	char *escaped_sid = NULL;
	char *escaped_tool_name = NULL;
	char *escaped_action = NULL;
	char *escaped_object = NULL;
	char *escaped_status = NULL;
	char *escaped_digest = NULL;
	char *json = NULL;
	int written = 0;

	escaped_req_id = json_escape_string(request->req_id);
	escaped_sid = json_escape_string(request->sid);
	escaped_tool_name = json_escape_string(request->tool_name);
	escaped_action = json_escape_string(request->action);
	escaped_object = json_escape_string(request->object);
	escaped_status = json_escape_string(status_text_value);
	escaped_digest = json_escape_string(result_digest);
	if (!escaped_req_id || !escaped_sid || !escaped_tool_name || !escaped_action ||
	    !escaped_object || !escaped_status || !escaped_digest)
		goto out;

	written = snprintf(
		NULL, 0,
		"{\"reqId\":%s,\"sid\":%s,\"toolName\":%s,\"action\":%s,"
		"\"object\":%s,\"status\":%s,\"resultDigest\":%s}",
		escaped_req_id, escaped_sid, escaped_tool_name, escaped_action,
		escaped_object, escaped_status, escaped_digest);
	if (written < 0)
		goto out;

	json = malloc((size_t)written + 1);
	if (!json)
		goto out;

	snprintf(json, (size_t)written + 1,
		 "{\"reqId\":%s,\"sid\":%s,\"toolName\":%s,\"action\":%s,"
		 "\"object\":%s,\"status\":%s,\"resultDigest\":%s}",
		 escaped_req_id, escaped_sid, escaped_tool_name, escaped_action,
		 escaped_object, escaped_status, escaped_digest);
out:
	free(escaped_req_id);
	free(escaped_sid);
	free(escaped_tool_name);
	free(escaped_action);
	free(escaped_object);
	free(escaped_status);
	free(escaped_digest);
	return json;
}

static char *build_remote_exec_response(const char *phase, bool authorized,
					bool executed, bool completed,
					const char *authorize_json,
					const char *execution_json,
					const char *complete_json)
{
	char *escaped_phase = json_escape_string(phase ? phase : "error");
	char *json = NULL;
	int written = 0;

	if (!escaped_phase)
		return NULL;

	written = snprintf(NULL, 0,
			   "{\"ok\":%s,\"phase\":%s,\"authorized\":%s,"
			   "\"executed\":%s,\"completed\":%s,\"authorize\":%s,"
			   "\"execution\":%s,\"complete\":%s}",
			   bool_json(authorized && executed && completed),
			   escaped_phase, bool_json(authorized),
			   bool_json(executed), bool_json(completed),
			   authorize_json ? authorize_json : "null",
			   execution_json ? execution_json : "null",
			   complete_json ? complete_json : "null");
	if (written < 0)
		goto out;

	json = malloc((size_t)written + 1);
	if (!json)
		goto out;

	snprintf(json, (size_t)written + 1,
		 "{\"ok\":%s,\"phase\":%s,\"authorized\":%s,"
		 "\"executed\":%s,\"completed\":%s,\"authorize\":%s,"
		 "\"execution\":%s,\"complete\":%s}",
		 bool_json(authorized && executed && completed), escaped_phase,
		 bool_json(authorized), bool_json(executed),
		 bool_json(completed), authorize_json ? authorize_json : "null",
		 execution_json ? execution_json : "null",
		 complete_json ? complete_json : "null");
out:
	free(escaped_phase);
	return json;
}

static bool b64url_encode(const unsigned char *data, size_t data_len, char **out)
{
	size_t base64_len = 4 * ((data_len + 2) / 3);
	unsigned char *base64 = NULL;
	size_t index = 0;
	size_t trimmed = 0;

	*out = NULL;

	base64 = calloc(1, base64_len + 1);
	if (!base64)
		return false;

	if (EVP_EncodeBlock(base64, data, (int)data_len) < 0) {
		free(base64);
		return false;
	}

	for (index = 0; index < base64_len; index++) {
		if (base64[index] == '+')
			base64[index] = '-';
		else if (base64[index] == '/')
			base64[index] = '_';
	}

	trimmed = base64_len;
	while (trimmed && base64[trimmed - 1] == '=')
		trimmed--;
	base64[trimmed] = '\0';

	*out = (char *)base64;
	return true;
}

static bool b64url_decode(const char *input, unsigned char **out, size_t *out_len)
{
	size_t input_len = 0;
	size_t padded_len = 0;
	char *normalized = NULL;
	unsigned char *decoded = NULL;
	int decoded_len = 0;
	size_t padding = 0;
	size_t index = 0;

	if (!input || !out || !out_len)
		return false;

	*out = NULL;
	*out_len = 0;
	input_len = strlen(input);
	padding = (4 - (input_len % 4)) % 4;
	padded_len = input_len + padding;

	normalized = calloc(1, padded_len + 1);
	if (!normalized)
		return false;
	memcpy(normalized, input, input_len);
	for (index = 0; index < input_len; index++) {
		if (normalized[index] == '-')
			normalized[index] = '+';
		else if (normalized[index] == '_')
			normalized[index] = '/';
	}
	for (index = 0; index < padding; index++)
		normalized[input_len + index] = '=';

	decoded = calloc(1, 3 * (padded_len / 4) + 1);
	if (!decoded)
		goto out;

	decoded_len = EVP_DecodeBlock(decoded, (const unsigned char *)normalized,
				      (int)padded_len);
	if (decoded_len < 0)
		goto out;
	while (padded_len > 0 && normalized[padded_len - 1] == '=') {
		decoded_len--;
		padded_len--;
	}
	if (decoded_len < 0)
		goto out;

	*out = decoded;
	*out_len = (size_t)decoded_len;
	decoded = NULL;
	free(normalized);
	return true;
out:
	free(normalized);
	free(decoded);
	return false;
}

static bool streq_or_empty(const char *left, const char *right)
{
	const char *lhs = left ? left : "";
	const char *rhs = right ? right : "";

	return strcmp(lhs, rhs) == 0;
}

static bool parse_approved_exec_binding(const char *remote_dispatch_json,
					struct approved_exec_binding *binding)
{
	char approved_exec_raw[MAX_SCOPE_JSON];
	char raw_args[MAX_SCOPE_JSON];

	memset(binding, 0, sizeof(*binding));
	memset(approved_exec_raw, 0, sizeof(approved_exec_raw));
	memset(raw_args, 0, sizeof(raw_args));

	if (!json_get_raw_value(remote_dispatch_json, "approvedExec",
				approved_exec_raw, sizeof(approved_exec_raw)))
		return false;
	if (!json_get_string(approved_exec_raw, "rawCommand",
			     binding->raw_command,
			     sizeof(binding->raw_command)))
		return false;
	if (!json_get_string(approved_exec_raw, "command", binding->command,
			     sizeof(binding->command)))
		return false;
	json_get_string(approved_exec_raw, "cwd", binding->cwd,
			sizeof(binding->cwd));
	json_get_string(approved_exec_raw, "workspaceRoot",
			binding->workspace_root,
			sizeof(binding->workspace_root));
	json_get_string(remote_dispatch_json, "remotePlatform",
			binding->remote_platform,
			sizeof(binding->remote_platform));

	if (json_get_raw_value(approved_exec_raw, "args", raw_args,
			       sizeof(raw_args)) &&
	    !json_parse_string_array(raw_args, binding->args,
				     ARRAY_SIZE(binding->args),
				     &binding->arg_count))
		return false;

	return true;
}

static bool approved_exec_matches_request(
	const struct approved_exec_binding *binding,
	const struct scope_request *request,
	const struct exec_spec *spec)
{
	size_t index = 0;

	if (!binding->raw_command[0] || !binding->command[0])
		return false;
	if (strcmp(binding->raw_command, spec->raw_command) != 0)
		return false;
	if (strcmp(binding->command, spec->command) != 0)
		return false;
	if (!streq_or_empty(binding->cwd, spec->cwd))
		return false;
	if (!streq_or_empty(binding->workspace_root, request->workspace_root))
		return false;
	if (binding->remote_platform[0] &&
	    strcasecmp(binding->remote_platform, "trustzone") != 0 &&
	    strcasecmp(binding->remote_platform, "optee") != 0)
		return false;
	if (binding->arg_count != spec->arg_count)
		return false;
	for (index = 0; index < binding->arg_count; index++) {
		if (strcmp(binding->args[index], spec->args[index]) != 0)
			return false;
	}

	return true;
}

static bool verify_ed25519_signature_with_public_key_file(
	const char *public_key_file_path, const char *signed_input,
	const unsigned char *signature, size_t signature_len)
{
	bool ok = false;
	FILE *public_key_file = NULL;
	EVP_PKEY *public_key = NULL;
	EVP_MD_CTX *md_ctx = NULL;

	if (!public_key_file_path || !public_key_file_path[0] || !signed_input ||
	    !signature || signature_len == 0)
		return false;

	public_key_file = fopen(public_key_file_path, "r");
	if (!public_key_file)
		goto out;
	public_key = PEM_read_PUBKEY(public_key_file, NULL, NULL, NULL);
	fclose(public_key_file);
	public_key_file = NULL;
	if (!public_key)
		goto out;

	md_ctx = EVP_MD_CTX_new();
	if (!md_ctx)
		goto out;
	if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, public_key) <= 0)
		goto out;
	if (EVP_DigestVerify(md_ctx, signature, signature_len,
			     (const unsigned char *)signed_input,
			     strlen(signed_input)) <= 0)
		goto out;

	ok = true;
out:
	if (md_ctx)
		EVP_MD_CTX_free(md_ctx);
	if (public_key)
		EVP_PKEY_free(public_key);
	if (public_key_file)
		fclose(public_key_file);
	return ok;
}

static char *verify_upstream_local_approval(const struct server_config *config,
					    const char *local_approval_json,
					    const struct scope_request *request,
					    const struct exec_spec *spec)
{
	char payload_json[MAX_REQUEST_JSON];
	char envelope_req_id[OC_TA_MAX_ID];
	char envelope_sid[OC_TA_MAX_ID];
	char envelope_action[OC_TA_MAX_ACTION];
	char envelope_object[OC_TA_MAX_OBJECT];
	char envelope_digest[OC_TA_MAX_DIGEST];
	char token[MAX_REQUEST_JSON];
	char payload_req_id[OC_TA_MAX_ID];
	char payload_sid[OC_TA_MAX_ID];
	char payload_action[OC_TA_MAX_ACTION];
	char payload_object[OC_TA_MAX_OBJECT];
	char payload_digest[OC_TA_MAX_DIGEST];
	char scope_raw[MAX_SCOPE_JSON];
	char remote_dispatch_raw[MAX_SCOPE_JSON];
	char *token_copy = NULL;
	char *separator = NULL;
	char *payload_b64 = NULL;
	char *signature_b64 = NULL;
	unsigned char *payload_bytes = NULL;
	unsigned char *signature_bytes = NULL;
	size_t payload_len = 0;
	size_t signature_len = 0;
	long long expires_at_ms = 0;
	struct approved_exec_binding binding;

	memset(envelope_req_id, 0, sizeof(envelope_req_id));
	memset(payload_json, 0, sizeof(payload_json));
	memset(envelope_sid, 0, sizeof(envelope_sid));
	memset(envelope_action, 0, sizeof(envelope_action));
	memset(envelope_object, 0, sizeof(envelope_object));
	memset(envelope_digest, 0, sizeof(envelope_digest));
	memset(token, 0, sizeof(token));
	memset(payload_req_id, 0, sizeof(payload_req_id));
	memset(payload_sid, 0, sizeof(payload_sid));
	memset(payload_action, 0, sizeof(payload_action));
	memset(payload_object, 0, sizeof(payload_object));
	memset(payload_digest, 0, sizeof(payload_digest));
	memset(scope_raw, 0, sizeof(scope_raw));
	memset(remote_dispatch_raw, 0, sizeof(remote_dispatch_raw));
	memset(&binding, 0, sizeof(binding));

	if (!config->upstream_tdx_public_key_file[0])
		return build_error_json("invalid_local_approval",
					"upstream TDX public key is not configured");

	if (!json_get_string_top_level(local_approval_json, "reqId",
				       envelope_req_id,
				       sizeof(envelope_req_id)) ||
	    !json_get_string_top_level(local_approval_json, "sid",
				       envelope_sid, sizeof(envelope_sid)) ||
	    !json_get_string_top_level(local_approval_json, "action",
				       envelope_action,
				       sizeof(envelope_action)) ||
	    !json_get_string_top_level(local_approval_json, "object",
				       envelope_object,
				       sizeof(envelope_object)) ||
	    !json_get_string_top_level(local_approval_json,
				       "normalizedScopeDigest",
				       envelope_digest,
				       sizeof(envelope_digest)) ||
	    !json_get_string_top_level(local_approval_json, "token", token,
				       sizeof(token)))
		return build_error_json("invalid_local_approval",
					"localApproval is missing required fields");

	token_copy = strdup(token);
	if (!token_copy)
		return build_error_json("invalid_local_approval",
					"failed to allocate localApproval token buffer");
	separator = strchr(token_copy, '.');
	if (!separator) {
		free(token_copy);
		return build_error_json("invalid_local_approval",
					"localApproval token format is invalid");
	}
	*separator = '\0';
	payload_b64 = token_copy;
	signature_b64 = separator + 1;
	if (!payload_b64[0] || !signature_b64[0]) {
		free(token_copy);
		return build_error_json("invalid_local_approval",
					"localApproval token format is invalid");
	}

	if (!b64url_decode(payload_b64, &payload_bytes, &payload_len) ||
	    !b64url_decode(signature_b64, &signature_bytes, &signature_len)) {
		free(token_copy);
		free(payload_bytes);
		free(signature_bytes);
		return build_error_json("invalid_local_approval",
					"failed to decode localApproval token");
	}
	if (!verify_ed25519_signature_with_public_key_file(
		    config->upstream_tdx_public_key_file, payload_b64,
		    signature_bytes, signature_len)) {
		free(token_copy);
		free(payload_bytes);
		free(signature_bytes);
		return build_error_json("invalid_local_approval",
					"localApproval token signature verification failed");
	}

	if (payload_len == 0 || payload_len + 1 > sizeof(payload_json)) {
		free(token_copy);
		free(payload_bytes);
		free(signature_bytes);
		return build_error_json("invalid_local_approval",
					"localApproval token payload is invalid");
	}
	memcpy(payload_json, payload_bytes, payload_len);
	payload_json[payload_len] = '\0';
	free(payload_bytes);
	payload_bytes = NULL;
	free(signature_bytes);
	signature_bytes = NULL;

	if (!json_get_string(payload_json, "reqId", payload_req_id,
			     sizeof(payload_req_id)) ||
	    !json_get_string(payload_json, "sid", payload_sid,
			     sizeof(payload_sid)) ||
	    !json_get_string(payload_json, "action", payload_action,
			     sizeof(payload_action)) ||
	    !json_get_string(payload_json, "object", payload_object,
			     sizeof(payload_object)) ||
	    !json_get_string(payload_json,
			     "normalizedScopeDigest", payload_digest,
			     sizeof(payload_digest)) ||
	    !json_get_raw_value(payload_json, "scope", scope_raw,
				sizeof(scope_raw))) {
		free(token_copy);
		return build_error_json("invalid_local_approval",
					"localApproval token payload is missing required fields");
	}
	if (strcmp(envelope_req_id, payload_req_id) != 0 ||
	    strcmp(envelope_sid, payload_sid) != 0 ||
	    strcmp(envelope_action, payload_action) != 0 ||
	    strcmp(envelope_object, payload_object) != 0 ||
	    strcmp(envelope_digest, payload_digest) != 0) {
		free(token_copy);
		return build_error_json("invalid_local_approval",
					"localApproval envelope does not match the signed token");
	}
	if (!json_get_int64(payload_json, "expiresAtMs", &expires_at_ms) ||
	    expires_at_ms < now_ms()) {
		free(token_copy);
		return build_error_json("invalid_local_approval",
					"localApproval token is expired");
	}
	if (!json_get_raw_value(scope_raw, "remoteDispatch", remote_dispatch_raw,
				sizeof(remote_dispatch_raw))) {
		free(token_copy);
		return build_error_json("invalid_local_approval",
					"localApproval token is missing remoteDispatch scope");
	}
	if (!parse_approved_exec_binding(remote_dispatch_raw, &binding)) {
		free(token_copy);
		return build_error_json("invalid_local_approval",
					"localApproval token is missing approvedExec binding");
	}
	if (!approved_exec_matches_request(&binding, request, spec)) {
		free(token_copy);
		return build_error_json("invalid_local_approval",
					"remote command differs from TDX-approved command binding");
	}

	free(token_copy);
	return NULL;
}

static bool mint_scope_token(const struct server_config *config,
			     const struct scope_request *request,
			     char **token_out)
{
	long long issued_at_ms =
		request->issued_at_ms > 0 ? request->issued_at_ms : now_ms();
	long long ttl_ms = request->ttl_ms > 0 ?
				request->ttl_ms :
				config->scope_token_ttl_ms;
	long long expires_at_ms = issued_at_ms + ttl_ms;
	char payload[8192];
	char *escaped_req_id = NULL;
	char *escaped_sid = NULL;
	char *escaped_action = NULL;
	char *escaped_object = NULL;
	char *escaped_digest = NULL;
	char *payload_b64 = NULL;
	char *signature_b64 = NULL;
	unsigned int signature_len = 0;
	unsigned char signature[EVP_MAX_MD_SIZE];
	unsigned char *dynamic_signature = NULL;
	size_t dynamic_signature_len = 0;
	bool ok = false;
	EVP_PKEY *private_key = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	FILE *private_key_file = NULL;

	*token_out = NULL;

	escaped_req_id = json_escape_string(request->req_id);
	escaped_sid = json_escape_string(request->sid);
	escaped_action = json_escape_string(request->action);
	escaped_object = json_escape_string(request->object);
	escaped_digest = json_escape_string(request->normalized_scope_digest);
	if (!escaped_req_id || !escaped_sid || !escaped_action ||
	    !escaped_object || !escaped_digest)
		goto out;

	snprintf(payload, sizeof(payload),
		 "{\"version\":1,\"reqId\":%s,\"sid\":%s,"
		 "\"action\":%s,\"object\":%s,\"scope\":%s,"
		 "\"normalizedScopeDigest\":%s,"
		 "\"issuedAtMs\":%lld,\"expiresAtMs\":%lld}",
		 escaped_req_id, escaped_sid, escaped_action, escaped_object,
		 request->scope_raw[0] ? request->scope_raw : "{}",
		 escaped_digest, issued_at_ms, expires_at_ms);

	if (!b64url_encode((const unsigned char *)payload, strlen(payload),
			   &payload_b64))
		goto out;

	if (strcmp(config->verify_mode, "none") == 0) {
		static const unsigned char none_signature[] = "none";

		if (!b64url_encode(none_signature, sizeof(none_signature) - 1,
				   &signature_b64))
			goto out;
	} else if (strcmp(config->verify_mode, "hmac-sha256") == 0) {
		unsigned char *digest = NULL;

		digest = HMAC(EVP_sha256(), config->hmac_key,
			      (int)strlen(config->hmac_key),
			      (const unsigned char *)payload_b64,
			      strlen(payload_b64),
			      signature, &signature_len);
		if (!digest)
			goto out;
		if (!b64url_encode(signature, signature_len, &signature_b64))
			goto out;
	} else if (strcmp(config->verify_mode, "ed25519") == 0) {
		if (!config->signing_private_key_file[0])
			goto out;

		private_key_file = fopen(config->signing_private_key_file, "r");
		if (!private_key_file)
			goto out;

		private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
		fclose(private_key_file);
		private_key_file = NULL;
		if (!private_key)
			goto out;

		md_ctx = EVP_MD_CTX_new();
		if (!md_ctx)
			goto out;
		if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, private_key) <= 0)
			goto out;
		if (EVP_DigestSign(md_ctx, NULL, &dynamic_signature_len,
				   (const unsigned char *)payload_b64,
				   strlen(payload_b64)) <= 0)
			goto out;

		dynamic_signature = malloc(dynamic_signature_len);
		if (!dynamic_signature)
			goto out;
		if (EVP_DigestSign(md_ctx, dynamic_signature, &dynamic_signature_len,
				   (const unsigned char *)payload_b64,
				   strlen(payload_b64)) <= 0)
			goto out;
		if (!b64url_encode(dynamic_signature, dynamic_signature_len,
				   &signature_b64))
			goto out;
	} else {
		goto out;
	}

	*token_out = malloc(strlen(payload_b64) + strlen(signature_b64) + 2);
	if (!*token_out)
		goto out;

	sprintf(*token_out, "%s.%s", payload_b64, signature_b64);
	ok = true;
out:
	free(escaped_req_id);
	free(escaped_sid);
	free(escaped_action);
	free(escaped_object);
	free(escaped_digest);
	free(payload_b64);
	free(signature_b64);
	free(dynamic_signature);
	if (md_ctx)
		EVP_MD_CTX_free(md_ctx);
	if (private_key)
		EVP_PKEY_free(private_key);
	if (private_key_file)
		fclose(private_key_file);
	if (!ok) {
		free(*token_out);
		*token_out = NULL;
	}
	return ok;
}

static void normalize_authorize_response_for_openclaw(char **output,
						      const struct scope_request *request)
{
	if (!output || !*output || !request)
		return;

	if (request->request_json[0])
		json_replace_value(output, "normalizedRequest", request->request_json);
}

static void normalize_confirm_response_for_openclaw(char **output,
						    const struct pending_confirmation *pending)
{
	if (!output || !*output || !pending)
		return;
	if (pending->request.request_json[0])
		json_replace_value(output, "normalizedRequest",
				   pending->request.request_json);
}

static void remember_pending(struct server_state *state,
			     const char *confirmation_request_id,
			     const struct scope_request *request)
{
	size_t index = 0;
	size_t slot = 0;

	for (index = 0; index < ARRAY_SIZE(state->pending); index++) {
		if (!state->pending[index].active) {
			slot = index;
			goto write_slot;
		}
		if (strcmp(state->pending[index].confirmation_request_id,
			   confirmation_request_id) == 0) {
			slot = index;
			goto write_slot;
		}
	}

	slot = 0;
write_slot:
	state->pending[slot].active = true;
	copy_text(state->pending[slot].confirmation_request_id,
		  sizeof(state->pending[slot].confirmation_request_id),
		  confirmation_request_id);
	state->pending[slot].expires_at_ms =
		now_ms() + state->config.confirmation_ttl_ms;
	memcpy(&state->pending[slot].request, request,
	       sizeof(state->pending[slot].request));
}

static struct pending_confirmation *find_pending(struct server_state *state,
						 const char *confirmation_request_id)
{
	size_t index = 0;

	for (index = 0; index < ARRAY_SIZE(state->pending); index++) {
		if (!state->pending[index].active)
			continue;
		if (strcmp(state->pending[index].confirmation_request_id,
			   confirmation_request_id) == 0)
			return &state->pending[index];
	}

	return NULL;
}

static void clear_pending(struct pending_confirmation *pending)
{
	if (!pending)
		return;

	memset(pending, 0, sizeof(*pending));
}

static bool parse_authorize_request(const char *json, struct scope_request *request,
				    int default_ttl_ms, char **error_message)
{
	long long seq = 1;
	long long ttl_ms = default_ttl_ms;

	memset(request, 0, sizeof(*request));

	if (strlen(json) >= sizeof(request->request_json)) {
		*error_message = build_error_json("bad_request",
						"authorize request too large");
		return false;
	}
	copy_text(request->request_json, sizeof(request->request_json), json);

	if (!json_get_string_top_level(json, "reqId", request->req_id,
				       sizeof(request->req_id))) {
		*error_message = build_error_json("bad_request",
						"missing or invalid field: reqId");
		return false;
	}
	if (!json_get_string_top_level(json, "sid", request->sid,
				       sizeof(request->sid))) {
		*error_message = build_error_json("bad_request",
						"missing or invalid field: sid");
		return false;
	}
	if (!json_get_string_top_level(json, "toolName", request->tool_name,
				       sizeof(request->tool_name))) {
		*error_message = build_error_json("bad_request",
						"missing or invalid field: toolName");
		return false;
	}
	if (!json_get_string_top_level(json, "action", request->action,
				       sizeof(request->action))) {
		*error_message = build_error_json("bad_request",
						"missing or invalid field: action");
		return false;
	}
	if (!json_get_string_top_level(json, "object", request->object,
				       sizeof(request->object))) {
		*error_message = build_error_json("bad_request",
						"missing or invalid field: object");
		return false;
	}
	if (!json_get_string_top_level(json, "level", request->level,
				       sizeof(request->level))) {
		*error_message = build_error_json("bad_request",
						"missing or invalid field: level");
		return false;
	}

	request->seq = 1;
	request->ttl_ms = default_ttl_ms;
	request->issued_at_ms = 0;
	json_get_int64_top_level(json, "seq", &seq);
	json_get_int64_top_level(json, "ttlMs", &ttl_ms);
	json_get_int64_top_level(json, "issuedAtMs", &request->issued_at_ms);
	request->seq = (int)seq;
	request->ttl_ms = (int)ttl_ms;
	if (request->ttl_ms <= 0)
		request->ttl_ms = default_ttl_ms;

	if (!json_get_string_top_level(json, "normalizedScopeDigest",
				       request->normalized_scope_digest,
				       sizeof(request->normalized_scope_digest))) {
		*error_message = build_error_json(
			"bad_request",
			"missing or invalid field: normalizedScopeDigest");
		return false;
	}

	if (!json_get_raw_value_top_level(json, "scope", request->scope_raw,
					  sizeof(request->scope_raw)))
		copy_text(request->scope_raw, sizeof(request->scope_raw), "{}");
	if (!json_get_string_top_level(json, "workspaceRoot",
				       request->workspace_root,
				       sizeof(request->workspace_root))) {
		request->workspace_root[0] = '\0';
	}
	if (!json_get_string_top_level(json, "sessionKey",
				       request->session_binding,
				       sizeof(request->session_binding)) &&
	    !json_get_string_top_level(json, "sessionId",
				       request->session_binding,
				       sizeof(request->session_binding))) {
		request->session_binding[0] = '\0';
	}

	return true;
}

static bool parse_required_string_field(const char *json, const char *field,
					char *out, size_t out_len,
					char **error_message)
{
	char message[MAX_JSON_TOKEN];

	if (json_get_string(json, field, out, out_len))
		return true;

	snprintf(message, sizeof(message), "missing or invalid field: %s", field);
	*error_message = build_error_json("bad_request", message);
	return false;
}

static bool response_is_approved(const char *json)
{
	char status[OC_TA_MAX_STATUS];
	bool ok = false;

	if (!json_get_bool(json, "ok", &ok) || !ok)
		return false;
	if (!json_get_string(json, "status", status, sizeof(status)))
		return false;
	return strcmp(status, "approved") == 0;
}

static bool response_allows_scope_token(const char *json)
{
	bool allow = false;
	char execution_mode[OC_TA_MAX_STATUS];

	if (!json_get_bool(json, "allow", &allow) || !allow)
		return false;
	if (!json_get_string(json, "executionMode", execution_mode,
			     sizeof(execution_mode)))
		return false;
	return strcmp(execution_mode, "ree-direct") != 0;
}

static char *run_healthz(struct server_state *state, int *status)
{
	char *output = NULL;
	int exit_code = 0;
	char *argv[] = {
		state->config.ca_binary,
		"healthz",
		NULL,
	};

	if (!run_ca_command(argv, &output, &exit_code)) {
		*status = 500;
		return build_error_json("internal_error",
				      "failed to invoke CA");
	}

	if (exit_code != 0) {
		*status = 500;
		return ca_failure_json(output, "CA healthz command failed");
	}

	json_replace_string(&output, "mode", state->config.verify_mode);
	*status = 200;
	return output;
}

static char *run_guest(struct server_state *state, int *status)
{
	char *output = NULL;
	int exit_code = 0;
	char *argv[] = {
		state->config.ca_binary,
		"guest",
		NULL,
	};

	if (!run_ca_command(argv, &output, &exit_code)) {
		*status = 500;
		return build_error_json("internal_error",
				      "failed to invoke CA");
	}

	if (exit_code != 0) {
		*status = 500;
		return ca_failure_json(output, "CA guest command failed");
	}

	*status = 200;
	return output;
}

static char *run_authorize(struct server_state *state, const char *body,
			   int *status)
{
	struct scope_request request;
	char *output = NULL;
	char *token = NULL;
	char *error_json = NULL;
	char confirmation_request_id[OC_TA_MAX_ID];
	int exit_code = 0;
	char seq_raw[16];
	char ttl_raw[16];
	char *argv[28];
	size_t argc = 0;

	if (!parse_authorize_request(body, &request,
				     state->config.scope_token_ttl_ms,
				     &error_json)) {
		*status = 400;
		return error_json;
	}

	snprintf(seq_raw, sizeof(seq_raw), "%d", request.seq);
	snprintf(ttl_raw, sizeof(ttl_raw), "%d", request.ttl_ms);

	argv[argc++] = state->config.ca_binary;
	argv[argc++] = "authorize";
	argv[argc++] = "--req-id";
	argv[argc++] = request.req_id;
	argv[argc++] = "--sid";
	argv[argc++] = request.sid;
	argv[argc++] = "--tool-name";
	argv[argc++] = request.tool_name;
	argv[argc++] = "--action";
	argv[argc++] = request.action;
	argv[argc++] = "--object";
	argv[argc++] = request.object;
	argv[argc++] = "--level";
	argv[argc++] = request.level;
	argv[argc++] = "--normalized-scope-digest";
	argv[argc++] = request.normalized_scope_digest;
	argv[argc++] = "--scope-json";
	argv[argc++] = request.scope_raw;
	argv[argc++] = "--workspace-root";
	argv[argc++] = request.workspace_root;
	argv[argc++] = "--session-binding";
	argv[argc++] = request.session_binding;
	argv[argc++] = "--seq";
	argv[argc++] = seq_raw;
	argv[argc++] = "--ttl-ms";
	argv[argc++] = ttl_raw;
	argv[argc] = NULL;

	if (!run_ca_command(argv, &output, &exit_code)) {
		*status = 500;
		return build_error_json("internal_error",
				      "failed to invoke CA");
	}

	if (exit_code != 0) {
		*status = 500;
		return ca_failure_json(output, "CA authorize command failed");
	}

	normalize_authorize_response_for_openclaw(&output, &request);

	if (response_allows_scope_token(output) &&
	    mint_scope_token(&state->config, &request, &token)) {
		json_replace_string(&output, "scopeToken", token);
	}
	free(token);

	if (json_get_string(output, "confirmationRequestId",
			    confirmation_request_id,
			    sizeof(confirmation_request_id))) {
		remember_pending(state, confirmation_request_id, &request);
		json_replace_number(&output, "expiresAtMs",
				    now_ms() +
				    state->config.confirmation_ttl_ms);
	}

	*status = 200;
	return output;
}

static char *run_confirm(struct server_state *state, const char *body,
			 int *status)
{
	char confirmation_request_id[OC_TA_MAX_ID];
	char challenge_token[OC_TA_MAX_TOKEN];
	char operator_id[OC_TA_MAX_ID];
	char decision[OC_TA_MAX_ACTION];
	struct pending_confirmation *pending = NULL;
	char *output = NULL;
	char *token = NULL;
	char *error_json = NULL;
	int exit_code = 0;
	char seq_raw[16];
	char ttl_raw[16];
	char *argv[34];
	size_t argc = 0;

	if (!parse_required_string_field(body, "confirmationRequestId",
					 confirmation_request_id,
					 sizeof(confirmation_request_id),
					 &error_json) ||
	    !parse_required_string_field(body, "challengeToken",
					 challenge_token,
					 sizeof(challenge_token),
					 &error_json) ||
	    !parse_required_string_field(body, "operatorId",
					 operator_id,
					 sizeof(operator_id),
					 &error_json) ||
	    !parse_required_string_field(body, "decision",
					 decision,
					 sizeof(decision),
					 &error_json)) {
		*status = 400;
		return error_json;
	}

	pending = find_pending(state, confirmation_request_id);

	argv[argc++] = state->config.ca_binary;
	argv[argc++] = "confirm";
	argv[argc++] = "--confirmation-request-id";
	argv[argc++] = confirmation_request_id;
	argv[argc++] = "--challenge-token";
	argv[argc++] = challenge_token;
	argv[argc++] = "--operator-id";
	argv[argc++] = operator_id;
	argv[argc++] = "--decision";
	argv[argc++] = decision;
	if (pending) {
		snprintf(seq_raw, sizeof(seq_raw), "%d", pending->request.seq);
		snprintf(ttl_raw, sizeof(ttl_raw), "%d", pending->request.ttl_ms);
		argv[argc++] = "--req-id";
		argv[argc++] = pending->request.req_id;
		argv[argc++] = "--sid";
		argv[argc++] = pending->request.sid;
		argv[argc++] = "--tool-name";
		argv[argc++] = pending->request.tool_name;
		argv[argc++] = "--action";
		argv[argc++] = pending->request.action;
		argv[argc++] = "--object";
		argv[argc++] = pending->request.object;
		argv[argc++] = "--level";
		argv[argc++] = pending->request.level;
		argv[argc++] = "--normalized-scope-digest";
		argv[argc++] = pending->request.normalized_scope_digest;
		argv[argc++] = "--scope-json";
		argv[argc++] = pending->request.scope_raw;
		argv[argc++] = "--workspace-root";
		argv[argc++] = pending->request.workspace_root;
		argv[argc++] = "--session-binding";
		argv[argc++] = pending->request.session_binding;
		argv[argc++] = "--seq";
		argv[argc++] = seq_raw;
		argv[argc++] = "--ttl-ms";
		argv[argc++] = ttl_raw;
	}
	argv[argc] = NULL;

	if (!run_ca_command(argv, &output, &exit_code)) {
		*status = 500;
		return build_error_json("internal_error",
				      "failed to invoke CA");
	}

	if (exit_code != 0) {
		*status = 500;
		return ca_failure_json(output, "CA confirm command failed");
	}

	normalize_confirm_response_for_openclaw(&output, pending);
	json_replace_number(&output, "confirmedAtMs", now_ms());

	if (pending && response_is_approved(output) &&
	    mint_scope_token(&state->config, &pending->request, &token)) {
		json_replace_string(&output, "scopeToken", token);
	}
	free(token);

	if (pending)
		clear_pending(pending);

	*status = 200;
	return output;
}

static char *run_complete(struct server_state *state, const char *body,
			  int *status)
{
	char req_id[OC_TA_MAX_ID];
	char sid[OC_TA_MAX_ID];
	char tool_name[OC_TA_MAX_TOOL_NAME];
	char action[OC_TA_MAX_ACTION];
	char object[OC_TA_MAX_OBJECT];
	char result_status[OC_TA_MAX_STATUS];
	char result_digest[OC_TA_MAX_DIGEST];
	char *output = NULL;
	char *error_json = NULL;
	int exit_code = 0;
	char *argv[18];
	size_t argc = 0;

	if (!parse_required_string_field(body, "reqId",
					 req_id, sizeof(req_id),
					 &error_json) ||
	    !parse_required_string_field(body, "sid",
					 sid, sizeof(sid),
					 &error_json) ||
	    !parse_required_string_field(body, "toolName",
					 tool_name, sizeof(tool_name),
					 &error_json) ||
	    !parse_required_string_field(body, "action",
					 action, sizeof(action),
					 &error_json) ||
	    !parse_required_string_field(body, "object",
					 object, sizeof(object),
					 &error_json) ||
	    !parse_required_string_field(body, "status",
					 result_status, sizeof(result_status),
					 &error_json) ||
	    !parse_required_string_field(body, "resultDigest",
					 result_digest,
					 sizeof(result_digest),
					 &error_json)) {
		*status = 400;
		return error_json;
	}

	argv[argc++] = state->config.ca_binary;
	argv[argc++] = "complete";
	argv[argc++] = "--req-id";
	argv[argc++] = req_id;
	argv[argc++] = "--sid";
	argv[argc++] = sid;
	argv[argc++] = "--tool-name";
	argv[argc++] = tool_name;
	argv[argc++] = "--action";
	argv[argc++] = action;
	argv[argc++] = "--object";
	argv[argc++] = object;
	argv[argc++] = "--status";
	argv[argc++] = result_status;
	argv[argc++] = "--result-digest";
	argv[argc++] = result_digest;
	argv[argc] = NULL;

	if (!run_ca_command(argv, &output, &exit_code)) {
		*status = 500;
		return build_error_json("internal_error",
				      "failed to invoke CA");
	}

	if (exit_code != 0) {
		*status = 500;
		return ca_failure_json(output, "CA complete command failed");
	}

	*status = 200;
	return output;
}

static char *run_remote_exec(struct server_state *state, const char *body,
			     int *status)
{
	char authorize_request_json[MAX_REQUEST_JSON];
	char local_approval_json[MAX_REQUEST_JSON];
	struct scope_request request;
	struct exec_spec spec;
	char *authorize_output = NULL;
	char *complete_body = NULL;
	char *complete_output = NULL;
	char *execution_json = NULL;
	char *response_json = NULL;
	char *stdout_text = NULL;
	char *stderr_text = NULL;
	char *escaped_status = NULL;
	char *escaped_stdout = NULL;
	char *escaped_stderr = NULL;
	char *escaped_digest = NULL;
	char result_digest[OC_TA_MAX_DIGEST];
	long long started_at_ms = 0;
	long long finished_at_ms = 0;
	int authorize_status = 0;
	int complete_status = 0;
	int exit_code = -1;
	int written = 0;
	bool allow = false;
	bool executed = false;
	bool completed = false;
	char decision[OC_TA_MAX_ACTION];
	char *error_json = NULL;

	memset(local_approval_json, 0, sizeof(local_approval_json));

	if (!json_get_raw_value_top_level(body, "authorizeRequest",
					  authorize_request_json,
					  sizeof(authorize_request_json))) {
		*status = 400;
		return build_error_json("invalid_remote_exec",
				      "missing authorizeRequest");
	}

	if (!parse_authorize_request(authorize_request_json, &request,
				     state->config.scope_token_ttl_ms,
				     &error_json)) {
		*status = 400;
		return error_json;
	}

	if (!parse_exec_spec(&request, &spec, &error_json)) {
		*status = 400;
		return error_json;
	}
	if (json_get_raw_value_top_level(body, "localApproval",
					 local_approval_json,
					 sizeof(local_approval_json))) {
		error_json = verify_upstream_local_approval(&state->config,
							    local_approval_json,
							    &request, &spec);
		if (error_json) {
			*status = 200;
			response_json = build_remote_exec_response(
				"local-approval-invalid", false, false, false,
				error_json, NULL, NULL);
			free(error_json);
			return response_json ? response_json :
				build_error_json("invalid_local_approval",
					       "failed to build local-approval-invalid response");
		}
	}

	authorize_output = run_authorize(state, authorize_request_json,
					 &authorize_status);
	if (!authorize_output) {
		*status = 500;
		return build_error_json("remote_authorize_failed",
				      "authorize returned no response");
	}
	if (authorize_status != 200) {
		*status = 200;
		response_json = build_remote_exec_response("authorize-error", false,
							  false, false,
							  authorize_output, NULL,
							  NULL);
		free(authorize_output);
		return response_json ? response_json :
			build_error_json("remote_authorize_failed",
				       "failed to build authorize-error response");
	}

	if (!json_get_bool(authorize_output, "allow", &allow))
		allow = false;
	if (!json_get_string(authorize_output, "decision", decision,
			     sizeof(decision)))
		copy_text(decision, sizeof(decision), allow ? "dia" : "ddeny");

	if (!allow || strcmp(decision, "duc") == 0) {
		*status = 200;
		response_json = build_remote_exec_response(
			strcmp(decision, "duc") == 0 ? "confirmation-required" :
						       "authorize-denied",
			false, false, false, authorize_output, NULL, NULL);
		free(authorize_output);
		return response_json ? response_json :
			build_error_json("remote_authorize_failed",
				       "failed to build denied response");
	}
	if (strcmp(decision, "die") == 0) {
		*status = 200;
		response_json = build_remote_exec_response(
			"authorize-isolated-unavailable", false, false, false,
			authorize_output, NULL, NULL);
		free(authorize_output);
		return response_json ? response_json :
			build_error_json("remote_authorize_failed",
				       "failed to build isolated-unavailable response");
	}

	started_at_ms = now_ms();
	if (!run_exec_spec(&spec, &stdout_text, &stderr_text, &exit_code)) {
		*status = 500;
		free(authorize_output);
		return build_error_json("remote_exec_failed",
				      "failed to execute remote command");
	}
	finished_at_ms = now_ms();
	executed = true;

	if (!compute_exec_result_digest(exit_code, stdout_text, stderr_text,
					 result_digest)) {
		*status = 500;
		free(authorize_output);
		free(stdout_text);
		free(stderr_text);
		return build_error_json("remote_exec_failed",
				      "failed to compute result digest");
	}

	complete_body = build_remote_exec_complete_body(
		&request, exit_code == 0 ? "ok" : "error", result_digest);
	if (!complete_body) {
		*status = 500;
		free(authorize_output);
		free(stdout_text);
		free(stderr_text);
		return build_error_json("remote_complete_failed",
				      "failed to build complete request");
	}

	complete_output = run_complete(state, complete_body, &complete_status);
	completed = complete_output && complete_status == 200;

	escaped_status = json_escape_string(exit_code == 0 ? "ok" : "error");
	escaped_stdout = json_escape_string(stdout_text ? stdout_text : "");
	escaped_stderr = json_escape_string(stderr_text ? stderr_text : "");
	escaped_digest = json_escape_string(result_digest);
	if (!escaped_status || !escaped_stdout || !escaped_stderr ||
	    !escaped_digest) {
		*status = 500;
		response_json = build_error_json("remote_exec_failed",
					       "failed to encode execution result");
		goto out;
	}

	written = snprintf(
		NULL, 0,
		"{\"startedAtMs\":%lld,\"finishedAtMs\":%lld,\"durationMs\":%lld,"
		"\"exitCode\":%d,\"status\":%s,\"stdout\":%s,\"stderr\":%s,"
		"\"resultDigest\":%s}",
		started_at_ms, finished_at_ms, finished_at_ms - started_at_ms,
		exit_code, escaped_status, escaped_stdout, escaped_stderr,
		escaped_digest);
	if (written < 0) {
		*status = 500;
		response_json = build_error_json("remote_exec_failed",
					       "failed to size execution result");
		goto out;
	}

	execution_json = malloc((size_t)written + 1);
	if (!execution_json) {
		*status = 500;
		response_json = build_error_json("remote_exec_failed",
					       "failed to allocate execution result");
		goto out;
	}

	snprintf(execution_json, (size_t)written + 1,
		 "{\"startedAtMs\":%lld,\"finishedAtMs\":%lld,\"durationMs\":%lld,"
		 "\"exitCode\":%d,\"status\":%s,\"stdout\":%s,\"stderr\":%s,"
		 "\"resultDigest\":%s}",
		 started_at_ms, finished_at_ms, finished_at_ms - started_at_ms,
		 exit_code, escaped_status, escaped_stdout, escaped_stderr,
		 escaped_digest);

	response_json = build_remote_exec_response(
		completed ? "completed" : "complete-error", true, executed,
		completed, authorize_output, execution_json, complete_output);
	if (!response_json) {
		*status = 500;
		response_json = build_error_json("remote_exec_failed",
					       "failed to build response");
		goto out;
	}

	*status = 200;
out:
	free(authorize_output);
	free(complete_body);
	free(complete_output);
	free(execution_json);
	free(stdout_text);
	free(stderr_text);
	free(escaped_status);
	free(escaped_stdout);
	free(escaped_stderr);
	free(escaped_digest);
	return response_json;
}

static char *dispatch_request(struct server_state *state,
			      const struct http_request *request, int *status)
{
	if (strcmp(request->method, "GET") == 0) {
		if (strcmp(request->path, "/healthz") == 0)
			return run_healthz(state, status);
		if (strcmp(request->path, "/v1/trusted/guest") == 0)
			return run_guest(state, status);
		*status = 404;
		return build_error_json("not_found", "not_found");
	}

	if (strcmp(request->method, "POST") == 0) {
		if (strcmp(request->path, "/v1/trusted/authorize") == 0)
			return run_authorize(state, request->body, status);
		if (strcmp(request->path, "/v1/trusted/confirm") == 0)
			return run_confirm(state, request->body, status);
		if (strcmp(request->path, "/v1/trusted/complete") == 0)
			return run_complete(state, request->body, status);
		if (strcmp(request->path, "/v1/trusted/remote-exec") == 0)
			return run_remote_exec(state, request->body, status);
		*status = 404;
		return build_error_json("not_found", "not_found");
	}

	*status = 404;
	return build_error_json("not_found", "not_found");
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s [--bind ADDR] [--port PORT] [--ca-binary PATH]\n"
		"     [--verify-mode none|hmac-sha256|ed25519] [--hmac-key KEY]\n"
		"     [--signing-private-key-file PATH]\n"
		"     [--upstream-tdx-public-key-file PATH]\n"
		"     [--scope-token-ttl-ms N] [--confirmation-ttl-ms N]\n",
		argv0);
}

static int parse_args(int argc, char *argv[], struct server_config *config)
{
	int index = 1;

	copy_text(config->bind, sizeof(config->bind),
		  getenv("OPTEE_BACKEND_BIND"));
	if (!config->bind[0])
		copy_text(config->bind, sizeof(config->bind), DEFAULT_BIND);

	config->port = coerce_int(getenv("OPTEE_BACKEND_PORT"), DEFAULT_PORT);

	copy_text(config->ca_binary, sizeof(config->ca_binary),
		  getenv("OPTEE_BACKEND_CA_BINARY"));
	if (!config->ca_binary[0])
		copy_text(config->ca_binary, sizeof(config->ca_binary),
			  DEFAULT_CA_BINARY);

	copy_text(config->verify_mode, sizeof(config->verify_mode),
		  getenv("OPTEE_TRUSTED_VERIFY_MODE"));
	if (!config->verify_mode[0])
		copy_text(config->verify_mode, sizeof(config->verify_mode),
			  DEFAULT_VERIFY_MODE);

	copy_text(config->hmac_key, sizeof(config->hmac_key),
		  getenv("OPTEE_TRUSTED_HMAC_KEY"));
	copy_text(config->signing_private_key_file,
		  sizeof(config->signing_private_key_file),
		  getenv("OPTEE_TRUSTED_SIGNING_PRIVATE_KEY_FILE"));
	if (!config->signing_private_key_file[0])
		copy_text(config->signing_private_key_file,
			  sizeof(config->signing_private_key_file),
			  DEFAULT_SIGNING_PRIVATE_KEY_FILE);
	copy_text(config->upstream_tdx_public_key_file,
		  sizeof(config->upstream_tdx_public_key_file),
		  getenv("OPTEE_TRUSTED_UPSTREAM_TDX_PUBLIC_KEY_FILE"));
	config->scope_token_ttl_ms =
		coerce_int(getenv("OPTEE_SCOPE_TOKEN_TTL_MS"),
			   DEFAULT_SCOPE_TOKEN_TTL_MS);
	config->confirmation_ttl_ms =
		coerce_int(getenv("OPTEE_CONFIRMATION_TTL_MS"),
			   DEFAULT_CONFIRMATION_TTL_MS);

	while (index < argc) {
		if (strcmp(argv[index], "--bind") == 0 && index + 1 < argc) {
			copy_text(config->bind, sizeof(config->bind), argv[++index]);
		} else if (strcmp(argv[index], "--port") == 0 &&
			   index + 1 < argc) {
			config->port = coerce_int(argv[++index], config->port);
		} else if (strcmp(argv[index], "--ca-binary") == 0 &&
			   index + 1 < argc) {
			copy_text(config->ca_binary, sizeof(config->ca_binary),
				  argv[++index]);
		} else if (strcmp(argv[index], "--verify-mode") == 0 &&
			   index + 1 < argc) {
			copy_text(config->verify_mode,
				  sizeof(config->verify_mode), argv[++index]);
		} else if (strcmp(argv[index], "--hmac-key") == 0 &&
			   index + 1 < argc) {
			copy_text(config->hmac_key, sizeof(config->hmac_key),
				  argv[++index]);
		} else if (strcmp(argv[index], "--signing-private-key-file") == 0 &&
			   index + 1 < argc) {
			copy_text(config->signing_private_key_file,
				  sizeof(config->signing_private_key_file),
				  argv[++index]);
		} else if (strcmp(argv[index], "--upstream-tdx-public-key-file") == 0 &&
			   index + 1 < argc) {
			copy_text(config->upstream_tdx_public_key_file,
				  sizeof(config->upstream_tdx_public_key_file),
				  argv[++index]);
		} else if (strcmp(argv[index], "--scope-token-ttl-ms") == 0 &&
			   index + 1 < argc) {
			config->scope_token_ttl_ms =
				coerce_int(argv[++index],
					   config->scope_token_ttl_ms);
		} else if (strcmp(argv[index], "--confirmation-ttl-ms") == 0 &&
			   index + 1 < argc) {
			config->confirmation_ttl_ms =
				coerce_int(argv[++index],
					   config->confirmation_ttl_ms);
		} else if (strcmp(argv[index], "--help") == 0 ||
			   strcmp(argv[index], "-h") == 0) {
			usage(argv[0]);
			return 1;
		} else {
			fprintf(stderr, "Unknown argument: %s\n", argv[index]);
			usage(argv[0]);
			return 1;
		}
		index++;
	}

	if (strcmp(config->verify_mode, "none") != 0 &&
	    strcmp(config->verify_mode, "hmac-sha256") != 0 &&
	    strcmp(config->verify_mode, "ed25519") != 0) {
		fprintf(stderr, "Unsupported verify mode: %s\n",
			config->verify_mode);
		return 1;
	}
	if (strcmp(config->verify_mode, "hmac-sha256") == 0 &&
	    !config->hmac_key[0]) {
		fprintf(stderr,
				"verify mode hmac-sha256 requires --hmac-key or OPTEE_TRUSTED_HMAC_KEY\n");
		return 1;
	}
	if (strcmp(config->verify_mode, "ed25519") == 0 &&
	    !config->signing_private_key_file[0]) {
		fprintf(stderr,
				"verify mode ed25519 requires --signing-private-key-file or OPTEE_TRUSTED_SIGNING_PRIVATE_KEY_FILE\n");
		return 1;
	}
	if (strcmp(config->verify_mode, "ed25519") == 0 &&
	    access(config->signing_private_key_file, R_OK) != 0) {
		fprintf(stderr, "ed25519 private key not readable: %s\n",
			config->signing_private_key_file);
		return 1;
	}
	if (!config->ca_binary[0]) {
		fprintf(stderr, "CA binary path is empty\n");
		return 1;
	}
	if (access(config->ca_binary, X_OK) != 0) {
		fprintf(stderr, "CA binary not found or not executable: %s\n",
			config->ca_binary);
		return 1;
	}

	return 0;
}

static int create_server_socket(const struct server_config *config)
{
	int server_fd = -1;
	int opt = 1;
	struct sockaddr_in addr;

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		perror("socket");
		return -1;
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt,
		       sizeof(opt)) < 0) {
		perror("setsockopt");
		close(server_fd);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)config->port);
	if (inet_pton(AF_INET, config->bind, &addr.sin_addr) != 1) {
		fprintf(stderr, "invalid bind address: %s\n", config->bind);
		close(server_fd);
		return -1;
	}

	if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(server_fd);
		return -1;
	}

	if (listen(server_fd, 16) < 0) {
		perror("listen");
		close(server_fd);
		return -1;
	}

	return server_fd;
}

int main(int argc, char *argv[])
{
	struct server_state state;
	int server_fd = -1;

	memset(&state, 0, sizeof(state));
	signal(SIGPIPE, SIG_IGN);

	if (parse_args(argc, argv, &state.config))
		return 1;

	server_fd = create_server_socket(&state.config);
	if (server_fd < 0)
		return 1;

	printf("openclaw-optee-backend listening on http://%s:%d (ca=%s, verify_mode=%s)\n",
	       state.config.bind, state.config.port,
	       state.config.ca_binary, state.config.verify_mode);

	while (1) {
		struct sockaddr_in peer_addr;
		socklen_t peer_len = sizeof(peer_addr);
		struct http_request request;
		char *response = NULL;
		int client_fd = accept(server_fd, (struct sockaddr *)&peer_addr,
				       &peer_len);
		int status = 0;

		if (client_fd < 0) {
			if (errno == EINTR)
				continue;
			perror("accept");
			break;
		}

		memset(&request, 0, sizeof(request));
		if (!read_http_request(client_fd, &request)) {
			response = build_error_json("bad_request",
						    "invalid http request");
			send_json_response(client_fd, 400,
					   response ? response :
					   "{\"error\":\"bad_request\"}");
			free(response);
			close(client_fd);
			continue;
		}

		response = dispatch_request(&state, &request, &status);
		send_json_response(client_fd, status,
				   response ? response :
				   "{\"error\":\"internal_error\"}");

		free(response);
		http_request_cleanup(&request);
		close(client_fd);
	}

	close(server_fd);
	return 0;
}
