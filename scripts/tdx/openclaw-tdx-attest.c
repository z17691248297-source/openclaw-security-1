#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <tdx_attest.h>

#define DEFAULT_SERVICE_NAME "openclaw-trusted-backend"

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

static int fill_random(uint8_t *buf, size_t len) {
  FILE *random = fopen("/dev/urandom", "rb");
  if (random != NULL) {
    size_t read_count = fread(buf, 1, len, random);
    fclose(random);
    if (read_count == len) {
      return 0;
    }
  }

  srand((unsigned int)time(NULL));
  for (size_t i = 0; i < len; i++) {
    buf[i] = (uint8_t)(rand() & 0xff);
  }
  return 0;
}

static int fill_report_data(tdx_report_data_t *report_data, const char *nonce_hex) {
  memset(report_data->d, 0, sizeof(report_data->d));

  if (nonce_hex == NULL || nonce_hex[0] == '\0') {
    return fill_random(report_data->d, sizeof(report_data->d));
  }

  size_t hex_len = strlen(nonce_hex);
  if ((hex_len % 2) != 0) {
    fprintf(stderr, "TRUSTED_TDX_NONCE_HEX must contain an even number of hex characters\n");
    return -1;
  }

  size_t byte_len = hex_len / 2;
  if (byte_len > sizeof(report_data->d)) {
    fprintf(
        stderr,
        "TRUSTED_TDX_NONCE_HEX is too large for TDX report data (%zu bytes > %zu bytes)\n",
        byte_len,
        sizeof(report_data->d));
    return -1;
  }

  for (size_t i = 0; i < byte_len; i++) {
    int high = hex_nibble(nonce_hex[i * 2]);
    int low = hex_nibble(nonce_hex[i * 2 + 1]);
    if (high < 0 || low < 0) {
      fprintf(stderr, "TRUSTED_TDX_NONCE_HEX contains non-hex characters\n");
      return -1;
    }
    report_data->d[i] = (uint8_t)((high << 4) | low);
  }

  return 0;
}

static char *hex_encode(const uint8_t *buf, size_t len) {
  static const char hex_table[] = "0123456789abcdef";
  size_t out_len = (len * 2) + 1;
  char *out = calloc(out_len, sizeof(char));
  if (out == NULL) {
    return NULL;
  }

  for (size_t i = 0; i < len; i++) {
    out[i * 2] = hex_table[(buf[i] >> 4) & 0x0f];
    out[(i * 2) + 1] = hex_table[buf[i] & 0x0f];
  }
  out[out_len - 1] = '\0';
  return out;
}

static char *base64_encode(const uint8_t *buf, size_t len) {
  static const char base64_table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t out_len = ((len + 2) / 3) * 4;
  char *out = calloc(out_len + 1, sizeof(char));
  if (out == NULL) {
    return NULL;
  }

  size_t input_index = 0;
  size_t output_index = 0;
  while (input_index < len) {
    uint32_t chunk = 0;
    size_t chunk_len = 0;

    for (size_t i = 0; i < 3; i++) {
      chunk <<= 8;
      if (input_index < len) {
        chunk |= buf[input_index++];
        chunk_len++;
      }
    }

    out[output_index++] = base64_table[(chunk >> 18) & 0x3f];
    out[output_index++] = base64_table[(chunk >> 12) & 0x3f];
    out[output_index++] = chunk_len > 1 ? base64_table[(chunk >> 6) & 0x3f] : '=';
    out[output_index++] = chunk_len > 2 ? base64_table[chunk & 0x3f] : '=';
  }

  out[out_len] = '\0';
  return out;
}

static void print_json_string(const char *value) {
  putchar('"');
  for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; cursor++) {
    switch (*cursor) {
      case '\\':
        fputs("\\\\", stdout);
        break;
      case '"':
        fputs("\\\"", stdout);
        break;
      case '\b':
        fputs("\\b", stdout);
        break;
      case '\f':
        fputs("\\f", stdout);
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
        if (*cursor < 0x20) {
          printf("\\u%04x", *cursor);
        } else {
          putchar(*cursor);
        }
        break;
    }
  }
  putchar('"');
}

static void print_json_field(const char *key, const char *value, int *needs_comma) {
  if (value == NULL || value[0] == '\0') {
    return;
  }
  if (*needs_comma) {
    putchar(',');
  }
  print_json_string(key);
  putchar(':');
  print_json_string(value);
  *needs_comma = 1;
}

int main(void) {
  tdx_report_data_t report_data = {{0}};
  tdx_uuid_t selected_att_key_id = {0};
  uint8_t *quote_buf = NULL;
  uint32_t quote_size = 0;

  const char *guest_id = getenv("TRUSTED_TDX_GUEST_ID");
  const char *service_name = getenv("TRUSTED_TDX_SERVICE_NAME");
  const char *nonce_hex = getenv("TRUSTED_TDX_NONCE_HEX");

  if (fill_report_data(&report_data, nonce_hex) != 0) {
    return 1;
  }

  int quote_result =
      tdx_att_get_quote(&report_data, NULL, 0, &selected_att_key_id, &quote_buf, &quote_size, 0);
  if (quote_result != TDX_ATTEST_SUCCESS) {
    fprintf(stderr, "tdx_att_get_quote failed: 0x%x\n", quote_result);
    return 1;
  }

  char *quote_base64 = base64_encode(quote_buf, quote_size);
  char *report_data_hex = hex_encode(report_data.d, sizeof(report_data.d));
  if (quote_base64 == NULL || report_data_hex == NULL) {
    fprintf(stderr, "failed to encode quote output\n");
    tdx_att_free_quote(quote_buf);
    free(quote_base64);
    free(report_data_hex);
    return 1;
  }

  char quote_format[32];
  if (quote_size >= 2) {
    unsigned int version = (unsigned int)quote_buf[0] | ((unsigned int)quote_buf[1] << 8);
    snprintf(quote_format, sizeof(quote_format), "tdx-quote-v%u", version);
  } else {
    snprintf(quote_format, sizeof(quote_format), "tdx-quote");
  }

  int needs_comma = 0;
  puts("{");
  print_json_field("guestId", guest_id, &needs_comma);
  print_json_field(
      "serviceName",
      (service_name != NULL && service_name[0] != '\0') ? service_name : DEFAULT_SERVICE_NAME,
      &needs_comma);
  print_json_field("quoteFormat", quote_format, &needs_comma);
  print_json_field("reportDataHex", report_data_hex, &needs_comma);
  print_json_field("quoteBase64", quote_base64, &needs_comma);
  puts("\n}");

  tdx_att_free_quote(quote_buf);
  free(quote_base64);
  free(report_data_hex);
  return 0;
}
