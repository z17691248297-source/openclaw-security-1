// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <string>

struct KeystoneAttestationResult {
  bool ready;
  long long attested_at_ms;
  std::string nonce;
  std::string enclave_hash_hex;
  std::string sm_hash_hex;
  std::string error;
};

class KeystoneAttestor {
 public:
  KeystoneAttestor(std::string eapp_file, std::string runtime_file, std::string loader_file);

  KeystoneAttestationResult Probe(const std::string& nonce) const;

 private:
  std::string eapp_file_;
  std::string runtime_file_;
  std::string loader_file_;
};
