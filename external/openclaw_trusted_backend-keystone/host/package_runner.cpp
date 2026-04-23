// SPDX-License-Identifier: BSD-2-Clause

#include "keystone_attestor.h"

#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr const char* kDefaultStatusFile = "keystone-attestation.status";

std::string SanitizeStatusValue(std::string value)
{
  for (char& ch : value) {
    if (ch == '\n' || ch == '\r')
      ch = ' ';
  }
  return value;
}

std::string GetCurrentDirectory()
{
  char buffer[PATH_MAX];

  if (!getcwd(buffer, sizeof(buffer))) {
    throw std::runtime_error(
        std::string("getcwd failed: ") + std::strerror(errno));
  }
  return std::string(buffer);
}

std::string ResolvePath(const std::string& cwd, const std::string& path)
{
  if (path.empty())
    return path;
  if (path.front() == '/')
    return path;
  return cwd + "/" + path;
}

std::string BuildNonce()
{
  return "keystone-probe-" + std::to_string(getpid());
}

bool HasOption(char* const* argv, const char* option)
{
  for (size_t index = 0; argv[index] != nullptr; index++) {
    if (std::strcmp(argv[index], option) == 0)
      return true;
  }
  return false;
}

void WriteStatusFile(const std::string& path, const KeystoneAttestationResult& result)
{
  std::ofstream stream(path, std::ios::out | std::ios::trunc);

  if (!stream.is_open()) {
    std::cerr << "warning: failed to write " << path << ": "
              << std::strerror(errno) << "\n";
    return;
  }

  stream << "attestation_ready=" << (result.ready ? "1" : "0") << "\n";
  stream << "attested_at_ms=" << result.attested_at_ms << "\n";
  stream << "nonce=" << SanitizeStatusValue(result.nonce) << "\n";
  stream << "enclave_hash_hex=" << SanitizeStatusValue(result.enclave_hash_hex)
         << "\n";
  stream << "sm_hash_hex=" << SanitizeStatusValue(result.sm_hash_hex) << "\n";
  stream << "error=" << SanitizeStatusValue(result.error) << "\n";
}

void ExportEnv(const char* name, const std::string& value)
{
  if (setenv(name, value.c_str(), 1) != 0) {
    throw std::runtime_error(
        std::string("setenv failed for ") + name + ": " + std::strerror(errno));
  }
}

void PrintUsage(const char* argv0)
{
  std::cerr << "Usage:\n  " << argv0
            << " <eapp> <eyrie-rt> <loader.bin> <server> <ca-binary> [server args...]\n";
}

}  // namespace

int main(int argc, char* argv[])
{
  if (argc < 6) {
    PrintUsage(argv[0]);
    return 1;
  }

  try {
    const std::string cwd = GetCurrentDirectory();
    const std::string eapp_path = ResolvePath(cwd, argv[1]);
    const std::string runtime_path = ResolvePath(cwd, argv[2]);
    const std::string loader_path = ResolvePath(cwd, argv[3]);
    const std::string server_path = ResolvePath(cwd, argv[4]);
    const std::string ca_binary_path = ResolvePath(cwd, argv[5]);
    const char* status_from_env = std::getenv("KEYSTONE_ATTESTATION_STATUS_FILE");
    const std::string status_path = status_from_env && status_from_env[0]
        ? ResolvePath(cwd, status_from_env)
        : ResolvePath(cwd, kDefaultStatusFile);
    const std::string nonce = BuildNonce();

    KeystoneAttestor attestor(eapp_path, runtime_path, loader_path);
    KeystoneAttestationResult result = attestor.Probe(nonce);
    WriteStatusFile(status_path, result);

    ExportEnv("KEYSTONE_ATTESTATION_STATUS_FILE", status_path);
    ExportEnv("KEYSTONE_ATTESTOR_RUNNER", ResolvePath(cwd, argv[0]));
    ExportEnv("KEYSTONE_EAPP_FILE", eapp_path);
    ExportEnv("KEYSTONE_RUNTIME_FILE", runtime_path);
    ExportEnv("KEYSTONE_LOADER_FILE", loader_path);
    ExportEnv("KEYSTONE_MEASUREMENT_FILE", eapp_path);
    ExportEnv("KEYSTONE_BACKEND_CA_BINARY", ca_binary_path);

    std::vector<char*> exec_argv;
    exec_argv.push_back(const_cast<char*>(server_path.c_str()));
    if (!HasOption(argv + 6, "--ca-binary")) {
      exec_argv.push_back(const_cast<char*>("--ca-binary"));
      exec_argv.push_back(const_cast<char*>(ca_binary_path.c_str()));
    }
    for (int index = 6; index < argc; index++)
      exec_argv.push_back(argv[index]);
    exec_argv.push_back(nullptr);

    execv(server_path.c_str(), exec_argv.data());
    std::cerr << "failed to exec server: " << std::strerror(errno) << "\n";
    return 127;
  } catch (const std::exception& error) {
    std::cerr << "package runner failed: " << error.what() << "\n";
    return 1;
  }
}
