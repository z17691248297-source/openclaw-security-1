// SPDX-License-Identifier: BSD-2-Clause

#include "keystone_attestor.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "edge/edge_common.h"
#include "host/keystone.h"
#include "verifier/report.h"

#include "../include/openclaw_trusted_backend_keystone.h"

namespace {

constexpr unsigned long kOcallCopyReport = 3;
constexpr unsigned long kOcallGetRequest = 4;
constexpr size_t kDefaultFreeMemSize = 48 * 1024 * 1024;
constexpr size_t kDefaultUntrustedSize = 2 * 1024 * 1024;

long long NowMs()
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string BytesToHex(const byte* data, size_t len)
{
  static const char* const kHex = "0123456789abcdef";
  std::string out;

  out.reserve(len * 2);
  for (size_t index = 0; index < len; index++) {
    out.push_back(kHex[(data[index] >> 4) & 0x0f]);
    out.push_back(kHex[data[index] & 0x0f]);
  }
  return out;
}

std::string ErrorToString(Keystone::Error error)
{
  switch (error) {
    case Keystone::Error::Success:
      return "Success";
    case Keystone::Error::FileInitFailure:
      return "FileInitFailure";
    case Keystone::Error::DeviceInitFailure:
      return "DeviceInitFailure";
    case Keystone::Error::DeviceError:
      return "DeviceError";
    case Keystone::Error::IoctlErrorCreate:
      return "IoctlErrorCreate";
    case Keystone::Error::IoctlErrorDestroy:
      return "IoctlErrorDestroy";
    case Keystone::Error::IoctlErrorFinalize:
      return "IoctlErrorFinalize";
    case Keystone::Error::IoctlErrorRun:
      return "IoctlErrorRun";
    case Keystone::Error::IoctlErrorResume:
      return "IoctlErrorResume";
    case Keystone::Error::IoctlErrorUTMInit:
      return "IoctlErrorUTMInit";
    case Keystone::Error::DeviceMemoryMapError:
      return "DeviceMemoryMapError";
    case Keystone::Error::ELFLoadFailure:
      return "ELFLoadFailure";
    case Keystone::Error::InvalidEnclave:
      return "InvalidEnclave";
    case Keystone::Error::VSpaceAllocationFailure:
      return "VSpaceAllocationFailure";
    case Keystone::Error::PageAllocationFailure:
      return "PageAllocationFailure";
    case Keystone::Error::EdgeCallHost:
      return "EdgeCallHost";
    case Keystone::Error::EnclaveInterrupted:
      return "EnclaveInterrupted";
    default:
      return "UnknownError";
  }
}

class SharedBuffer {
 public:
  SharedBuffer(void* buffer, size_t buffer_len)
      : edge_call_((struct edge_call*)buffer),
        buffer_((uintptr_t)buffer),
        buffer_len_(buffer_len) {}

  uintptr_t ptr() const { return buffer_; }

  std::optional<std::pair<uintptr_t, size_t>> GetCallArgsPtrOrSetBadOffset()
  {
    uintptr_t call_args = 0;
    size_t arg_len = 0;

    if (ArgsPtr(&call_args, &arg_len) != 0) {
      SetBadOffset();
      return std::nullopt;
    }
    return std::pair{call_args, arg_len};
  }

  std::optional<Report> GetReportOrSetBadOffset()
  {
    auto args = GetCallArgsPtrOrSetBadOffset();

    if (!args.has_value())
      return std::nullopt;

    Report report;
    report.fromBytes((byte*)args.value().first);
    return report;
  }

  void SetOk() { edge_call_->return_data.call_status = CALL_STATUS_OK; }

  void SetupWrappedRetOrBadPtr(const void* value, size_t value_len)
  {
    if (SetupWrappedRet(const_cast<void*>(value), value_len) != 0)
      SetBadPtr();
    else
      SetOk();
  }

 private:
  uintptr_t DataPtr() const
  {
    return (uintptr_t)edge_call_ + sizeof(struct edge_call);
  }

  int ArgsPtr(uintptr_t* ptr, size_t* size)
  {
    *size = edge_call_->call_arg_size;
    return GetPtrFromOffset(edge_call_->call_arg_offset, ptr);
  }

  int ValidatePtr(uintptr_t ptr) const
  {
    if (ptr > buffer_ + buffer_len_ || ptr < buffer_)
      return 1;
    return 0;
  }

  int GetOffsetFromPtr(uintptr_t ptr, edge_data_offset* offset) const
  {
    if (ValidatePtr(ptr) != 0)
      return 1;

    *offset = ptr - buffer_;
    return 0;
  }

  int GetPtrFromOffset(edge_data_offset offset, uintptr_t* ptr) const
  {
    if (offset > UINTPTR_MAX - buffer_ || offset > buffer_len_)
      return -1;

    *ptr = buffer_ + offset;
    return 0;
  }

  void SetBadOffset()
  {
    edge_call_->return_data.call_status = CALL_STATUS_BAD_OFFSET;
  }

  void SetBadPtr()
  {
    edge_call_->return_data.call_status = CALL_STATUS_BAD_PTR;
  }

  int SetupWrappedRet(void* ptr, size_t size)
  {
    struct edge_data wrapper;

    wrapper.size = size;
    GetOffsetFromPtr(
        buffer_ + sizeof(struct edge_call) + sizeof(struct edge_data),
        &wrapper.offset);

    memcpy(
        (void*)(buffer_ + sizeof(struct edge_call) + sizeof(struct edge_data)),
        ptr, size);
    memcpy((void*)(buffer_ + sizeof(struct edge_call)),
           &wrapper,
           sizeof(struct edge_data));

    edge_call_->return_data.call_ret_size = sizeof(struct edge_data);
    return GetOffsetFromPtr(
        DataPtr(), &edge_call_->return_data.call_ret_offset);
  }

  struct edge_call* edge_call_;
  uintptr_t buffer_;
  size_t buffer_len_;
};

class AttestationHost {
 public:
  AttestationHost(const Keystone::Params& params,
                  std::string eapp_file,
                  std::string runtime_file,
                  std::string loader_file)
      : params_(params),
        eapp_file_(std::move(eapp_file)),
        runtime_file_(std::move(runtime_file)),
        loader_file_(std::move(loader_file)) {}

  Report Run(const std::string& nonce) const
  {
    Keystone::Enclave enclave;
    Keystone::Error error = enclave.init(
        eapp_file_.c_str(), runtime_file_.c_str(), loader_file_.c_str(), params_);

    if (error != Keystone::Error::Success) {
      throw std::runtime_error(
          "Keystone enclave init failed: " + ErrorToString(error));
    }

    RunData run_data{
        SharedBuffer{enclave.getSharedBuffer(), enclave.getSharedBufferSize()},
        {},
        std::nullopt,
    };
    memset(&run_data.request, 0, sizeof(run_data.request));
    run_data.request.command = OC_KEYSTONE_CMD_PROBE;
    snprintf(run_data.request.attestation_nonce,
             sizeof(run_data.request.attestation_nonce),
             "%s",
             nonce.c_str());

    error = enclave.registerOcallDispatch([&run_data](void* buffer) {
      assert(buffer == (void*)run_data.shared_buffer.ptr());
      DispatchOcall(run_data);
    });
    if (error != Keystone::Error::Success) {
      throw std::runtime_error(
          "Keystone ocall registration failed: " + ErrorToString(error));
    }

    uintptr_t enclave_ret = 0;
    error = enclave.run(&enclave_ret);
    if (error != Keystone::Error::Success) {
      throw std::runtime_error(
          "Keystone enclave run failed: " + ErrorToString(error));
    }
    if (!run_data.report) {
      throw std::runtime_error("Keystone attestation report missing");
    }

    return *run_data.report;
  }

 private:
  struct RunData {
    SharedBuffer shared_buffer;
    struct oc_keystone_enclave_request request;
    std::optional<Report> report;
  };

  static void CopyReportWrapper(RunData& run_data)
  {
    auto report = run_data.shared_buffer.GetReportOrSetBadOffset();

    if (report.has_value()) {
      run_data.report = report;
      run_data.shared_buffer.SetOk();
    }
  }

  static void GetRequestWrapper(RunData& run_data)
  {
    run_data.shared_buffer.SetupWrappedRetOrBadPtr(&run_data.request,
                                                   sizeof(run_data.request));
  }

  static void DispatchOcall(RunData& run_data)
  {
    struct edge_call* edge_call = (struct edge_call*)run_data.shared_buffer.ptr();

    switch (edge_call->call_id) {
      case kOcallCopyReport:
        CopyReportWrapper(run_data);
        break;
      case kOcallGetRequest:
        GetRequestWrapper(run_data);
        break;
      default:
        run_data.shared_buffer.SetOk();
        break;
    }
  }

  Keystone::Params params_;
  std::string eapp_file_;
  std::string runtime_file_;
  std::string loader_file_;
};

}  // namespace

KeystoneAttestor::KeystoneAttestor(
    std::string eapp_file, std::string runtime_file, std::string loader_file)
    : eapp_file_(std::move(eapp_file)),
      runtime_file_(std::move(runtime_file)),
      loader_file_(std::move(loader_file))
{
}

KeystoneAttestationResult KeystoneAttestor::Probe(const std::string& nonce) const
{
  KeystoneAttestationResult result{
      false,
      0,
      nonce,
      "",
      "",
      "",
  };

  try {
    Keystone::Params params;
    params.setFreeMemSize(kDefaultFreeMemSize);
    params.setUntrustedSize(kDefaultUntrustedSize);

    AttestationHost host(params, eapp_file_, runtime_file_, loader_file_);
    Report report = host.Run(nonce);

    result.attested_at_ms = NowMs();
    result.enclave_hash_hex = BytesToHex(report.getEnclaveHash(), MDSIZE);
    result.sm_hash_hex = BytesToHex(report.getSmHash(), MDSIZE);

    if (report.getDataSize() != nonce.size() + 1 ||
        memcmp(report.getDataSection(), nonce.c_str(), nonce.size() + 1) != 0) {
      result.error = "Keystone attestation nonce mismatch";
      return result;
    }

    result.ready = true;
    return result;
  } catch (const std::exception& error) {
    result.error = error.what();
    return result;
  }
}
