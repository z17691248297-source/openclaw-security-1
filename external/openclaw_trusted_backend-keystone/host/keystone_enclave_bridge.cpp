// SPDX-License-Identifier: BSD-2-Clause

#include "keystone_enclave_bridge.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <optional>
#include <stdexcept>
#include <string>

#include "edge/edge_common.h"
#include "host/keystone.h"
#include "verifier/report.h"

namespace {

constexpr unsigned long kOcallCopyReport = 3;
constexpr unsigned long kOcallGetRequest = 4;
constexpr unsigned long kOcallCopyResponse = 5;
constexpr const char *kDefaultEappPath = "./openclaw-keystone-backend-eapp";
constexpr const char *kDefaultRuntimePath = "./eyrie-rt";
constexpr const char *kDefaultLoaderPath = "./loader.bin";
constexpr size_t kDefaultFreeMemSize = 48 * 1024 * 1024;
constexpr size_t kDefaultUntrustedSize = 2 * 1024 * 1024;

bool BridgeDebugEnabled()
{
	const char *value = getenv("KEYSTONE_BRIDGE_DEBUG");

	return value && value[0] && strcmp(value, "0") != 0;
}

void BridgeDebug(const char *message)
{
	if (!BridgeDebugEnabled() || !message)
		return;
	fprintf(stderr, "[keystone-bridge] %s\n", message);
}

void BridgeDebugf(const char *format, unsigned long long value1,
		  unsigned long long value2 = 0)
{
	if (!BridgeDebugEnabled() || !format)
		return;
	fprintf(stderr, "[keystone-bridge] ");
	fprintf(stderr, format, value1, value2);
	fputc('\n', stderr);
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

std::string ResolvePath(const char *env_name, const char *fallback)
{
	const char *configured = getenv(env_name);

	if (configured && configured[0])
		return configured;
	return fallback;
}

void CopyError(const std::string &error, char *buffer, size_t buffer_len)
{
	if (!buffer || !buffer_len)
		return;
	snprintf(buffer, buffer_len, "%s", error.c_str());
}

uint64_t HashText(const char *text, uint64_t seed)
{
	const unsigned char *cursor =
		reinterpret_cast<const unsigned char *>(text ? text : "");
	uint64_t hash = seed;

	while (*cursor) {
		hash ^= *cursor++;
		hash *= 1099511628211ULL;
	}
	return hash;
}

void BuildAttestationNonce(const struct oc_keystone_enclave_request *request,
			   char *out, size_t out_len)
{
	uint64_t hash = 1469598103934665603ULL;
	const char *prefix = "keystone-op";

	if (!request || !out || !out_len)
		return;

	switch (request->command) {
	case OC_KEYSTONE_CMD_AUTHORIZE:
		prefix = "authorize";
		hash = HashText(request->payload.authorize.req_id, hash);
		hash = HashText(request->payload.authorize.sid, hash);
		hash = HashText(request->payload.authorize.tool_name, hash);
		hash = HashText(request->payload.authorize.action, hash);
		hash = HashText(request->payload.authorize.object, hash);
		hash = HashText(request->payload.authorize.normalized_scope_digest,
				hash);
		break;
	case OC_KEYSTONE_CMD_CONFIRM:
		prefix = "confirm";
		hash = HashText(
			request->payload.confirm.confirm.confirmation_request_id, hash);
		hash = HashText(request->payload.confirm.confirm.challenge_token, hash);
		hash = HashText(request->payload.confirm.confirm.operator_id, hash);
		hash = HashText(request->payload.confirm.confirm.decision, hash);
		hash = HashText(request->payload.confirm.pending_authorize.req_id,
				hash);
		hash = HashText(
			request->payload.confirm.pending_authorize.normalized_scope_digest,
			hash);
		break;
	case OC_KEYSTONE_CMD_COMPLETE:
		prefix = "complete";
		hash = HashText(request->payload.complete.req_id, hash);
		hash = HashText(request->payload.complete.sid, hash);
		hash = HashText(request->payload.complete.action, hash);
		hash = HashText(request->payload.complete.object, hash);
		hash = HashText(request->payload.complete.result_digest, hash);
		break;
	default:
		prefix = "probe";
		break;
	}

	snprintf(out, out_len, "%s:%016llx", prefix,
		 static_cast<unsigned long long>(hash));
}

class SharedBuffer {
public:
	SharedBuffer(void *buffer, size_t buffer_len)
		: edge_call_(static_cast<struct edge_call *>(buffer)),
		  buffer_(reinterpret_cast<uintptr_t>(buffer)),
		  buffer_len_(buffer_len)
	{
	}

	uintptr_t ptr() const { return buffer_; }

	void SetOk() { edge_call_->return_data.call_status = CALL_STATUS_OK; }

	void SetBadOffset()
	{
		edge_call_->return_data.call_status = CALL_STATUS_BAD_OFFSET;
	}

	void SetBadPtr() { edge_call_->return_data.call_status = CALL_STATUS_BAD_PTR; }

	int SetupWrappedRet(const void *ptr, size_t size)
	{
		struct edge_data wrapper;

		if (size > buffer_len_ - sizeof(struct edge_call) -
				 sizeof(struct edge_data))
			return 1;
		wrapper.size = size;
		if (GetOffsetFromPtr(
			    buffer_ + sizeof(struct edge_call) +
				    sizeof(struct edge_data),
			    &wrapper.offset) != 0)
			return 1;
		memcpy(reinterpret_cast<void *>(buffer_ + sizeof(struct edge_call) +
					       sizeof(struct edge_data)),
		       ptr, size);
		memcpy(reinterpret_cast<void *>(buffer_ + sizeof(struct edge_call)),
		       &wrapper, sizeof(wrapper));
		edge_call_->return_data.call_ret_size = sizeof(struct edge_data);
		return GetOffsetFromPtr(buffer_ + sizeof(struct edge_call),
					&edge_call_->return_data.call_ret_offset);
	}

	std::optional<std::pair<uintptr_t, size_t>>
	GetCallArgsPtrOrSetBadOffset() const
	{
		uintptr_t call_args = 0;
		size_t arg_len = 0;

		if (ArgsPtr(&call_args, &arg_len) != 0) {
			const_cast<SharedBuffer *>(this)->SetBadOffset();
			return std::nullopt;
		}
		return std::pair{call_args, arg_len};
	}

	std::optional<Report> GetReportOrSetBadOffset() const
	{
		auto args = GetCallArgsPtrOrSetBadOffset();

		if (!args.has_value())
			return std::nullopt;

		Report report;
		report.fromBytes(reinterpret_cast<byte *>(args->first));
		return report;
	}

private:
	int ValidatePtr(uintptr_t ptr) const
	{
		if (ptr > buffer_ + buffer_len_ || ptr < buffer_)
			return 1;
		return 0;
	}

	int GetOffsetFromPtr(uintptr_t ptr, edge_data_offset *offset) const
	{
		if (ValidatePtr(ptr) != 0)
			return 1;
		*offset = ptr - buffer_;
		return 0;
	}

	int GetPtrFromOffset(edge_data_offset offset, uintptr_t *ptr) const
	{
		if (offset > UINTPTR_MAX - buffer_ || offset > buffer_len_)
			return 1;
		*ptr = buffer_ + offset;
		return 0;
	}

	int ArgsPtr(uintptr_t *ptr, size_t *size) const
	{
		*size = edge_call_->call_arg_size;
		return GetPtrFromOffset(edge_call_->call_arg_offset, ptr);
	}

	struct edge_call *edge_call_;
	uintptr_t buffer_;
	size_t buffer_len_;
};

struct RunData {
	SharedBuffer shared_buffer;
	const struct oc_keystone_enclave_request &request;
	struct oc_keystone_enclave_response response;
	bool has_response;
	std::optional<Report> report;
};

class KeystoneEnclaveInvoker {
public:
	KeystoneEnclaveInvoker(std::string eapp_file, std::string runtime_file,
			       std::string loader_file)
		: eapp_file_(std::move(eapp_file)),
		  runtime_file_(std::move(runtime_file)),
		  loader_file_(std::move(loader_file))
	{
	}

	struct oc_keystone_enclave_response
	Invoke(const struct oc_keystone_enclave_request &request) const
	{
		Keystone::Params params;
		Keystone::Enclave enclave;
		Keystone::Error error = Keystone::Error::Success;
		struct oc_keystone_enclave_response response;
		uintptr_t enclave_ret = 0;
		std::optional<RunData> run_data;

		memset(&response, 0, sizeof(response));
		params.setFreeMemSize(kDefaultFreeMemSize);
		params.setUntrustedSize(kDefaultUntrustedSize);
		BridgeDebug("Invoke: enclave.init start");

		error = enclave.init(eapp_file_.c_str(), runtime_file_.c_str(),
				    loader_file_.c_str(), params);
		if (error != Keystone::Error::Success) {
			throw std::runtime_error("Keystone enclave init failed: " +
					     ErrorToString(error));
		}
		BridgeDebug("Invoke: enclave.init ok");

		run_data.emplace(RunData{
			SharedBuffer(enclave.getSharedBuffer(),
				     enclave.getSharedBufferSize()),
			request,
			{},
			false,
			std::nullopt,
		});
		memset(&run_data->response, 0, sizeof(run_data->response));

		error = enclave.registerOcallDispatch([&run_data](void *buffer) {
			if (buffer != reinterpret_cast<void *>(
					       run_data->shared_buffer.ptr())) {
				run_data->shared_buffer.SetBadPtr();
				return;
			}
			DispatchOcall(*run_data);
		});
		if (error != Keystone::Error::Success) {
			throw std::runtime_error(
				"Keystone ocall registration failed: " +
				ErrorToString(error));
		}
		BridgeDebug("Invoke: registerOcallDispatch ok");

		BridgeDebug("Invoke: enclave.run start");
		error = enclave.run(&enclave_ret);
		if (error != Keystone::Error::Success) {
			throw std::runtime_error("Keystone enclave run failed: " +
					     ErrorToString(error));
		}
		BridgeDebug("Invoke: enclave.run ok");
		if (!run_data->has_response)
			throw std::runtime_error("Keystone enclave response missing");
		if (!run_data->report.has_value())
			throw std::runtime_error("Keystone enclave attestation missing");
		VerifyReport(*run_data->report, request.attestation_nonce);
		response = run_data->response;
		return response;
	}

private:
	static void VerifyReport(Report &report, const char *nonce)
	{
		size_t nonce_len = nonce ? strlen(nonce) + 1 : 0;

		if (!nonce || !nonce[0])
			return;
		if (report.getDataSize() != nonce_len ||
		    memcmp(report.getDataSection(), nonce, nonce_len) != 0) {
			throw std::runtime_error(
				"Keystone decision attestation nonce mismatch");
		}
	}

	static void GetRequestWrapper(RunData &run_data)
	{
		BridgeDebugf("OCALL_GET_REQUEST size=%llu",
			     static_cast<unsigned long long>(
				     sizeof(run_data.request)));
		if (run_data.shared_buffer.SetupWrappedRet(&run_data.request,
						   sizeof(run_data.request)) != 0)
			run_data.shared_buffer.SetBadPtr();
		else
			run_data.shared_buffer.SetOk();
	}

	static void CopyResponseWrapper(RunData &run_data)
	{
		auto args = run_data.shared_buffer.GetCallArgsPtrOrSetBadOffset();

		if (!args.has_value())
			return;
		BridgeDebugf("OCALL_COPY_RESPONSE arg_size=%llu expected=%llu",
			     static_cast<unsigned long long>(args->second),
			     static_cast<unsigned long long>(
				     sizeof(run_data.response)));
		if (args->second != sizeof(run_data.response)) {
			run_data.shared_buffer.SetBadPtr();
			BridgeDebug("OCALL_COPY_RESPONSE rejected size mismatch");
			return;
		}
		memcpy(&run_data.response, reinterpret_cast<const void *>(args->first),
		       sizeof(run_data.response));
		run_data.has_response = true;
		BridgeDebug("OCALL_COPY_RESPONSE accepted");
		run_data.shared_buffer.SetOk();
	}

	static void CopyReportWrapper(RunData &run_data)
	{
		auto report = run_data.shared_buffer.GetReportOrSetBadOffset();

		if (!report.has_value())
			return;
		run_data.report = report;
		BridgeDebug("OCALL_COPY_REPORT accepted");
		run_data.shared_buffer.SetOk();
	}

	static void DispatchOcall(RunData &run_data)
	{
		auto *edge_call =
			reinterpret_cast<struct edge_call *>(run_data.shared_buffer.ptr());

		BridgeDebugf("dispatch call_id=%llu arg_size=%llu",
			     static_cast<unsigned long long>(edge_call->call_id),
			     static_cast<unsigned long long>(
				     edge_call->call_arg_size));

		switch (edge_call->call_id) {
		case kOcallCopyReport:
			CopyReportWrapper(run_data);
			break;
		case kOcallGetRequest:
			GetRequestWrapper(run_data);
			break;
		case kOcallCopyResponse:
			CopyResponseWrapper(run_data);
			break;
		default:
			run_data.shared_buffer.SetOk();
			break;
		}
	}

	std::string eapp_file_;
	std::string runtime_file_;
	std::string loader_file_;
};

int Invoke(const struct oc_keystone_enclave_request *request,
	   struct oc_keystone_enclave_response *response, char *error_message,
	   size_t error_message_len)
{
	try {
		KeystoneEnclaveInvoker invoker(
			ResolvePath("KEYSTONE_EAPP_FILE", kDefaultEappPath),
			ResolvePath("KEYSTONE_RUNTIME_FILE", kDefaultRuntimePath),
			ResolvePath("KEYSTONE_LOADER_FILE", kDefaultLoaderPath));
		*response = invoker.Invoke(*request);
		if (!response->ok) {
			CopyError("Keystone enclave returned unsuccessful response",
				  error_message, error_message_len);
			return 0;
		}
		return 1;
	} catch (const std::exception &error) {
		CopyError(error.what(), error_message, error_message_len);
		return 0;
	}
}

} // namespace

extern "C" int oc_keystone_enclave_authorize(
	const struct oc_ta_authorize_request *request,
	struct oc_ta_authorize_response *response, char *error_message,
	size_t error_message_len)
{
	struct oc_keystone_enclave_request enclave_request;
	struct oc_keystone_enclave_response enclave_response;

	if (!request || !response) {
		CopyError("invalid authorize invocation", error_message,
			  error_message_len);
		return 0;
	}

	memset(&enclave_request, 0, sizeof(enclave_request));
	memset(&enclave_response, 0, sizeof(enclave_response));
	enclave_request.command = OC_KEYSTONE_CMD_AUTHORIZE;
	enclave_request.payload.authorize = *request;
	BuildAttestationNonce(&enclave_request, enclave_request.attestation_nonce,
			      sizeof(enclave_request.attestation_nonce));
	if (!Invoke(&enclave_request, &enclave_response, error_message,
		    error_message_len) ||
	    enclave_response.command != OC_KEYSTONE_CMD_AUTHORIZE) {
		if (enclave_response.command != OC_KEYSTONE_CMD_AUTHORIZE &&
		    error_message && error_message_len && !error_message[0]) {
			CopyError("unexpected Keystone authorize response",
				  error_message, error_message_len);
		}
		return 0;
	}

	*response = enclave_response.payload.authorize;
	return 1;
}

extern "C" int oc_keystone_enclave_confirm(
	const struct oc_keystone_confirm_enclave_request *request,
	struct oc_ta_confirm_response *response, char *error_message,
	size_t error_message_len)
{
	struct oc_keystone_enclave_request enclave_request;
	struct oc_keystone_enclave_response enclave_response;

	if (!request || !response) {
		CopyError("invalid confirm invocation", error_message,
			  error_message_len);
		return 0;
	}

	memset(&enclave_request, 0, sizeof(enclave_request));
	memset(&enclave_response, 0, sizeof(enclave_response));
	enclave_request.command = OC_KEYSTONE_CMD_CONFIRM;
	enclave_request.payload.confirm = *request;
	BuildAttestationNonce(&enclave_request, enclave_request.attestation_nonce,
			      sizeof(enclave_request.attestation_nonce));
	if (!Invoke(&enclave_request, &enclave_response, error_message,
		    error_message_len) ||
	    enclave_response.command != OC_KEYSTONE_CMD_CONFIRM) {
		if (enclave_response.command != OC_KEYSTONE_CMD_CONFIRM &&
		    error_message && error_message_len && !error_message[0]) {
			CopyError("unexpected Keystone confirm response",
				  error_message, error_message_len);
		}
		return 0;
	}

	*response = enclave_response.payload.confirm;
	return 1;
}

extern "C" int oc_keystone_enclave_complete(
	const struct oc_ta_complete_request *request,
	struct oc_ta_complete_response *response, char *error_message,
	size_t error_message_len)
{
	struct oc_keystone_enclave_request enclave_request;
	struct oc_keystone_enclave_response enclave_response;

	if (!request || !response) {
		CopyError("invalid complete invocation", error_message,
			  error_message_len);
		return 0;
	}

	memset(&enclave_request, 0, sizeof(enclave_request));
	memset(&enclave_response, 0, sizeof(enclave_response));
	enclave_request.command = OC_KEYSTONE_CMD_COMPLETE;
	enclave_request.payload.complete = *request;
	BuildAttestationNonce(&enclave_request, enclave_request.attestation_nonce,
			      sizeof(enclave_request.attestation_nonce));
	if (!Invoke(&enclave_request, &enclave_response, error_message,
		    error_message_len) ||
	    enclave_response.command != OC_KEYSTONE_CMD_COMPLETE) {
		if (enclave_response.command != OC_KEYSTONE_CMD_COMPLETE &&
		    error_message && error_message_len && !error_message[0]) {
			CopyError("unexpected Keystone complete response",
				  error_message, error_message_len);
		}
		return 0;
	}

	*response = enclave_response.payload.complete;
	return 1;
}
