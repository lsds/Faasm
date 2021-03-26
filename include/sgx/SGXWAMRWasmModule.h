#pragma once

#include "sgx/faasm_sgx_attestation.h"
#include "sgx/faasm_sgx_error.h"

#include <storage/FileLoader.h>
#include <storage/FileSystem.h>
#include <wasm/WasmModule.h>

#include <sgx.h>
#include <sgx_urts.h>

extern sgx_enclave_id_t globalEnclaveId;

extern "C"
{

    extern void ocall_printf(const char* msg);

    extern faasm_sgx_status_t faasm_sgx_get_sgx_support(void);

    extern sgx_status_t faasm_sgx_enclave_init_wamr(
      sgx_enclave_id_t enclave_id,
      faasm_sgx_status_t* ret_val);

    extern sgx_status_t faasm_sgx_enclave_load_module(
      sgx_enclave_id_t enclave_id,
      faasm_sgx_status_t* ret_val,
      const char* user,
      const char* function,
      const void* wasm_opcode_ptr,
      const uint32_t wasm_opcode_size,
      const void* wasm_op_nonce,
      const void* wasm_op_mac,
      uint32_t* thread_id,
      sgx_wamr_msg_t** response_ptr,
      faaslet_sgx_gp_buffer_t* output_ptr,
      faaslet_sgx_gp_buffer_t* result_ptr);

    extern sgx_status_t faasm_sgx_enclave_unload_module(
      sgx_enclave_id_t enclave_id,
      faasm_sgx_status_t* ret_val,
      const unsigned int thread_id);

    extern sgx_status_t faasm_sgx_enclave_call_function(
      sgx_enclave_id_t enclave_id,
      faasm_sgx_status_t* ret_val,
      const uint32_t thread_id,
      const uint32_t func_id,
      const char* sid,
      const sgx_wamr_encrypted_data_blob_t* payload,
      uint32_t payload_len,
      const void* policy,
      uint32_t policy_len);
}

namespace wasm {
class SGXWAMRWasmModule final : public WasmModule
{
  public:
    explicit SGXWAMRWasmModule();

    ~SGXWAMRWasmModule() override;

    void bindToFunction(const faabric::Message& msg) override;

    void bindToFunctionNoZygote(const faabric::Message& msg) override;

    bool unbindFunction();

    bool execute(faabric::Message& msg, bool forceNoop = false) override;

    bool isBound() override;

    // TODO: Move in gs/fs
    faaslet_sgx_msg_buffer_t sgxWamrMsgResponse;

  private:
    bool _isBound = false;
    uint32_t threadId = 0;
};
}
