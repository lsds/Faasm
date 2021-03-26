#include <cstdio>

#include <faabric/util/func.h>
#include <sgx/SGXWAMRWasmModule.h>
#include <sgx/base64.h>
#include <sgx/faasm_sgx_attestation.h>
#include <sgx/faasm_sgx_system.h>

extern __thread faaslet_sgx_msg_buffer_t* faaslet_sgx_msg_buffer_ptr;
extern __thread faaslet_sgx_gp_buffer_t *faaslet_sgx_attestation_output_ptr,
  *faaslet_sgx_attestation_result_ptr;

extern "C"
{
    void ocall_printf(const char* msg) { printf("%s", msg); }
}

__thread faaslet_sgx_msg_buffer_t* faasletSgxMsgBufferPtr;

using namespace sgx;

namespace wasm {
SGXWAMRWasmModule::SGXWAMRWasmModule()
{
    auto logger = faabric::util::getLogger();

    // init sgx in case we're using this module outside a Faaslet
    sgx::checkSgxSetup();

    // Allocate memory for response
    sgxWamrMsgResponse.buffer_len =
      (sizeof(sgx_wamr_msg_t) + sizeof(sgx_wamr_msg_hdr_t));
    sgxWamrMsgResponse.buffer_ptr =
      (sgx_wamr_msg_t*)calloc(sgxWamrMsgResponse.buffer_len, sizeof(uint8_t));

    if (!sgxWamrMsgResponse.buffer_ptr) {
        logger->error(
          "Unable to allocate space for SGX message response buffer");
        throw std::runtime_error(
          "Unable to allocate space for SGX message response buffer");
    }

    faasletSgxMsgBufferPtr = &sgxWamrMsgResponse;

    logger->debug("Created SGX wasm module for enclave {}", globalEnclaveId);
}

SGXWAMRWasmModule::~SGXWAMRWasmModule()
{
    unbindFunction();

    if (sgxWamrMsgResponse.buffer_ptr) {
        free(sgxWamrMsgResponse.buffer_ptr);
    }
}

void SGXWAMRWasmModule::bindToFunction(const faabric::Message& msg)
{
    auto logger = faabric::util::getLogger();

    // Set up filesystem
    storage::FileSystem fs;
    fs.prepareFilesystem();

    // Load AoT or wasm
    storage::FileLoader& fl = storage::getFileLoader();

#if (FAASM_SGX_WAMR_AOT_MODE)
    std::vector<uint8_t> wasmBytes = fl.loadFunctionWamrAotFile(msg);
#else
    std::vector<uint8_t> wasmBytes = fl.loadEncryptedFunctionWasm(msg);
#endif

    // Extract nonce + tag
    std::vector<uint8_t> nonce = { wasmBytes.begin(),
                                   wasmBytes.begin() + SGX_AESGCM_IV_SIZE };
    std::vector<uint8_t> tag = { wasmBytes.begin() + SGX_AESGCM_IV_SIZE,
                                 wasmBytes.begin() + SGX_AESGCM_IV_SIZE +
                                   SGX_AESGCM_MAC_SIZE };
    wasmBytes.erase(wasmBytes.begin(),
                    wasmBytes.begin() + SGX_AESGCM_IV_SIZE +
                      SGX_AESGCM_MAC_SIZE);
    // Load the wasm module
    faasm_sgx_status_t returnValue;
    sgx_status_t status =
      faasm_sgx_enclave_load_module(globalEnclaveId,
                                    &returnValue,
                                    msg.user().c_str(),
                                    msg.function().c_str(),
                                    (void*)wasmBytes.data(),
                                    (uint32_t)wasmBytes.size(),
                                    (void*)nonce.data(),
                                    (void*)tag.data(),
                                    &threadId,
                                    &(faasletSgxMsgBufferPtr->buffer_ptr),
                                    faaslet_sgx_attestation_output_ptr,
                                    faaslet_sgx_attestation_result_ptr);

    if (status != SGX_SUCCESS) {
        logger->error("Unable to enter enclave: {}", sgxErrorString(status));
        throw std::runtime_error("Unable to enter enclave");
    }

    if (returnValue != FAASM_SGX_SUCCESS) {
        logger->error("Unable to load WASM module: {}",
                      faasmSgxErrorString(returnValue));
        throw std::runtime_error("Unable to load WASM module");
    }

    _isBound = true;
}

void SGXWAMRWasmModule::bindToFunctionNoZygote(const faabric::Message& msg)
{
    bindToFunction(msg);
}

bool SGXWAMRWasmModule::unbindFunction()
{
    if (!_isBound) {
        return true;
    }

    auto logger = faabric::util::getLogger();
    logger->debug("Unloading SGX wasm module");

    faasm_sgx_status_t returnValue;
    sgx_status_t sgxReturnValue =
      faasm_sgx_enclave_unload_module(globalEnclaveId, &returnValue, threadId);

    if (sgxReturnValue != SGX_SUCCESS) {
        logger->error("Unable to unbind function due to SGX error: {}",
                      sgxErrorString(sgxReturnValue));
        throw std::runtime_error("Unable to unbind function due to SGX error");
    }

    if (returnValue != FAASM_SGX_SUCCESS) {
        logger->error("Unable to unbind function: {}",
                      faasmSgxErrorString(returnValue));
        throw std::runtime_error("Unable to unbind function");
    }

    return true;
}

bool SGXWAMRWasmModule::execute(faabric::Message& msg, bool forceNoop)
{
    auto logger = faabric::util::getLogger();
    std::string funcStr = faabric::util::funcToString(msg, true);
    if (!_isBound) {
        logger->error("Function not bound {}", funcStr);
        throw std::runtime_error("Function not bound");
    }

    // Set executing call
    wasm::setExecutingCall(const_cast<faabric::Message*>(&msg));

    // Enter enclave and call function
    sgx_status_t sgxReturnValue;
    faasm_sgx_status_t returnValue;
    std::string inputdata = util::b64decode(msg.inputdata());
    logger->debug("Entering enclave {} to execute {} with sid '{}', policy "
                  "length {} and input '{}'",
                  globalEnclaveId,
                  funcStr,
                  msg.sgxsid(),
                  msg.sgxpolicy().size(),
                  msg.inputdata());
    if (msg.sgxpolicy().size() == 0) {
        sgxReturnValue = faasm_sgx_enclave_call_function(
          globalEnclaveId,
          &returnValue,
          threadId,
          msg.funcptr(),
          msg.sgxsid().c_str(),
          (const sgx_wamr_encrypted_data_blob_t*)inputdata.c_str(),
          inputdata.size(),
          nullptr,
          0);
    } else {
        sgxReturnValue = faasm_sgx_enclave_call_function(
          globalEnclaveId,
          &returnValue,
          threadId,
          msg.funcptr(),
          msg.sgxsid().c_str(),
          (const sgx_wamr_encrypted_data_blob_t*)inputdata.c_str(),
          inputdata.size(),
          (const uint8_t*)msg.sgxpolicy().c_str(),
          msg.sgxpolicy().size());
    }

    if (sgxReturnValue != SGX_SUCCESS) {
        logger->error("Unable to enter enclave: {}",
                      sgxErrorString(sgxReturnValue));
        throw std::runtime_error("Unable to enter enclave");
    }

    if (returnValue != FAASM_SGX_SUCCESS) {
        // Check if an ocall has failed
        sgxReturnValue =
          (sgx_status_t)FAASM_SGX_OCALL_GET_SGX_ERROR(returnValue);
        if (sgxReturnValue) {
            logger->error("An OCALL failed: {}",
                          sgxErrorString(sgxReturnValue));
            throw std::runtime_error("OCALL failed");
        }

        logger->error("Error occurred during function execution: {}",
                      faasmSgxErrorString(returnValue));
        throw std::runtime_error("Error occurred during function execution");
    }

    return true;
}

bool SGXWAMRWasmModule::isBound()
{
    return _isBound;
}
}
