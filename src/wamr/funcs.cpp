#include "thread_manager.h"

#include <faabric/proto/faabric.pb.h>
#include <faabric/util/bytes.h>
#include <faabric/util/macros.h>
#include <wamr/native.h>
#include <wasm/WasmModule.h>
#include <wasm/chaining.h>
#include <wasm_export.h>

namespace wasm {

/**
 * Read the function input
 */
static int32_t __faasm_read_input_wrapper(wasm_exec_env_t exec_env,
                                          char* inBuff,
                                          int32_t inLen)
{
    faabric::util::getLogger()->debug(
      "S - faasm_read_input {} {}", inBuff, inLen);

    faabric::Message* call = getExecutingCall();
    std::vector<uint8_t> inputBytes =
      faabric::util::stringToBytes(call->inputdata());

    // If nothing, return nothing
    if (inputBytes.empty()) {
        return 0;
    }

    // Write to the wasm buffer
    int inputSize = faabric::util::safeCopyToBuffer(
      inputBytes, reinterpret_cast<uint8_t*>(inBuff), inLen);
    return inputSize;
}

/**
 * Set the function output
 */
static void __faasm_write_output_wrapper(wasm_exec_env_t exec_env,
                                         char* outBuff,
                                         int32_t outLen)
{
    faabric::util::getLogger()->debug(
      "S - faasm_write_output {} {}", outBuff, outLen);

    faabric::Message* call = getExecutingCall();
    call->set_outputdata(outBuff, outLen);
}

/**
 * Chain a function by function pointer
 */
static int32_t __faasm_chain_ptr_wrapper(wasm_exec_env_t exec_env,
                                         int32_t wasmFuncPtr,
                                         char* inBuff,
                                         int32_t inLen)
{
    faabric::util::getLogger()->debug(
      "S - faasm_chain_ptr {} {} {}", wasmFuncPtr, inBuff, inLen);

    faabric::Message* call = getExecutingCall();
    std::vector<uint8_t> inputData(BYTES(inBuff), BYTES(inBuff) + inLen);
    return makeChainedCall(call->function(), wasmFuncPtr, nullptr, inputData);
}

/**
 * Chain a function by function name
 */
static int32_t __faasm_chain_name_wrapper(wasm_exec_env_t exec_env,
                                          char* funcName,
                                          char* inBuff,
                                          int32_t inLen)
{
    std::string funcNameString(funcName);
    faabric::util::getLogger()->debug(
      "S - faasm_chain_name {} {} {}", funcNameString, inBuff, inLen);

    std::vector<uint8_t> inputData(BYTES(inBuff), BYTES(inBuff) + inLen);
    return makeChainedCall(funcNameString, 0, nullptr, inputData);
}

/**
 * Await a chained function's completion
 */
static int32_t __faasm_await_call_wrapper(wasm_exec_env_t exec_env,
                                          int32_t callId)
{
    faabric::util::getLogger()->debug("S - faasm_await_call {}", callId);

    int32_t result = wasm::awaitChainedCall((uint32_t)callId);
    return result;
}

static NativeSymbol ns[] = {
    REG_NATIVE_FUNC(__faasm_write_output, "($i)"),
    REG_NATIVE_FUNC(__faasm_read_input, "($i)i"),
    REG_NATIVE_FUNC(__faasm_chain_ptr, "(i$i)i"),
    REG_NATIVE_FUNC(__faasm_chain_name, "($$i)i"),
    REG_NATIVE_FUNC(__faasm_await_call, "(i)i"),
};

uint32_t getFaasmFunctionsApi(NativeSymbol** nativeSymbols)
{
    *nativeSymbols = ns;
    return sizeof(ns) / sizeof(NativeSymbol);
}
}
