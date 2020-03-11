#include "WasmModule.h"
#include "syscalls.h"

#include <scheduler/Scheduler.h>

#include <WAVM/Runtime/Runtime.h>
#include <WAVM/Runtime/Intrinsics.h>

namespace wasm {
    void chainLink() {

    }

    WAVM_DEFINE_INTRINSIC_FUNCTION(env, "__faasm_get_idx", I32, __faasm_get_idx) {
        util::getLogger()->debug("S - get_idx");

        message::Message *call = getExecutingCall();
        int idx = call->idx();

        return idx;
    }

    WAVM_DEFINE_INTRINSIC_FUNCTION(env, "__faasm_get_py_idx", I32, __faasm_get_py_idx) {
        util::getLogger()->debug("S - get_py_idx");

        message::Message *call = getExecutingCall();
        int idx = call->pythonidx();

        return idx;
    }

    WAVM_DEFINE_INTRINSIC_FUNCTION(env, "__faasm_await_call", I32, __faasm_await_call, U32 messageId) {
        util::getLogger()->debug("S - await_call - {}", messageId);

        return awaitChainedCall(messageId);
    }

    WAVM_DEFINE_INTRINSIC_FUNCTION(env, "__faasm_chain_function", U32, __faasm_chain_function,
                                   I32 namePtr, I32 inputDataPtr, I32 inputDataLen) {
        std::string funcName = getStringFromWasm(namePtr);
        util::getLogger()->debug("S - chain_function - {} {} {}", funcName, inputDataPtr, inputDataLen);

        const std::vector<uint8_t> inputData = getBytesFromWasm(inputDataPtr, inputDataLen);

        return makeChainedCall(funcName, 0, 0, inputData);
    }

    WAVM_DEFINE_INTRINSIC_FUNCTION(env, "__faasm_chain_this", U32, __faasm_chain_this,
                                   I32 idx, I32 inputDataPtr, I32 inputDataLen) {
        util::getLogger()->debug("S - chain_this - {} {} {}", idx, inputDataPtr, inputDataLen);

        message::Message *call = getExecutingCall();
        const std::vector<uint8_t> inputData = getBytesFromWasm(inputDataPtr, inputDataLen);

        return makeChainedCall(call->function(), idx, 0, inputData);
    }

    WAVM_DEFINE_INTRINSIC_FUNCTION(env, "__faasm_chain_py", U32, __faasm_chain_py,
                                   I32 idx, I32 inputDataPtr, I32 inputDataLen) {
        util::getLogger()->debug("S - chain_py - {} {} {}", idx, inputDataPtr, inputDataLen);

        message::Message *call = getExecutingCall();
        const std::vector<uint8_t> inputData = getBytesFromWasm(inputDataPtr, inputDataLen);

        return makeChainedCall(call->function(), 0, idx, inputData);
    }
}
