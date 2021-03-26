#include <cstring>

#include <sgx/SGXWAMRWasmModule.h>
#include <sgx/base64.h>
#include <wasm/chaining.h>

using namespace faabric::state;

#define STATE_KV(key, stateLen)                                                \
    State& state = getGlobalState();                                           \
    std::shared_ptr<StateKeyValue> stateKv = state.getKV(                      \
      wasm::getExecutingCall()->user(), std::string(key), stateLen);

extern "C"
{

    uint64_t ocall_faasm_read_state(const char* key,
                                    uint8_t* bufferPtr,
                                    const uint32_t bufferLen)
    {
        STATE_KV(key, bufferLen)
        stateKv->get(bufferPtr);

        if (bufferLen == 0) {
            return (uint64_t)state.getStateSize(
              wasm::getExecutingCall()->user(), std::string(key));
        }

        return stateKv->size();
    }

    void ocall_faasm_read_appended_state(const char* key,
                                         uint8_t* bufferPtr,
                                         const uint32_t bufferLen,
                                         const uint32_t element_num)
    {
        STATE_KV(key, bufferLen)
        stateKv->getAppended(bufferPtr, bufferLen, element_num);
    }

    void ocall_faasm_read_state_offset(const char* key,
                                       const uint64_t totalLen,
                                       const uint64_t offset,
                                       uint8_t* bufferPtr,
                                       const uint32_t bufferLen)
    {
        STATE_KV(key, totalLen)
        stateKv->getChunk(offset, bufferPtr, bufferLen);
    }

    void ocall_faasm_write_state(const char* key,
                                 const uint8_t* bufferPtr,
                                 const uint32_t bufferLen)
    {
        STATE_KV(key, bufferLen)
        stateKv->set(bufferPtr);
    }

    void ocall_faasm_append_state(const char* key,
                                  const uint8_t* bufferPtr,
                                  const uint32_t bufferLen)
    {
        STATE_KV(key, bufferLen)
        stateKv->append(bufferPtr, bufferLen);
    }

    void ocall_faasm_clear_appended_state(const char* key)
    {
        STATE_KV(key, 0)
        stateKv->clearAppended();
    }

    void ocall_faasm_write_state_offset(const char* key,
                                        const uint64_t totalLen,
                                        const uint64_t offset,
                                        const uint8_t* bufferPtr,
                                        const uint32_t bufferLen)
    {
        STATE_KV(key, totalLen)
        stateKv->setChunk(offset, bufferPtr, bufferLen);
    }

    void ocall_faasm_flag_state_dirty(const char* key, const uint64_t totalLen)
    {
        STATE_KV(key, totalLen)
        stateKv->flagDirty();
    }

    void ocall_faasm_flag_state_offset_dirty(const char* key,
                                             const uint64_t totalLen,
                                             const uint64_t offset,
                                             const uint64_t len)
    {
        STATE_KV(key, totalLen)
        stateKv->flagChunkDirty(offset, len);
    }

    void ocall_faasm_push_state(const char* key)
    {
        STATE_KV(key, 0)
        stateKv->pushFull();
    }

    void ocall_faasm_push_state_partial(const char* key)
    {
        STATE_KV(key, 0)
        stateKv->pushPartial();
    }

    void ocall_faasm_push_state_partial_mask(const char* key,
                                             const char* maskKey)
    {
        STATE_KV(key, 0)
        auto maskKv = state.getKV(
          wasm::getExecutingCall()->user(), std::string(maskKey), 0);
        stateKv->pushPartialMask(maskKv);
    }

    void ocall_faasm_pull_state(const char* key, const uint64_t state_len)
    {
        STATE_KV(key, state_len)
        stateKv->pull();
    }

    void ocall_faasm_lock_state_global(const char* key)
    {
        STATE_KV(key, 0)
        stateKv->lockGlobal();
    }

    void ocall_faasm_unlock_state_global(const char* key)
    {
        STATE_KV(key, 0)
        stateKv->unlockGlobal();
    }

    void ocall_faasm_lock_state_read(const char* key)
    {
        STATE_KV(key, 0)
        stateKv->lockRead();
    }

    void ocall_faasm_unlock_state_read(const char* key)
    {
        STATE_KV(key, 0)
        stateKv->unlockRead();
    }

    void ocall_faasm_lock_state_write(const char* key)
    {
        STATE_KV(key, 0)
        stateKv->lockWrite();
    }

    void ocall_faasm_lock_state_write2(const char* key, uint32_t len)
    {
        STATE_KV(key, len)
        stateKv->lockWrite();
    }

    void ocall_faasm_unlock_state_write(const char* key)
    {
        STATE_KV(key, 0)
        stateKv->unlockWrite();
    }

    void ocall_faasm_unlock_state_write2(const char* key, uint32_t len)
    {
        STATE_KV(key, len)
        stateKv->unlockWrite();
    }

    int ocall_faasm_read_input(uint8_t* buffer, unsigned int bufferSize)
    {
        faabric::util::getLogger()->debug(
          "Ocall - faasm_read_input [encrypted input] {}", bufferSize);
        faabric::Message* msg = wasm::getExecutingCall();

        unsigned long inputLen = msg->inputdata().size();

        if (bufferSize == 0) {
            return (int)inputLen;
        }

        if (inputLen > 0) {
            const std::string& _input = msg->inputdata();
            if (_input.size() > bufferSize) {
                memcpy(buffer, _input.data(), bufferSize);
                return (int)bufferSize;
            } else {
                memcpy(buffer, _input.data(), _input.size());
                return (int)inputLen;
            }
        }

        return 0;
    }

    void ocall_faasm_write_output(uint8_t* output, unsigned int outputSize)
    {
        faabric::util::getLogger()->debug(
          "Ocall - faasm_write_output [encrypted output] {}", outputSize);
        std::string encoded_output =
          util::b64encode(std::string(output, output + outputSize));
        wasm::getExecutingCall()->set_outputdata(encoded_output);
    }

    unsigned int ocall_faasm_chain_name(const char* name,
                                        const uint8_t* input,
                                        unsigned int inputSize,
                                        const uint8_t* policy,
                                        unsigned int policySize)
    {
        faabric::util::getLogger()->debug(
          "Ocall - faasm_chain_name {} [encrypted input] {}", name, inputSize);
        std::string encoded_input =
          util::b64encode(std::string(input, input + inputSize));
        const std::vector<uint8_t> _input(encoded_input.begin(),
                                          encoded_input.end());
        const std::vector<uint8_t> _policy(policy, policy + policySize);
        return wasm::makeChainedCall2(
          std::string(name), 0, nullptr, _input, _policy);
    }

    unsigned int ocall_faasm_chain_ptr(int wasmFuncPtr,
                                       uint8_t* input,
                                       unsigned int inputSize,
                                       const uint8_t* policy,
                                       unsigned int policySize)
    {
        faabric::util::getLogger()->debug(
          "Ocall - faasm_chain_ptr {} [encrpyted input] {}",
          wasmFuncPtr,
          inputSize);
        const std::vector<uint8_t> _input(input, input + inputSize);
        const std::vector<uint8_t> _policy(policy, policy + policySize);
        return wasm::makeChainedCall2(wasm::getExecutingCall()->function(),
                                      wasmFuncPtr,
                                      nullptr,
                                      _input,
                                      _policy);
    }

    unsigned int ocall_faasm_await_call(unsigned int callId)
    {
        faabric::util::getLogger()->debug("Ocall - faasm_await_call {}",
                                          callId);
        return wasm::awaitChainedCall2(callId);
    }

    unsigned int ocall_faasm_await_call_output(unsigned int callId,
                                               uint8_t* buffer,
                                               unsigned int bufferSize)
    {
        faabric::util::getLogger()->debug(
          "Ocall - faasm_await_call_output {} [encrypted buffer] {}",
          callId,
          bufferSize);
        return wasm::awaitChainedCallOutput2(callId, buffer, bufferSize);
    }
}
