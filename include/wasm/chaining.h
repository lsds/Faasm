#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace wasm {

int awaitChainedCall(unsigned int messageId);

int awaitChainedCall2(unsigned int messageId);

int awaitChainedCallOutput(unsigned int messageId,
                           uint8_t* buffer,
                           int bufferLen);

int awaitChainedCallOutput2(unsigned int messageId,
                            uint8_t* buffer,
                            int bufferLen);

int makeChainedCall(const std::string& functionName,
                    int wasmFuncPtr,
                    const char* pyFunc,
                    const std::vector<uint8_t>& inputData);

int makeChainedCall2(const std::string& functionName,
                     int wasmFuncPtr,
                     const char* pyFunc,
                     const std::vector<uint8_t>& inputData,
                     const std::vector<uint8_t>& policy);
}
