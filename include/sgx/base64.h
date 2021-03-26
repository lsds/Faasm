#pragma once

#include <string>
#ifdef __cplusplus
extern "C"
{
#endif
    int Base64decode_len(const char* bufcoded);
    int Base64encode_len(int len);
    int Base64decode(char* bufplain, const char* bufcoded);
    int Base64encode(char* encoded, const char* string, int len);
#ifdef __cplusplus
};
#endif

namespace util {
std::string b64encode(const std::string& bytes);
std::string b64decode(const std::string& bytes);
}
