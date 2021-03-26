#pragma once

#include <sgx/faasm_sgx_attestation.h>

#if (FAASM_SGX_WHITELISTING)
#include <sgx/faasm_sgx_whitelisting.h>
#endif

#include <wasm_export.h>

#include <map>
#include <string>
#include <vector>

#define _FAASM_SGX_TCS_SLOT_FREE (_faasm_sgx_tcs_t*)0x0

#define _FAASM_SGX_TCS_SLOT_IN_USE (_faasm_sgx_tcs_t*)0x1

#define _FAASM_SGX_TCS_LOAD_SLOT(PTR, THREAD_ID)                               \
    read_lock(&_rwlock_faasm_sgx_tcs_realloc);                                 \
    _faasm_sgx_tcs_t* PTR = faasm_sgx_tcs[THREAD_ID];                          \
    read_unlock(&_rwlock_faasm_sgx_tcs_realloc);

#define _FAASM_SGX_TCS_FREE_SLOT(THREAD_ID)                                    \
    read_lock(&_rwlock_faasm_sgx_tcs_realloc);                                 \
    faasm_sgx_tcs[THREAD_ID] = _FAASM_SGX_TCS_SLOT_FREE;                       \
    read_unlock(&_rwlock_faasm_sgx_tcs_realloc);

struct cmp_str
{
    bool operator()(char const* a, char const* b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

typedef struct _attestation_env
{
    char* user;
    char* name;
    sgx_aes_gcm_128bit_key_t payload_secret;
    sgx_sha256_hash_t encrypted_op_code_hash;
    sgx_sha256_hash_t op_code_hash;
    uint8_t policy_nonce[SGX_AESGCM_IV_SIZE];
    uint8_t output_nonce[SGX_AESGCM_IV_SIZE];
    uint32_t payload_len;
    uint8_t* payload;
    std::map<const char*, std::string, cmp_str>* chain_policy;
    std::map<const uint32_t, std::string>* nonce_store;
    char* execution_stack;
    char* entry_execution_stack;

} _sgx_wamr_attestation_env_t;

typedef struct _sgx_wamr_execution_policy_t
{
    uint8_t hash[SGX_SHA256_HASH_SIZE];
    uint8_t input_nonce[SGX_AESGCM_IV_SIZE];
    uint8_t fid;
    uint8_t data[];
} sgx_wamr_execution_policy_t;

typedef struct _sgx_wamr_execution_attestation_t
{
    uint32_t return_value;
    uint8_t output_nonce[SGX_AESGCM_IV_SIZE];
    uint8_t policy_nonce[SGX_AESGCM_IV_SIZE];
    uint32_t execution_stack_len;
    uint8_t data[];
} sgx_wamr_execution_attestation_t;

typedef struct __faasm_sgx_tcs
{
    wasm_module_t module;
    wasm_module_inst_t module_inst;
    uint8_t* wasm_opcode;

    faaslet_sgx_gp_buffer_t *output_ptr, *result_ptr;
    sgx_wamr_msg_t** response_ptr;
    _sgx_wamr_attestation_env_t env;

#if (FAASM_SGX_WHITELISTING)
    _faasm_sgx_whitelist_t* module_whitelist;
#endif

} _faasm_sgx_tcs_t;
