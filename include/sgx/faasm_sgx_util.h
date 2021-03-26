#ifndef FAASM_SGX_WAMR_UTIL_H
#define FAASM_SGX_WAMR_UTIL_H
#include <sgx/faasm_sgx_enclave_types.h>
#include <sgx/faasm_sgx_error.h>
#ifdef __cplusplus
extern "C"
{
#endif
    faasm_sgx_status_t parse_chain_policy_to_map(
      std::map<const char*, std::string, cmp_str>* chain_policy_map,
      char* policy_str,
      uint32_t policy_str_len);
    faasm_sgx_status_t initialize_execution_stack(char** execution_stack_ptr,
                                                  const uint32_t func_id);
    faasm_sgx_status_t push_to_execution_stack(char** execution_stack_ptr,
                                               const char* stack);
    faasm_sgx_status_t finish_execution_stack(char** execution_stack_ptr);
    faasm_sgx_status_t create_total_execution_stack(char** total_stack,
                                                    char* entry_stack,
                                                    char* execution_stack);
    faasm_sgx_status_t free_execution_stack(char** execution_stack_ptr);
#ifdef __cplusplus
};
#endif
#endif // FAASM_SGX_WAMR_UTIL_H
