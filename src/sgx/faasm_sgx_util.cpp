#include <sgx/faasm_sgx_enclave_types.h>
#include <sgx/faasm_sgx_util.h>
#include <stdio.h>
extern "C"
{
    extern __thread uint32_t tls_thread_id;
    extern _faasm_sgx_tcs_t** faasm_sgx_tcs;
    extern int os_printf(const char* message, ...);

    void hex_decode(const char* in, size_t len, uint8_t* out)
    {
        unsigned int i, hn, ln;
        char hc, lc;
        memset(out, 0, len);
        for (i = 0; i < 2 * len; i += 2) {
            hc = in[i];
            if ('a' <= hc && hc <= 'f')
                hc = toupper(hc);
            lc = in[i + 1];
            if ('a' <= lc && lc <= 'f')
                lc = toupper(lc);
            hn = hc > '9' ? hc - 'A' + 10 : hc - '0';
            ln = lc > '9' ? lc - 'A' + 10 : lc - '0';
            out[i >> 1] = (hn << 4) | ln;
        }
    }

    faasm_sgx_status_t parse_chain_policy_to_map(
      std::map<const char*, std::string, cmp_str>* chain_policy_map,
      char* policy_str,
      uint32_t policy_str_len)
    {
        if (policy_str_len < SGX_SHA256_HASH_SIZE * 2) {
            return FAASM_SGX_SUCCESS;
        }
        char *delim = (char*)">,", *token, *key;
        uint8_t* hash;
        while ((token = strstr(policy_str, delim)) != NULL) {
            *token = '\0';
            int key_len = strlen(policy_str) - 1 - SGX_SHA256_HASH_SIZE * 2 - 1;
            if ((key = (char*)calloc(key_len + 1, sizeof(char))) == NULL) {
                return FAASM_SGX_OUT_OF_MEMORY;
            }
            if ((hash = (uint8_t*)calloc(SGX_SHA256_HASH_SIZE * 2 / 2 + 1,
                                         sizeof(uint8_t))) == NULL) {
                return FAASM_SGX_OUT_OF_MEMORY;
            }
            memcpy(key, policy_str + 1, key_len);
            hex_decode(
              policy_str + key_len + 2, SGX_SHA256_HASH_SIZE * 2, hash);
            chain_policy_map->insert(
              std::pair<char*, std::string>(key, std::string(hash, hash + 32)));
            policy_str = token + strlen(delim);
        }
        return FAASM_SGX_SUCCESS;
    }
    faasm_sgx_status_t initialize_execution_stack(char** execution_stack_ptr,
                                                  const uint32_t func_id)
    {
        const char* name = faasm_sgx_tcs[tls_thread_id]->env.name; // TODO mutex
        char func_id_str[12];
        snprintf(func_id_str, sizeof(func_id_str), "%d", func_id);
        char hex_hash[SGX_SHA256_HASH_SIZE * 2 + 1];
        for (size_t i = 0; i < SGX_SHA256_HASH_SIZE; i++)
            snprintf(hex_hash + i * 2,
                     SGX_SHA256_HASH_SIZE,
                     "%02x",
                     faasm_sgx_tcs[tls_thread_id]->env.op_code_hash[i]);
        uint32_t new_size = strlen("<") + strlen(name) + strlen(":") +
                            strlen(hex_hash) + strlen(":") +
                            strlen(func_id_str) + 1;
        if ((*execution_stack_ptr = (char*)calloc(new_size, sizeof(char))) ==
            NULL) {
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        strncpy(*execution_stack_ptr, "<", strlen("<"));
        strncpy(*execution_stack_ptr + strlen("<"), name, strlen(name));
        strncpy(
          *execution_stack_ptr + strlen("<") + strlen(name), ":", strlen(":"));
        strncpy(*execution_stack_ptr + strlen("<") + strlen(name) + strlen(":"),
                hex_hash,
                strlen(hex_hash));
        strncpy(*execution_stack_ptr + strlen("<") + strlen(name) +
                  strlen(":") + strlen(hex_hash),
                ":",
                strlen(":"));
        strncpy(*execution_stack_ptr + strlen("<") + strlen(name) +
                  strlen(":") + strlen(hex_hash) + strlen(":"),
                func_id_str,
                strlen(func_id_str));
        return FAASM_SGX_SUCCESS;
    }
    faasm_sgx_status_t push_to_execution_stack(char** execution_stack_ptr,
                                               const char* stack)
    {
        uint32_t new_size =
          strlen(*execution_stack_ptr) + 1 + strlen(stack) + strlen(",");
        if ((*execution_stack_ptr = (char*)realloc(
               *execution_stack_ptr, new_size * sizeof(char))) == NULL) {
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        uint32_t temp = strlen(*execution_stack_ptr);
        strncpy(*execution_stack_ptr + temp, ",", strlen(","));
        strncpy(
          *execution_stack_ptr + temp + strlen(","), stack, strlen(stack));
        (*execution_stack_ptr)[new_size - 1] = '\0';
        return FAASM_SGX_SUCCESS;
    }
    faasm_sgx_status_t finish_execution_stack(char** execution_stack_ptr)
    {
        uint32_t new_size = strlen(*execution_stack_ptr) + 2;
        if ((*execution_stack_ptr = (char*)realloc(
               *execution_stack_ptr, new_size * sizeof(char))) == NULL) {
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        strncpy(*execution_stack_ptr + strlen(*execution_stack_ptr), ">", 1);
        (*execution_stack_ptr)[new_size - 1] = '\0';
        return FAASM_SGX_SUCCESS;
    }
    faasm_sgx_status_t create_total_execution_stack(char** total_stack_ptr,
                                                    char* entry_stack,
                                                    char* execution_stack)
    {
        if (entry_stack == 0x0) {
            uint32_t new_size = strlen(execution_stack) + 2;
            if ((*total_stack_ptr = (char*)calloc(new_size, sizeof(char))) ==
                NULL) {
                return FAASM_SGX_OUT_OF_MEMORY;
            }
            strncpy(*total_stack_ptr, execution_stack, strlen(execution_stack));
            strncpy(*total_stack_ptr + strlen(execution_stack), ",", 1);
            return FAASM_SGX_SUCCESS;
        }
        uint32_t new_size = strlen(entry_stack) + strlen(execution_stack) + 1;
        if ((*total_stack_ptr = (char*)calloc(new_size, sizeof(char))) ==
            NULL) {
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        strncpy(*total_stack_ptr, entry_stack, strlen(entry_stack));
        strncpy(*total_stack_ptr + strlen(entry_stack),
                execution_stack,
                strlen(execution_stack));
        return FAASM_SGX_SUCCESS;
    }
    faasm_sgx_status_t free_execution_stack(char** execution_stack_ptr)
    {
        free(*execution_stack_ptr);
        *execution_stack_ptr = 0x0;
        return FAASM_SGX_SUCCESS;
    }
};
