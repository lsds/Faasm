#include "sgx/faasm_sgx_native_symbols_wrapper.h"
#include "sgx/faasm_sgx_enclave_types.h"
#include "sgx/faasm_sgx_error.h"

#if (FAASM_SGX_WAMR_AOT_MODE)
#include <iwasm/aot/aot_runtime.h>
#else
#include <iwasm/interpreter/wasm_runtime.h>
#endif

#include <iwasm/common/wasm_exec_env.h>

#include <rw_lock.h>
#include <sgx/faasm_sgx_enclave_types.h>
#include <sgx/faasm_sgx_util.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
extern "C"
{
    extern _faasm_sgx_tcs_t** faasm_sgx_tcs;
    extern __thread uint32_t tls_thread_id;
    extern sgx_aes_gcm_128bit_key_t master_secret;
    extern faasm_sgx_status_t send_recv_msg(uint32_t thread_id,
                                            const void* send_payload_ptr,
                                            const uint32_t send_payload_len,
                                            void** recv_payload_ptr,
                                            uint32_t* recv_payload_len);
    extern rwlock_t _rwlock_faasm_sgx_tcs_realloc;
}

// SET_ERROR definition for AoT and interpreter mode
#if (FAASM_SGX_WAMR_AOT_MODE)
#define SET_ERROR(X)                                                           \
    memcpy(((AOTModuleInstance*)exec_env->module_inst)->cur_exception,         \
           _FAASM_SGX_ERROR_PREFIX,                                            \
           sizeof(_FAASM_SGX_ERROR_PREFIX));                                   \
    *((uint32_t*)&((AOTModuleInstance*)exec_env->module_inst)                  \
        ->cur_exception[sizeof(_FAASM_SGX_ERROR_PREFIX)]) = (X);
#else
#define SET_ERROR(X)                                                           \
    memcpy(((WASMModuleInstance*)exec_env->module_inst)->cur_exception,        \
           _FAASM_SGX_ERROR_PREFIX,                                            \
           sizeof(_FAASM_SGX_ERROR_PREFIX));                                   \
    *((uint32_t*)&((WASMModuleInstance*)exec_env->module_inst)                 \
        ->cur_exception[sizeof(_FAASM_SGX_ERROR_PREFIX)]) = (X);
#endif

#define NATIVE_FUNC(funcName, funcSig)                                         \
    {                                                                          \
        "__" #funcName, (void*)funcName##_wrapper, funcSig, 0x0                \
    }

#define WASI_NATIVE_FUNC(funcName, funcSig)                                    \
    {                                                                          \
#funcName, (void*)funcName##_wrapper, funcSig, 0x0                     \
    }

extern "C"
{

    // ------------------------------------
    // FUNCTIONS
    // ------------------------------------

    static int32_t faasm_read_input_wrapper(wasm_exec_env_t exec_env,
                                            uint8_t* buffer,
                                            unsigned int buffer_size)
    {
        int32_t returnValue = 0;
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if (buffer_size > faasm_sgx_tcs[tls_thread_id]->env.payload_len) {
            memcpy(buffer,
                   faasm_sgx_tcs[tls_thread_id]->env.payload,
                   faasm_sgx_tcs[tls_thread_id]->env.payload_len);
        } else {
            memcpy(
              buffer, faasm_sgx_tcs[tls_thread_id]->env.payload, buffer_size);
        }
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        return returnValue;
    }

    static void faasm_write_output_wrapper(wasm_exec_env_t exec_env,
                                           uint8_t* output,
                                           unsigned int output_size)
    {
        sgx_status_t sgxReturnValue;
        uint32_t output_data_len;
        sgx_wamr_encrypted_data_blob_t* output_data;
        faasm_sgx_nonce_t p_iv;
        output_data_len = sizeof(sgx_wamr_encrypted_data_blob_t) + output_size;
        if ((output_data = (sgx_wamr_encrypted_data_blob_t*)calloc(
               output_data_len, sizeof(uint8_t))) == NULL) {
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return;
        }
        if (sgx_read_rand(p_iv, SGX_AESGCM_IV_SIZE) != SGX_SUCCESS) {
            free(output_data);
            SET_ERROR(FAASM_SGX_READ_RAND_FAILED);
            return;
        }
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if (sgx_rijndael128GCM_encrypt(
              &faasm_sgx_tcs[tls_thread_id]->env.payload_secret,
              output,
              output_size,
              output_data->data,
              p_iv,
              SGX_AESGCM_IV_SIZE,
              NULL,
              0,
              &output_data->tag) != SGX_SUCCESS) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            free(output_data);
            SET_ERROR(FAASM_SGX_ENCRYPTION_FAILED);
            return;
        }
        memcpy(output_data->nonce, p_iv, sizeof(output_data->nonce));
        memcpy(faasm_sgx_tcs[tls_thread_id]->env.output_nonce,
               p_iv,
               sizeof(output_data->nonce));
        output_data->data_len = output_size;
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        if ((sgxReturnValue = ocall_faasm_write_output(
               (uint8_t*)output_data, output_data_len)) != SGX_SUCCESS) {
            free(output_data);
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
            return;
        }
        free(output_data);
    }

    // --------------------------------------
    // STATE
    // --------------------------------------

    static uint64_t faasm_read_state_wrapper(wasm_exec_env_t exec_env,
                                             const char* key,
                                             uint8_t* buffer_ptr,
                                             const uint32_t buffer_len)
    {
        sgx_status_t sgxReturnValue;
        uint64_t returnValue;
        uint32_t msg_payload_len, res_payload_len, encrypted_state_len;
        sgx_wamr_msg_state_read_t* msg_payload;
        faasm_sgx_status_t faasm_ret_val;
        void* res_payload;
        sgx_wamr_msg_hdr_t header;
        sgx_wamr_encrypted_state_blob_t* encrypted_state;
        sgx_wamr_msg_state_read_res_t* typed_res_payload;
        sgx_sha256_hash_t buffer_hash;
        char* execution_stack;
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        msg_payload_len = sizeof(sgx_wamr_msg_state_read_t) +
                          strlen(faasm_sgx_tcs[tls_thread_id]->env.user) +
                          strlen(":") + strlen(key);
        if ((msg_payload = (sgx_wamr_msg_state_read_t*)calloc(
               msg_payload_len, sizeof(uint8_t*))) == NULL) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        memcpy(msg_payload->state_name,
               faasm_sgx_tcs[tls_thread_id]->env.user,
               strlen(faasm_sgx_tcs[tls_thread_id]->env.user));
        memcpy(msg_payload->state_name +
                 strlen(faasm_sgx_tcs[tls_thread_id]->env.user),
               ":",
               strlen(":"));
        memcpy(msg_payload->state_name +
                 strlen(faasm_sgx_tcs[tls_thread_id]->env.user) + strlen(":"),
               key,
               strlen(key));
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        msg_payload->hdr.type = FAASM_SGX_ATTESTATION_TYPE_STATE_READ;
        if ((faasm_ret_val = send_recv_msg(tls_thread_id,
                                           msg_payload,
                                           msg_payload_len,
                                           &res_payload,
                                           &res_payload_len)) !=
            FAASM_SGX_SUCCESS) {
            free(msg_payload);
            SET_ERROR(faasm_ret_val);
            return 1;
        }
        free(msg_payload);
        header = *((sgx_wamr_msg_hdr_t*)res_payload);
        if (header.status) {
            free(res_payload);
            SET_ERROR(FAASM_SGX_KM_STATUS_ERROR);
            return 1;
        }
        encrypted_state_len =
          sizeof(sgx_wamr_encrypted_state_blob_t) + buffer_len;
        if ((encrypted_state = (sgx_wamr_encrypted_state_blob_t*)calloc(
               encrypted_state_len, sizeof(uint8_t))) == NULL) {
            free(res_payload);
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        if ((sgxReturnValue = ocall_faasm_read_state(&returnValue,
                                                     key,
                                                     (uint8_t*)encrypted_state,
                                                     encrypted_state_len)) !=
            SGX_SUCCESS) {
            free(res_payload);
            free(encrypted_state);
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
            return 1;
        }
        typed_res_payload = (sgx_wamr_msg_state_read_res_t*)res_payload;
        if (memcmp(typed_res_payload->buffer_nonce,
                   encrypted_state->nonce,
                   SGX_AESGCM_IV_SIZE) != 0) {
            free(res_payload);
            free(encrypted_state);
            SET_ERROR(FAASM_SGX_INVALID_INPUT_NONCE);
            return 1;
        }
        if ((execution_stack = (char*)calloc(
               res_payload_len - sizeof(sgx_wamr_msg_state_read_res_t) + 1 +
                 strlen(key) + strlen(":[]"),
               sizeof(uint8_t))) == NULL) {
            free(res_payload);
            free(encrypted_state);
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        memcpy(execution_stack, "[", strlen("["));
        memcpy(execution_stack + strlen("["), key, strlen(key));
        memcpy(execution_stack + strlen("[") + strlen(key), ";", strlen(";"));
        memcpy(execution_stack + strlen("[;") + strlen(key),
               typed_res_payload->data,
               res_payload_len - sizeof(sgx_wamr_msg_state_read_res_t));
        memcpy(execution_stack + strlen("[;") + strlen(key) + res_payload_len -
                 sizeof(sgx_wamr_msg_state_read_res_t),
               "]",
               strlen("]"));
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if ((faasm_ret_val = push_to_execution_stack(
               &faasm_sgx_tcs[tls_thread_id]->env.execution_stack,
               execution_stack)) != FAASM_SGX_SUCCESS) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            free(res_payload);
            free(encrypted_state);
            free(execution_stack);
            SET_ERROR(faasm_ret_val);
            return 1;
        }
        free(execution_stack);
        if (sgx_rijndael128GCM_decrypt(&typed_res_payload->state_secret,
                                       encrypted_state->data,
                                       buffer_len,
                                       buffer_ptr,
                                       encrypted_state->nonce,
                                       SGX_AESGCM_IV_SIZE,
                                       NULL,
                                       0,
                                       &encrypted_state->tag) != SGX_SUCCESS) {
            free(res_payload);
            free(encrypted_state);
            SET_ERROR(FAASM_SGX_DECRYPTION_FAILED);
            return 1;
        }
        free(res_payload);
        free(encrypted_state);
        if (sgx_sha256_msg(buffer_ptr, buffer_len, &buffer_hash) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_HASH_FAILED);
            return 1;
        }
        return buffer_len;
    }

    static void faasm_read_appended_state_wrapper(wasm_exec_env_t exec_env,
                                                  const char* key,
                                                  uint8_t* buffer_ptr,
                                                  const uint32_t buffer_len,
                                                  const uint32_t element_num)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_read_appended_state(
               key, buffer_ptr, buffer_len, element_num)) != SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_read_state_offset_wrapper(wasm_exec_env_t exec_env,
                                                const char* key,
                                                const uint64_t total_len,
                                                const uint64_t offset,
                                                uint8_t* buffer_ptr,
                                                const uint32_t buffer_len)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_read_state_offset(
               key, total_len, offset, buffer_ptr, buffer_len)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_write_state_wrapper(wasm_exec_env_t exec_env,
                                          const char* key,
                                          const uint8_t* buffer_ptr,
                                          const uint32_t buffer_len)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_write_state(
               key, buffer_ptr, buffer_len)) != SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_append_state_wrapper(wasm_exec_env_t exec_env,
                                           const char* key,
                                           const uint8_t* buffer_ptr,
                                           const uint32_t buffer_len)
    {
        sgx_status_t sgxReturnValue;
        uint32_t domain_len, msg_payload_len, res_payload_len,
          encrypted_state_len;
        sgx_wamr_msg_state_write_t* msg_payload;
        faasm_sgx_status_t faasm_ret_val;
        void* res_payload;
        sgx_wamr_msg_hdr_t header;
        sgx_wamr_payload_key_t* typed_res_payload;
        faasm_sgx_nonce_t p_iv;
        char* total_execution_stack;
        sgx_wamr_encrypted_state_blob_t* encrypted_state;
        sgx_wamr_msg_state_read_t* msg_read_payload;
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if ((faasm_ret_val = create_total_execution_stack(
               &total_execution_stack,
               faasm_sgx_tcs[tls_thread_id]->env.entry_execution_stack,
               faasm_sgx_tcs[tls_thread_id]->env.execution_stack)) !=
            FAASM_SGX_SUCCESS) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            SET_ERROR(faasm_ret_val);
            return;
        }
        domain_len = strlen(faasm_sgx_tcs[tls_thread_id]->env.user) +
                     strlen(":") + strlen(key);
        msg_payload_len = sizeof(sgx_wamr_msg_state_write_t) + domain_len +
                          strlen(total_execution_stack);
        if ((msg_payload = (sgx_wamr_msg_state_write_t*)calloc(
               msg_payload_len, sizeof(uint8_t*))) == NULL) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            free_execution_stack(&total_execution_stack);
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return;
        }
        if (sgx_read_rand(p_iv, SGX_AESGCM_IV_SIZE) != SGX_SUCCESS) {
            free(msg_payload);
            free_execution_stack(&total_execution_stack);
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            SET_ERROR(FAASM_SGX_READ_RAND_FAILED);
            return;
        }
        memcpy(
          msg_payload->buffer_nonce, p_iv, sizeof(msg_payload->buffer_nonce));
        msg_payload->name_length = domain_len;
        memcpy(msg_payload->data,
               faasm_sgx_tcs[tls_thread_id]->env.user,
               strlen(faasm_sgx_tcs[tls_thread_id]->env.user));
        memcpy(msg_payload->data +
                 strlen(faasm_sgx_tcs[tls_thread_id]->env.user),
               ":",
               strlen(":"));
        memcpy(msg_payload->data +
                 strlen(faasm_sgx_tcs[tls_thread_id]->env.user) + strlen(":"),
               key,
               strlen(key));
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        memcpy(msg_payload->data + domain_len,
               total_execution_stack,
               strlen(total_execution_stack));
        free_execution_stack(&total_execution_stack);
        msg_payload->hdr.type = FAASM_SGX_ATTESTATION_TYPE_STATE_WRITE;
        encrypted_state_len =
          sizeof(sgx_wamr_encrypted_state_blob_t) + buffer_len;
        if ((sgxReturnValue = ocall_faasm_lock_state_write2(
               key, encrypted_state_len)) != SGX_SUCCESS) {
            free(msg_payload);
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
            return;
        }
        if ((faasm_ret_val = send_recv_msg(tls_thread_id,
                                           msg_payload,
                                           msg_payload_len,
                                           &res_payload,
                                           &res_payload_len)) !=
            FAASM_SGX_SUCCESS) {
            free(msg_payload);
            if ((sgxReturnValue = ocall_faasm_unlock_state_write2(
                   key, encrypted_state_len)) != SGX_SUCCESS) {
                SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
                return;
            }
            SET_ERROR(faasm_ret_val);
            return;
        }
        free(msg_payload);
        header = *((sgx_wamr_msg_hdr_t*)res_payload);
        if (header.status) {
            free(res_payload);
            if ((sgxReturnValue = ocall_faasm_unlock_state_write2(
                   key, encrypted_state_len)) != SGX_SUCCESS) {
                SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
                return;
            }
            SET_ERROR(FAASM_SGX_KM_STATUS_ERROR);
            return;
        }
        typed_res_payload = (sgx_wamr_payload_key_t*)res_payload;
        if ((encrypted_state = (sgx_wamr_encrypted_state_blob_t*)calloc(
               encrypted_state_len, sizeof(uint8_t))) == NULL) {
            free(res_payload);
            if ((sgxReturnValue = ocall_faasm_unlock_state_write2(
                   key, encrypted_state_len)) != SGX_SUCCESS) {
                SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
                return;
            }
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return;
        }
        if (sgx_rijndael128GCM_encrypt(&typed_res_payload->payload_key,
                                       (uint8_t*)buffer_ptr,
                                       buffer_len,
                                       encrypted_state->data,
                                       p_iv,
                                       SGX_AESGCM_IV_SIZE,
                                       NULL,
                                       0,
                                       &encrypted_state->tag) != SGX_SUCCESS) {
            free(res_payload);
            free(encrypted_state);
            if ((sgxReturnValue = ocall_faasm_unlock_state_write2(
                   key, encrypted_state_len)) != SGX_SUCCESS) {
                SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
                return;
            }
            SET_ERROR(FAASM_SGX_ENCRYPTION_FAILED);
            return;
        }
        free(res_payload);
        memcpy(encrypted_state->nonce, p_iv, sizeof(encrypted_state->nonce));
        if ((sgxReturnValue = ocall_faasm_write_state(
               key, (uint8_t*)encrypted_state, encrypted_state_len)) !=
            SGX_SUCCESS) {
            free(encrypted_state);
            if ((sgxReturnValue = ocall_faasm_unlock_state_write2(
                   key, encrypted_state_len)) != SGX_SUCCESS) {
                SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
                return;
            }
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
            return;
        }
        free(encrypted_state);
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        msg_payload_len = sizeof(sgx_wamr_msg_state_read_t) +
                          strlen(faasm_sgx_tcs[tls_thread_id]->env.user) +
                          strlen(":") + strlen(key);
        if ((msg_read_payload = (sgx_wamr_msg_state_read_t*)calloc(
               msg_payload_len, sizeof(uint8_t*))) == NULL) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            if ((sgxReturnValue = ocall_faasm_unlock_state_write2(
                   key, encrypted_state_len)) != SGX_SUCCESS) {
                SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
                return;
            }
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return;
        }
        memcpy(msg_read_payload->state_name,
               faasm_sgx_tcs[tls_thread_id]->env.user,
               strlen(faasm_sgx_tcs[tls_thread_id]->env.user));
        memcpy(msg_read_payload->state_name +
                 strlen(faasm_sgx_tcs[tls_thread_id]->env.user),
               ":",
               strlen(":"));
        memcpy(msg_read_payload->state_name +
                 strlen(faasm_sgx_tcs[tls_thread_id]->env.user) + strlen(":"),
               key,
               strlen(key));
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        msg_read_payload->hdr.type = FAASM_SGX_ATTESTATION_TYPE_STATE_WRITE_ACK;
        if ((faasm_ret_val = send_recv_msg(tls_thread_id,
                                           msg_read_payload,
                                           msg_payload_len,
                                           &res_payload,
                                           &res_payload_len)) !=
            FAASM_SGX_SUCCESS) {
            free(msg_read_payload);
            if ((sgxReturnValue = ocall_faasm_unlock_state_write2(
                   key, encrypted_state_len)) != SGX_SUCCESS) {
                SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
                return;
            }
            SET_ERROR(faasm_ret_val);
            return;
        }
        free(msg_read_payload);
        header = *((sgx_wamr_msg_hdr_t*)res_payload);
        if (header.status) {
            free(res_payload);
            if ((sgxReturnValue = ocall_faasm_unlock_state_write2(
                   key, encrypted_state_len)) != SGX_SUCCESS) {
                SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
                return;
            }
            SET_ERROR(FAASM_SGX_KM_STATUS_ERROR);
            return;
        }
        free(res_payload);
        if ((sgxReturnValue = ocall_faasm_unlock_state_write2(
               key, encrypted_state_len)) != SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
            return;
        }
    }

    static void faasm_clear_appended_state_wrapper(wasm_exec_env_t exec_env,
                                                   const char* key)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_clear_appended_state(key)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_write_state_offset_wrapper(wasm_exec_env_t exec_env,
                                                 const char* key,
                                                 const uint64_t total_len,
                                                 const uint64_t offset,
                                                 const uint8_t* buffer_ptr,
                                                 const uint32_t buffer_len)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_write_state_offset(
               key, total_len, offset, buffer_ptr, buffer_len)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_flag_state_dirty_wrapper(wasm_exec_env_t exec_env,
                                               const char* key,
                                               const uint64_t total_len)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_flag_state_dirty(key, total_len)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_flag_state_offset_dirty_wrapper(wasm_exec_env_t exec_env,
                                                      const char* key,
                                                      const uint64_t total_len,
                                                      const uint64_t offset,
                                                      const uint64_t len)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_flag_state_offset_dirty(
               key, total_len, offset, len)) != SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_push_state_wrapper(wasm_exec_env_t exec_env,
                                         const char* key)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_push_state(key)) != SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_push_state_partial_wrapper(wasm_exec_env_t exec_env,
                                                 const char* key)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_push_state_partial(key)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_push_state_partial_mask_wrapper(wasm_exec_env_t exec_env,
                                                      const char* key,
                                                      const char* mask_key)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_push_state_partial_mask(
               key, mask_key)) != SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_pull_state_wrapper(wasm_exec_env_t exec_env,
                                         const char* key,
                                         const uint64_t state_len)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_pull_state(key, state_len)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_lock_state_global_wrapper(wasm_exec_env_t exec_env,
                                                const char* key)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_lock_state_global(key)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_unlock_state_global_wrapper(wasm_exec_env_t exec_env,
                                                  const char* key)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_unlock_state_global(key)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_lock_state_read_wrapper(wasm_exec_env_t exec_env,
                                              const char* key)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_lock_state_read(key)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_unlock_state_read_wrapper(wasm_exec_env_t exec_env,
                                                const char* key)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_unlock_state_read(key)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_lock_state_write_wrapper(wasm_exec_env_t exec_env,
                                               const char* key)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_lock_state_write(key)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    static void faasm_unlock_state_write_wrapper(wasm_exec_env_t exec_env,
                                                 const char* key)
    {
        sgx_status_t sgxReturnValue;
        if ((sgxReturnValue = ocall_faasm_unlock_state_write(key)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
        }
    }

    // ------------------------------
    // CHAINING
    // ------------------------------

    static unsigned int faasm_chain_name_wrapper(wasm_exec_env_t exec_env,
                                                 const char* name,
                                                 const uint8_t* input,
                                                 unsigned int input_size)
    {
        sgx_status_t sgxReturnValue;
        unsigned int returnValue;
        std::map<const char*, std::string>::iterator it;
        faasm_sgx_status_t faasm_ret_val;
        char* total_execution_stack;
        uint32_t policy_len, encrypted_policy_len;
        sgx_wamr_execution_policy_t* policy;
        sgx_wamr_encrypted_data_blob_t *encrypted_policy, *encrypted_input;
        faasm_sgx_nonce_t p_iv, p_iv1;
        if (sgx_read_rand(p_iv1, SGX_AESGCM_IV_SIZE) != SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_READ_RAND_FAILED);
            return 1;
        }
        if ((encrypted_input = (sgx_wamr_encrypted_data_blob_t*)calloc(
               input_size + sizeof(sgx_wamr_encrypted_data_blob_t),
               sizeof(uint8_t))) == NULL) {
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        if (sgx_rijndael128GCM_encrypt(&master_secret,
                                       input,
                                       input_size,
                                       encrypted_input->data,
                                       p_iv1,
                                       SGX_AESGCM_IV_SIZE,
                                       NULL,
                                       0,
                                       &encrypted_input->tag) != SGX_SUCCESS) {
            free(encrypted_input);
            SET_ERROR(FAASM_SGX_ENCRYPTION_FAILED);
            return 1;
        }
        encrypted_input->data_len = input_size;
        memcpy(encrypted_input->nonce, p_iv1, sizeof(encrypted_input->nonce));
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if ((it = faasm_sgx_tcs[tls_thread_id]->env.chain_policy->find(name)) ==
            faasm_sgx_tcs[tls_thread_id]->env.chain_policy->end()) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            free(encrypted_input);
            SET_ERROR(FAASM_SGX_CORRUPTED_CHAIN_POLICY);
            return 1;
        }
        if ((faasm_ret_val = create_total_execution_stack(
               &total_execution_stack,
               faasm_sgx_tcs[tls_thread_id]->env.entry_execution_stack,
               faasm_sgx_tcs[tls_thread_id]->env.execution_stack)) !=
            FAASM_SGX_SUCCESS) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            free(encrypted_input);
            SET_ERROR(faasm_ret_val);
            return 1;
        }
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        policy_len = sizeof(sgx_wamr_execution_policy_t) +
                     strlen(total_execution_stack) + 1;
        if ((policy = (sgx_wamr_execution_policy_t*)calloc(
               policy_len, sizeof(uint8_t))) == NULL) {
            free(encrypted_input);
            free_execution_stack(&total_execution_stack);
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        memcpy(policy->input_nonce, p_iv1, sizeof(policy->input_nonce));
        memcpy(policy->hash, it->second.c_str(), sizeof(policy->hash));
        memcpy(
          policy->data, total_execution_stack, strlen(total_execution_stack));
        free_execution_stack(&total_execution_stack);
        if (sgx_read_rand(p_iv, SGX_AESGCM_IV_SIZE) != SGX_SUCCESS) {
            free(encrypted_input);
            free(policy);
            SET_ERROR(FAASM_SGX_READ_RAND_FAILED);
            return 1;
        }
        encrypted_policy_len =
          sizeof(sgx_wamr_encrypted_data_blob_t) + policy_len;
        if ((encrypted_policy = (sgx_wamr_encrypted_data_blob_t*)calloc(
               encrypted_policy_len, sizeof(uint8_t))) == NULL) {
            free(encrypted_input);
            free(policy);
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        if (sgx_rijndael128GCM_encrypt(&master_secret,
                                       (uint8_t*)policy,
                                       policy_len,
                                       (uint8_t*)encrypted_policy->data,
                                       p_iv,
                                       SGX_AESGCM_IV_SIZE,
                                       NULL,
                                       0,
                                       &encrypted_policy->tag) != SGX_SUCCESS) {
            free(encrypted_input);
            free(policy);
            free(encrypted_policy);
            SET_ERROR(FAASM_SGX_ENCRYPTION_FAILED);
            return 1;
        }
        free(policy);
        encrypted_policy->data_len = policy_len;
        memcpy(encrypted_policy->nonce, p_iv, sizeof(encrypted_policy->nonce));
        if ((sgxReturnValue = ocall_faasm_chain_name(
               &returnValue,
               name,
               (uint8_t*)encrypted_input,
               input_size + sizeof(sgx_wamr_encrypted_data_blob_t),
               (uint8_t*)encrypted_policy,
               encrypted_policy_len)) != SGX_SUCCESS) {
            free(encrypted_policy);
            free(encrypted_input);
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
            return 1;
        }
        free(encrypted_policy);
        free(encrypted_input);
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        faasm_sgx_tcs[tls_thread_id]->env.nonce_store->insert(
          std::pair<const uint32_t, std::string>(
            returnValue, std::string(p_iv, p_iv + sizeof(p_iv))));
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        return returnValue;
    }

    static unsigned int faasm_chain_ptr_wrapper(wasm_exec_env_t exec_env,
                                                int wasmFuncPtr,
                                                const uint8_t* input_data,
                                                unsigned int input_size)
    {
        unsigned int returnValue;
        sgx_status_t sgxReturnValue;
        faasm_sgx_status_t faasm_ret_val;
        uint32_t policy_len, encrypted_policy_len;
        sgx_wamr_execution_policy_t* policy;
        char* total_execution_stack;
        sgx_wamr_encrypted_data_blob_t *encrypted_policy, *encrypted_input;
        faasm_sgx_nonce_t p_iv, p_iv1;
        if (sgx_read_rand(p_iv1, SGX_AESGCM_IV_SIZE) != SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_READ_RAND_FAILED);
            return 1;
        }
        if ((encrypted_input = (sgx_wamr_encrypted_data_blob_t*)calloc(
               input_size + sizeof(sgx_wamr_encrypted_data_blob_t),
               sizeof(uint8_t))) == NULL) {
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        if (sgx_rijndael128GCM_encrypt(&master_secret,
                                       input_data,
                                       input_size,
                                       encrypted_input->data,
                                       p_iv1,
                                       SGX_AESGCM_IV_SIZE,
                                       NULL,
                                       0,
                                       &encrypted_input->tag) != SGX_SUCCESS) {
            free(encrypted_input);
            SET_ERROR(FAASM_SGX_ENCRYPTION_FAILED);
            return 1;
        }
        encrypted_input->data_len = input_size;
        memcpy(encrypted_input->nonce, p_iv1, sizeof(encrypted_input->nonce));
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if ((faasm_ret_val = create_total_execution_stack(
               &total_execution_stack,
               faasm_sgx_tcs[tls_thread_id]->env.entry_execution_stack,
               faasm_sgx_tcs[tls_thread_id]->env.execution_stack)) !=
            FAASM_SGX_SUCCESS) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            free(encrypted_input);
            SET_ERROR(faasm_ret_val);
            return 1;
        }
        policy_len = sizeof(sgx_wamr_execution_policy_t) +
                     strlen(total_execution_stack) + 1;
        if ((policy = (sgx_wamr_execution_policy_t*)calloc(
               policy_len, sizeof(uint8_t))) == NULL) {
            free(encrypted_input);
            free_execution_stack(&total_execution_stack);
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        memcpy(policy->input_nonce, p_iv1, sizeof(policy->input_nonce));
        memcpy(policy->hash,
               faasm_sgx_tcs[tls_thread_id]->env.op_code_hash,
               sizeof(policy->hash));
        memcpy(
          policy->data, total_execution_stack, strlen(total_execution_stack));
        free_execution_stack(&total_execution_stack);
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        policy->fid = wasmFuncPtr;
        if (sgx_read_rand(p_iv, SGX_AESGCM_IV_SIZE) != SGX_SUCCESS) {
            free(encrypted_input);
            free(policy);
            SET_ERROR(FAASM_SGX_READ_RAND_FAILED);
            return 1;
        }
        encrypted_policy_len =
          sizeof(sgx_wamr_encrypted_data_blob_t) + policy_len;
        if ((encrypted_policy = (sgx_wamr_encrypted_data_blob_t*)calloc(
               encrypted_policy_len, sizeof(uint8_t))) == NULL) {
            free(encrypted_input);
            free(policy);
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        if (sgx_rijndael128GCM_encrypt(&master_secret,
                                       (uint8_t*)policy,
                                       policy_len,
                                       (uint8_t*)encrypted_policy->data,
                                       p_iv,
                                       SGX_AESGCM_IV_SIZE,
                                       NULL,
                                       0,
                                       &encrypted_policy->tag) != SGX_SUCCESS) {
            free(encrypted_input);
            free(policy);
            free(encrypted_policy);
            SET_ERROR(FAASM_SGX_ENCRYPTION_FAILED);
            return 1;
        }
        free(policy);
        encrypted_policy->data_len = policy_len;
        memcpy(encrypted_policy->nonce, p_iv, sizeof(encrypted_policy->nonce));
        if ((sgxReturnValue = ocall_faasm_chain_ptr(
               &returnValue,
               wasmFuncPtr,
               (uint8_t*)encrypted_input,
               sizeof(sgx_wamr_encrypted_data_blob_t) + input_size,
               (uint8_t*)encrypted_policy,
               encrypted_policy_len)) != SGX_SUCCESS) {
            free(encrypted_policy);
            free(encrypted_input);
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
            return 1;
        }
        free(encrypted_policy);
        free(encrypted_input);
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        faasm_sgx_tcs[tls_thread_id]->env.nonce_store->insert(
          std::pair<const uint32_t, std::string>(
            returnValue, std::string(p_iv, p_iv + sizeof(p_iv))));
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        return returnValue;
    }

    static unsigned int faasm_await_call_wrapper(wasm_exec_env_t exec_env,
                                                 unsigned int call_id)
    {
        sgx_status_t sgxReturnValue;
        unsigned int returnValue;
        std::map<const uint32_t, std::string>::iterator it;
        sgx_wamr_execution_attestation_t* decrypted_result;
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if ((it =
               faasm_sgx_tcs[tls_thread_id]->env.nonce_store->find(call_id)) ==
            faasm_sgx_tcs[tls_thread_id]->env.nonce_store->end()) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            SET_ERROR(FAASM_SGX_UNKNOWN_MSG_ID);
            return 1;
        }
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        if ((sgxReturnValue = ocall_faasm_await_call(&returnValue, call_id)) !=
            SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
            return 1;
        }
        uint8_t* raw_msg =
          (uint8_t*)faasm_sgx_tcs[tls_thread_id]->result_ptr->buffer_ptr;
        uint32_t msg_len = faasm_sgx_tcs[tls_thread_id]->result_ptr->buffer_len;
        if (msg_len < sizeof(sgx_wamr_encrypted_data_blob_t) +
                        sizeof(sgx_wamr_execution_attestation_t)) {
            SET_ERROR(FAASM_SGX_MISSING_RESULT);
            return 1;
        }
        sgx_wamr_encrypted_data_blob_t* msg =
          (sgx_wamr_encrypted_data_blob_t*)raw_msg;
        if ((decrypted_result = (sgx_wamr_execution_attestation_t*)calloc(
               msg->data_len, sizeof(uint8_t))) == NULL) {
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        if (sgx_rijndael128GCM_decrypt(
              (sgx_aes_gcm_128bit_key_t*)master_secret,
              msg->data,
              msg->data_len,
              (uint8_t*)decrypted_result,
              msg->nonce,
              SGX_AESGCM_IV_SIZE,
              NULL,
              0,
              (const sgx_aes_gcm_128bit_tag_t*)msg->tag) != SGX_SUCCESS) {
            free(decrypted_result);
            SET_ERROR(FAASM_SGX_DECRYPTION_FAILED);
            return 1;
        }
        if (memcmp(it->second.c_str(),
                   decrypted_result->policy_nonce,
                   SGX_AESGCM_IV_SIZE) != 0) {
            free(decrypted_result);
            SET_ERROR(FAASM_SGX_NONCE_ALREADY_SEEN);
            return 1;
        }
        if (returnValue != decrypted_result->return_value) {
            free(decrypted_result);
            SET_ERROR(FAASM_SGX_RETURN_VALUE_MISMATCH);
            return 1;
        }
        free(decrypted_result);
        return returnValue;
    }

    static unsigned int faasm_await_call_output_wrapper(
      wasm_exec_env_t exec_env,
      unsigned int call_id,
      uint8_t* buffer,
      unsigned int buffer_size)
    {
        sgx_status_t sgxReturnValue;
        unsigned int returnValue;
        std::map<const uint32_t, std::string>::iterator it;
        char* result_stack;
        sgx_wamr_execution_attestation_t* decrypted_result;
        faasm_sgx_status_t faasm_ret_val;
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if ((it =
               faasm_sgx_tcs[tls_thread_id]->env.nonce_store->find(call_id)) ==
            faasm_sgx_tcs[tls_thread_id]->env.nonce_store->end()) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            SET_ERROR(FAASM_SGX_UNKNOWN_MSG_ID);
            return 1;
        }
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);

        if ((sgxReturnValue = ocall_faasm_await_call_output(
               &returnValue, call_id)) != SGX_SUCCESS) {
            SET_ERROR(FAASM_SGX_OCALL_ERROR(sgxReturnValue));
            return 1;
        }
        sgx_wamr_encrypted_data_blob_t* output =
          (sgx_wamr_encrypted_data_blob_t*)faasm_sgx_tcs[tls_thread_id]
            ->output_ptr->buffer_ptr;
        uint8_t *result = (uint8_t*)faasm_sgx_tcs[tls_thread_id]
                            ->result_ptr->buffer_ptr,
                *decrypted_output;
        uint32_t result_len =
                   faasm_sgx_tcs[tls_thread_id]->result_ptr->buffer_len,
                 output_len =
                   faasm_sgx_tcs[tls_thread_id]->output_ptr->buffer_len;
        sgx_wamr_encrypted_data_blob_t* msg =
          (sgx_wamr_encrypted_data_blob_t*)result;
        if (result_len <= sizeof(sgx_wamr_encrypted_data_blob_t) +
                            sizeof(sgx_wamr_execution_attestation_t)) {
            SET_ERROR(FAASM_SGX_MISSING_RESULT);
            return 1;
        }
        if ((decrypted_result = (sgx_wamr_execution_attestation_t*)calloc(
               msg->data_len, sizeof(uint8_t))) == NULL) {
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        if (sgx_rijndael128GCM_decrypt(&master_secret,
                                       msg->data,
                                       msg->data_len,
                                       (uint8_t*)decrypted_result,
                                       msg->nonce,
                                       SGX_AESGCM_IV_SIZE,
                                       NULL,
                                       0,
                                       &msg->tag) != SGX_SUCCESS) {
            free(decrypted_result);
            SET_ERROR(FAASM_SGX_DECRYPTION_FAILED);
            return 1;
        }
        if (memcmp(it->second.c_str(),
                   decrypted_result->policy_nonce,
                   SGX_AESGCM_IV_SIZE) != 0) {
            free(decrypted_result);
            SET_ERROR(FAASM_SGX_NONCE_ALREADY_SEEN);
            return 1;
        }
        if (returnValue != decrypted_result->return_value) {
            free(decrypted_result);
            SET_ERROR(FAASM_SGX_RETURN_VALUE_MISMATCH);
            return 1;
        }
        if (memcmp(output->nonce,
                   decrypted_result->output_nonce,
                   sizeof(decrypted_result->output_nonce)) != 0) {
            SET_ERROR(FAASM_SGX_RESULT_OUTPUT_MISLINK);
            return 1;
        }
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if ((result_stack =
               (char*)calloc(decrypted_result->execution_stack_len + 1,
                             sizeof(uint8_t))) == NULL) {
            free(decrypted_result);
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        memcpy(result_stack,
               decrypted_result->data,
               decrypted_result->execution_stack_len);
        if ((faasm_ret_val = push_to_execution_stack(
               &faasm_sgx_tcs[tls_thread_id]->env.execution_stack,
               result_stack)) != FAASM_SGX_SUCCESS) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            free(decrypted_result);
            free(result_stack);
            SET_ERROR(faasm_ret_val);
            return 1;
        }
        free(result_stack);
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        free(decrypted_result);
        if ((decrypted_output =
               (uint8_t*)calloc(output->data_len, sizeof(uint8_t))) == NULL) {
            SET_ERROR(FAASM_SGX_OUT_OF_MEMORY);
            return 1;
        }
        if (sgx_rijndael128GCM_decrypt(&master_secret,
                                       output->data,
                                       output->data_len,
                                       decrypted_output,
                                       output->nonce,
                                       SGX_AESGCM_IV_SIZE,
                                       NULL,
                                       0,
                                       &output->tag) != SGX_SUCCESS) {
            free(decrypted_output);
            SET_ERROR(FAASM_SGX_DECRYPTION_FAILED);
            return 1;
        }
        if (buffer_size > output_len) {
            memcpy(buffer, decrypted_output, output_len);
        } else {
            memcpy(buffer, decrypted_output, buffer_size);
        }
        free(decrypted_output);
        return returnValue;
    }

    // ------------------------------
    // WHITELISTING
    // ------------------------------

#if (FAASM_SGX_WHITELISTING)
    void sgx_wamr_function_not_whitelisted_wrapper(wasm_exec_env_t exec_env)
    {
        SET_ERROR(FAASM_SGX_FUNCTION_NOT_WHITELISTED);
    }
#endif

    // ------------------------------
    // WASI default wrapper
    // ------------------------------

    static int args_get_wrapper(wasm_exec_env_t exec_env, int a, int b)
    {
        return 0;
    }

    static int args_sizes_get_wrapper(wasm_exec_env_t exec_env, int a, int b)
    {
        return 0;
    }

    static int fd_close_wrapper(wasm_exec_env_t exec_env, int a) { return 0; }

    static int fd_seek_wrapper(wasm_exec_env_t exec_env,
                               int a,
                               int64 b,
                               int c,
                               int d)
    {
        return 0;
    }

    static int fd_write_wrapper(wasm_exec_env_t exec_env,
                                int a,
                                int b,
                                int c,
                                int d)
    {
        return 0;
    }

    static void proc_exit_wrapper(wasm_exec_env_t exec_env, int returnCode) {}

    NativeSymbol faasm_sgx_native_symbols[FAASM_SGX_NATIVE_SYMBOLS_LEN] = {
        NATIVE_FUNC(faasm_read_input, "($i)i"),
        NATIVE_FUNC(faasm_write_output, "($i)"),
        NATIVE_FUNC(faasm_read_state, "($$i)i"),
        // NATIVE_FUNC(faasm_read_state_size, "($)i"),
        NATIVE_FUNC(faasm_read_state_offset, "($ii$i)i"),
        NATIVE_FUNC(faasm_write_state, "($$i)"),
        NATIVE_FUNC(faasm_write_state_offset, "($ii$i)"),
        NATIVE_FUNC(faasm_push_state, "($)"),
        NATIVE_FUNC(faasm_push_state_partial, "($)"),
        NATIVE_FUNC(faasm_push_state_partial_mask, "($$)"),
        NATIVE_FUNC(faasm_pull_state, "($i)"),
        NATIVE_FUNC(faasm_lock_state_global, "($)"),
        NATIVE_FUNC(faasm_unlock_state_global, "($)"),
        NATIVE_FUNC(faasm_lock_state_read, "($)"),
        NATIVE_FUNC(faasm_unlock_state_read, "($)"),
        NATIVE_FUNC(faasm_lock_state_write, "($)"),
        NATIVE_FUNC(faasm_unlock_state_write, "($)"),
        NATIVE_FUNC(faasm_append_state, "($$i)"),
        NATIVE_FUNC(faasm_read_appended_state, "($$ii)"),
        NATIVE_FUNC(faasm_clear_appended_state, "($)"),
        NATIVE_FUNC(faasm_flag_state_dirty, "($i)"),
        NATIVE_FUNC(faasm_flag_state_offset_dirty, "($iii)"),
        NATIVE_FUNC(faasm_chain_name, "($$i)i"),
        NATIVE_FUNC(faasm_chain_ptr, "(*$i)i"),
        NATIVE_FUNC(faasm_await_call, "(i)i"),
        NATIVE_FUNC(faasm_await_call_output, "(i)i")
    };

    NativeSymbol faasm_sgx_wasi_symbols[FAASM_SGX_WASI_SYMBOLS_LEN] = {
        WASI_NATIVE_FUNC(args_get, "(ii)i"),
        WASI_NATIVE_FUNC(args_sizes_get, "(ii)i"),
        WASI_NATIVE_FUNC(fd_close, "(i)i"),
        WASI_NATIVE_FUNC(fd_seek, "(iIii)i"),
        WASI_NATIVE_FUNC(fd_write, "(iiii)i"),
        WASI_NATIVE_FUNC(proc_exit, "(i)")
    };
}
