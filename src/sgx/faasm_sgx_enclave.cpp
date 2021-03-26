#include "sgx/faasm_sgx_enclave_types.h"
#include "sgx/faasm_sgx_error.h"
#include "sgx/faasm_sgx_native_symbols_wrapper.h"
#include "sgx/rw_lock.h"

#include <iwasm/include/wasm_export.h>
#include <libcxx/cstdlib>
#include <sgx.h>
#include <sgx/faasm_sgx_util.h>
#include <sgx_defs.h>
#include <sgx_thread.h>
#include <sgx_tkey_exchange.h>
#include <tlibc/mbusafecrt.h>

#if (FAASM_SGX_WAMR_AOT_MODE)
#include <iwasm/aot/aot_runtime.h>
#else
#include <iwasm/interpreter/wasm_runtime.h>
#endif

#include <sgx/faasm_sgx_attestation.h>
#include <sgx_tkey_exchange.h>
#include <sgx_trts.h>

#define WASM_CTORS_FUNC_NAME "__wasm_call_ctors"
#define WASM_ENTRY_FUNC "_start"

extern "C"
{

#if (FAASM_SGX_DEBUG)
    // Print functions
    typedef void (*os_print_function_t)(const char* msg);
    extern void os_set_print_function(os_print_function_t pf);
    extern sgx_status_t SGX_CDECL ocall_printf(const char* msg);
    extern int os_printf(const char* message, ...);
#endif

    // WAMR native symbols
    extern NativeSymbol faasm_sgx_native_symbols[FAASM_SGX_NATIVE_SYMBOLS_LEN];
    extern NativeSymbol faasm_sgx_wasi_symbols[FAASM_SGX_WASI_SYMBOLS_LEN];

#define INCREMENT_MSG_ID() __sync_fetch_and_add(&_sgx_wamr_msg_id, 1)
    extern sgx_status_t SGX_CDECL
    ocall_init_crt(faasm_sgx_status_t* returnValue);
    extern sgx_status_t SGX_CDECL
    ocall_attest_to_km(faasm_sgx_status_t* returnValue);
    extern sgx_status_t SGX_CDECL
    ocall_send_msg(faasm_sgx_status_t* returnValue,
                   sgx_wamr_msg_t* msg,
                   uint32_t msg_len);
    extern sgx_status_t SGX_CDECL
    ocall_set_result(faasm_sgx_status_t* returnValue,
                     uint8_t* msg,
                     uint32_t msg_len);
    static uint8_t _sgx_wamr_msg_id = 0;
    static sgx_ra_key_128_t shared_secret;
    sgx_aes_gcm_128bit_key_t master_secret;
    static sgx_ra_context_t* inner_ctx;
    static const sgx_ec256_public_t key = {
        { 0xdc, 0xbd, 0x32, 0x2e, 0x8d, 0x46, 0xa9, 0xeb, 0xdf, 0xdd, 0x64,
          0x4,  0x1b, 0x80, 0xde, 0x22, 0xb2, 0x14, 0x2,  0x2e, 0x6a, 0xf6,
          0xab, 0xe0, 0xdc, 0x5e, 0x8,  0xb0, 0xdd, 0x12, 0x96, 0x15 },
        {
          0x2,  0x83, 0x71, 0xd0, 0x80, 0x72, 0xc8, 0x8f, 0xd3, 0x9a, 0x73,
          0x5f, 0x75, 0x33, 0xbc, 0x6f, 0x1b, 0x52, 0xc2, 0x62, 0x36, 0x1b,
          0x3f, 0x2f, 0x28, 0x6d, 0x6d, 0xc,  0x4d, 0x87, 0x24, 0x2f,
        }
    };
    __thread uint32_t tls_thread_id;
    rwlock_t _rwlock_faasm_sgx_tcs_realloc = { 0 };

    _faasm_sgx_tcs_t** faasm_sgx_tcs = NULL;
    static uint32_t _faasm_sgx_tcs_len;
    static sgx_thread_mutex_t _mutex_faasm_sgx_tcs =
      SGX_THREAD_MUTEX_INITIALIZER;

    static uint8_t _wamr_global_heap_buffer[FAASM_SGX_WAMR_HEAP_SIZE * 1024];

    static inline faasm_sgx_status_t __get_response_msg(
      const uint32_t thread_id,
      sgx_wamr_msg_t** response_ptr)
    {
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        *response_ptr = *faasm_sgx_tcs[thread_id]->response_ptr;
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        return FAASM_SGX_SUCCESS;
    }

    static faasm_sgx_status_t recv_msg(uint32_t thread_id,
                                       void** payload_ptr,
                                       uint32_t* payload_len)
    {
        // Check error conditions
        // TODO: Maybe replace thread_id with __thread
        if (thread_id >= _faasm_sgx_tcs_len) {
            return FAASM_SGX_INVALID_THREAD_ID;
        }

        if (!payload_ptr || !payload_len) {
            return FAASM_SGX_INVALID_PTR;
        }

        faasm_sgx_status_t returnValue;
        sgx_wamr_msg_t* response_ptr;

        if ((returnValue = __get_response_msg(thread_id, &response_ptr)) !=
            FAASM_SGX_SUCCESS) {
            return returnValue;
        }

        ///////////ENCRYPTION///////////
        // TODO - implement encryption
        ///////////ENCRYPTION///////////
        *payload_ptr = (void*)response_ptr->payload;
        *payload_len = response_ptr->payload_len;
        return FAASM_SGX_SUCCESS;
    }

    static faasm_sgx_status_t send_msg(const void* payload_ptr,
                                       const uint32_t payload_len)
    {
        sgx_wamr_msg_t* msg_ptr;
        sgx_status_t sgxReturnValue;
        faasm_sgx_status_t returnValue;

        if (!payload_ptr) {
            return FAASM_SGX_INVALID_PTR;
        }

        if (!payload_len) {
            return FAASM_SGX_INVALID_PAYLOAD_LEN;
        }

        if (!(msg_ptr = (sgx_wamr_msg_t*)calloc(
                (sizeof(sgx_wamr_msg_t) + payload_len), sizeof(uint8_t)))) {

#if (FAASM_SGX_DEBUG)
            ocall_printf("Enclave send_msg failed, OOM\n");
#endif

            return FAASM_SGX_OUT_OF_MEMORY;
        }

        msg_ptr->msg_id = INCREMENT_MSG_ID();

        ///////////ENCRYPTION///////////
        // TODO - implement encryption
        ///////////ENCRYPTION///////////

        ///////////REMOVE IF ENCRYPTION WORKS///////////
        msg_ptr->payload_len = payload_len;
        memcpy(((uint8_t*)msg_ptr->payload), payload_ptr, payload_len);
        ///////////REMOVE IF ENCRYPTION WORKS///////////

        if ((sgxReturnValue = ocall_send_msg(
               &returnValue,
               msg_ptr,
               sizeof(sgx_wamr_msg_t) + msg_ptr->payload_len)) != SGX_SUCCESS) {
            free(msg_ptr);
            return FAASM_SGX_OCALL_ERROR(sgxReturnValue);
        }

        free(msg_ptr);
        return returnValue;
    }

    faasm_sgx_status_t send_recv_msg(uint32_t thread_id,
                                     const void* send_payload_ptr,
                                     const uint32_t send_payload_len,
                                     void** recv_payload_ptr,
                                     uint32_t* recv_payload_len)
    {
        sgx_wamr_msg_t* msg_ptr;
        sgx_status_t sgx_ret_val;
        faasm_sgx_status_t ret_val;
        faasm_sgx_nonce_t p_iv;
        sgx_wamr_msg_t* response_ptr;
        uint8_t* decrypted_payload;
        sgx_wamr_msg_nonce_payload* nonce_payload;
        uint8_t* result;
        if (thread_id >= _faasm_sgx_tcs_len)
            return FAASM_SGX_INVALID_THREAD_ID;
        if (!recv_payload_ptr || !recv_payload_len)
            return FAASM_SGX_INVALID_PTR;
        if (!send_payload_ptr)
            return FAASM_SGX_INVALID_PTR;
        if (!send_payload_len)
            return FAASM_SGX_INVALID_PAYLOAD_LEN;
        if (!(msg_ptr = (sgx_wamr_msg_t*)calloc(
                (sizeof(sgx_wamr_msg_t) + send_payload_len),
                sizeof(uint8_t)))) {
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        msg_ptr->msg_id = INCREMENT_MSG_ID();
        if (sgx_read_rand(p_iv, SGX_AESGCM_IV_SIZE) != SGX_SUCCESS) {
            free(msg_ptr);
            return FAASM_SGX_READ_RAND_FAILED;
        }
        if (sgx_rijndael128GCM_encrypt(
              (sgx_aes_gcm_128bit_key_t*)&shared_secret,
              (uint8_t*)send_payload_ptr,
              send_payload_len,
              msg_ptr->payload,
              p_iv,
              SGX_AESGCM_IV_SIZE,
              NULL,
              0,
              (sgx_aes_gcm_128bit_tag_t*)msg_ptr->mac) != SGX_SUCCESS) {
            free(msg_ptr);
            return FAASM_SGX_ENCRYPTION_FAILED;
        }
        memcpy(msg_ptr->nonce, p_iv, sizeof(msg_ptr->nonce));
        msg_ptr->payload_len = send_payload_len;
        if ((sgx_ret_val = ocall_send_msg(
               &ret_val,
               msg_ptr,
               sizeof(sgx_wamr_msg_t) + msg_ptr->payload_len)) != SGX_SUCCESS) {
            free(msg_ptr);
            return FAASM_SGX_OCALL_ERROR(sgx_ret_val);
        }
        free(msg_ptr);
        if ((ret_val = __get_response_msg(thread_id, &response_ptr)) !=
            FAASM_SGX_SUCCESS)
            return ret_val;
        if ((decrypted_payload = (uint8_t*)calloc(response_ptr->payload_len,
                                                  sizeof(uint8_t))) == NULL) {
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        // read_unlock(&_rwlock_faasm_sgx_tcs_realloc); //TODO removed this
        // unlock, cannot find where this is locked first
        if (sgx_rijndael128GCM_decrypt(
              (sgx_aes_gcm_128bit_key_t*)&shared_secret,
              (uint8_t*)response_ptr->payload,
              response_ptr->payload_len,
              decrypted_payload,
              response_ptr->nonce,
              sizeof(response_ptr->nonce),
              NULL,
              0,
              (const sgx_aes_gcm_128bit_tag_t*)response_ptr->mac) !=
            SGX_SUCCESS) {
            free(decrypted_payload);
            return FAASM_SGX_DECRYPTION_FAILED;
        }
        nonce_payload = (sgx_wamr_msg_nonce_payload*)decrypted_payload;
        if (memcmp((uint8_t*)&p_iv,
                   (uint8_t*)nonce_payload->nonce,
                   sizeof(faasm_sgx_nonce_t)) != 0) {
            return FAASM_SGX_NONCE_MISMATCH;
        }
        if ((result = (uint8_t*)calloc(response_ptr->payload_len -
                                         sizeof(sgx_wamr_msg_nonce_payload),
                                       sizeof(uint8_t))) == NULL) {
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        memcpy(result,
               nonce_payload->payload,
               response_ptr->payload_len - sizeof(sgx_wamr_msg_nonce_payload));
        free(decrypted_payload);
        *recv_payload_ptr = result;
        *recv_payload_len =
          response_ptr->payload_len - sizeof(sgx_wamr_msg_nonce_payload);
        return FAASM_SGX_SUCCESS;
    }

    static __attribute__((always_inline)) faasm_sgx_status_t __get_tcs_slot(
      uint32_t* thread_id)
    {
        _faasm_sgx_tcs_t** temp_ptr;
        uint32_t temp_len, i = 0;
        sgx_thread_mutex_lock(&_mutex_faasm_sgx_tcs);

        // Search for an unused TCS slot
        for (; i < _faasm_sgx_tcs_len; i++) {
            if (!faasm_sgx_tcs[i]) {
                goto _FAASM_SGX_TCS_BLOCK_SLOT_AND_ALLOCATE_MEMORY;
            }
        }

        // In case that all TCS slots are in use, the existing TCS structure
        // will be dynamically extended
        temp_len = (_faasm_sgx_tcs_len << 1);
        write_lock(&_rwlock_faasm_sgx_tcs_realloc);

        if (!(temp_ptr = (_faasm_sgx_tcs_t**)realloc(
                faasm_sgx_tcs, (temp_len * sizeof(_faasm_sgx_tcs_t*))))) {
            // Revert all changes due to an memory-error
            write_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            sgx_thread_mutex_unlock(&_mutex_faasm_sgx_tcs);
#if (FAASM_SGX_DEBUG)
            ocall_printf("OOM on get TCS slot\n");
#endif
            return FAASM_SGX_OUT_OF_MEMORY;
        }

        /* Have to zero out new memory because realloc can refer to already used
           memory, hence faasm_sgx_tcs[X].module might not be zero */
        memset((void*)(temp_ptr + _faasm_sgx_tcs_len),
               0x0,
               (temp_len - _faasm_sgx_tcs_len) * sizeof(_faasm_sgx_tcs_t*));

        // Update faasm_sgx_tcs ptr & len
        faasm_sgx_tcs = temp_ptr;
        write_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        _faasm_sgx_tcs_len = temp_len;

    // Block Faasm-SGX TCS slot and reserve memory for Faasm-SGX TCS structure
    _FAASM_SGX_TCS_BLOCK_SLOT_AND_ALLOCATE_MEMORY:
        faasm_sgx_tcs[i] = _FAASM_SGX_TCS_SLOT_IN_USE;
        sgx_thread_mutex_unlock(&_mutex_faasm_sgx_tcs);
        if (!(faasm_sgx_tcs[i] = (_faasm_sgx_tcs_t*)calloc(
                sizeof(_faasm_sgx_tcs_t), sizeof(uint8_t)))) {
#if (FAASM_SGX_DEBUG)
            ocall_printf("OOM on allocate TCS structure\n");
#endif
            return FAASM_SGX_OUT_OF_MEMORY;
        }

        *thread_id = i;
        return FAASM_SGX_SUCCESS;
    }

    faasm_sgx_status_t faasm_sgx_enclave_call_function(
      const uint32_t thread_id,
      const uint32_t func_ptr,
      const char* sid,
      const sgx_wamr_encrypted_data_blob_t* input,
      uint32_t payload_len,
      const uint8_t* raw_encrypted_policy,
      uint32_t raw_encrypted_policy_len)
    {
        faasm_sgx_status_t ret_val;
        sgx_status_t sgx_ret_val;

        // Check if thread_id is in range
        if (thread_id >= _faasm_sgx_tcs_len) {
            return FAASM_SGX_INVALID_THREAD_ID;
        }

        // Get Faasm-SGX TCS slot using thread_id
        _FAASM_SGX_TCS_LOAD_SLOT(tcs_ptr, thread_id);

        // Get function to execute
        WASMFunctionInstanceCommon* wasm_func;
        if (func_ptr == 0) {
            if (!(wasm_func = wasm_runtime_lookup_function(
                    tcs_ptr->module_inst, WASM_ENTRY_FUNC, NULL))) {
            }

        } else {
            // Lookup by function pointer not supported in SGX yet
            return FAASM_SGX_INVALID_FUNC_ID;
        }
        // Set thread_id to fs/gs to make it accessible in native symbols
        // wrapper
        tls_thread_id = thread_id;
        // == START decrypt the payload ==
        uint8_t* decrypted_payload;
        if (strlen(sid) == FAASM_SGX_ATTESTATION_SID_SIZE) {
            uint32_t res_payload_len;
            sgx_wamr_hash_sid_t msg_payload;
            void* res_payload;
            sgx_wamr_msg_hdr_t header;
            sgx_wamr_payload_key_t* typed_res_payload;
            if (payload_len == 0) {
                return FAASM_SGX_EMPTY_PAYLOAD;
            }
            if (func_ptr != 0) {
                return FAASM_SGX_PROTOCOL_LOADED_FUNCTION_MISMATCH;
            }
            msg_payload.hdr.status = FAASM_SGX_ATTESTATION_STATUS_SUCCESS;
            msg_payload.hdr.type = FAASM_SGX_ATTESTATION_TYPE_CALL;
            read_lock(&_rwlock_faasm_sgx_tcs_realloc);
            memcpy(msg_payload.opcode_enc_hash,
                   faasm_sgx_tcs[thread_id]->env.encrypted_op_code_hash,
                   sizeof(msg_payload.opcode_enc_hash));
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            memcpy(msg_payload.session_id, sid, sizeof(msg_payload.session_id));
            memcpy(msg_payload.payload_nonce,
                   input->nonce,
                   sizeof(msg_payload.payload_nonce));
            if ((ret_val = send_recv_msg(thread_id,
                                         &msg_payload,
                                         sizeof(sgx_wamr_hash_sid_t),
                                         &res_payload,
                                         &res_payload_len)) !=
                FAASM_SGX_SUCCESS) {
                return ret_val;
            }
            header = *((sgx_wamr_msg_hdr_t*)res_payload);
            if (header.status) {
                return FAASM_SGX_PROTOCOL_FAASLET_ATTESTATION_FAILED;
            }
            typed_res_payload = (sgx_wamr_payload_key_t*)res_payload;
            read_lock(&_rwlock_faasm_sgx_tcs_realloc);
            memcpy(faasm_sgx_tcs[thread_id]->env.payload_secret,
                   typed_res_payload->payload_key,
                   sizeof(faasm_sgx_tcs[thread_id]->env.payload_secret));
            free(res_payload);
            memcpy(faasm_sgx_tcs[thread_id]->env.policy_nonce,
                   input->nonce,
                   sizeof(faasm_sgx_tcs[thread_id]->env.policy_nonce));
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        } else if (raw_encrypted_policy_len >=
                   sizeof(sgx_wamr_encrypted_data_blob_t) +
                     sizeof(sgx_wamr_execution_policy_t)) {
            uint32_t res_payload_len, entry_stack_len;
            sgx_wamr_msg_nonce_offer_t msg_payload;
            void* res_payload;
            sgx_wamr_msg_hdr_t header;
            sgx_wamr_execution_policy_t* policy;
            sgx_wamr_encrypted_data_blob_t* encrypted_policy;
            char* entry_stack;
            msg_payload.hdr.type = FAASM_SGX_ATTESTATION_TYPE_NONCE;
            memcpy(msg_payload.nonce, input->nonce, sizeof(msg_payload.nonce));
            if ((ret_val = send_recv_msg(thread_id,
                                         &msg_payload,
                                         sizeof(sgx_wamr_msg_nonce_offer_t),
                                         &res_payload,
                                         &res_payload_len)) !=
                FAASM_SGX_SUCCESS) {
                return ret_val;
            }
            header = *((sgx_wamr_msg_hdr_t*)res_payload);
            if (header.status) {
                free(res_payload);
                return FAASM_SGX_PROTOCOL_FAASLET_ATTESTATION_FAILED;
            }
            free(res_payload);
            encrypted_policy =
              (sgx_wamr_encrypted_data_blob_t*)raw_encrypted_policy;
            if ((policy = (sgx_wamr_execution_policy_t*)calloc(
                   encrypted_policy->data_len, sizeof(uint8_t))) == NULL) {
                return FAASM_SGX_OUT_OF_MEMORY;
            }
            if (sgx_rijndael128GCM_decrypt(&master_secret,
                                           encrypted_policy->data,
                                           encrypted_policy->data_len,
                                           (uint8_t*)policy,
                                           encrypted_policy->nonce,
                                           SGX_AESGCM_IV_SIZE,
                                           NULL,
                                           0,
                                           &encrypted_policy->tag) !=
                SGX_SUCCESS) {
                free(policy);
                return FAASM_SGX_DECRYPTION_FAILED;
            }
            read_lock(&_rwlock_faasm_sgx_tcs_realloc);
            if (memcmp((uint8_t*)policy->hash,
                       (uint8_t*)&faasm_sgx_tcs[thread_id]->env.op_code_hash,
                       sizeof(policy->hash)) != 0) {
                read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
                free(policy);
                return FAASM_SGX_CHAIN_POLICY_HASH_MISMATCH;
            }
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            if (memcmp(policy->input_nonce,
                       input->nonce,
                       sizeof(policy->input_nonce)) != 0) {
                free(policy);
                return FAASM_SGX_INVALID_INPUT_NONCE;
            }
            /* TODO removed because no function id
            if (policy->fid != func_id) {
                free(policy);
                return FAASM_SGX_CHAIN_POLICY_FUNCID_MISMATCH;
            }*/
            read_lock(&_rwlock_faasm_sgx_tcs_realloc);
            memcpy(faasm_sgx_tcs[thread_id]->env.policy_nonce,
                   encrypted_policy->nonce,
                   sizeof(faasm_sgx_tcs[thread_id]->env.policy_nonce));
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            entry_stack_len =
              encrypted_policy->data_len - sizeof(sgx_wamr_execution_policy_t);
            if ((entry_stack =
                   (char*)calloc(entry_stack_len + 1, sizeof(char))) == NULL) {
                free(policy);
                return FAASM_SGX_OUT_OF_MEMORY;
            }
            memcpy(entry_stack, policy->data, entry_stack_len);
            free(policy);
            read_lock(&_rwlock_faasm_sgx_tcs_realloc);
            faasm_sgx_tcs[thread_id]->env.entry_execution_stack = entry_stack;
            memcpy(faasm_sgx_tcs[thread_id]->env.payload_secret,
                   master_secret,
                   sizeof(faasm_sgx_tcs[thread_id]->env.payload_secret));
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        } else
            return FAASM_SGX_UNKNOWN_EXECUTION_TYPE;
        if ((decrypted_payload =
               (uint8_t*)calloc(input->data_len, sizeof(uint8_t))) == NULL)
            return FAASM_SGX_OUT_OF_MEMORY;
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if (payload_len > 0) {
            if (sgx_rijndael128GCM_decrypt(
                  (sgx_aes_gcm_128bit_key_t*)faasm_sgx_tcs[thread_id]
                    ->env.payload_secret,
                  input->data,
                  input->data_len,
                  decrypted_payload,
                  input->nonce,
                  SGX_AESGCM_IV_SIZE,
                  NULL,
                  0,
                  (const sgx_aes_gcm_128bit_tag_t*)input->tag) != SGX_SUCCESS) {
                read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
                free(decrypted_payload);
                return FAASM_SGX_DECRYPTION_FAILED;
            }
        }
        if ((ret_val = initialize_execution_stack(
               &faasm_sgx_tcs[thread_id]->env.execution_stack, func_ptr)) !=
            FAASM_SGX_SUCCESS) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            return ret_val;
        }
        faasm_sgx_tcs[thread_id]->env.payload_len = input->data_len;
        faasm_sgx_tcs[thread_id]->env.payload = decrypted_payload;
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        // == END decrypt the payload ==

        // Create an execution environment and call the wasm function
#if (FAASM_SGX_WAMR_AOT_MODE)
        // If AoT is enabled, then the WAMR AoT implementation will be invoked
#if (FAASM_SGX_DEBUG)
        ocall_printf("Faasm-SGX: AoT\n");
#endif
        if (!(aot_create_exec_env_and_call_function(
              (AOTModuleInstance*)tcs_ptr->module_inst,
              (AOTFunctionInstance*)wasm_func,
              0x0,
              0x0))) {

            /* Error handling
             * First, check if the _FAASM_SGX_ERROR_PREFIX is set
             * If so, then obtain and return the faasm_sgx_status_t error code
             * If not, just print the exception and return the matching
             * Faasm-SGX error code
             */
            if (!memcmp(
                  ((AOTModuleInstance*)tcs_ptr->module_inst)->cur_exception,
                  _FAASM_SGX_ERROR_PREFIX,
                  sizeof(_FAASM_SGX_ERROR_PREFIX))) {

                return *((faasm_sgx_status_t*)&(
                  ((AOTModuleInstance*)tcs_ptr->module_inst)
                    ->cur_exception[sizeof(_FAASM_SGX_ERROR_PREFIX)]));
            }

#if (FAASM_SGX_DEBUG)
            ocall_printf(
              ((AOTModuleInstance*)tcs_ptr->module_inst)->cur_exception);
#endif
            return FAASM_SGX_WAMR_FUNCTION_UNABLE_TO_CALL;
        }
#else
        // If AoT is disabled, then the WAMR interpreter will be invoked
#if (FAASM_SGX_DEBUG)
        ocall_printf("Faasm-SGX: Interpreter\n");
#endif
        if (!(wasm_create_exec_env_and_call_function(
              (WASMModuleInstance*)tcs_ptr->module_inst,
              (WASMFunctionInstance*)wasm_func,
              0x0,
              0x0))) {

            /* Error handling
             * First, check if the _FAASM_SGX_ERROR_PREFIX is set
             * If so, then obtain and return the faasm_sgx_status_t error code
             * If not, just print the exception and return the matching
             * Faasm-SGX error code
             */
            if (!memcmp(
                  ((WASMModuleInstance*)tcs_ptr->module_inst)->cur_exception,
                  _FAASM_SGX_ERROR_PREFIX,
                  sizeof(_FAASM_SGX_ERROR_PREFIX))) {

                return *((faasm_sgx_status_t*)&(
                  ((WASMModuleInstance*)tcs_ptr->module_inst)
                    ->cur_exception[sizeof(_FAASM_SGX_ERROR_PREFIX)]));
            }

#if (FAASM_SGX_DEBUG)
            ocall_printf(
              ((WASMModuleInstance*)tcs_ptr->module_inst)->cur_exception);
#endif
            return FAASM_SGX_WAMR_FUNCTION_UNABLE_TO_CALL;
        }
#endif
        // START prepare result
        sgx_wamr_execution_attestation_t* result;
        uint32_t result_len, data_len;
        faasm_sgx_nonce_t p_iv;
        sgx_wamr_encrypted_data_blob_t* data;
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if ((ret_val = finish_execution_stack(
               &faasm_sgx_tcs[thread_id]->env.execution_stack)) !=
            FAASM_SGX_SUCCESS) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            return ret_val;
        }
        result_len = sizeof(sgx_wamr_execution_attestation_t) +
                     strlen(faasm_sgx_tcs[thread_id]->env.execution_stack);
        if ((result = (sgx_wamr_execution_attestation_t*)calloc(
               result_len, sizeof(uint8_t))) == NULL) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        memcpy(result->data,
               faasm_sgx_tcs[thread_id]->env.execution_stack,
               strlen(faasm_sgx_tcs[thread_id]->env.execution_stack));
        result->execution_stack_len =
          strlen(faasm_sgx_tcs[thread_id]->env.execution_stack);
        memcpy(result->output_nonce,
               faasm_sgx_tcs[thread_id]->env.output_nonce,
               sizeof(result->output_nonce));
        memcpy(result->policy_nonce,
               faasm_sgx_tcs[thread_id]->env.policy_nonce,
               sizeof(result->policy_nonce));
        if (sgx_read_rand(p_iv, SGX_AESGCM_IV_SIZE) != SGX_SUCCESS) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            free(result);
            return FAASM_SGX_READ_RAND_FAILED;
        }
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        data_len = sizeof(sgx_wamr_encrypted_data_blob_t) + result_len;
        if ((data = (sgx_wamr_encrypted_data_blob_t*)calloc(
               data_len, sizeof(uint8_t))) == NULL) {
            free(result);
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if (sgx_rijndael128GCM_encrypt(
              (sgx_aes_gcm_128bit_key_t*)faasm_sgx_tcs[thread_id]
                ->env.payload_secret,
              (uint8_t*)result,
              result_len,
              data->data,
              p_iv,
              sizeof(p_iv),
              NULL,
              0,
              (sgx_aes_gcm_128bit_tag_t*)data->tag) != SGX_SUCCESS) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            free(result);
            free(data);
            return FAASM_SGX_ENCRYPTION_FAILED;
        }
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        free(result);
        memcpy(data->nonce, p_iv, sizeof(data->nonce));
        data->data_len = result_len;
        if ((sgx_ret_val = ocall_set_result(
               &ret_val, (uint8_t*)data, data_len)) != SGX_SUCCESS) {
            free(data);
            return FAASM_SGX_OCALL_ERROR(sgx_ret_val);
        }
        free(data);
        if (ret_val != FAASM_SGX_SUCCESS) {
            return ret_val;
        }
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        free_execution_stack(&faasm_sgx_tcs[thread_id]->env.execution_stack);
        free_execution_stack(
          &faasm_sgx_tcs[thread_id]->env.entry_execution_stack);
        memset(faasm_sgx_tcs[thread_id]->env.payload_secret,
               0,
               sizeof(faasm_sgx_tcs[thread_id]->env.payload_secret));
        memset(faasm_sgx_tcs[thread_id]->env.output_nonce,
               0,
               sizeof(faasm_sgx_tcs[thread_id]->env.output_nonce));
        memset(faasm_sgx_tcs[thread_id]->env.policy_nonce,
               0,
               sizeof(faasm_sgx_tcs[thread_id]->env.policy_nonce));
        if (faasm_sgx_tcs[thread_id]->env.payload_len != 0) {
            free(faasm_sgx_tcs[thread_id]->env.payload);
            faasm_sgx_tcs[thread_id]->env.payload_len = 0;
        }
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        // END prepare result

        return FAASM_SGX_SUCCESS;
    }

    faasm_sgx_status_t faasm_sgx_enclave_unload_module(const uint32_t thread_id)
    {
        // Important possibility check before unloading a module
        if (thread_id >= _faasm_sgx_tcs_len) {
            return FAASM_SGX_INVALID_THREAD_ID;
        }

        // Check if the linked module is already unloaded
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if (faasm_sgx_tcs[thread_id] == _FAASM_SGX_TCS_SLOT_FREE) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            return FAASM_SGX_MODULE_NOT_LOADED;
        }

        _faasm_sgx_tcs_t* tcs_ptr = faasm_sgx_tcs[thread_id];
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);

        // Unload the module and release the TCS slot
        wasm_runtime_unload(tcs_ptr->module);
        wasm_runtime_deinstantiate(tcs_ptr->module_inst);
        free(tcs_ptr->wasm_opcode);
        _FAASM_SGX_TCS_FREE_SLOT(thread_id);
        free(tcs_ptr);

        return FAASM_SGX_SUCCESS;
    }

    faasm_sgx_status_t faasm_sgx_enclave_load_module(
      const char* user,
      const char* function,
      const char* wasm_opcode_ptr,
      const uint32_t wasm_opcode_size,
      const void* wasm_op_nonce,
      const void* wasm_op_tag,
      uint32_t* thread_id,
      sgx_wamr_msg_t** response_ptr,
      faaslet_sgx_gp_buffer_t* output_ptr,
      faaslet_sgx_gp_buffer_t* result_ptr)
    {
        char wamr_error_buffer[FAASM_SGX_WAMR_MODULE_ERROR_BUFFER_SIZE];
        faasm_sgx_status_t return_value;

        // Check if passed wasm opcode size or wasm opcode ptr is zero
        if (!wasm_opcode_size) {
            return FAASM_SGX_INVALID_OPCODE_SIZE;
        }
        if (!wasm_opcode_ptr || !response_ptr) {
            return FAASM_SGX_INVALID_PTR;
        }

        // Get Faasm-SGX TCS slot for further use and set thread-specific
        // thread_id
        if ((return_value = __get_tcs_slot(thread_id)) != FAASM_SGX_SUCCESS) {
            return return_value;
        }

        tls_thread_id = *thread_id;

        // Initialize Faasm-SGX TCS slot and copy wasm code
        _FAASM_SGX_TCS_LOAD_SLOT(tcs_ptr, *thread_id);
        tcs_ptr->response_ptr = response_ptr;
        tcs_ptr->output_ptr = output_ptr;
        tcs_ptr->result_ptr = result_ptr;

        uint32_t msg_payload_len, res_payload_len;
        sgx_wamr_msg_hash_fct_t* msg_payload;
        void *res_payload, *decrypted_module;
        sgx_wamr_msg_hdr_t header;
        sgx_wamr_okey_policy_t* typed_res_payload;
        char* chain_policy;
        char **user_ptr, **function_ptr;
        faasm_sgx_status_t ret_val;

        // terminate function name
        msg_payload_len = sizeof(sgx_wamr_msg_hash_fct_t) + strlen(function) +
                          1; //+1 for string termination
        if ((msg_payload = (sgx_wamr_msg_hash_fct_t*)calloc(
               msg_payload_len, sizeof(uint8_t))) == NULL) {
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        msg_payload->hdr.type = FAASM_SGX_ATTESTATION_TYPE_BIND;
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if (sgx_sha256_msg(
              (uint8_t*)wasm_opcode_ptr,
              wasm_opcode_size,
              &faasm_sgx_tcs[*thread_id]->env.encrypted_op_code_hash) !=
            SGX_SUCCESS) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            free(msg_payload);
            return FAASM_SGX_HASH_FAILED;
        }
        memcpy(msg_payload->opcode_enc_hash,
               faasm_sgx_tcs[*thread_id]->env.encrypted_op_code_hash,
               sizeof(msg_payload->opcode_enc_hash));
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        memcpy(msg_payload->fct_name, function, strlen(function));
        msg_payload->fct_name[strlen(function)] = '\0';
        if ((ret_val = send_recv_msg(*thread_id,
                                     msg_payload,
                                     msg_payload_len,
                                     &res_payload,
                                     &res_payload_len)) != FAASM_SGX_SUCCESS) {
            free(msg_payload);
            return ret_val;
        }
        free(msg_payload);
        header = *((sgx_wamr_msg_hdr_t*)res_payload);
        if (header.status) {
            free(res_payload);
            return FAASM_SGX_PROTOCOL_LOADED_FUNCTION_MISMATCH;
        }
        typed_res_payload = (sgx_wamr_okey_policy_t*)res_payload;
        if ((decrypted_module =
               (void*)calloc(wasm_opcode_size, sizeof(uint8_t))) == NULL) {
            free(res_payload);
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        if (sgx_rijndael128GCM_decrypt(
              (sgx_aes_gcm_128bit_key_t*)typed_res_payload->opcode_key,
              (uint8_t*)wasm_opcode_ptr,
              wasm_opcode_size,
              (uint8_t*)decrypted_module,
              (uint8_t*)wasm_op_nonce,
              SGX_AESGCM_IV_SIZE,
              NULL,
              0,
              (const sgx_aes_gcm_128bit_tag_t*)wasm_op_tag) != SGX_SUCCESS) {
            free(res_payload);
            return FAASM_SGX_DECRYPTION_FAILED;
        }
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        if (sgx_sha256_msg((uint8_t*)decrypted_module,
                           wasm_opcode_size,
                           &faasm_sgx_tcs[*thread_id]->env.op_code_hash) !=
            SGX_SUCCESS) {
            free(res_payload);
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            return FAASM_SGX_HASH_FAILED;
        }
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        if ((chain_policy = (char*)calloc(typed_res_payload->policy_len,
                                          sizeof(char*))) == NULL) {
            free(res_payload);
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        memcpy(chain_policy,
               typed_res_payload->policy,
               typed_res_payload->policy_len);
        free(res_payload);
        read_lock(&_rwlock_faasm_sgx_tcs_realloc);
        faasm_sgx_tcs[*thread_id]->env.chain_policy =
          new std::map<const char*, std::string, cmp_str>;
        if ((ret_val = parse_chain_policy_to_map(
               faasm_sgx_tcs[*thread_id]->env.chain_policy,
               (char*)chain_policy,
               typed_res_payload->policy_len)) != FAASM_SGX_SUCCESS) {
            read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
            free(chain_policy);
            return ret_val;
        }
        free(chain_policy);
        faasm_sgx_tcs[*thread_id]->env.nonce_store =
          new std::map<const uint32_t, std::string>;
        read_unlock(&_rwlock_faasm_sgx_tcs_realloc);
        user_ptr = &faasm_sgx_tcs[*thread_id]->env.user;
        if ((*user_ptr = (char*)calloc(strlen(user) + 1, sizeof(char))) ==
            NULL) {
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        memcpy(*user_ptr, (char*)user, strlen(user));
        function_ptr = &faasm_sgx_tcs[*thread_id]->env.name;
        if ((*function_ptr =
               (char*)calloc(strlen(function) + 1, sizeof(char))) == NULL) {
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        memcpy(*function_ptr, (char*)function, strlen(function));
        // wasm_opcode_ptr = (char*)decrypted_module;
        tcs_ptr->wasm_opcode = (uint8_t*)decrypted_module;

        // Load the WASM module
        if (!(tcs_ptr->module = wasm_runtime_load(tcs_ptr->wasm_opcode,
                                                  wasm_opcode_size,
                                                  wamr_error_buffer,
                                                  sizeof(wamr_error_buffer)))) {
            // Revert all changes due to a module load error
            free(tcs_ptr->wasm_opcode);
            _FAASM_SGX_TCS_FREE_SLOT(*thread_id);
            free(tcs_ptr);
#if (FAASM_SGX_DEBUG)
            ocall_printf(wamr_error_buffer);
#endif
            return FAASM_SGX_WAMR_MODULE_LOAD_FAILED;
        }

        // Instantiate the WASM module
        if (!(tcs_ptr->module_inst = wasm_runtime_instantiate(
                tcs_ptr->module,
                (uint32_t)FAASM_SGX_WAMR_INSTANCE_DEFAULT_STACK_SIZE,
                (uint32_t)FAASM_SGX_WAMR_INSTANCE_DEFAULT_HEAP_SIZE,
                wamr_error_buffer,
                sizeof(wamr_error_buffer)))) {
            // Revert all changes due to a module instantiate error
            free(tcs_ptr->wasm_opcode);
            wasm_runtime_unload(tcs_ptr->module);
            _FAASM_SGX_TCS_FREE_SLOT(*thread_id);
            free(tcs_ptr);
#if (FAASM_SGX_DEBUG)
            ocall_printf(wamr_error_buffer);
#endif
            return FAASM_SGX_WAMR_MODULE_INSTANTIATION_FAILED;
        }

        return FAASM_SGX_SUCCESS;
    }

    faasm_sgx_status_t faasm_sgx_enclave_init_wamr(void)
    {
#if (FAASM_SGX_DEBUG)
        // Set our ocall_printf as default printf function if FAASM_SGX_DEBUG ==
        // 1
        os_set_print_function((os_print_function_t)ocall_printf);
#endif

        // Initialize FAASM-SGX TCS
        _faasm_sgx_tcs_len = FAASM_SGX_INIT_TCS_SLOTS;
        if (!(faasm_sgx_tcs = (_faasm_sgx_tcs_t**)calloc(
                FAASM_SGX_INIT_TCS_SLOTS, sizeof(_faasm_sgx_tcs_t*)))) {
#if (FAASM_SGX_DEBUG)
            ocall_printf("OOM initialising WAMR\n");
#endif
            return FAASM_SGX_OUT_OF_MEMORY;
        }

        // Initialise the WAMR runtime
        RuntimeInitArgs wamr_rte_args;
        memset(&wamr_rte_args, 0x0, sizeof(wamr_rte_args));
        wamr_rte_args.mem_alloc_type = Alloc_With_Pool;
        wamr_rte_args.mem_alloc_option.pool.heap_buf =
          (void*)_wamr_global_heap_buffer;
        wamr_rte_args.mem_alloc_option.pool.heap_size =
          sizeof(_wamr_global_heap_buffer);

        if (!wasm_runtime_full_init(&wamr_rte_args)) {
            return FAASM_SGX_WAMR_RTE_INIT_FAILED;
        }

        // Set up native symbols
        wasm_native_register_natives(
          "env", faasm_sgx_native_symbols, FAASM_SGX_NATIVE_SYMBOLS_LEN);

        wasm_native_register_natives("wasi_snapshot_preview1",
                                     faasm_sgx_wasi_symbols,
                                     FAASM_SGX_WASI_SYMBOLS_LEN);

        // Initialize necessary attestation stuff
        sgx_status_t sgx_return_value;
        faasm_sgx_status_t return_value;

        if ((sgx_return_value = ocall_init_crt(&return_value)) != SGX_SUCCESS) {
            return FAASM_SGX_OCALL_ERROR(sgx_return_value);
        }

        if ((sgx_return_value = ocall_attest_to_km(&return_value)) !=
            SGX_SUCCESS) {
            return FAASM_SGX_OCALL_ERROR(sgx_return_value);
        }

        if (return_value != FAASM_SGX_SUCCESS) {
            return return_value;
        }

        return FAASM_SGX_SUCCESS;
    }

    faasm_sgx_status_t faasm_sgx_enclave_init_ra(sgx_ra_context_t* ctx)
    {
        inner_ctx = ctx;
        if (sgx_ra_init(&key, 0, ctx) != SGX_SUCCESS) {
            return FAASM_SGX_NOT_IMPLEMENTED;
        }
        return FAASM_SGX_SUCCESS;
    }

    faasm_sgx_status_t faasm_sgx_enclave_finalize_key_exchange(
      sgx_wamr_msg_t* wamr_msg,
      uint32_t msg_len)
    {
        sgx_wamr_msg_pkey_mkey_t msg;
        if (sgx_ra_get_keys(*inner_ctx, SGX_RA_KEY_SK, &shared_secret) !=
            SGX_SUCCESS) {
            ocall_printf("sgx_ra_get_keys failed\n");
            return FAASM_SGX_NOT_IMPLEMENTED;
        }

        if (sgx_rijndael128GCM_decrypt(
              (sgx_aes_gcm_128bit_key_t*)&shared_secret,
              (uint8_t*)wamr_msg->payload,
              sizeof(sgx_wamr_msg_pkey_mkey_t),
              (uint8_t*)&msg,
              wamr_msg->nonce,
              sizeof(wamr_msg->nonce),
              NULL,
              0,
              (const sgx_aes_gcm_128bit_tag_t*)wamr_msg->mac) != SGX_SUCCESS) {
            return FAASM_SGX_DECRYPTION_FAILED;
        }
        return FAASM_SGX_SUCCESS;
    }
}
