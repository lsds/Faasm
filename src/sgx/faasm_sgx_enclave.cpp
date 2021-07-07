#include <sgx/enclaveConfig.h>
#include <sgx/faasm_sgx_enclave_types.h>
#include <sgx/faasm_sgx_error.h>
#include <sgx/faasm_sgx_native_symbols_wrapper.h>
#include <sgx/rw_lock.h>

#include <iwasm/include/wasm_export.h>
#include <libcxx/cstdlib>
#include <sgx.h>
#include <sgx_defs.h>
#include <sgx_thread.h>
#include <tlibc/mbusafecrt.h>

#include <iwasm/aot/aot_runtime.h>

#if (FAASM_SGX_ATTESTATION)
#include <sgx/faasm_sgx_attestation.h>
#endif

#define WASM_CTORS_FUNC_NAME "__wasm_call_ctors"
#define WASM_ENTRY_FUNC "_start"

// Implementation of the exposed Ecalls API. The code in this file is meant to
// run _inside_ the enclave, thus is the only bit of code that actually
// interacts with the WAMR runtime.
extern "C"
{

#if (FAASM_SGX_DEBUG)
    // Print functions
    typedef void (*os_print_function_t)(const char* msg);
    extern void os_set_print_function(os_print_function_t pf);
    extern sgx_status_t SGX_CDECL ocall_printf(const char* msg);
    extern int os_printf(const char* message, ...);
#endif

    // Print function wrapper
    void SGX_DEBUG_LOG(const char* message)
    {
#if (FAASM_SGX_DEBUG)
        ocall_printf(message);
#else
        ;
#endif
    }

    // WAMR native symbols
    extern NativeSymbol faasm_sgx_native_symbols[FAASM_SGX_NATIVE_SYMBOLS_LEN];
    extern NativeSymbol faasm_sgx_wasi_symbols[FAASM_SGX_WASI_SYMBOLS_LEN];

#if (FAASM_SGX_ATTESTATION)
#define INCREMENT_MSG_ID() __sync_fetch_and_add(&_sgx_wamr_msg_id, 1)
    extern sgx_status_t SGX_CDECL
    ocall_init_crt(faasm_sgx_status_t* returnValue);
    extern sgx_status_t SGX_CDECL
    ocall_send_msg(faasm_sgx_status_t* returnValue,
                   sgx_wamr_msg_t* msg,
                   uint32_t msg_len);
    static uint8_t _sgx_wamr_msg_id = 0;
    __thread uint32_t tls_thread_id;
    rwlock_t _rwlock_faasm_sgx_tcs_realloc = { 0 };
#else
    static rwlock_t _rwlock_faasm_sgx_tcs_realloc = { 0 };
#endif

    _faasm_sgx_tcs_t** faasm_sgx_tcs = NULL;
    static uint32_t _faasm_sgx_tcs_len;
    static sgx_thread_mutex_t _mutex_faasm_sgx_tcs =
      SGX_THREAD_MUTEX_INITIALIZER;

    static uint8_t _wamr_global_heap_buffer[FAASM_SGX_WAMR_HEAP_SIZE];

#if (FAASM_SGX_ATTESTATION)
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
            SGX_DEBUG_LOG("Enclave send_msg failed, OOM\n");
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
#endif

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
            SGX_DEBUG_LOG("OOM on get TCS slot\n");
            return FAASM_SGX_OUT_OF_MEMORY;
        }

        // Have to zero out new memory because realloc can refer to already used
        // memory, hence faasm_sgx_tcs[X].module might not be zero
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
            SGX_DEBUG_LOG("OOM on allocate TCS structure\n");
            return FAASM_SGX_OUT_OF_MEMORY;
        }

        *thread_id = i;
        return FAASM_SGX_SUCCESS;
    }

    // Execute the main function
    faasm_sgx_status_t faasm_sgx_enclave_call_function(const uint32_t thread_id)
    {
        // Check if thread_id is in range
        if (thread_id >= _faasm_sgx_tcs_len) {
            return FAASM_SGX_INVALID_THREAD_ID;
        }

        // Get Faasm-SGX TCS slot using thread_id
        _FAASM_SGX_TCS_LOAD_SLOT(tcs_ptr, thread_id);

        // Get function to execute
        WASMFunctionInstanceCommon* wasm_func;
        if (!(wasm_func = wasm_runtime_lookup_function(
                tcs_ptr->module_inst, WASM_ENTRY_FUNC, NULL))) {
            return FAASM_SGX_WAMR_FUNCTION_NOT_FOUND;
        }

#if (FAASM_SGX_ATTESTATION)
        // Set thread_id to fs/gs to make it accessible in native symbols
        // wrapper
        tls_thread_id = thread_id;
#endif
        // Create an execution environment and call the wasm function
        if (!(aot_create_exec_env_and_call_function(
              (AOTModuleInstance*)tcs_ptr->module_inst,
              (AOTFunctionInstance*)wasm_func,
              0x0,
              0x0))) {

            // First, check if the _FAASM_SGX_ERROR_PREFIX is set
            // If so, then obtain and return the faasm_sgx_status_t error code
            // If not, just print the exception and return the matching
            // Faasm-SGX error code
            if (!memcmp(
                  ((AOTModuleInstance*)tcs_ptr->module_inst)->cur_exception,
                  _FAASM_SGX_ERROR_PREFIX,
                  sizeof(_FAASM_SGX_ERROR_PREFIX))) {

                return *((faasm_sgx_status_t*)&(
                  ((AOTModuleInstance*)tcs_ptr->module_inst)
                    ->cur_exception[sizeof(_FAASM_SGX_ERROR_PREFIX)]));
            }

            SGX_DEBUG_LOG(
              ((AOTModuleInstance*)tcs_ptr->module_inst)->cur_exception);
            return FAASM_SGX_WAMR_FUNCTION_UNABLE_TO_CALL;
        }
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

    // Load the provided web assembly module to the enclave's runtime
    faasm_sgx_status_t faasm_sgx_enclave_load_module(
      const void* wasm_opcode_ptr,
      const uint32_t wasm_opcode_size,
      uint32_t* thread_id
#if (FAASM_SGX_ATTESTATION)
      ,
      sgx_wamr_msg_t** response_ptr
#endif
    )
    {
        char wamr_error_buffer[FAASM_SGX_WAMR_MODULE_ERROR_BUFFER_SIZE];
        faasm_sgx_status_t return_value;

        // Check if passed wasm opcode size or wasm opcode ptr is zero
        if (!wasm_opcode_size) {
            return FAASM_SGX_INVALID_OPCODE_SIZE;
        }
#if (FAASM_SGX_ATTESTATION)
        if (!wasm_opcode_ptr || !response_ptr) {
#else
        if (!wasm_opcode_ptr) {
#endif
            return FAASM_SGX_INVALID_PTR;
        }

        // Get Faasm-SGX TCS slot for further use and set thread-specific
        // thread_id
        if ((return_value = __get_tcs_slot(thread_id)) != FAASM_SGX_SUCCESS) {
            return return_value;
        }

        // Initialize Faasm-SGX TCS slot and copy wasm code
        _FAASM_SGX_TCS_LOAD_SLOT(tcs_ptr, *thread_id);
#if (FAASM_SGX_ATTESTATION)
        tcs_ptr->response_ptr = response_ptr;
#endif
        uint8_t* wasm_buffer_ptr =
          (uint8_t*)calloc(wasm_opcode_size, sizeof(uint8_t));
        if (!wasm_buffer_ptr) {
            // Revert all changes due to the out of memory error
            _FAASM_SGX_TCS_FREE_SLOT(*thread_id);
            free(tcs_ptr);
            SGX_DEBUG_LOG("Unable to allocate memory for wasmBytes\n");
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        tcs_ptr->wasm_opcode = wasm_buffer_ptr;
        memcpy(tcs_ptr->wasm_opcode, wasm_opcode_ptr, wasm_opcode_size);

        // Load the WASM module
        if (!(tcs_ptr->module = wasm_runtime_load(tcs_ptr->wasm_opcode,
                                                  wasm_opcode_size,
                                                  wamr_error_buffer,
                                                  sizeof(wamr_error_buffer)))) {
            // Revert all changes due to a module load error
            free(tcs_ptr->wasm_opcode);
            _FAASM_SGX_TCS_FREE_SLOT(*thread_id);
            free(tcs_ptr);
            SGX_DEBUG_LOG(wamr_error_buffer);
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
            SGX_DEBUG_LOG(wamr_error_buffer);
            return FAASM_SGX_WAMR_MODULE_INSTANTIATION_FAILED;
        }

        return FAASM_SGX_SUCCESS;
    }

    // Set up the WAMR runtime, and initialise all enclave-related
    // variables. Currently, this happens _once_ per Faasm instance. This is,
    // we only run one enclave per Faasm instance.
    faasm_sgx_status_t faasm_sgx_enclave_init_wamr(void)
    {
        os_set_print_function((os_print_function_t)SGX_DEBUG_LOG);

        // Initialize FAASM-SGX TCS
        _faasm_sgx_tcs_len = FAASM_SGX_INIT_TCS_SLOTS;
        if (!(faasm_sgx_tcs = (_faasm_sgx_tcs_t**)calloc(
                FAASM_SGX_INIT_TCS_SLOTS, sizeof(_faasm_sgx_tcs_t*)))) {
            SGX_DEBUG_LOG("OOM error initialising TCS\n");
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

#if (FAASM_SGX_ATTESTATION)
        // Initialize necessary attestation stuff if FAASM-SGX Attestation
        // extention is enabled
        sgx_status_t sgx_return_value;
        faasm_sgx_status_t return_value;

        if ((sgx_return_value = ocall_init_crt(&return_value)) != SGX_SUCCESS) {
            return FAASM_SGX_OCALL_ERROR(sgx_return_value);
        }

        if (return_value != FAASM_SGX_SUCCESS) {
            return return_value;
        }
#endif

        return FAASM_SGX_SUCCESS;
    }
}
