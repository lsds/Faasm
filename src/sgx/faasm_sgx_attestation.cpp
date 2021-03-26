#include <faasm_sgx_attestation.h>
#include <faasm_sgx_error.h>
#include <rw_lock.h>

#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

#include <sgx_uae_epid.h>
#include <sgx_ukey_exchange.h>

#include <faabric/util/logging.h>

#include <sgx/SGXWAMRWasmModule.h>

#define WAKEUP_SEND_THREAD()                                                   \
    pthread_mutex_lock(&_callback_store[i].mutex);                             \
    pthread_cond_signal(&_callback_store[i].cond);                             \
    pthread_mutex_unlock(&_callback_store[i].mutex)

extern "C"
{
    extern __thread faaslet_sgx_msg_buffer_t* faasletSgxMsgBufferPtr;
    extern sgx_status_t sgx_ra_get_ga(unsigned long,
                                      _status_t*,
                                      unsigned int,
                                      _sgx_ec256_public_t*);
    extern sgx_status_t faasm_sgx_enclave_init_ra(sgx_enclave_id_t,
                                                  faasm_sgx_status_t*,
                                                  sgx_ra_context_t*);
    extern sgx_status_t sgx_ra_proc_msg2_trusted(unsigned long,
                                                 _status_t*,
                                                 unsigned int,
                                                 const _ra_msg2_t*,
                                                 const _target_info_t*,
                                                 _report_t*,
                                                 _quote_nonce*);
    extern sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid,
                                                sgx_status_t* retval,
                                                sgx_ra_context_t context,
                                                uint32_t quote_size,
                                                sgx_report_t* qe_report,
                                                sgx_ra_msg3_t* p_msg3,
                                                uint32_t msg3_size);
    extern sgx_status_t faasm_sgx_enclave_finalize_key_exchange(
      sgx_enclave_id_t,
      faasm_sgx_status_t*,
      sgx_wamr_msg_t*,
      uint32_t);

    typedef struct __thread_callback
    {
        uint8_t msg_id;
        pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
        pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
        faaslet_sgx_msg_buffer_t* response_ptr;
    } _sgx_wamr_thread_callback;

    static pthread_t _crt;
    static int _keymgr_socket;
    static _sgx_wamr_thread_callback* _callback_store;
    static uint32_t _callback_store_len =
      FAASM_SGX_ATTESTATION_CALLBACK_STORE_INIT_LEN;
    static pthread_mutex_t _mutex_callback_store = PTHREAD_MUTEX_INITIALIZER,
                           _mutex_keymgr_socket = PTHREAD_MUTEX_INITIALIZER;
    static rwlock_t _rwlock_callback_store_realloc;

    static __attribute__((always_inline)) uint8_t __memcmp_zero(
      uint8_t* mem_ptr,
      uint64_t mem_len)
    {
        while (mem_len-- > 0) {
            if (*(mem_ptr++))
                return 1;
        }
        return 0;
    }

    static inline faasm_sgx_status_t _find_callback_store_slot(
      uint32_t* id,
      faaslet_sgx_msg_buffer_t* response_ptr)
    {
        _sgx_wamr_thread_callback* temp_ptr;
        uint32_t temp_size, i = 0;

        pthread_mutex_lock(&_mutex_callback_store);
        read_lock(&_rwlock_callback_store_realloc);
        for (; i < _callback_store_len; i++) {
            if (!_callback_store[i].response_ptr) {
                _callback_store[i].response_ptr = response_ptr;
                pthread_mutex_unlock(&_mutex_callback_store);
                read_unlock(&_rwlock_callback_store_realloc);
                *id = i;
                return FAASM_SGX_SUCCESS;
            }
        }

        read_unlock(&_rwlock_callback_store_realloc);
        write_lock(&_rwlock_callback_store_realloc);
        temp_size = _callback_store_len << 1;
        if (!(temp_ptr = (_sgx_wamr_thread_callback*)realloc(
                (void*)_callback_store,
                (temp_size * sizeof(_sgx_wamr_thread_callback))))) {
            write_unlock(&_rwlock_callback_store_realloc);
            pthread_mutex_unlock(&_mutex_callback_store);
            return FAASM_SGX_OUT_OF_MEMORY;
        }

        memset((void*)(temp_ptr + _callback_store_len),
               0x0,
               (temp_size - _callback_store_len) *
                 sizeof(_sgx_wamr_thread_callback));
        _callback_store = temp_ptr;
        _callback_store_len = temp_size;
        _callback_store[i].response_ptr = response_ptr;
        write_unlock(&_rwlock_callback_store_realloc);
        pthread_mutex_unlock(&_mutex_callback_store);
        *id = i;

        return FAASM_SGX_SUCCESS;
    }

    faasm_sgx_status_t ocall_send_msg(sgx_wamr_msg_t* msg, uint32_t msg_len)
    {
        faasm_sgx_status_t ret_val;
        uint32_t cb_store_id;

        auto logger = faabric::util::getLogger();

        if ((ret_val = _find_callback_store_slot(
               &cb_store_id, faasletSgxMsgBufferPtr)) != FAASM_SGX_SUCCESS) {
            return ret_val;
        }

        logger->debug("sending message to key manager ({})", msg->msg_id);

        read_lock(&_rwlock_callback_store_realloc);
        _callback_store[cb_store_id].msg_id = msg->msg_id;
        pthread_mutex_lock(&_callback_store[cb_store_id].mutex);
        pthread_mutex_lock(&_mutex_keymgr_socket);

        if (send(_keymgr_socket, (void*)msg, msg_len, MSG_NOSIGNAL) <= 0) {
            pthread_mutex_unlock(&_mutex_keymgr_socket);
            pthread_mutex_unlock(&_callback_store[cb_store_id].mutex);
            _callback_store[cb_store_id].response_ptr = 0x0;
            read_unlock(&_rwlock_callback_store_realloc);
            return FAASM_SGX_CRT_SEND_FAILED;
        }

        pthread_mutex_unlock(&_mutex_keymgr_socket);
        pthread_cond_wait(&_callback_store[cb_store_id].cond,
                          &_callback_store[cb_store_id].mutex);
        pthread_mutex_unlock(&_callback_store[cb_store_id].mutex);

        if (!__memcmp_zero(
              _callback_store[cb_store_id].response_ptr->buffer_ptr->payload,
              _callback_store[cb_store_id]
                .response_ptr->buffer_ptr->payload_len)) {
            _callback_store[cb_store_id].response_ptr = 0x0;
            read_unlock(&_rwlock_callback_store_realloc);
            return FAASM_SGX_CRT_RECV_FAILED;
        }

        _callback_store[cb_store_id].response_ptr = 0x0;
        read_unlock(&_rwlock_callback_store_realloc);
        return FAASM_SGX_SUCCESS;
    }

    void* handle_messages(void* args)
    {
        sgx_wamr_msg_t recv_buffer;

        while (
          recv(_keymgr_socket, (void*)&recv_buffer, sizeof(sgx_wamr_msg_t), 0) >
          0) {
            read_lock(&_rwlock_callback_store_realloc);

            for (uint32_t i = 0; i < _callback_store_len; i++) {
                if (_callback_store[i].msg_id == recv_buffer.msg_id) {
                    if (_callback_store[i].response_ptr->buffer_len <
                        sizeof(sgx_wamr_msg_t) + recv_buffer.payload_len) {
                        sgx_wamr_msg_t* temp_ptr;
                        uint32_t temp_len =
                          sizeof(sgx_wamr_msg_t) + recv_buffer.payload_len;
                        if (!(temp_ptr = (sgx_wamr_msg_t*)realloc(
                                _callback_store[i].response_ptr->buffer_ptr,
                                temp_len))) {
                            memset((void*)(((uint8_t*)_callback_store[i]
                                              .response_ptr->buffer_ptr) +
                                           sizeof(sgx_wamr_msg_t)),
                                   0x0,
                                   _callback_store[i]
                                     .response_ptr->buffer_ptr->payload_len);
                            WAKEUP_SEND_THREAD();
                            read_unlock(&_rwlock_callback_store_realloc);
                            goto __CLEAR_SOCKET;
                        }
                        _callback_store[i].response_ptr->buffer_ptr = temp_ptr;
                        _callback_store[i].response_ptr->buffer_len = temp_len;
                    }

                    memcpy((void*)_callback_store[i].response_ptr->buffer_ptr,
                           (void*)&recv_buffer,
                           sizeof(sgx_wamr_msg_t));

                    if (recv(_keymgr_socket,
                             (uint8_t*)_callback_store[i]
                                 .response_ptr->buffer_ptr +
                               sizeof(sgx_wamr_msg_t),
                             recv_buffer.payload_len,
                             0) <= 0) {
                        memset((void*)(((uint8_t*)_callback_store[i]
                                          .response_ptr->buffer_ptr) +
                                       sizeof(sgx_wamr_msg_t)),
                               0x0,
                               recv_buffer.payload_len);
                        WAKEUP_SEND_THREAD();
                        read_unlock(&_rwlock_callback_store_realloc);
                        goto __CLOSE_SOCKET_AND_RETURN;
                    }

                    WAKEUP_SEND_THREAD();
                    read_unlock(&_rwlock_callback_store_realloc);

                    break;
                }
            }

            continue;
        __CLEAR_SOCKET:
            uint8_t dev_null[recv_buffer.payload_len];
            if (recv(_keymgr_socket,
                     (void*)dev_null,
                     recv_buffer.payload_len,
                     0) <= 0) {
                goto __CLOSE_SOCKET_AND_RETURN;
            }
        }

    __CLOSE_SOCKET_AND_RETURN:
        pthread_mutex_lock(&_mutex_keymgr_socket);
        shutdown(_keymgr_socket, SHUT_RDWR);
        pthread_mutex_unlock(&_mutex_keymgr_socket);

        return NULL;
    }

    faasm_sgx_status_t ocall_init_crt(void)
    {
        auto logger = faabric::util::getLogger();

        struct sockaddr_in keymgr_sockaddr;

        if ((_callback_store = (_sgx_wamr_thread_callback*)calloc(
               _callback_store_len, sizeof(_sgx_wamr_thread_callback))) ==
            NULL) {
            return FAASM_SGX_OUT_OF_MEMORY;
        }

        if ((_keymgr_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            return FAASM_SGX_CRT_SOCKET_FAILED;
        }

        memset((void*)&keymgr_sockaddr, 0x0, sizeof(struct sockaddr_in));
        keymgr_sockaddr.sin_family = AF_INET;
        keymgr_sockaddr.sin_port = htons(FAASM_SGX_ATTESTATION_PORT);

        logger->debug("Initiating connection to KM Guard on {}:{}",
                      FAASM_SGX_ATTESTATION_HOST,
                      FAASM_SGX_ATTESTATION_PORT);
        const char* hostname = FAASM_SGX_ATTESTATION_HOST;
        if (inet_pton(AF_INET, hostname, &keymgr_sockaddr.sin_addr) != 1) {
            struct hostent* resolved_addr;
            if (!(resolved_addr = gethostbyname(hostname))) {
                logger->error("Unresolved host: {}", hostname);
                close(_keymgr_socket);
                return FAASM_SGX_CRT_INVALID_ADDR;
            }

            memcpy((void*)&keymgr_sockaddr.sin_addr,
                   (void*)resolved_addr->h_addr_list[0],
                   sizeof(struct in_addr));
        }

        if (connect(_keymgr_socket,
                    (struct sockaddr*)&keymgr_sockaddr,
                    sizeof(struct sockaddr_in))) {
            close(_keymgr_socket);
            return FAASM_SGX_CRT_CONNECT_FAILED;
        }

        if (pthread_create(&_crt, NULL, handle_messages, NULL)) {
            close(_keymgr_socket);
            return FAASM_SGX_CRT_THREAD_FAILED;
        }
        return FAASM_SGX_SUCCESS;
    }

    faasm_sgx_status_t ocall_attest_to_km(void)
    {
        auto logger = faabric::util::getLogger();
        logger->info("attesting to KM");

        // Initiate attestation to KM, see SGX developer reference, fig 11 for
        // RA flow detaills
        // https://01.org/sites/default/files/documentation/intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf
        sgx_ra_context_t RActx;                   // remote attestation context
        uint32_t msg0_extended_epid_group_id = 0; // epid group id
        sgx_ra_msg1_t msg1;
        sgx_ra_msg2_t p_msg2;
        uint32_t msg3_len;
        sgx_ra_msg3_t* msg3;
        uint32_t res_msg_size;
        sgx_wamr_msg_t* res_msg;
        sgx_status_t sgxReturnValue;
        faasm_sgx_status_t returnValue;

        sgxReturnValue =
          faasm_sgx_enclave_init_ra(globalEnclaveId, &returnValue, &RActx);
        if (sgxReturnValue != SGX_SUCCESS || returnValue != FAASM_SGX_SUCCESS) {
            logger->error(
              "ecall init_ra failed: {} | {}", sgxReturnValue, returnValue);
            return FAASM_SGX_ECALL_FAILED;
        } else {
            logger->debug("successfully initialized RA context");
        }

        sgxReturnValue =
          sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id);
        if (sgxReturnValue != SGX_SUCCESS) {
            logger->error("SDK call get_extended_epid_group_id failed: {}",
                          sgxReturnValue);
            return FAASM_SGX_SDK_CALL_FAILED;
        }

        sgxReturnValue =
          sgx_ra_get_msg1(RActx, globalEnclaveId, sgx_ra_get_ga, &msg1);
        if (sgxReturnValue != SGX_SUCCESS) {
            logger->error("SDK call ra_get_msg1 failed: {}", sgxReturnValue);
            return FAASM_SGX_SDK_CALL_FAILED;
        }

        // send msg0 to KM
        if (send(_keymgr_socket,
                 &msg0_extended_epid_group_id,
                 sizeof(msg0_extended_epid_group_id),
                 0) <= 0) {
            logger->error("sending msg0 to KM failed");
            return FAASM_SGX_CRT_SEND_FAILED;
        } else {
            logger->debug("sending msg0 to KM successful");
        }

        // send msg1 to KM
        if (send(_keymgr_socket, &msg1, sizeof(msg1), 0) <= 0) {
            logger->error("sending msg1 to KM failed");
            return FAASM_SGX_CRT_SEND_FAILED;
        } else {
            logger->debug("sending msg1 to KM successful");
        }

        // get msg2 from KM and process
        logger->debug("waiting for msg2 ({} bytes)...", sizeof(p_msg2));
        if (recv(_keymgr_socket, &p_msg2, sizeof(p_msg2), MSG_WAITALL) <= 0) {
            logger->error("could not recieve msg2 from KM");
            return FAASM_SGX_CRT_SEND_FAILED;
        } else {
            logger->debug("successfully recieved msg2 from KM");
        }

        sgxReturnValue = sgx_ra_proc_msg2(RActx,
                                          globalEnclaveId,
                                          sgx_ra_proc_msg2_trusted,
                                          sgx_ra_get_msg3_trusted,
                                          &p_msg2,
                                          sizeof(p_msg2),
                                          &msg3,
                                          &msg3_len);
        if (sgxReturnValue != SGX_SUCCESS) {
            logger->error("ecall ra_proc_msg2 failed: {}", sgxReturnValue);
            return FAASM_SGX_ECALL_FAILED;
        } else {
            logger->debug("processing of RA msg2 successful");
        }

        // send msg3 to KM
        if (send(_keymgr_socket, msg3, msg3_len, 0) <= 0) {
            logger->error("sending msg3 to KM failed");
            return FAASM_SGX_CRT_SEND_FAILED;
        } else {
            logger->debug("sending of RA msg3 successful");
        }

        res_msg_size =
          sizeof(sgx_wamr_msg_t) + sizeof(sgx_wamr_msg_pkey_mkey_t);
        if ((res_msg = (sgx_wamr_msg_t*)calloc(res_msg_size,
                                               sizeof(uint8_t))) == NULL) {
            logger->error("memory allocation error. exiting");
            free(res_msg);
            exit(0);
        }

        // recieve res_msg and finalize key exchange
        logger->debug("waiting for final msg from KM ({} bytes)...",
                      res_msg_size);
        if (recv(_keymgr_socket, res_msg, res_msg_size, MSG_WAITALL) <= 0) {
            logger->error("could not recieve final msg from KM");
            return FAASM_SGX_CRT_SEND_FAILED;
        } else {
            logger->debug("successfully recieved final msg from KM");
        }
        sgxReturnValue = faasm_sgx_enclave_finalize_key_exchange(
          globalEnclaveId, &returnValue, res_msg, res_msg_size);
        if (sgxReturnValue != SGX_SUCCESS) {
            free(res_msg);
            logger->warn("key exchange not successful! ecall failed with {}",
                         sgxReturnValue);
        } else if (returnValue != FAASM_SGX_SUCCESS) {
            logger->warn("key exchange not successful! failure within ecall");
        } else {
            logger->debug("key exchange successful");
        }
        return FAASM_SGX_SUCCESS;
    }

    faasm_sgx_status_t ocall_set_result(uint8_t* msg, uint32_t msg_len)
    {
        auto logger = faabric::util::getLogger();
        logger->debug("setting result of size {} via ocall", msg_len);
        faabric::Message* bounded_message = wasm::getExecutingCall();
        bounded_message->set_sgxresult((void*)msg, msg_len);
        return FAASM_SGX_SUCCESS;
    }
}
