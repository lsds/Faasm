#pragma once

//#include <sgx/faasm_sgx_attestation.h>
#include <sgx_tcrypto.h>

#define FAASM_SGX_ATTESTATION_STATUS_SUCCESS 0x0
#define FAASM_SGX_ATTESTATION_STATUS_ERROR 0x1
#define FAASM_SGX_ATTESTATION_PAYLOAD_HASH_SID 0x0
#define FAASM_SGX_ATTESTATION_PAYLOAD_HASH_FCT 0x1
#define FAASM_SGX_ATTESTATION_TYPE_CALL 0x0
#define FAASM_SGX_ATTESTATION_TYPE_BIND 0x1
#define FAASM_SGX_ATTESTATION_TYPE_STATE_WRITE 0x2
#define FAASM_SGX_ATTESTATION_TYPE_STATE_READ 0x3
#define FAASM_SGX_ATTESTATION_TYPE_NONCE 0x4
#define FAASM_SGX_ATTESTATION_TYPE_STATE_WRITE_ACK 0x5
#define FAASM_SGX_ATTESTATION_SID_SIZE 12

typedef uint8_t faasm_sgx_nonce_t[SGX_AESGCM_IV_SIZE];
typedef struct __attribute__((packed)) _msg
{
    uint8_t msg_id;
    uint8_t mac[SGX_AESGCM_MAC_SIZE];
    uint8_t nonce[SGX_AESGCM_IV_SIZE];
    uint32_t payload_len;
    uint8_t payload[];
} sgx_wamr_msg_t;

typedef struct __attribute__((packed)) _msg_hdr
{
    uint8_t status;
    uint8_t type;
} sgx_wamr_msg_hdr_t;

typedef struct __attribute__((packed)) _nonce_payload
{
    uint8_t nonce[SGX_AESGCM_IV_SIZE];
    uint8_t payload[];
} sgx_wamr_msg_nonce_payload;

typedef struct __attribute__((packed)) _msg_pkey_quote
{
    sgx_wamr_msg_hdr_t hdr;
    uint8_t public_key[2 * SGX_ECP256_KEY_SIZE];
    uint8_t quote[];
} sgx_wamr_msg_pkey_quote_t;

typedef struct __attribute__((packed)) _msg_pkey_mkey
{
    sgx_wamr_msg_hdr_t hdr;
    uint8_t enclave_master_key[SGX_AESGCM_KEY_SIZE];
} sgx_wamr_msg_pkey_mkey_t;

typedef struct __attribute__((packed)) _msg_hash_sid
{
    sgx_wamr_msg_hdr_t hdr;
    uint8_t opcode_enc_hash[SGX_SHA256_HASH_SIZE];
    uint8_t session_id[FAASM_SGX_ATTESTATION_SID_SIZE];
    uint8_t payload_nonce[SGX_AESGCM_IV_SIZE];
} sgx_wamr_hash_sid_t;

typedef struct __attribute((packed)) _msg_payload_key
{
    sgx_wamr_msg_hdr_t hdr;
    uint8_t payload_key[SGX_AESGCM_KEY_SIZE];
} sgx_wamr_payload_key_t;

typedef struct __attribute((packed)) _msg_okey_policy
{
    sgx_wamr_msg_hdr_t hdr;
    uint8_t opcode_key[SGX_AESGCM_KEY_SIZE];
    uint8_t nonce[SGX_AESGCM_IV_SIZE];
    uint32_t policy_len; // Uint32_t because the policy can be really large
    uint8_t policy[];
} sgx_wamr_okey_policy_t;

typedef struct __attribute((packed)) _msg_hash_fct
{
    sgx_wamr_msg_hdr_t hdr;
    uint8_t opcode_enc_hash[SGX_SHA256_HASH_SIZE];
    uint8_t fct_name[];
} sgx_wamr_msg_hash_fct_t;

typedef struct __attribute((packed)) _msg_state_read
{
    sgx_wamr_msg_hdr_t hdr;
    uint8_t state_name[];
} sgx_wamr_msg_state_read_t;

typedef struct __attribute((packed)) _msg_state_read_res
{
    sgx_wamr_msg_hdr_t hdr;
    uint8_t state_secret[SGX_AESGCM_KEY_SIZE];
    uint8_t buffer_nonce[SGX_AESGCM_IV_SIZE];
    uint8_t data[];
} sgx_wamr_msg_state_read_res_t;

typedef struct __attribute((packed)) _msg_state_write
{
    sgx_wamr_msg_hdr_t hdr;
    uint8_t buffer_nonce[SGX_AESGCM_IV_SIZE];
    uint32_t name_length;
    uint8_t data[];
} sgx_wamr_msg_state_write_t;

typedef struct _faaslet_sgx_msg_buffer
{
    uint32_t buffer_len;
    sgx_wamr_msg_t* buffer_ptr;
} faaslet_sgx_msg_buffer_t;

typedef struct _faaslet_sgx_gp_buffer
{
    uint32_t buffer_len;
    void* buffer_ptr;
} faaslet_sgx_gp_buffer_t;

typedef struct __attribute__((packed)) _data
{
    uint8_t nonce[SGX_AESGCM_IV_SIZE];
    uint8_t tag[SGX_AESGCM_MAC_SIZE];
    uint32_t data_len;
    uint8_t data[];
} sgx_wamr_encrypted_data_blob_t;

typedef struct __attribute__((packed)) _state_data
{
    uint8_t nonce[SGX_AESGCM_IV_SIZE];
    uint8_t tag[SGX_AESGCM_MAC_SIZE];
    uint8_t data[];
} sgx_wamr_encrypted_state_blob_t;

typedef struct __attribute__((packed)) _nonce_offer
{
    sgx_wamr_msg_hdr_t hdr;
    uint8_t nonce[SGX_AESGCM_IV_SIZE];
} sgx_wamr_msg_nonce_offer_t;
