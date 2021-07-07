#include <sgx/crypto/utils.h>

extern "C"
{
    // TODO - support different algorithms (or at least choosing)
    faasm_sgx_status_t doSymEncrypt(FaasmSgxMsg_t* plainMsg,
                                    FaasmSgxEncryptedMsg_t* encryptedMsg,
                                    FaasmSgxSymKey_t* symKey)
    {
        return doAesGcmEncrypt(plainMsg, encryptedMsg, symKey);
    }

    faasm_sgx_status_t doSymDecrypt(FaasmSgxMsg_t* plainMsg,
                                    FaasmSgxEncryptedMsg_t* encryptedMsg,
                                    FaasmSgxSymKey_t* symKey)
    {
        return doAesGcmDecrypt(plainMsg, encryptedMsg, symKey);
    }

    faasm_sgx_status_t doAesGcmEncrypt(FaasmSgxMsg_t* decryptedMsg,
                                       FaasmSgxEncryptedMsg_t* encryptedMsg,
                                       FaasmSgxSymKey_t* symKey)
    {
        // Prepare initialisation vector (IV) with random values
        FaasmSgxIv_t iv;
        /*
        if (!(iv = (FaasmSgxIv_t*) malloc(sizeof(FaasmSgxIv_t)))) {
            return FAASM_SGX_OUT_OF_MEMORY;
        }
        */
        // memset(iv, 0, sizeof(FaasmSgxIv_t));

        // Prepare initialisation vector (IV) with random values
        if (sgx_read_rand(iv, SGX_AESGCM_IV_SIZE) != SGX_SUCCESS) {
            return FAASM_SGX_READ_RAND_FAILED;
        }

        // Do the actual encryption
        // Note - we set the Additional Authentication Data (AAD) pointer to null
        // and it's corresponding length to 0
        if (sgx_rijndael128GCM_encrypt(
              (sgx_aes_gcm_128bit_key_t*) symKey,
              decryptedMsg->buffer,
              decryptedMsg->bufferLen,
              encryptedMsg->buffer,
              iv,
              SGX_AESGCM_IV_SIZE,
              NULL,
              0,
              (sgx_aes_gcm_128bit_tag_t*) encryptedMsg->mac) != SGX_SUCCESS) {
            return FAASM_SGX_ENCRYPTION_FAILED;
        }

        return FAASM_SGX_SUCCESS;
    }

    faasm_sgx_status_t doAesGcmDecrypt(FaasmSgxMsg_t* decryptedMsg,
                                       FaasmSgxEncryptedMsg_t* encryptedMsg,
                                       FaasmSgxSymKey_t* symKey)
    {
        // Do the actual decryption
        // Note - we set the Additional Authentication Data (AAD) pointer to null
        // and it's corresponding length to 0
        if (sgx_rijndael128GCM_decrypt(
                  (sgx_aes_gcm_128bit_key_t*) symKey,
                  encryptedMsg->buffer,
                  encryptedMsg->bufferLen,
                  decryptedMsg->buffer,
                  encryptedMsg->iv,
                  SGX_AESGCM_IV_SIZE,
                  NULL,
                  0,
                  (const sgx_aes_gcm_128bit_tag_t*) encryptedMsg->mac) != SGX_SUCCESS) {
                return FAASM_SGX_DECRYPTION_FAILED;
            }

        return FAASM_SGX_SUCCESS;
    }
}
