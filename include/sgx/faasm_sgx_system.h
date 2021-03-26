#pragma once

#include "faasm_sgx_error.h"
#include <sgx/faasm_sgx_attestation.h>

// SGX SDK includes
#include <sgx_eid.h>
#include <sgx_error.h>

#define FAASM_SGX_ATTESTATION_GP_BUFFER_DEFAULT_SIZE 128

namespace sgx {
sgx_enclave_id_t getGlobalEnclaveId();

std::string sgxErrorString(sgx_status_t status);

std::string faasmSgxErrorString(faasm_sgx_status_t status);

void checkSgxSetup();

void tearDownEnclave();
}
