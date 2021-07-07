set(FAASM_SGX_CRYPTO_HEADERS
        ${FAASM_INCLUDE_DIR}/sgx/crypto/utils.h
        )

set(FAASM_SGX_CRYPTO_SRC
        utils.cpp
        ${FAASM_SGX_CRYPTO_HEADERS}
        )

faasm_private_lib(faasm_sgx_crypto ${FAASM_SGX_CRYPTO_SRC})

# if (FAASM_SGX_SIM_MODE)
#     target_link_libraries(faasm_sgx_crypto
#         -Wl,--whole-archive ${SGX_SDK_LIB_PATH}/libsgx_trts_sim.a
#         )
# else()
#     target_link_libraries(faasm_sgx_crypto
#         -Wl,--whole-archive ${SGX_SDK_LIB_PATH}/libsgx_trts.a
#         )
# endif()
target_link_libraries(faasm_sgx_crypto
        ${SGX_SDK_LIB_PATH}/libsgx_tstdc.a
        ${SGX_SDK_LIB_PATH}/libsgx_tcrypto.a
        )

add_executable(crypto_tests test.cpp)
target_link_libraries(crypto_tests faasm_sgx_crypto)
