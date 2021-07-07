# --------------------------------------------------------
#                        WARNING
#
# Before modifying please read /docs/sgx.md
# This file contains many low level settings
# --------------------------------------------------------

# NASM configuration
enable_language(ASM_NASM)
set(CMAKE_ASM_NASM_FLAGS -felf64)
set(CMAKE_ASM_NASM_COMPILE_OBJECT "<CMAKE_ASM_NASM_COMPILER> <INCLUDES> ${CMAKE_ASM_NASM_FLAGS} -o <OBJECT> <SOURCE>")

# FAASM-SGX enclave configuration
set(FAASM_SGX_ENCLAVE_PATH "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/faasm_sgx_enclave.sign.so")

# Enable(1)/ Disable(0) SGX-specific debug/error messages
# Disable for better performance
set(FAASM_SGX_DEBUG 1)

# SGX configuration
set(SGX_DEBUG_MODE 1)
set(SGX_SDK_LIB_PATH ${SGX_SDK_PATH}/lib64)
set(SGX_SDK_ENCLAVE_SIGNER ${SGX_SDK_PATH}/bin/x64/sgx_sign)
set(SGX_SDK_ENCLAVE_EDGER8R ${SGX_SDK_PATH}/bin/x64/sgx_edger8r)

# TODO: check this
if(FAASM_SGX_XRA)
    add_definitions(-DFAASM_SGX_XRA=1)
endif()

set(SGX_C_GLOBAL_FLAGS -m64)
set(THREADS_PREFER_PTHREAD_FLAG ON)
set(SGX_SDK_ENCLAVE_SIGNER ${SGX_SDK_PATH}/bin/x64/sgx_sign)
set(SGX_SDK_ENCLAVE_EDGER8R ${SGX_SDK_PATH}/bin/x64/sgx_edger8r)

# --------------------------------------------------------
# WAMR Build
#
# 28/06/2021 - To build WAMR inside SGX, we follow the provided example:
# https://github.com/bytecodealliance/wasm-micro-runtime/blob/main/product-mini/platforms/linux-sgx/CMakeLists.txt
# --------------------------------------------------------

# Set target platform details
set (WAMR_BUILD_PLATFORM "linux-sgx")
set (WAMR_BUILD_TARGET X86_64)
set (WAMR_BUILD_SPEC_TEST)

# Set AOT mode, disable JIT
set (WAMR_BUILD_AOT 1)
set (WAMR_BUILD_JIT 0)

# Set libraries
set (WAMR_BUILD_LIBC_BUILTIN 1)
set (WAMR_BUILD_LIBC_WASI 0)
set (WAMR_BUILD_LIB_PTHREAD 0)

# Let WAMR do the including and importing of the sources
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
set(FAASM_SGX_WAMR_SRC ${WAMR_RUNTIME_LIB_SOURCE})

set(FAASM_SGX_WAMR_SRC_UNTRUSTED
        ${PLATFORM_SHARED_SOURCE_UNTRUSTED}
        )

# --------------------------------------------------------
# Crypto submodule
# --------------------------------------------------------
add_subdirectory(crypto)

# --------------------------------------------------------
# Attestation configuration
# --------------------------------------------------------

if (FAASM_SGX_ATTESTATION)
    # IP-address or hostname is possible to specify host
    add_definitions(
            -DFAASM_SGX_ATTESTATION_HOST="localhost"
            -DFAASM_SGX_ATTESTATION_PORT=8009
            -DFAASM_SGX_ATTESTATION_CALLBACK_STORE_INIT_LEN=4
    )
endif ()

# eXtended Remote Attestation XRA configuration
if(FAASM_SGX_XRA)
    add_definitions(-DFAASM_SGX_XRA=1)
endif()

# Create definitions if necessary
add_definitions(
        -DFAASM_SGX_DEBUG=${FAASM_SGX_DEBUG}
        -DFAASM_SGX_ENCLAVE_PATH="${FAASM_SGX_ENCLAVE_PATH}"
)

# Debug message
message("-- Faasm-SGX Configuration:
 FAASM-SGX Debug Mode: ${FAASM_SGX_DEBUG}
 FAASM-SGX SGX Simulation Mode: ${FAASM_SGX_SIM_MODE}
 FAASM-SGX ATTESTATION: ${FAASM_SGX_ATTESTATION}
 FAASM-SGX XRA: ${FAASM_SGX_XRA}
 FAASM_SGX Enclave Path: ${FAASM_SGX_ENCLAVE_PATH}"
)

# --------------------------------------------------------
# INITIAL CHECKS
# --------------------------------------------------------

# Check for SGX SDK
find_package(Threads REQUIRED)
if (EXISTS ${SGX_SDK_PATH})
    message(STATUS "Found SGX-SDK: TRUE")
else ()
    message(STATUS "Found SGX-SDK: FALSE")
    message(FATAL_ERROR "SGX-SDK not installed in ${SGX_SDK_PATH}")
endif ()

# SGX compilation flags
if (SGX_DEBUG_MODE)
    message(STATUS "Enclave will be built with debug information and -O0 optimization")
    set(SGX_C_GLOBAL_FLAGS ${SGX_C_GLOBAL_FLAGS} -O0 -g)

    set(FAASM_SGX_C_FLAGS ${SGX_C_GLOBAL_FLAGS}
            -fPIC
            -Wno-attributes
            -DDEBUG
            -UNDEBUG
            -UEDEBUG
            )
else ()
    message(STATUS "Enclave will be build without debug information and -O2 optimization")
    set(SGX_C_GLOBAL_FLAGS ${SGX_C_GLOBAL_FLAGS} -O2)

    set(FAASM_SGX_C_FLAGS ${SGX_C_GLOBAL_FLAGS}
            -fPIC
            -Wno-attributes
            )

endif ()

# Note - these are the same in debug/ non-debug mode
set(FAASM_SGX_ENCLAVE_C_FLAGS ${SGX_C_GLOBAL_FLAGS}
        -nostdinc
        -fvisibility=hidden
        -fpie
        -ffunction-sections
        -fdata-sections
        -fstack-protector-strong
        )

set(FAASM_SGX_HEADERS
        ${FAASM_INCLUDE_DIR}/sgx/enclaveConfig.h
        ${FAASM_INCLUDE_DIR}/sgx/faasm_sgx_attestation.h
        ${FAASM_INCLUDE_DIR}/sgx/faasm_sgx_enclave_types.h
        ${FAASM_INCLUDE_DIR}/sgx/faasm_sgx_error.h
        ${FAASM_INCLUDE_DIR}/sgx/faasm_sgx_native_symbols_wrapper.h
        ${FAASM_INCLUDE_DIR}/sgx/faasm_sgx_system.h
        ${FAASM_INCLUDE_DIR}/sgx/rw_lock.h
        ${FAASM_INCLUDE_DIR}/sgx/SGXWAMRWasmModule.h
)

# --------------------------------------------------------
# ENCLAVE BUILD
# --------------------------------------------------------

# SGX WAMR enclave library
set(FAASM_SGX_ENCLAVE_SRC
        faasm_sgx_enclave.cpp
        faasm_sgx_native_symbols_wrapper.cpp
        rw_lock.cpp
        )

add_library(faasm_sgx_enclave SHARED
    ${FAASM_SGX_HEADERS}
    ${FAASM_SGX_ENCLAVE_SRC}
)
add_dependencies(faasm_sgx_enclave wamr_sgx)

set_target_properties(faasm_sgx_enclave PROPERTIES PREFIX "")
target_include_directories(faasm_sgx_enclave PRIVATE
        ${SGX_SDK_PATH}/include
        ${SGX_SDK_PATH}/include/tlibc
        ${SGX_SDK_PATH}/include/libcxx
        ${WAMR_ROOT_DIR}/core
        ${WAMR_ROOT_DIR}/core/shared/utils
        ${WAMR_ROOT_DIR}/core/shared/platform/linux-sgx
        )

# Set XRA includes if needed
if(FAASM_SGX_XRA)
target_include_directories(faasm_sgx_enclave PRIVATE
        ${FAASM_XRA_ROOT_DIR}/include
        )
endif()

target_link_directories(faasm_sgx_enclave PRIVATE ${SGX_SDK_LIB_PATH})
target_compile_options(faasm_sgx_enclave PRIVATE
        ${FAASM_SGX_ENCLAVE_C_FLAGS}
        -std=c++11
        -nostdinc++
        )

target_link_options(faasm_sgx_enclave PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}/faasm_sgx_enclave_t.o
        ${SGX_C_GLOBAL_FLAGS}
        -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles
        -Bstatic -Bsymbolic
        -Wl,-pie,-eenclave_entry
        -Wl,--export-dynamic
        -Wl,--defsym,__ImageBase=0
        -Wl,--gc-sections
        -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/faasm_sgx_enclave.lds
        )

if (FAASM_SGX_SIM_MODE)
    target_link_libraries(faasm_sgx_enclave
            -Wl,--whole-archive sgx_trts_sim
            -Wl,--no-whole-archive
            -Wl,--start-group
            ${SGX_SDK_LIB_PATH}/libsgx_tservice_sim.a
            -Wl,--end-group
            )
else ()
    target_link_libraries(faasm_sgx_enclave
            -Wl,--whole-archive sgx_trts
            -Wl,--no-whole-archive
            -Wl,--start-group
            ${SGX_SDK_LIB_PATH}/libsgx_tservice.a
            -Wl,--end-group
            )
endif ()

# Common libraries
target_link_libraries(faasm_sgx_enclave
        -Wl,--no-whole-archive
        -Wl,--start-group
        ${SGX_SDK_LIB_PATH}/libsgx_pthread.a
        ${SGX_SDK_LIB_PATH}/libsgx_tstdc.a
        ${SGX_SDK_LIB_PATH}/libsgx_tcxx.a
        ${SGX_SDK_LIB_PATH}/libsgx_tcrypto.a
        wamr_sgx
        -Wl,--end-group
        )

# Enclave + XRA
if (FAASM_SGX_XRA)
    add_dependencies(faasm_sgx_enclave xra_t)

    target_link_libraries(faasm_sgx_enclave
            -Wl,--no-whole-archive
            -Wl,--start-group
            xra_t
            -Wl,--end-group
            )
endif ()

# --------------------------------------------------------
# FAASM SGX WAMR MODULE
# --------------------------------------------------------

# SGX WAMR library
set(FAASM_SGX_ASM_SRC
        SGXWAMRWasmModule.S
        )
set_source_files_properties(${FAASM_SGX_ASM_SRC}
        PROPERTIES LANGUAGE ASM_NASM
        )

set(FAASM_SGX_SRC
        SGXWAMRWasmModule.cpp
        faasm_sgx_system.cpp
        faasm_sgx_native_symbols.cpp
        )

if (FAASM_SGX_ATTESTATION)
    set(FAASM_SGX_SRC ${FAASM_SGX_SRC}
            faasm_sgx_attestation.cpp
            rw_lock.cpp
            )
endif ()


add_library(faasm_sgx STATIC
        ${FAASM_SGX_HEADERS}
        ${FAASM_SGX_SRC}
        ${FAASM_SGX_ASM_SRC}
        )

add_dependencies(faasm_sgx faasm_sgx_enclave wamr_sgx_untrusted wasm)

if(FAASM_SGX_ATTESTATION)
    add_dependencies(faasm_sgx)
endif()

target_include_directories(faasm_sgx PUBLIC ${SGX_SDK_PATH}/include)

# Necessary in HW sim mode because libsgx_urts and libsgx_uae_service are probably
# not installed in default lib folder because the build system hasn't sgx support
if(NOT FAASM_SGX_SIM_MODE)
    find_library(SGX_URTS_LIB "sgx_urts")
    find_library(SGX_UAE_SERVICE_LIB "sgx_uae_service")

    if(SGX_URTS_LIB STREQUAL "SGX_URTS_LIB-NOTFOUND" OR SGX_UAE_SERVICE_LIB STREQUAL "SGX_UAE_SERVICE_LIB-NOTFOUND")
        message(WARNING "SGX PSW NOT INSTALLED! SET RPATH TO ${SGX_SDK_LIB_PATH}")
        target_link_directories(faasm_sgx INTERFACE ${SGX_SDK_LIB_PATH})
    endif()
else()
    target_link_directories(faasm_sgx INTERFACE ${SGX_SDK_LIB_PATH})
endif()

target_compile_options(faasm_sgx PRIVATE
        ${FAASM_SGX_C_FLAGS}
        -std=c++11
        -ffunction-sections
        -fdata-sections
        )

target_link_options(faasm_sgx PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}/faasm_sgx_enclave_u.o
        -Wl,--gc-sections
        )

if (FAASM_SGX_SIM_MODE)
    target_link_libraries(faasm_sgx
            sgx_urts_sim
            sgx_uae_service_sim
            )
else ()
    target_link_libraries(faasm_sgx
            sgx_urts
            sgx_uae_service
            )
endif ()

target_link_libraries(faasm_sgx
        Threads::Threads
        wamr_sgx_untrusted
        wasm
        )

# --------------------------------------------------------
# WAMR Runtime Libraries
# --------------------------------------------------------

add_library(wamr_sgx STATIC
        ${FAASM_SGX_HEADERS}
        ${FAASM_SGX_WAMR_SRC}
        )

target_compile_options(wamr_sgx PRIVATE
        -std=gnu99
        -fPIC
        -ffunction-sections
        -fdata-sections
        -Wall
        -Wno-unused-parameter
        -Wno-pedantic
        )

target_include_directories(wamr_sgx PRIVATE
        ${SGX_SDK_PATH}/include
        ${SGX_SDK_PATH}/include/tlibc
        ${SGX_SDK_PATH}/include/libcxx
        )

add_library(wamr_sgx_untrusted STATIC
        ${FAASM_SGX_HEADERS}
        ${FAASM_SGX_WAMR_SRC_UNTRUSTED}
        )

target_compile_options(wamr_sgx_untrusted PRIVATE
        -fPIC
        -ffunction-sections
        -fdata-sections
        )

# --------------------------------------------------------
# CUSTOM COMMANDS
# --------------------------------------------------------

# WAMR enclave
add_custom_command(TARGET faasm_sgx_enclave
        PRE_BUILD COMMAND ${SGX_SDK_ENCLAVE_EDGER8R}
        --trusted faasm_sgx_enclave.edl
        --search-path ${FAASM_SOURCE_DIR}/sgx
        --search-path ${SGX_SDK_PATH}/include
        --search-path ${WAMR_SHARED_DIR}/platform/linux-sgx/
        )

add_custom_command(TARGET faasm_sgx_enclave
        PRE_BUILD COMMAND gcc
        ${FAASM_SGX_ENCLAVE_C_FLAGS}
        -I${SGX_SDK_PATH}/include
        -I${SGX_SDK_PATH}/include/tlibc
        -c faasm_sgx_enclave_t.c
        -o faasm_sgx_enclave_t.o
        )

add_custom_command(TARGET faasm_sgx_enclave
        POST_BUILD COMMAND
        ${SGX_SDK_ENCLAVE_SIGNER} sign
        -key ${CMAKE_CURRENT_SOURCE_DIR}/faasm_sgx_enclave.pem
        -enclave ${CMAKE_BINARY_DIR}/lib/faasm_sgx_enclave.so
        -out ${CMAKE_BINARY_DIR}/bin/faasm_sgx_enclave.sign.so
        -config ${CMAKE_CURRENT_SOURCE_DIR}/faasm_sgx_enclave.config
        )

# SGX-WAMR
add_custom_command(TARGET faasm_sgx
        PRE_BUILD COMMAND ${SGX_SDK_ENCLAVE_EDGER8R}
        --untrusted faasm_sgx_enclave.edl
        --search-path ${FAASM_SOURCE_DIR}/sgx
        --search-path ${SGX_SDK_PATH}/include
        --search-path ${WAMR_SHARED_DIR}/platform/linux-sgx/
        )

add_custom_command(TARGET faasm_sgx
        PRE_BUILD COMMAND gcc
        ${FAASM_SGX_C_FLAGS}
        -I${SGX_SDK_PATH}/include
        -c faasm_sgx_enclave_u.c
        -o faasm_sgx_enclave_u.o
        )
