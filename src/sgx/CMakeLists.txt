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
set(FAASM_SGX_INIT_TCS_SLOTS 2)
set(FAASM_SGX_ENCLAVE_PATH "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/faasm_sgx_enclave.sign.so")
set(FAASM_SGX_WAMR_BUILDIN_LIBC 1)
set(FAASM_SGX_WAMR_WASI_LIBC 0)


if($ENV{FAASM_DOCKER})
	set(FAASM_SGX_EDL "faasm_sgx_enclave_docker.edl")
else()
	set(FAASM_SGX_EDL "faasm_sgx_enclave_nodocker.edl")
endif()

# Enable(1)/ Disable(0) SGX-specific debug/error messages 
# Disable for better performance
set(FAASM_SGX_DEBUG 1) 

if(FAASM_SGX_WHITELISTING)
    add_definitions(-DFAASM_SGX_WHITELISTING=1)
else()
    add_definitions(-DFAASM_SGX_WHITELISTING=0)
endif()

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

# WAMR build configuration
set(WAMR_BUILD_TARGET X86_64)

if(FAASM_SGX_WAMR_AOT_MODE)
    add_definitions(-DFAASM_SGX_WAMR_AOT_MODE=1)
    include (${WAMR_IWASM_DIR}/aot/iwasm_aot.cmake)
else()
    add_definitions(-DFAASM_SGX_WAMR_AOT_MODE=0)
    include (${WAMR_IWASM_DIR}/interpreter/iwasm_interp.cmake)
endif()

if(FAASM_SGX_WAMR_BUILDIN_LIBC)
    include (${WAMR_IWASM_DIR}/libraries/libc-builtin/libc_builtin.cmake)
endif()

if(FAASM_SGX_WAMR_WASI_LIBC)
    set(WAMR_BUILD_LIBC_WASI 1)
    include (${WAMR_IWASM_DIR}/libraries/libc-wasi/libc_wasi.cmake)
endif()

include (${WAMR_SHARED_DIR}/platform/linux-sgx/shared_platform.cmake)
include (${WAMR_SHARED_DIR}/mem-alloc/mem_alloc.cmake)
include (${WAMR_IWASM_DIR}/common/iwasm_common.cmake)
include (${WAMR_SHARED_DIR}/utils/shared_utils.cmake)

set(FAASM_SGX_WAMR_SRC
        ${IWASM_AOT_SOURCE}
        ${IWASM_COMMON_SOURCE}
        ${IWASM_INTERP_SOURCE}
        ${LIBC_BUILTIN_SOURCE}
        ${LIBC_WASI_SOURCE}
        ${MEM_ALLOC_SHARED_SOURCE}
        ${PLATFORM_SHARED_SOURCE}
        ${UTILS_SHARED_SOURCE}
        )

set(FAASM_SGX_WAMR_SRC_UNTRUSTED
        ${PLATFORM_SHARED_SOURCE_UNTRUSTED}
        )

# Attestation configuration
# IP-address or hostname is possible to specify host
add_definitions(
		-DFAASM_SGX_ATTESTATION_HOST="localhost"
		-DFAASM_SGX_ATTESTATION_PORT=8009
		-DFAASM_SGX_ATTESTATION_CALLBACK_STORE_INIT_LEN=4
)

# eXtended Remote Attestation XRA configuration
if(FAASM_SGX_XRA)
    add_definitions(-DFAASM_SGX_XRA=1)
endif()

# WAMR Memory sizes
set(FAASM_SGX_WAMR_HEAP_SIZE 32768)
set(FAASM_SGX_WAMR_MODULE_ERROR_BUFFER_SIZE 128)
set(FAASM_SGX_WAMR_INSTANCE_DEFAULT_HEAP_SIZE 8192)
set(FAASM_SGX_WAMR_INSTANCE_DEFAULT_STACK_SIZE 8192)

# Create definitions if necessary
add_definitions(
        -DFAASM_SGX_DEBUG=${FAASM_SGX_DEBUG}
        -DFAASM_SGX_INIT_TCS_SLOTS=${FAASM_SGX_INIT_TCS_SLOTS}
        -DFAASM_SGX_ENCLAVE_PATH="${FAASM_SGX_ENCLAVE_PATH}"
        -DFAASM_SGX_WAMR_HEAP_SIZE=${FAASM_SGX_WAMR_HEAP_SIZE}
        -DFAASM_SGX_WAMR_MODULE_ERROR_BUFFER_SIZE=${FAASM_SGX_WAMR_MODULE_ERROR_BUFFER_SIZE}
        -DFAASM_SGX_WAMR_INSTANCE_DEFAULT_HEAP_SIZE=${FAASM_SGX_WAMR_INSTANCE_DEFAULT_HEAP_SIZE}
        -DFAASM_SGX_WAMR_INSTANCE_DEFAULT_STACK_SIZE=${FAASM_SGX_WAMR_INSTANCE_DEFAULT_STACK_SIZE}
)

# Debug message
message("-- Faasm-SGX Configuration:
 FAASM-SGX Debug Mode: ${FAASM_SGX_DEBUG}
 FAASM-SGX SGX Simulation Mode: ${FAASM_SGX_SIM_MODE}
 FAASM-SGX WAMR AoT Mode: ${FAASM_SGX_WAMR_AOT_MODE}
 FAASM-SGX WAMR Buildin Libc: ${FAASM_SGX_WAMR_BUILDIN_LIBC}
 FAASM-SGX WAMR Wasi Libc: ${FAASM_SGX_WAMR_WASI_LIBC}
 FAASM-SGX WHITELISTING: ${FAASM_SGX_WHITELISTING}
 FAASM-SGX XRA: ${FAASM_SGX_XRA}
 FAASM_SGX Enclave Path: ${FAASM_SGX_ENCLAVE_PATH}
 FAASM-SGX Enclave Init TCS Slots: ${FAASM_SGX_INIT_TCS_SLOTS}
 FAASM-SGX WAMR_HEAP_SIZE: ${FAASM_SGX_WAMR_HEAP_SIZE}KB
 FAASM-SGX WAMR_MODULE_ERROR_BUFFER_SIZE: ${FAASM_SGX_WAMR_MODULE_ERROR_BUFFER_SIZE}B
 FAASM-SGX WAMR_INSTANCE_DEFAULT_HEAP_SIZE: ${FAASM_SGX_WAMR_INSTANCE_DEFAULT_HEAP_SIZE}B
 FAASM-SGX WAMR_INSTANCE_DEFAULT_STACK_SIZE: ${FAASM_SGX_WAMR_INSTANCE_DEFAULT_STACK_SIZE}B"
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

# --------------------------------------------------------
# Global include for all builds
# --------------------------------------------------------

include_directories(${FAASM_INCLUDE_DIR}/sgx)
include_directories(/usr/local/faasm/native/include)

# --------------------------------------------------------
# ENCLAVE BUILD
# --------------------------------------------------------

# SGX WAMR enclave library
set(FAASM_SGX_ENCLAVE_SRC
        faasm_sgx_enclave.cpp
        faasm_sgx_native_symbols_wrapper.cpp
        faasm_sgx_util.cpp
        rw_lock.cpp
        )


if (FAASM_SGX_WHITELISTING)
    set(FAASM_SGX_ENCLAVE_SRC ${FAASM_SGX_ENCLAVE_SRC} faasm_sgx_whitelisting.cpp)
endif ()

add_library(faasm_sgx_enclave SHARED ${FAASM_SGX_ENCLAVE_SRC})
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
            sgx_tservice_sim
            sgx_tkey_exchange
            -Wl,--end-group
            )
else ()
    target_link_libraries(faasm_sgx_enclave
            -Wl,--whole-archive sgx_trts
            -Wl,--no-whole-archive
            -Wl,--start-group
            sgx_tservice
            sgx_tkey_exchange
            -Wl,--end-group
            )
endif ()

# Common libraries
target_link_libraries(faasm_sgx_enclave
        -Wl,--no-whole-archive
        -Wl,--start-group
        sgx_pthread
        sgx_tstdc
        sgx_tcxx
        sgx_tcrypto
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

set(FAASM_SGX_SRC ${FAASM_SGX_SRC}
		faasm_sgx_attestation.cpp
		rw_lock.cpp
		base64.cpp
		)


add_library(faasm_sgx STATIC
        ${FAASM_SGX_SRC}
        ${FAASM_SGX_ASM_SRC}
        )

add_dependencies(faasm_sgx faasm_sgx_enclave wamr_sgx_untrusted wasm)

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
            sgx_ukey_exchange
            )
else ()
    target_link_libraries(faasm_sgx
            sgx_urts
            sgx_uae_service
            sgx_ukey_exchange
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

# copy edl to same name to get same file names
add_custom_command(TARGET faasm_sgx_enclave
        PRE_BUILD COMMAND cp -f
        ${FAASM_SOURCE_DIR}/sgx/${FAASM_SGX_EDL}
        ${FAASM_SOURCE_DIR}/sgx/faasm_sgx_enclave.edl
        )

add_custom_command(TARGET faasm_sgx_enclave
        PRE_BUILD COMMAND ${SGX_SDK_ENCLAVE_EDGER8R}
        --trusted --untrusted faasm_sgx_enclave.edl
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
        PRE_BUILD COMMAND gcc
        ${FAASM_SGX_C_FLAGS}
        -I${SGX_SDK_PATH}/include
        -c faasm_sgx_enclave_u.c
        -o faasm_sgx_enclave_u.o
        )

add_custom_command(TARGET faasm_sgx_enclave
        POST_BUILD COMMAND
        ${SGX_SDK_ENCLAVE_SIGNER} sign
        -key ${CMAKE_CURRENT_SOURCE_DIR}/faasm_sgx_enclave.pem
        -enclave ${CMAKE_BINARY_DIR}/lib/faasm_sgx_enclave.so
        -out ${CMAKE_BINARY_DIR}/bin/faasm_sgx_enclave.sign.so
        -config ${CMAKE_CURRENT_SOURCE_DIR}/faasm_sgx_enclave.config
        )

