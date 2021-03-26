#include "WAMRWasmModule.h"
#include "faabric/util/logging.h"
#include "platform_common.h"
#include "wasm_exec_env.h"
#include "wasm_runtime.h"

#include <faabric/util/locks.h>
#include <wamr/native.h>

#include <cstdint>
#include <stdexcept>
#include <storage/FileLoader.h>
#include <wasm_export.h>

#if (WAMR_EXECUTION_MODE_INTERP)
#include <wasm_runtime.h>
#else
#include <aot_runtime.h>
#endif

namespace wasm {
static bool wamrInitialised = false;
std::mutex wamrInitMx;

static thread_local WAMRWasmModule* executingModule;

void WAMRWasmModule::initialiseWAMRGlobally()
{
    if (wamrInitialised) {
        return;
    } else {
        faabric::util::UniqueLock lock(wamrInitMx);

        if (wamrInitialised) {
            return;
        }

        // Initialise runtime
        bool success = wasm_runtime_init();
        if (!success) {
            throw std::runtime_error("Failed to initialise WAMR");
        }

        faabric::util::getLogger()->debug("Successfully initialised WAMR");

        // Initialise native functions
        initialiseWAMRNatives();
    }
}

void tearDownWAMRGlobally()
{
    wasm_runtime_destroy();
}

WAMRWasmModule* getExecutingWAMRModule()
{
    return executingModule;
}

void setExecutingModule(WAMRWasmModule* executingModuleIn)
{
    executingModule = executingModuleIn;
}

WAMRWasmModule::WAMRWasmModule()
{
    // Lazily initialise WAMR
    initialiseWAMRGlobally();
}

WAMRWasmModule::~WAMRWasmModule()
{
    tearDown();
}

// ----- Module lifecycle -----
void WAMRWasmModule::bindToFunction(const faabric::Message& msg)
{
    const std::shared_ptr<spdlog::logger>& logger = faabric::util::getLogger();

    // Set up the module
    boundUser = msg.user();
    boundFunction = msg.function();
    _isBound = true;

    // Prepare the filesystem
    filesystem.prepareFilesystem();

    // Load the wasm file
    storage::FileLoader& functionLoader = storage::getFileLoader();
#if (WAMR_EXECUTION_MODE_INTERP)
    wasmBytes = functionLoader.loadFunctionWasm(msg);
#else
    std::vector<uint8_t> wasmBytes =
      functionLoader.loadFunctionWamrAotFile(msg);
#endif

    // Load wasm module
    wasmModule = wasm_runtime_load(
      wasmBytes.data(), wasmBytes.size(), errorBuffer, ERROR_BUFFER_SIZE);

    if (wasmModule == nullptr) {
        std::string errorMsg = std::string(errorBuffer);
        logger->error("Failed to load WAMR module: \n{}", errorMsg);
        throw std::runtime_error("Failed to load WAMR module");
    }

    // Instantiate module
    moduleInstance = wasm_runtime_instantiate(
      wasmModule, STACK_SIZE_KB, HEAP_SIZE_KB, errorBuffer, ERROR_BUFFER_SIZE);

    if (moduleInstance == nullptr) {
        std::string errorMsg = std::string(errorBuffer);
        logger->error("Failed to instantiate WAMR module: \n{}", errorMsg);
        throw std::runtime_error("Failed to instantiate WAMR module");
    }
}

void WAMRWasmModule::bindToFunctionNoZygote(const faabric::Message& msg)
{
    // WAMR does not support zygotes yet so it's
    // equivalent to binding with zygote
    bindToFunction(msg);
}

bool WAMRWasmModule::execute(faabric::Message& msg, bool forceNoop)
{
    setExecutingCall(&msg);
    setExecutingModule(this);

    // Run wasm initialisers
    executeFunction(WASM_CTORS_FUNC_NAME);

    if (msg.funcptr() > 0) {
        // Run the function from the pointer
        executeFunctionFromPointer(msg.funcptr());
    } else {
        // Run the main function
        executeFunction(ENTRY_FUNC_NAME);
    }

    return true;
}

int WAMRWasmModule::executeFunctionFromPointer(int wasmFuncPtr)
{
    auto logger = faabric::util::getLogger();

    // NOTE: WAMR doesn't provide a nice interface for calling functions using
    // function pointers, so we have to call a few more low-level functions to
    // get it to work.

    WASMExecEnv* execEnv = wasm_exec_env_create(moduleInstance, STACK_SIZE_KB);
    if (execEnv == nullptr) {
        logger->error("Failed to create exec env for func ptr {}", wasmFuncPtr);
        throw std::runtime_error("Failed to create WAMR exec env");
    }

    // Set thread handle and stack boundary (required by WAMR)
    wasm_exec_env_set_thread_info(execEnv);

    // Call the function pointer
    // NOTE: for some reason WAMR uses the argv array to pass the function
    // return value, so we have to provide something big enough
    std::vector<uint32_t> argv = { 0 };
    bool success =
      wasm_runtime_call_indirect(execEnv, wasmFuncPtr, 0, argv.data());

    // Handle errors
    if (!success) {
#if (WAMR_EXECUTION_MODE_INTERP)
        std::string errorMessage(
          ((WASMModuleInstance*)moduleInstance)->cur_exception);
#else
        std::string errorMessage(
          ((AOTModuleInstance*)moduleInstance)->cur_exception);
#endif

        logger->error("Failed to execute from function pointer {}",
                      wasmFuncPtr);

        return 1;
    }

    return 0;
}

int WAMRWasmModule::executeFunction(const std::string& funcName)
{
    auto logger = faabric::util::getLogger();

    WASMFunctionInstanceCommon* func =
      wasm_runtime_lookup_function(moduleInstance, funcName.c_str(), nullptr);

    // Note, for some reason WAMR sets the return value in the argv array you
    // pass it, therefore we should provide a single integer argv even though
    // it's not actually used
    std::vector<uint32_t> argv = { 0 };

    // Invoke the function
#if (WAMR_EXECUTION_MODE_INTERP)
    bool success = wasm_create_exec_env_and_call_function(
      reinterpret_cast<WASMModuleInstance*>(moduleInstance),
      reinterpret_cast<WASMFunctionInstance*>(func),
      0x0,
      argv.data());
#else
    bool success = aot_create_exec_env_and_call_function(
      reinterpret_cast<AOTModuleInstance*>(moduleInstance),
      reinterpret_cast<AOTFunctionInstance*>(func),
      0x0,
      argv.data());
#endif

    // Check function result
    if (success) {
        logger->debug("{} finished", funcName);
    } else {
#if (WAMR_EXECUTION_MODE_INTERP)
        std::string errorMessage(
          ((WASMModuleInstance*)moduleInstance)->cur_exception);
#else
        std::string errorMessage(
          ((AOTModuleInstance*)moduleInstance)->cur_exception);
#endif
        logger->error("Function failed: {}", errorMessage);

        return 1;
    }

    return 0;
}

bool WAMRWasmModule::isBound()
{
    return _isBound;
}

void WAMRWasmModule::tearDown()
{
    wasm_runtime_deinstantiate(moduleInstance);
    wasm_runtime_unload(wasmModule);
}

uint32_t WAMRWasmModule::mmapMemory(uint32_t length)
{
    void* nativePtr;
    wasm_runtime_module_malloc(moduleInstance, length, &nativePtr);
    int32 wasmPtr = wasm_runtime_addr_native_to_app(moduleInstance, nativePtr);
    return wasmPtr;
}

uint32_t WAMRWasmModule::mmapPages(uint32_t pages)
{
    uint32_t bytes = pages * WASM_BYTES_PER_PAGE;
    return mmapMemory(bytes);
}

uint8_t* WAMRWasmModule::wasmPointerToNative(int32_t wasmPtr)
{
    void* nativePtr = wasm_runtime_addr_app_to_native(moduleInstance, wasmPtr);
    return static_cast<uint8_t*>(nativePtr);
}

uint32_t WAMRWasmModule::mmapFile(uint32_t fp, uint32_t length)
{
    // TODO - implement
    return 0;
}
}
