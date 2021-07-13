#include <wavm/WAVMWasmModule.h>

#include <faabric/util/config.h>
#include <faabric/util/func.h>
#include <faabric/util/locks.h>
#include <faabric/util/logging.h>

#include <sys/mman.h>

namespace wasm {
WAVMModuleCache& getWAVMModuleCache()
{
    static WAVMModuleCache r;
    return r;
}

size_t WAVMModuleCache::getTotalCachedModuleCount()
{
    return cachedModuleMap.size();
}

int WAVMModuleCache::getCachedModuleCount(const std::string& key)
{
    faabric::util::SharedLock lock(mx);
    int count = cachedModuleMap.count(key);
    return count;
}

wasm::WAVMWasmModule& WAVMModuleCache::getCachedModule(faabric::Message& msg)
{
    std::string key = faabric::util::funcToString(msg, false);

    // If there's no cached module, we need to create it
    if (cachedModuleMap.find(key) == cachedModuleMap.end()) {
        faabric::util::FullLock lock(mx);

        // Re-check condition
        if (cachedModuleMap.find(key) == cachedModuleMap.end()) {

            SPDLOG_DEBUG("WAVM module cache initialising {}", key);

            // Instantiate the base module
            wasm::WAVMWasmModule& module = cachedModuleMap[key];
            module.bindToFunction(msg, false);
        }
    }

    {
        // Note that we need a shared lock here to avoid a race condition on
        // initialising the module
        faabric::util::SharedLock lock(mx);
        return cachedModuleMap[key];
    }
}

void WAVMModuleCache::clear()
{
    cachedModuleMap.clear();
}
}
