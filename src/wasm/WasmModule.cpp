#include "wasm/WasmModule.h"

#include <faabric/snapshot/SnapshotRegistry.h>
#include <faabric/util/bytes.h>
#include <faabric/util/config.h>
#include <faabric/util/environment.h>
#include <faabric/util/func.h>
#include <faabric/util/gids.h>
#include <faabric/util/locks.h>
#include <faabric/util/memory.h>
#include <faabric/util/timing.h>

#include <boost/filesystem.hpp>
#include <sstream>
#include <sys/mman.h>
#include <sys/uio.h>

namespace wasm {
// Using TLS here to isolate between executing functions
static thread_local faabric::Message* executingCall;

bool isWasmPageAligned(int32_t offset)
{
    if (offset & (WASM_BYTES_PER_PAGE - 1)) {
        return false;
    } else {
        return true;
    }
}

faabric::Message* getExecutingCall()
{
    return executingCall;
}

void setExecutingCall(faabric::Message* other)
{
    executingCall = other;
}

size_t getNumberOfWasmPagesForBytes(uint32_t nBytes)
{
    // Round up to nearest page
    size_t pageCount =
      (size_t(nBytes) + WASM_BYTES_PER_PAGE - 1) / WASM_BYTES_PER_PAGE;

    return pageCount;
}

uint32_t roundUpToWasmPageAligned(uint32_t nBytes)
{
    size_t nPages = getNumberOfWasmPagesForBytes(nBytes);
    return (uint32_t)(nPages * WASM_BYTES_PER_PAGE);
}

size_t getPagesForGuardRegion()
{
    size_t regionSize = GUARD_REGION_SIZE;
    size_t nWasmPages = getNumberOfWasmPagesForBytes(regionSize);
    return nWasmPages;
}

WasmModule::~WasmModule()
{
    // Does nothing
}

void WasmModule::flush() {}

storage::FileSystem& WasmModule::getFileSystem()
{
    return filesystem;
}

wasm::WasmEnvironment& WasmModule::getWasmEnvironment()
{
    return wasmEnvironment;
}

std::string WasmModule::snapshot(bool locallyRestorable)
{
    PROF_START(wasmSnapshot)

    // Create snapshot key
    uint32_t gid = faabric::util::generateGid();
    std::string snapKey =
      this->boundUser + "_" + this->boundFunction + "_" + std::to_string(gid);

    // Note - we only want to take the snapshot to the current brk, not the top
    // of the allocated memory
    faabric::util::SnapshotData data;
    data.data = getMemoryBase();
    data.size = getCurrentBrk();

    faabric::snapshot::SnapshotRegistry& reg =
      faabric::snapshot::getSnapshotRegistry();
    reg.takeSnapshot(snapKey, data, locallyRestorable);

    PROF_END(wasmSnapshot)

    return snapKey;
}

void WasmModule::restore(const std::string& snapshotKey)
{
    PROF_START(wasmSnapshotRestore)

    auto logger = faabric::util::getLogger();
    faabric::snapshot::SnapshotRegistry& reg =
      faabric::snapshot::getSnapshotRegistry();

    // Expand memory if necessary
    faabric::util::SnapshotData data = reg.getSnapshot(snapshotKey);
    uint32_t memSize = getCurrentBrk();
    if (data.size == memSize) {
        logger->debug("Snapshot memory size equal to current memory");
    } else if (data.size > memSize) {
        logger->debug("Growing memory to fit snapshot");
        size_t bytesRequired = data.size - memSize;
        this->growMemory(bytesRequired);
    } else {
        logger->debug("Shrinking memory to fit snapshot");
        size_t shrinkBy = memSize - data.size;
        this->shrinkMemory(shrinkBy);
    }

    // Map the snapshot into memory
    uint8_t* memoryBase = getMemoryBase();
    reg.mapSnapshot(snapshotKey, memoryBase);

    PROF_END(wasmSnapshotRestore)
}

std::string WasmModule::getBoundUser()
{
    return boundUser;
}

std::string WasmModule::getBoundFunction()
{
    return boundFunction;
}

int WasmModule::getStdoutFd()
{
    if (stdoutMemFd == 0) {
        stdoutMemFd = memfd_create("stdoutfd", 0);
        faabric::util::getLogger()->debug("Capturing stdout: fd={}",
                                          stdoutMemFd);
    }

    return stdoutMemFd;
}

ssize_t WasmModule::captureStdout(const struct iovec* iovecs, int iovecCount)
{
    int memFd = getStdoutFd();
    ssize_t writtenSize = ::writev(memFd, iovecs, iovecCount);

    if (writtenSize < 0) {
        faabric::util::getLogger()->error("Failed capturing stdout: {}",
                                          strerror(errno));
        throw std::runtime_error(std::string("Failed capturing stdout: ") +
                                 strerror(errno));
    }

    faabric::util::getLogger()->debug("Captured {} bytes of formatted stdout",
                                      writtenSize);
    stdoutSize += writtenSize;
    return writtenSize;
}

ssize_t WasmModule::captureStdout(const void* buffer)
{
    int memFd = getStdoutFd();

    ssize_t writtenSize =
      dprintf(memFd, "%s\n", reinterpret_cast<const char*>(buffer));

    if (writtenSize < 0) {
        faabric::util::getLogger()->error("Failed capturing stdout: {}",
                                          strerror(errno));
        throw std::runtime_error("Failed capturing stdout");
    }

    faabric::util::getLogger()->debug("Captured {} bytes of unformatted stdout",
                                      writtenSize);
    stdoutSize += writtenSize;
    return writtenSize;
}

std::string WasmModule::getCapturedStdout()
{
    if (stdoutSize == 0) {
        return "";
    }

    // Go back to start
    int memFd = getStdoutFd();
    lseek(memFd, 0, SEEK_SET);

    // Read in and return
    char* buf = new char[stdoutSize];
    read(memFd, buf, stdoutSize);
    std::string stdoutString(buf, stdoutSize);
    faabric::util::getLogger()->debug(
      "Read stdout length {}:\n{}", stdoutSize, stdoutString);

    return stdoutString;
}

void WasmModule::clearCapturedStdout()
{
    close(stdoutMemFd);
    stdoutMemFd = 0;
    stdoutSize = 0;
}

uint32_t WasmModule::getArgc()
{
    return argc;
}

uint32_t WasmModule::getArgvBufferSize()
{
    return argvBufferSize;
}

void WasmModule::prepareArgcArgv(const faabric::Message& msg)
{
    // Here we set up the arguments to main(), i.e. argc and argv
    // We allow passing of arbitrary commandline arguments via the invocation
    // message. These are passed as a string with a space separating each
    // argument.
    argv = faabric::util::getArgvForMessage(msg);
    argc = argv.size();

    // Work out the size of the buffer to hold the strings (allowing
    // for null terminators)
    argvBufferSize = 0;
    for (const auto& thisArg : argv) {
        argvBufferSize += thisArg.size() + 1;
    }
}

/**
 * Maps the given state into the module's memory.
 *
 * If we are dealing with a chunk of a larger state value, the host memory
 * will be reserved for the full value, but only the necessary wasm pages
 * will be created. Loading many chunks of the same value leads to
 * fragmentation, but usually only one or two chunks are loaded per module.
 *
 * To perform the mapping we need to ensure allocated memory is page-aligned.
 */
uint32_t WasmModule::mapSharedStateMemory(
  const std::shared_ptr<faabric::state::StateKeyValue>& kv,
  long offset,
  uint32_t length)
{
    // See if we already have this segment mapped into memory
    std::string segmentKey = kv->user + "_" + kv->key + "__" +
                             std::to_string(offset) + "__" +
                             std::to_string(length);
    if (sharedMemWasmPtrs.count(segmentKey) == 0) {
        // Lock and double check
        faabric::util::UniqueLock lock(moduleStateMutex);
        if (sharedMemWasmPtrs.count(segmentKey) == 0) {
            // Page-align the chunk
            faabric::util::AlignedChunk chunk =
              faabric::util::getPageAlignedChunk(offset, length);

            // Create the wasm memory region and work out the offset to the
            // start of the desired chunk in this region (this will be zero if
            // the offset is already zero, or if the offset is page-aligned
            // already).
            // We need to round the allocation up to a wasm page boundary
            uint32_t allocSize = roundUpToWasmPageAligned(chunk.nBytesLength);
            uint32_t wasmBasePtr = this->growMemory(allocSize);
            uint32_t wasmOffsetPtr = wasmBasePtr + chunk.offsetRemainder;

            // Map the shared memory
            uint8_t* wasmMemoryRegionPtr = wasmPointerToNative(wasmBasePtr);
            kv->mapSharedMemory(static_cast<void*>(wasmMemoryRegionPtr),
                                chunk.nPagesOffset,
                                chunk.nPagesLength);

            // Cache the wasm pointer
            sharedMemWasmPtrs[segmentKey] = wasmOffsetPtr;
        }
    }

    // Return the wasm pointer
    return sharedMemWasmPtrs[segmentKey];
}

uint32_t WasmModule::getCurrentBrk()
{
    return currentBrk;
}

uint32_t WasmModule::createMemoryGuardRegion()
{
    auto logger = faabric::util::getLogger();

    size_t regionSize = GUARD_REGION_SIZE;
    uint32_t wasmOffset = growMemory(regionSize);

    uint8_t* nativePtr = wasmPointerToNative(wasmOffset);

    // NOTE: we want to protect these regions from _writes_, but we don't want
    // to stop them being read, otherwise snapshotting will fail. Therefore we
    // make them read-only
    int res = mprotect(nativePtr, regionSize, PROT_READ);
    if (res != 0) {
        logger->error("Failed to create memory guard: {}",
                      std::strerror(errno));
        throw std::runtime_error("Failed to create memory guard");
    }

    logger->debug(
      "Created guard region {}-{}", wasmOffset, wasmOffset + regionSize);

    return wasmOffset;
}

void WasmModule::addThreadStackToPool()
{
    createMemoryGuardRegion();
    uint32_t thisStack = growMemory(THREAD_STACK_SIZE);
    createMemoryGuardRegion();

    threadStacks.push_back(thisStack);
}

void WasmModule::createThreadStackPool()
{
    auto logger = faabric::util::getLogger();

    faabric::util::UniqueLock lock(threadStackMutex);

    uint32_t cores = faabric::util::getUsableCores();
    uint32_t poolSize = cores + 5;
    logger->debug(
      "Creating thread stack pool size {} (cores={})", poolSize, cores);

    for (int i = 0; i < poolSize; i++) {
        addThreadStackToPool();
    }
}

void WasmModule::returnThreadStack(uint32_t wasmPtr)
{
    faabric::util::UniqueLock lock(threadStackMutex);

    auto logger = faabric::util::getLogger();
    logger->debug("Returned thread stack {}", wasmPtr);
    threadStacks.push_back(wasmPtr);
}

uint32_t WasmModule::claimThreadStack()
{
    faabric::util::UniqueLock lock(threadStackMutex);

    auto logger = faabric::util::getLogger();

    if (threadStacks.empty()) {
        logger->warn("Thread stack pool empty, having to allocate from heap");
        addThreadStackToPool();
    }

    uint32_t wasmPtr = threadStacks.back();
    threadStacks.pop_back();
    logger->debug("Claimed thread stack {}", wasmPtr);
    return wasmPtr;
}

// ------------------------------------------
// Functions to be implemented by subclasses
// ------------------------------------------

void WasmModule::bindToFunction(const faabric::Message& msg)
{
    throw std::runtime_error("bindToFunction not implemented");
}

void WasmModule::bindToFunctionNoZygote(const faabric::Message& msg)
{
    throw std::runtime_error("bindToFunctionNoZygote not implemented");
}

bool WasmModule::execute(faabric::Message& msg, bool forceNoop)
{
    throw std::runtime_error("execute not implemented");
}

bool WasmModule::executeAsOMPThread(faabric::Message& msg)
{
    throw std::runtime_error("executeAsOMPThread not implemented");
}

bool WasmModule::isBound()
{
    throw std::runtime_error("isBound not implemented");
}

void WasmModule::writeArgvToMemory(uint32_t wasmArgvPointers,
                                   uint32_t wasmArgvBuffer)
{
    throw std::runtime_error("writeArgvToMemory not implemented");
}

void WasmModule::writeWasmEnvToMemory(uint32_t envPointers, uint32_t envBuffer)
{
    throw std::runtime_error("writeWasmEnvToMemory not implemented");
}

uint32_t WasmModule::growMemory(uint32_t nBytes)
{
    throw std::runtime_error("growMemory not implemented");
}

void WasmModule::shrinkMemory(uint32_t nBytes)
{
    throw std::runtime_error("shrinkMemory not implemented");
}

uint32_t WasmModule::mmapMemory(uint32_t nBytes)
{
    throw std::runtime_error("mmapMemory not implemented");
}

uint32_t WasmModule::mmapFile(uint32_t fp, uint32_t length)
{
    throw std::runtime_error("mmapFile not implemented");
}

void WasmModule::unmapMemory(uint32_t offset, uint32_t nBytes)
{
    throw std::runtime_error("unmapMemory not implemented");
}

uint8_t* WasmModule::wasmPointerToNative(int32_t wasmPtr)
{
    throw std::runtime_error("wasmPointerToNative not implemented");
}

void WasmModule::printDebugInfo()
{
    throw std::runtime_error("printDebugInfo not implemented");
}

size_t WasmModule::getMemorySizeBytes()
{
    throw std::runtime_error("getMemorySizeBytes not implemented");
}

uint8_t* WasmModule::getMemoryBase()
{
    throw std::runtime_error("getMemoryBase not implemented");
}
}
