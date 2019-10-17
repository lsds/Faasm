#include "StateKeyValue.h"

#include <redis/Redis.h>
#include <util/config.h>
#include <util/memory.h>
#include <util/locks.h>
#include <util/logging.h>

#include <sys/mman.h>

using namespace util;

namespace state {

    /**
     * Key/value
     */
    StateKeyValue::StateKeyValue(const std::string &keyIn, size_t sizeIn) : key(keyIn),
                                                                            valueSize(sizeIn) {

        // Work out size of required shared memory
        size_t nHostPages = getRequiredHostPages(valueSize);
        sharedMemSize = nHostPages * HOST_PAGE_SIZE;
        sharedMemory = nullptr;

        isWholeValueDirty = false;
        isPartiallyDirty = false;
        _empty = true;
    }

    void StateKeyValue::pull() {
        const std::shared_ptr<spdlog::logger> &logger = getLogger();
        logger->debug("Pulling state for {}", key);
        pullImpl(false);
    }

    void StateKeyValue::pullImpl(bool onlyIfEmpty) {
        // Drop out if we already have the data and we don't care about updating
        {
            SharedLock lock(valueMutex);
            if(onlyIfEmpty && !_empty) {
                return;
            }
        }

        // Unique lock on the whole value
        FullLock lock(valueMutex);

        // Check condition again
        if(onlyIfEmpty && !_empty) {
            return;
        }

        // Initialise the storage if empty
        if (_empty) {
            initialiseStorage();
        }

        // Read from the remote
        redis::Redis &redis = redis::Redis::getState();
        redis.get(key, static_cast<uint8_t *>(sharedMemory), valueSize);

        _empty = false;
    }

    long StateKeyValue::waitOnRemoteLock() {
        const std::shared_ptr<spdlog::logger> &logger = getLogger();

        redis::Redis &redis = redis::Redis::getState();

        long remoteLockId = redis.acquireLock(key, remoteLockTimeout);
        unsigned int retryCount = 0;
        while (remoteLockId <= 0) {
            logger->debug("Waiting on remote lock for {} (loop {})", key, retryCount);

            if (retryCount >= remoteLockMaxRetries) {
                logger->error("Timed out waiting for lock on {}", key);
                break;
            }

            // usleep in microseconds
            usleep(remoteLockWaitTime * 1000);

            remoteLockId = redis.acquireLock(key, remoteLockTimeout);
            retryCount++;
        }

        return remoteLockId;
    }

    void StateKeyValue::get(uint8_t *buffer) {
        pullImpl(true);

        SharedLock lock(valueMutex);

        auto bytePtr = static_cast<uint8_t *>(sharedMemory);
        std::copy(bytePtr, bytePtr + valueSize, buffer);
    }

    uint8_t *StateKeyValue::get() {
        pullImpl(true);

        SharedLock lock(valueMutex);

        return static_cast<uint8_t *>(sharedMemory);
    }

    void StateKeyValue::getSegment(long offset, uint8_t *buffer, size_t length) {
        pullImpl(true);

        SharedLock lock(valueMutex);

        // Return just the required segment
        if ((offset + length) > valueSize) {
            const std::shared_ptr<spdlog::logger> &logger = getLogger();

            logger->error("Out of bounds read at {} on {} with length {}", offset + length, key, valueSize);
            throw std::runtime_error("Out of bounds read");
        }

        auto bytePtr = static_cast<uint8_t *>(sharedMemory);
        std::copy(bytePtr + offset, bytePtr + offset + length, buffer);
    }

    uint8_t *StateKeyValue::getSegment(long offset, long len) {
        pullImpl(true);

        SharedLock lock(valueMutex);

        uint8_t *segmentPtr = static_cast<uint8_t *>(sharedMemory) + offset;
        return segmentPtr;
    }

    void StateKeyValue::set(const uint8_t *buffer) {
        // Unique lock for setting the whole value
        FullLock lock(valueMutex);

        if (sharedMemory == nullptr) {
            initialiseStorage();
        }

        // Copy data into shared region
        std::copy(buffer, buffer + valueSize, static_cast<uint8_t *>(sharedMemory));
        isWholeValueDirty = true;
        _empty = false;
    }

    void StateKeyValue::setSegment(long offset, const uint8_t *buffer, size_t length) {
        const std::shared_ptr<spdlog::logger> &logger = getLogger();

        // Check we're in bounds
        size_t end = offset + length;
        if (end > valueSize) {
            logger->error("Trying to write segment finishing at {} (value length {})", end, valueSize);
            throw std::runtime_error("Attempting to set segment out of bounds");
        }

        // If empty, set to full size
        if (sharedMemory == nullptr) {
            FullLock lock(valueMutex);

            if (sharedMemory == nullptr) {
                initialiseStorage();
                _empty = false;
            }
        }

        // Check size
        if (offset + length > valueSize) {
            logger->error("Segment length {} at offset {} too big for size {}", length, offset, valueSize);
            throw std::runtime_error("Setting state segment too big for container");
        }

        // Copy data into shared region
        {
            SharedLock lock(valueMutex);
            auto bytePtr = static_cast<uint8_t *>(sharedMemory);
            std::copy(buffer, buffer + length, bytePtr + offset);
        }

        this->flagSegmentDirty(offset, length);
    }

    void StateKeyValue::flagFullValueDirty() {
        isWholeValueDirty = true;
    }

    void StateKeyValue::flagSegmentDirty(long offset, long len) {
        SharedLock lock(valueMutex);
        isPartiallyDirty = true;
        memset(dirtyFlags + offset, 1, len);
    }

    void StateKeyValue::clear() {
        // Unique lock on the whole value while clearing
        FullLock lock(valueMutex);

        const std::shared_ptr<spdlog::logger> &logger = getLogger();
        logger->debug("Clearing value {}", key);

        // Set flag to say this is effectively new again
        _empty = true;

        delete[] dirtyFlags;
        dirtyFlags = nullptr;
    }

    bool StateKeyValue::empty() {
        return _empty;
    }

    size_t StateKeyValue::size() {
        return valueSize;
    }

    void StateKeyValue::mapSharedMemory(void *newAddr) {
        const std::shared_ptr<spdlog::logger> &logger = getLogger();

        if (!isPageAligned(newAddr)) {
            logger->error("Attempting to map non-page-aligned memory at {} for {}", newAddr, key);
            throw std::runtime_error("Mapping misaligned shared memory");
        }

        FullLock lock(valueMutex);

        // Remap our existing shared memory onto this new region
        void *result = mremap(sharedMemory, 0, sharedMemSize, MREMAP_FIXED | MREMAP_MAYMOVE, newAddr);
        if (result == MAP_FAILED) {
            logger->error("Failed to map shared memory at {} with size {}. errno: {}",
                          sharedMemory, sharedMemSize, errno);

            throw std::runtime_error("Failed mapping shared memory");
        }

        if (newAddr != result) {
            logger->error("New mapped addr doesn't match required {} != {}",
                          newAddr, result);

            throw std::runtime_error("Misaligned shared memory mapping");
        }
    }

    void StateKeyValue::unmapSharedMemory(void *mappedAddr) {
        FullLock lock(valueMutex);
        const std::shared_ptr<spdlog::logger> &logger = getLogger();

        if (!isPageAligned(mappedAddr)) {
            logger->error("Attempting to unmap non-page-aligned memory at {} for {}", mappedAddr, key);
            throw std::runtime_error("Unmapping misaligned shared memory");
        }

        // Unmap the current memory so it can be reused
        int result = munmap(mappedAddr, sharedMemSize);
        if (result == -1) {
            logger->error("Failed to unmap shared memory at {} with size {}. errno: {}", mappedAddr, sharedMemSize,
                          errno);

            throw std::runtime_error("Failed unmapping shared memory");
        }
    }

    void StateKeyValue::initialiseStorage() {
        const std::shared_ptr<spdlog::logger> &logger = getLogger();

        if(sharedMemSize == 0) {
            throw StateKeyValueException("Initialising storage without a size for " + key);
        }

        // Create shared memory region
        sharedMemory = mmap(nullptr, sharedMemSize, PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (sharedMemory == MAP_FAILED) {
            logger->debug("Mmapping of storage size {} failed. errno: {}", sharedMemSize, errno);

            throw std::runtime_error("Failed mapping memory for KV");
        }

        logger->debug("Mmapped {} pages of shared storage for {}", sharedMemSize / HOST_PAGE_SIZE, key);

        // Set up dirty flags
        dirtyFlags = new short[valueSize];
    }

    void StateKeyValue::pushFull() {
        // Ignore if not dirty
        if (!isWholeValueDirty and !isPartiallyDirty) {
            return;
        }

        // Get full lock for complete push
        FullLock fullLock(valueMutex);

        // Double check condition
        if (!isWholeValueDirty and !isPartiallyDirty) {
            return;
        }

        const std::shared_ptr<spdlog::logger> &logger = getLogger();
        logger->debug("Pushing whole value for {}", key);

        redis::Redis &redis = redis::Redis::getState();
        redis.set(key, static_cast<uint8_t *>(sharedMemory), valueSize);

        // Remove any dirty flags
        isWholeValueDirty = false;
        if(isPartiallyDirty) {
            isPartiallyDirty = false;
            memset(dirtyFlags, 0, valueSize);
        }
    }

    void StateKeyValue::pushPartial() {
        // Ignore if the whole value is dirty or not partially dirty
        if (isWholeValueDirty || !isPartiallyDirty) {
            return;
        }

        const std::shared_ptr<spdlog::logger> &logger = getLogger();

        // Attempt to lock the value remotely
        redis::Redis &redis = redis::Redis::getState();
        long remoteLockId = this->waitOnRemoteLock();

        // If we don't get remote lock, just skip this push and wait for next one
        if (remoteLockId <= 0) {
            logger->debug("Failed to acquire remote lock for {}", key);
            return;
        }

        // logger->debug("Got remote lock for {} with id {}", key, remoteLockId);

        // TODO Potential locking issues here.
        // If we get the remote lock, then have to wait a long time for the local
        // value lock, the remote one may have expired by the time we get to updating
        // the value, and we end up clashing.

        // Create copy of the dirty flags and clear the old version
        bool * dirtyFlagsCopy = new bool[valueSize];
        {
            FullLock lock(valueMutex);

            // Double check condition
            if (isWholeValueDirty || !isPartiallyDirty) {
                logger->debug("Released remote lock (doing nothing) for {} with id {}", key, remoteLockId);
                redis.releaseLock(key, remoteLockId);
                return;
            }

            std::copy(dirtyFlags, dirtyFlags + valueSize, dirtyFlagsCopy);

            // Reset dirty flags
            isPartiallyDirty = false;
            memset(dirtyFlags, 0, valueSize);
        }

        // Don't need any more local locking here
        auto tempBuff = new uint8_t[valueSize];
        redis.get(key, tempBuff, valueSize);

        logger->debug("Pushing partial state for {}", key);

        // Go through all dirty flags and update value

        // Find first true flag
        auto start = std::find(dirtyFlagsCopy, dirtyFlagsCopy + valueSize, 1);

        // While we still have more segments
        while (start != dirtyFlagsCopy + valueSize) {
            // Find next false
            auto end = std::find(start + 1, dirtyFlagsCopy + valueSize, 0);

            // Copy the dirty parts into the new value
            long size = end - start;
            long offset = start - dirtyFlagsCopy;
            uint8_t *ptr = static_cast<uint8_t *>(sharedMemory) + offset;
            std::copy(ptr, ptr + size, tempBuff + offset);

            // Find next true
            start = std::find(end + 1, dirtyFlagsCopy + valueSize, true);
        }

        // Set whole value back again
        redis.set(key, tempBuff, valueSize);

        // Release remote lock
        redis.releaseLock(key, remoteLockId);
        logger->debug("Released remote lock for {} with id {}", key, remoteLockId);
    }

    void StateKeyValue::lockRead() {
        valueMutex.lock_shared();
    }

    void StateKeyValue::unlockRead() {
        valueMutex.unlock_shared();
    }

    void StateKeyValue::lockWrite() {
        valueMutex.lock();
    }

    void StateKeyValue::unlockWrite() {
        valueMutex.unlock();
    }
}