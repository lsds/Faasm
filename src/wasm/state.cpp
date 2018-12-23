#include <prof/prof.h>

#include "wasm.h"

namespace wasm {
    typedef std::unique_lock<std::shared_mutex> FullLock;
    typedef std::shared_lock<std::shared_mutex> SharedLock;

    /**
     * Shared memory segment
     */
    StateMemorySegment::StateMemorySegment(Uptr offsetIn, uint8_t *ptrIn, size_t lengthIn) : offset(offsetIn),
                                                                                             ptr(ptrIn),
                                                                                             length(lengthIn) {

        inUse = true;
    }

    /**
     * Shared memory
     */
    StateMemory::StateMemory(const std::string &userIn) : user(userIn) {
        compartment = Runtime::createCompartment();

        // Prepare memory, each user can have up to 1000
        IR::MemoryType memoryType(true, {0, 1000});

        // Create a shared memory for this user
        wavmMemory = Runtime::createMemory(compartment, memoryType, user + "_shared");

        // Create some space initially
        Runtime::growMemory(wavmMemory, 5);

        nextByte = 0;
    }

    StateMemory::~StateMemory() {
        wavmMemory = nullptr;

        Runtime::tryCollectCompartment(std::move(compartment));
    };

    uint8_t *StateMemory::createSegment(size_t length) {
        const std::shared_ptr<spdlog::logger> logger = util::getLogger();

        // Need to lock the whole memory to make changes
        FullLock lock(memMutex);

        Uptr bytesToAdd = (Uptr) length;
        Uptr thisStart = nextByte;
        nextByte += bytesToAdd;

        // See if we need to grow
        Uptr requiredPages = getNumberOfPagesForBytes(nextByte);
        const Uptr currentPageCount = getMemoryNumPages(wavmMemory);
        Uptr maxPages = getMemoryMaxPages(wavmMemory);
        if (requiredPages > maxPages) {
            logger->error("Allocating {} pages of shared memory when max is {}", requiredPages, maxPages);
            throw std::runtime_error("Attempting to allocate more than max pages of shared memory.");
        }

        // Grow memory if required
        if (requiredPages > currentPageCount) {
            Uptr expansion = requiredPages - currentPageCount;
            growMemory(wavmMemory, expansion);
        }

        // Return pointer to memory
        U8 *ptr = Runtime::memoryArrayPtr<U8>(wavmMemory, thisStart, length);

        // Record the use of this segment
        segments.emplace_back(StateMemorySegment(thisStart, ptr, length));

        return ptr;
    }

    void StateMemory::releaseSegment(uint8_t *ptr) {
        // Lock the memory to make changes
        FullLock lock(memMutex);

        // TODO make this more efficient
        for (auto s : segments) {
            if (s.ptr == ptr) {
                s.inUse = false;
                break;
            }
        }
    }

    /**
     * Key/value
     */
    StateKeyValue::StateKeyValue(const std::string &keyIn, size_t sizeIn) : key(keyIn),
                                                                            size(sizeIn) {

        isWholeValueDirty = false;
        _empty = true;

        // Gets over the stale threshold trigger a pull from remote
        const util::SystemConfig &conf = util::getSystemConfig();
        staleThreshold = conf.stateStaleThreshold;

        // State over the clear threshold is removed from local
        idleThreshold = conf.stateClearThreshold;
    }

    void StateKeyValue::pull(bool async) {
        this->updateLastInteraction();

        // Check if new (one-off initialisation)
        if (_empty) {
            // Unique lock on the whole value while loading
            FullLock lock(valueMutex);

            // Double check assumption
            if (_empty) {
                const std::shared_ptr<spdlog::logger> &logger = util::getLogger();
                logger->debug("Initialising state for {}", key);

                doRemoteRead();
                _empty = false;
                return;
            }
        }

        const std::shared_ptr<spdlog::logger> &logger = util::getLogger();

        if(async) {
            // Check staleness
            util::Clock &clock = util::getGlobalClock();
            const util::TimePoint now = clock.now();

            // If stale, try to update from remote
            if (this->isStale(now)) {
                // Unique lock on the whole value while loading
                FullLock lock(valueMutex);

                // Double check staleness
                if (this->isStale(now)) {
                    logger->debug("Refreshing stale state for {}", key);
                    doRemoteRead();
                }
            }
        }
        else {
            FullLock lock(valueMutex);
            logger->debug("Sync read for state {}", key);
            doRemoteRead();
        }
    }

    void StateKeyValue::doRemoteRead() {
        // Initialise the data array with zeroes
        if(_empty) {
            value.resize(size);
        }

        // Read from the remote
        infra::Redis *redis = infra::Redis::getThreadState();
        redis->get(key, value.data(), size);

        util::Clock &clock = util::getGlobalClock();
        const util::TimePoint now = clock.now();
        lastPull = now;

        this->updateLastInteraction();
    }

    void StateKeyValue::updateLastInteraction() {
        util::Clock &clock = util::getGlobalClock();
        const util::TimePoint now = clock.now();
        lastInteraction = now;
    }

    bool StateKeyValue::isStale(const util::TimePoint &now) {
        util::Clock &clock = util::getGlobalClock();
        long age = clock.timeDiff(now, lastPull);
        return age > staleThreshold;
    }

    bool StateKeyValue::isIdle(const util::TimePoint &now) {
        util::Clock &clock = util::getGlobalClock();
        long idleTime = clock.timeDiff(now, lastInteraction);
        return idleTime > idleThreshold;
    }

    void StateKeyValue::get(uint8_t *buffer) {
        if(this->empty()) {
            throw std::runtime_error("Must pull before accessing state");
        }

        this->updateLastInteraction();

        // Shared lock for full reads
        SharedLock lock(valueMutex);

        std::copy(value.data(), value.data() + size, buffer);
    }

    void StateKeyValue::getSegment(long offset, uint8_t *buffer, size_t length) {
        if(this->empty()) {
            throw std::runtime_error("Must pull before accessing state");
        }

        this->updateLastInteraction();

        SharedLock lock(valueMutex);

        // Return just the required segment
        if ((offset + length) > size) {
            const std::shared_ptr<spdlog::logger> &logger = util::getLogger();

            logger->error("Out of bounds read at {} on {} with length {}", offset + length, key, size);
            throw std::runtime_error("Out of bounds read");
        }

        std::copy(value.data() + offset, value.data() + offset + length, buffer);
    }

    void StateKeyValue::set(uint8_t *buffer) {
        this->updateLastInteraction();

        // Unique lock for setting the whole value
        FullLock lock(valueMutex);

        if(value.empty()) {
            value.resize(size);
        }

        // Copy data into shared region
        std::copy(buffer, buffer + size, value.data());

        isWholeValueDirty = true;
        _empty = false;
    }

    void StateKeyValue::setSegment(long offset, uint8_t *buffer, size_t length) {
        this->updateLastInteraction();

        // Check we're in bounds
        size_t end = offset + length;
        if (end > size) {
            const std::shared_ptr<spdlog::logger> &logger = util::getLogger();
            logger->error("Trying to write segment finishing at {} (value length {})", end, size);
            throw std::runtime_error("Attempting to set segment out of bounds");
        }

        // If empty, set to full size
        if(value.empty()) {
            FullLock lock(valueMutex);
            if(value.empty()) {
                value.resize(size);
            }
        }

        // Record that this segment is dirty
        {
            FullLock segmentsLock(dirtySegmentsMutex);
            dirtySegments.insert(Segment(offset, end));
        }

        // Check size
        if (offset + length > size) {
            const std::shared_ptr<spdlog::logger> &logger = util::getLogger();

            logger->error("Segment length {} at offset {} too big for size {}", length, offset, size);
            throw std::runtime_error("Setting state segment too big for container");
        }

        // Copy data into shared region
        SharedLock lock(valueMutex);
        std::copy(buffer, buffer + length, value.data() + offset);
    }

    void StateKeyValue::clear() {
        // Check age since last interaction
        util::Clock &c = util::getGlobalClock();
        util::TimePoint now = c.now();

        // If over clear threshold, remove
        if (this->isIdle(now) && !_empty) {
            // Unique lock on the whole value while clearing
            FullLock lock(valueMutex);

            // Double check still over the threshold
            if (this->isIdle(now)) {
                const std::shared_ptr<spdlog::logger> &logger = util::getLogger();
                logger->debug("Clearing unused value {}", key);

                value.clear();

                // Set flag to say this is effectively new again
                _empty = true;
            }
        }
    }

    bool StateKeyValue::empty() {
        return _empty;
    }

    void StateKeyValue::pushFull() {
        // Double check condition
        if (!isWholeValueDirty) {
            return;
        }

        // Get full lock for complete write
        FullLock fullLock(valueMutex);

        // Double check condition
        if (!isWholeValueDirty) {
            return;
        }

        const std::shared_ptr<spdlog::logger> &logger = util::getLogger();
        logger->debug("Pushing whole value for {}", key);

        infra::Redis *redis = infra::Redis::getThreadState();
        redis->set(key, value.data(), size);

        // Reset (as we're setting the full value, we've effectively pulled)
        util::Clock &clock = util::getGlobalClock();
        lastPull = clock.now();
        isWholeValueDirty = false;
        dirtySegments.clear();
    }

    SegmentSet StateKeyValue::mergeSegments(SegmentSet setIn) {
        SegmentSet mergedSet;

        if (setIn.size() < 2) {
            mergedSet = setIn;
            return mergedSet;
        }

        // Note: standard set sort order does fine here
        long count = 0;
        long currentStart = INT_MAX;
        long currentEnd = -INT_MAX;

        for (const auto p : setIn) {
            // On first loop, just set up
            if (count == 0) {
                currentStart = p.first;
                currentEnd = p.second;
                count++;
                continue;
            }

            if (p.first > currentEnd) {
                // If new segment is disjoint, write the last one and continue
                mergedSet.insert(Segment(currentStart, currentEnd));

                currentStart = p.first;
                currentEnd = p.second;
            } else {
                // Update current segment if not
                currentEnd = std::max(p.second, currentEnd);
            }

            // If on the last loop, make sure we've recorded the current range
            if (count == setIn.size() - 1) {
                mergedSet.insert(Segment(currentStart, currentEnd));
            }

            count++;
        }

        return mergedSet;
    }

    void StateKeyValue::pushPartial() {
        // Ignore if the whole value is dirty
        if (isWholeValueDirty) {
            return;
        }

        // Create copy of the dirty segments and clear the old version
        SegmentSet dirtySegmentsCopy;
        {
            FullLock segmentsLock(dirtySegmentsMutex);
            dirtySegmentsCopy = dirtySegments;
            dirtySegments.clear();
        }

        // Merge segments that are next to each other to save on writes
        SegmentSet segmentsToMerge = this->mergeSegments(dirtySegmentsCopy);

        // Shared lock for writing segments
        SharedLock sharedLock(valueMutex);

        // Write the dirty segments
        const std::shared_ptr<spdlog::logger> &logger = util::getLogger();
        for (const auto segment : segmentsToMerge) {
            logger->debug("Pushing partial value for {} ({} - {})", key, segment.first, segment.second);

            long size = segment.second - segment.first;
            infra::Redis *redis = infra::Redis::getThreadState();
            redis->setRange(
                    key,
                    segment.first,
                    value.data() + segment.first,
                    (size_t) size
            );
        }
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

    /**
     * User state (can have multiple key/ values)
     */

    UserState::UserState(const std::string &userIn) : user(userIn) {

    }

    UserState::~UserState() {
        // Delete contents of key value store
        for (const auto &iter: kvMap) {
            delete iter.second;
        }
    }

    StateKeyValue *UserState::getValue(const std::string &key, size_t size) {
        if (kvMap.count(key) == 0) {
            if (size == 0) {
                throw std::runtime_error("Must provide a size when getting a value that's not already present");
            }

            // Lock on editing local state registry
            FullLock fullLock(kvMapMutex);

            std::string actualKey = user + "_" + key;

            // Double check it still doesn't exist
            if (kvMap.count(key) == 0) {
                auto kv = new StateKeyValue(actualKey, size);

                kvMap.emplace(KVPair(key, kv));
            }
        }

        return kvMap[key];
    }

    void UserState::pushAll() {
        // Iterate through all key-values
        SharedLock sharedLock(kvMapMutex);

        for (const auto &kv : kvMap) {
            // Attempt to push partial updates
            kv.second->pushPartial();

            // Attempt to push partial updates
            kv.second->pushFull();

            // Attempt to clear (will be ignored if not relevant)
            kv.second->clear();
        }
    }

    /**
     * Global state (can hold many users' state)
     */

    State &getGlobalState() {
        static State s;
        return s;
    }

    State::State() {
        const util::SystemConfig &conf = util::getSystemConfig();
        pushInterval = conf.statePushInterval;
    }

    State::~State() {
        // Delete contents of user state map
        for (const auto &iter: userStateMap) {
            delete iter.second;
        }
    }

    void State::pushLoop() {
        while (true) {
            // usleep takes microseconds
            usleep(1000 * pushInterval);

            this->pushAll();
        }
    }

    void State::pushAll() {
        // Run the sync for all users' state
        for (const auto &iter: userStateMap) {
            iter.second->pushAll();
        }
    }

    StateKeyValue *State::getKV(const std::string &user, const std::string &key, size_t size) {
        UserState *us = this->getUserState(user);
        return us->getValue(key, size);
    }

    UserState *State::getUserState(const std::string &user) {
        if (userStateMap.count(user) == 0) {
            // Lock on editing user state registry
            FullLock fullLock(userStateMapMutex);

            // Double check it still doesn't exist
            if (userStateMap.count(user) == 0) {
                auto s = new UserState(user);

                userStateMap.emplace(UserStatePair(user, s));
            }
        }

        return userStateMap[user];
    }
}