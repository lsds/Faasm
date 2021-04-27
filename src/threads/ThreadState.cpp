#include <faabric/util/config.h>
#include <faabric/util/timing.h>
#include <threads/ThreadState.h>

using namespace faabric::util;

namespace threads {

static thread_local std::shared_ptr<Level> currentLevel;

size_t sizeOfSerialisedLevel(SerialisedLevel& serialisedLevel)
{
    size_t slSize = sizeof(serialisedLevel);
    slSize += serialisedLevel.nSharedVars * sizeof(uint32_t);

    return slSize;
}

void setCurrentOpenMPLevel(const std::shared_ptr<Level>& level)
{
    currentLevel = level;
}

void setCurrentOpenMPLevel(
  const std::shared_ptr<faabric::BatchExecuteRequest> req)
{
    const SerialisedLevel* serialisedLevel =
      reinterpret_cast<const SerialisedLevel*>(req->contextdata().data());

    currentLevel = std::make_shared<Level>(serialisedLevel->nThreads);
    currentLevel->deserialise(serialisedLevel);
}

std::shared_ptr<Level> getCurrentOpenMPLevel()
{
    return currentLevel;
}

Level::Level(int numThreadsIn)
  : numThreads(numThreadsIn)
  , barrier(numThreadsIn)
{}

void Level::fromParentLevel(const std::shared_ptr<Level>& parent)
{
    depth = parent->depth + 1;

    if (numThreads > 1) {
        activeLevels = parent->activeLevels + 1;
    } else {
        activeLevels = parent->activeLevels;
    }

    maxActiveLevels = parent->maxActiveLevels;
}

int Level::getMaxThreadsAtNextLevel() const
{
    // Limit to one thread if the next level exceededs max active levels
    if (activeLevels >= maxActiveLevels) {
        return 1;
    }

    // Return pushed number if set
    if (pushedThreads > 0) {
        return pushedThreads;
    }

    // Return wanted number if set
    if (wantedThreads > 0) {
        return wantedThreads;
    }

    int defaultNumThreads = faabric::util::getUsableCores();
    return defaultNumThreads;
}

void Level::masterWait(int threadNum)
{
    // All threads must lock when entering this function
    std::unique_lock<std::mutex> lock(nowaitMutex);

    if (threadNum == 0) {
        // Wait until all non-master threads have finished
        while (nowaitCount < numThreads - 1) {
            nowaitCv.wait(lock);
        }

        // Reset, after we've finished
        nowaitCount = 0;
    } else {
        // Notify master that this thread has finished and continue
        nowaitCount++;
        nowaitCv.notify_one();
    }
}

SerialisedLevel Level::serialise()
{
    SerialisedLevel sl;
    sl.depth = depth;
    sl.effectiveDepth = activeLevels;
    sl.maxActiveLevels = maxActiveLevels;
    sl.nThreads = numThreads;

    sl.nSharedVars = sharedVarPtrs.size();
    sl.sharedVars = sharedVarPtrs.data();

    return sl;
}

void Level::deserialise(const SerialisedLevel* level)
{
    depth = level->depth;
    activeLevels = level->effectiveDepth;
    maxActiveLevels = level->maxActiveLevels;
    numThreads = level->nThreads;

    for (int i = 0; i < level->nSharedVars; i++) {
        sharedVarPtrs.emplace_back(level->sharedVars[i]);
    }
}
}
