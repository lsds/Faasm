#pragma once

#include <memory>
#include <mutex>
#include <vector>

#include <faabric/proto/faabric.pb.h>
#include <faabric/util/barrier.h>
#include <faabric/util/environment.h>
#include <faabric/util/locks.h>

namespace threads {

void clearOpenMPState();

class SerialisedLevel
{
  public:
    uint32_t id;
    int32_t depth;
    int32_t effectiveDepth;
    int32_t maxActiveLevels;
    int32_t nThreads;

    uint32_t nSharedVars = 0;
    uint32_t* sharedVars;
};

size_t sizeOfSerialisedLevel(SerialisedLevel& serialisedLevel);

// A Level is a layer of threads in an OpenMP application.
// Note, defaults are set to replicate the behaviour as of Clang 9.0.1
class Level
{
  public:
    // Id for this level
    uint32_t id;

    // Number of nested OpenMP constructs
    int depth = 0;

    // Number of parallel regions with more than 1 thread above this level
    int activeLevels = 0;

    // Max number of active parallel regions allowed
    int maxActiveLevels = 1;

    // Number of threads of this level
    int numThreads = 1;

    // Desired number of thread set by omp_set_num_threads for all future levels
    int wantedThreads = -1;

    // Num threads pushed by compiler, valid for one parallel section.
    // Overrides wantedThreads
    int pushedThreads = -1;

    std::vector<uint32_t> sharedVarPtrs;

    Level(int numThreadsIn);

    void fromParentLevel(const std::shared_ptr<Level>& parent);

    // Instance functions
    int getMaxThreadsAtNextLevel() const;

    void masterWait(int threadNum);

    SerialisedLevel serialise();

    void deserialise(const SerialisedLevel* serialised);

    void waitOnBarrier();

    void lockCritical();

    void unlockCritical();

    int getLocalThreadNum(faabric::Message* msg);

    int getGlobalThreadNum(int localThreadNum);

    int getGlobalThreadNum(faabric::Message* msg);
};

class PthreadTask
{
  public:
    PthreadTask(faabric::Message* parentMsgIn,
                std::shared_ptr<faabric::Message> msgIn)
      : parentMsg(parentMsgIn)
      , msg(msgIn)
    {}

    bool isShutdown = false;
    faabric::Message* parentMsg;
    std::shared_ptr<faabric::Message> msg;
};

class OpenMPTask
{
  public:
    faabric::Message* parentMsg;
    std::shared_ptr<faabric::Message> msg;
    std::shared_ptr<threads::Level> nextLevel;
    bool isShutdown = false;

    OpenMPTask(faabric::Message* parentMsgIn,
               std::shared_ptr<faabric::Message> msgIn,
               std::shared_ptr<threads::Level> nextLevelIn)
      : parentMsg(parentMsgIn)
      , msg(msgIn)
      , nextLevel(nextLevelIn)
    {}
};

std::shared_ptr<Level> getCurrentOpenMPLevel();

void setCurrentOpenMPLevel(
  const std::shared_ptr<faabric::BatchExecuteRequest> req);

void setCurrentOpenMPLevel(const std::shared_ptr<Level>& level);
}
