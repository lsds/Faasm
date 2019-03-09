#include "WorkerThreadPool.h"

#include <aws/aws.h>

#include <util/logging.h>
#include <util/config.h>

int main() {
    util::initLogging();

    scheduler::Scheduler &sch = scheduler::getScheduler();
    
    util::SystemConfig &config = util::getSystemConfig();
    config.print();

    awswrapper::initSDK();

    worker::WorkerThreadPool pool(config.threadsPerWorker);

    // Worker pool in background
    pool.startThreadPool();

    // Work sharing thread
//    pool.startSharingThread();
//
//    // State management thread
//    pool.startStateThread();

    // Global queue listener
    pool.startGlobalQueueThread();

    const std::shared_ptr<spdlog::logger> &logger = util::getLogger();
    logger->info("Removing from global working set");
    
    sch.clear();

    pool.shutdown();
}
