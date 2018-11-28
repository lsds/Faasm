#include "worker.h"

#include <infra/infra.h>
#include <prof/prof.h>

#include <spdlog/spdlog.h>
#include <thread>


namespace worker {
    static util::TokenPool tokenPool(infra::N_THREADS_PER_WORKER);

    void startWorkerThreadPool() {
        // Spawn worker threads until we've hit the limit (thus creating a pool that will replenish
        // when one releases its token)
        while (true) {
            // Try to get an available slot (blocks if none available)
            int workerIdx = tokenPool.getToken();

            // Spawn thread to execute function
            std::thread funcThread([workerIdx] {
                WorkerThread w(workerIdx);
                w.run();
            });

            funcThread.detach();
        }
    }

    WorkerThread::WorkerThread(int workerIdx) : workerIdx(workerIdx) {
        const std::shared_ptr<spdlog::logger> &logger = util::getLogger();
        logger->debug("Cold starting worker {}", workerIdx);

        const std::string hostname = util::getEnvVar("HOSTNAME", "");
        id = hostname + "_" + std::to_string(workerIdx);

        // Get Redis connection
        redis = infra::Redis::getThreadConnection();

        // If we need more prewarm containers, set this worker to be prewarm.
        // If not, sit in cold queue
        long prewarmCount = redis->scard(infra::PREWARM_SET);
        if(prewarmCount < infra::PREWARM_TARGET) {
            this->initialise();
        }
        else {
            // Add to cold
            this->updateQueue(infra::COLD_QUEUE, infra::COLD_SET);
        }
    }

    WorkerThread::~WorkerThread() {
        delete ns;

        delete module;
    }

    void WorkerThread::updateQueue(const std::string &queueName, const std::string &setName) {
        // Remove from current queue if necessary
        if(!currentQueue.empty()) {
            redis->srem(currentSet, id);
        }

        currentQueue = queueName;
        currentSet = setName;

        // Add to new queue
        redis->sadd(currentSet, id);
    }

    void WorkerThread::initialise() {
        const std::shared_ptr<spdlog::logger> &logger = util::getLogger();
        logger->debug("Prewarming worker {}", workerIdx);

        // Set up network namespace
        isolationIdx = workerIdx + 1;
        std::string netnsName = BASE_NETNS_NAME + std::to_string(isolationIdx);
        ns = new NetworkNamespace(netnsName);
        ns->addCurrentThread();

        // Add this thread to the cgroup
        CGroup cgroup(BASE_CGROUP_NAME);
        cgroup.addCurrentThread();

        // Initialise wasm module
        module = new wasm::WasmModule();
        module->initialise();

        // Add to prewarm
        this->updateQueue(infra::PREWARM_QUEUE, infra::PREWARM_SET);
    }

    const bool WorkerThread::isBound() {
        return _isBound;
    }

    void WorkerThread::finish() {
        ns->removeCurrentThread();
        tokenPool.releaseToken(workerIdx);

        // Remove from set
        redis->srem(currentSet, id);
    }

    void WorkerThread::finishCall(message::Message &call, const std::string &errorMsg) {
        const std::shared_ptr<spdlog::logger> &logger = util::getLogger();
        logger->info("Finished {}", infra::funcToString(call));

        bool isSuccess = errorMsg.empty();
        if (!isSuccess) {
            call.set_outputdata(errorMsg);
        }

        // Set result
        redis->setFunctionResult(call, isSuccess);

        // Restore the module memory after the execution
        // module->restoreCleanMemory();
    }

    void WorkerThread::bindToFunction(const message::Message &msg) {
        const std::shared_ptr<spdlog::logger> &logger = util::getLogger();
        logger->info("WorkerThread binding to {}", infra::funcToString(msg));

        // Check if the target has already been reached, in which case ignore
        const std::string newSet = infra::getFunctionSetName(msg);
        long currentCount = redis->scard(newSet);
        if (currentCount >= msg.target()) {
            return;
        }

        // Bind to new function
        this->updateQueue(infra::getFunctionQueueName(msg), newSet);
        module->bindToFunction(msg);

        _isBound = true;
    }

    void WorkerThread::run() {
        const std::shared_ptr<spdlog::logger> &logger = util::getLogger();

        // Wait for next message
        while (true) {
            try {
                std::string errorMessage = this->processNextMessage();

                // Drop out if there's some issue
                if (!errorMessage.empty()) {
                    break;
                }
            }
            catch (infra::RedisNoResponseException &e) {
                logger->debug("No messages received in timeout");

                this->finish();
                return;
            }
        }

        this->finish();
    }

    const std::string WorkerThread::processNextMessage() {
        // Work out which timeout
        int timeout;
        if (currentQueue == infra::COLD_QUEUE || currentQueue == infra::PREWARM_QUEUE) {
            timeout = infra::UNBOUND_TIMEOUT;
        } else {
            timeout = infra::BOUND_TIMEOUT;
        }

        // Wait for next message
        message::Message msg = redis->nextMessage(currentQueue, timeout);

        // Handle the message
        std::string errorMessage;
        if (msg.type() == message::Message_MessageType_BIND) {
            this->bindToFunction(msg);
        }
        else if (msg.type() == message::Message_MessageType_PREWARM) {
            // Remove from current set
            redis->srem(currentSet, id);

            // Become prewarm
            this->initialise();
        } else {
            errorMessage = this->executeCall(msg);
        }

        return errorMessage;
    }

    void WorkerThread::runSingle() {
        const std::shared_ptr<spdlog::logger> &logger = util::getLogger();

        std::string errorMessage = this->processNextMessage();

        if (!errorMessage.empty()) {
            logger->error("WorkerThread failed with error: {}", errorMessage);
        }

        this->finish();
    }

    const std::string WorkerThread::executeCall(message::Message &call) {
        const std::shared_ptr<spdlog::logger> &logger = util::getLogger();

        const std::chrono::steady_clock::time_point &t = prof::startTimer();

        logger->info("WorkerThread executing {}", infra::funcToString(call));

        // Create and execute the module
        wasm::CallChain callChain(call);
        try {
            module->execute(call, callChain);
        }
        catch (const std::exception &e) {
            std::string errorMessage = "Error: " + std::string(e.what());
            logger->error(errorMessage);

            this->finishCall(call, errorMessage);
            return errorMessage;
        }

        // Process any chained calls
        std::string chainErrorMessage = callChain.execute();
        if (!chainErrorMessage.empty()) {
            this->finishCall(call, chainErrorMessage);
            return chainErrorMessage;
        }

        const std::string empty;
        this->finishCall(call, empty);

        prof::logEndTimer("func-total", t);
        return empty;
    }
}
