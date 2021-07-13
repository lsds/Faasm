#include "utils.h"
#include <catch2/catch.hpp>

#include <faabric/proto/faabric.pb.h>
#include <faabric/runner/FaabricMain.h>
#include <faabric/scheduler/FunctionCallClient.h>
#include <faabric/snapshot/SnapshotClient.h>
#include <faabric/snapshot/SnapshotRegistry.h>
#include <faabric/util/bytes.h>
#include <faabric/util/config.h>
#include <faabric/util/environment.h>
#include <faabric/util/logging.h>
#include <faabric/util/testing.h>
#include <faaslet/Faaslet.h>

#include <conf/FaasmConfig.h>
#include <wavm/WAVMWasmModule.h>

using namespace faaslet;

namespace tests {

void execFunction(faabric::Message& call, const std::string& expectedOutput)
{
    // Turn off python preloading
    conf::FaasmConfig& conf = conf::getFaasmConfig();
    std::string originalPreload = conf.pythonPreload;
    conf.pythonPreload = "off";

    wasm::WAVMWasmModule module;
    module.bindToFunction(call);
    int returnValue = module.executeFunction(call);

    if (!expectedOutput.empty()) {
        std::string actualOutput = call.outputdata();
        REQUIRE(actualOutput == expectedOutput);
    }

    REQUIRE(returnValue == 0);
    REQUIRE(call.returnvalue() == 0);

    conf.pythonPreload = originalPreload;
}

std::string execFunctionWithStringResult(faabric::Message& call)
{
    // Turn off python preloading
    conf::FaasmConfig& conf = conf::getFaasmConfig();
    std::string originalPreload = conf.pythonPreload;
    conf.pythonPreload = "off";

    auto fac = std::make_shared<faaslet::FaasletFactory>();
    faabric::runner::FaabricMain m(fac);
    m.startRunner();

    // Call the function
    faabric::scheduler::Scheduler& sch = faabric::scheduler::getScheduler();
    sch.callFunction(call);

    const faabric::Message result = sch.getFunctionResult(call.id(), 1);
    if (result.returnvalue() != 0) {
        SPDLOG_ERROR("Function failed: {}", result.outputdata());
        FAIL();
    }
    REQUIRE(result.returnvalue() == 0);

    conf.pythonPreload = originalPreload;

    m.shutdown();

    return result.outputdata();
}

void checkMultipleExecutions(faabric::Message& msg, int nExecs)
{
    wasm::WAVMWasmModule module;
    module.bindToFunction(msg);

    for (int i = 0; i < nExecs; i++) {
        int returnValue = module.executeFunction(msg);
        REQUIRE(returnValue == 0);

        // Reset
        module.reset(msg);
    }
}

void execBatchWithPool(std::shared_ptr<faabric::BatchExecuteRequest> req,
                       int nSlots,
                       bool clean)
{
    if (clean) {
        cleanSystem();
    }

    faabric::util::SystemConfig& conf = faabric::util::getSystemConfig();
    conf::FaasmConfig& faasmConf = conf::getFaasmConfig();
    conf.boundTimeout = 1000;
    faasmConf.chainedCallTimeout = 10000;

    faabric::scheduler::Scheduler& sch = faabric::scheduler::getScheduler();

    // Start up system
    auto fac = std::make_shared<faaslet::FaasletFactory>();
    faabric::runner::FaabricMain m(fac);
    m.startRunner();

    // Execute forcing local
    sch.callFunctions(req, true);

    usleep(1000 * 500);

    // Wait for all functions to complete
    for (auto m : req->messages()) {
        if (req->type() == faabric::BatchExecuteRequest::THREADS) {
            int returnValue = sch.awaitThreadResult(m.id());
            REQUIRE(returnValue == 0);
        } else {
            faabric::Message result = sch.getFunctionResult(m.id(), 20000);
            REQUIRE(result.returnvalue() == 0);
        }
    }

    m.shutdown();
}

void execFuncWithPool(faabric::Message& call, bool clean, int timeout)
{
    if (clean) {
        cleanSystem();
    }

    faabric::scheduler::Scheduler& sch = faabric::scheduler::getScheduler();
    sch.shutdown();
    sch.addHostToGlobalSet();

    // Modify system config (network ns requires root)
    faabric::util::SystemConfig& conf = faabric::util::getSystemConfig();
    conf::FaasmConfig& faasmConf = conf::getFaasmConfig();
    std::string originalNsMode = faasmConf.netNsMode;
    conf.boundTimeout = timeout;
    faasmConf.netNsMode = "off";

    // Set up the system
    auto fac = std::make_shared<faaslet::FaasletFactory>();
    faabric::runner::FaabricMain m(fac);
    m.startRunner();

    // Make the call
    sch.callFunction(call);

    // Await the result of the main function
    // NOTE - this timeout will only get hit when things have failed.
    // It also needs to be long enough to let longer tests complete
    faabric::Message result = sch.getFunctionResult(call.id(), 30000);
    REQUIRE(result.returnvalue() == 0);

    // Shut down the pool
    m.shutdown();

    faasmConf.netNsMode = originalNsMode;

    cleanSystem();
}

void doWamrPoolExecution(faabric::Message& msg)
{
    conf::FaasmConfig& conf = conf::getFaasmConfig();
    const std::string originalVm = conf.wasmVm;
    conf.wasmVm = "wamr";

    // Don't clean so that the WAMR configuration persists
    execFuncWithPool(msg, false);

    conf.wasmVm = originalVm;
}

void executeWithWamrPool(const std::string& user, const std::string& func)
{
    faabric::Message call = faabric::util::messageFactory(user, func);
    doWamrPoolExecution(call);
}

void executeWithSGX(const std::string& user, const std::string& func)
{
    faabric::Message call = faabric::util::messageFactory(user, func);
    call.set_issgx(true);
    doWamrPoolExecution(call);
}

void checkCallingFunctionGivesBoolOutput(const std::string& user,
                                         const std::string& funcName,
                                         bool expected)
{
    faabric::Message call = faabric::util::messageFactory("demo", funcName);

    faabric::scheduler::Scheduler& sch = faabric::scheduler::getScheduler();
    sch.callFunction(call);

    auto fac = std::make_shared<faaslet::FaasletFactory>();
    faabric::runner::FaabricMain m(fac);
    m.startRunner();

    // Check output is true
    faabric::Message result = sch.getFunctionResult(call.id(), 1);
    REQUIRE(result.returnvalue() == 0);
    std::vector<uint8_t> outputBytes =
      faabric::util::stringToBytes(result.outputdata());

    std::vector<uint8_t> expectedOutput;

    if (expected) {
        expectedOutput = { 1 };
    } else {
        expectedOutput = { 0 };
    }

    REQUIRE(outputBytes == expectedOutput);
}
}
