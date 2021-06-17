#define CATCH_CONFIG_RUNNER

#include <catch2/catch.hpp>

#include <faaslet/Faaslet.h>

#include <faabric/endpoint/FaabricEndpoint.h>
#include <faabric/runner/FaabricMain.h>
#include <faabric/scheduler/ExecutorFactory.h>
#include <faabric/util/logging.h>

using namespace faabric::scheduler;

struct LogListener : Catch::TestEventListenerBase
{
    // Note, we must call base class versions of overridden methods
    // https://github.com/catchorg/Catch2/pull/1617
    using TestEventListenerBase::TestEventListenerBase;

    void testCaseStarting(Catch::TestCaseInfo const& testInfo) override
    {
        this->Catch::TestEventListenerBase::testCaseStarting(testInfo);

        SPDLOG_INFO("=============================================");
        SPDLOG_INFO("TEST: {}", testInfo.name);
        SPDLOG_INFO("=============================================");
    }

    void sectionStarting(Catch::SectionInfo const& sectionInfo) override
    {
        this->Catch::TestEventListenerBase::sectionStarting(sectionInfo);

        SPDLOG_INFO("---------------------------------------------");
        SPDLOG_INFO("SECTION: {}", sectionInfo.name);
        SPDLOG_INFO("---------------------------------------------");
    }
};

CATCH_REGISTER_LISTENER(LogListener)

int main(int argc, char* argv[])
{
    faabric::util::initLogging();

    // Start everything up
    SPDLOG_INFO("Starting distributed test server on master");
    std::shared_ptr<faaslet::FaasletFactory> fac =
      std::make_shared<faaslet::FaasletFactory>();
    faabric::runner::FaabricMain m(fac);
    m.startBackground();

    // Wait for things to start
    usleep(3000 * 1000);

    // Run the tests
    int result = Catch::Session().run(argc, argv);
    fflush(stdout);

    // Shut down
    SPDLOG_INFO("Shutting down");
    m.shutdown();

    return result;
}
