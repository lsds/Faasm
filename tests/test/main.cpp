#define CATCH_CONFIG_RUNNER

#include "faabric_utils.h"
#include "utils.h"

#include <storage/S3Wrapper.h>
#include <catch2/catch.hpp>
#include <faabric/util/logging.h>

FAABRIC_CATCH_LOGGER

int main(int argc, char* argv[])
{
    storage::initSDK();
    faabric::util::initLogging();

    tests::cleanSystem();

    int result = Catch::Session().run(argc, argv);

    fflush(stdout);

    storage::cleanUpSDK();

    return result;
}
