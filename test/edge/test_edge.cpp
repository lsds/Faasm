#include <catch/catch.hpp>

#include "utils.h"
#include <edge/FunctionEndpoint.h>
#include <scheduler/GlobalMessageBus.h>

using namespace Pistache;

namespace tests {
    TEST_CASE("Test invoking a function", "[edge]") {
        cleanSystem();
        message::Message call;

        std::string user;
        std::string func;
        std::string inputData;

        std::string expectedUser;
        std::string expectedFunc;
        std::string expectedInputData;

        SECTION("Normal function") {
            user = expectedUser = "demo";
            func = expectedFunc = "echo";
            inputData = expectedInputData = "123";
        }

        SECTION("Python function") {
            user = "python";
            func = "numpy_test";
            inputData = "";

            expectedUser = PYTHON_USER;
            expectedFunc = PYTHON_FUNC;
            expectedInputData = "python/numpy_test/function.py";
        }

        // Note - must be async to avoid needing a result
        call.set_isasync(true);

        call.set_user(user);
        call.set_function(func);
        call.set_inputdata(inputData);

        // Get global bus
        scheduler::GlobalMessageBus &globalBus = scheduler::getGlobalMessageBus();

        edge::FunctionEndpoint endpoint;
        endpoint.handleFunction(call);

        const message::Message actual = globalBus.nextMessage();

        REQUIRE(actual.user() == user);
        REQUIRE(actual.function() == func);
        REQUIRE(actual.inputdata() == inputData);
    }
}