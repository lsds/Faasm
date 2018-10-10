#include <catch/catch.hpp>

#include <worker/worker.h>

using namespace worker;

namespace tests {
    static infra::Redis redis;

    void setUp() {
        redis.flushAll();

        // Network ns requires root
        util::setEnvVar("NETNS_MODE", "off");
    }

    void tearDown() {
        util::unsetEnvVar("NETNS_MODE");
    }

    TEST_CASE("Test full execution of WASM module", "[worker]") {
        setUp();

        message::FunctionCall call;
        call.set_user("simon");
        call.set_function("echo");
        call.set_inputdata("this is input");
        call.set_resultkey("test_echo");

        // Run the execution
        execFunction(1, call);
        message::FunctionCall result = redis.getFunctionResult(call);

        // Check output
        REQUIRE(result.outputdata() == "this is input");
        REQUIRE(result.success());

        tearDown();
    }

    TEST_CASE("Test executing non-existent function", "[worker]") {
        setUp();

        message::FunctionCall call;
        call.set_user("foobar");
        call.set_function("baz");
        call.set_resultkey("test_invalid");

        execFunction(1, call);
        message::FunctionCall result = redis.getFunctionResult(call);

        REQUIRE(!result.success());
        REQUIRE(result.outputdata() == "foobar - baz is not a valid function");

        tearDown();
    }

    TEST_CASE("Test function chaining", "[worker]") {
        setUp();

        message::FunctionCall call;
        call.set_user("simon");
        call.set_function("chain");
        call.set_resultkey("test_chain");

        // Run the execution
        execFunction(1, call);

        // Check the call executed successfully
        message::FunctionCall result = redis.getFunctionResult(call);
        REQUIRE(result.success());

        // Check the chained calls have been set up
        message::FunctionCall chainA = redis.nextFunctionCall();
        message::FunctionCall chainB = redis.nextFunctionCall();
        message::FunctionCall chainC = redis.nextFunctionCall();

        // Check all are set with the right user
        REQUIRE(chainA.user() == "simon");
        REQUIRE(chainB.user() == "simon");
        REQUIRE(chainC.user() == "simon");

        // Check function names
        REQUIRE(chainA.function() == "echo");
        REQUIRE(chainB.function() == "x2");
        REQUIRE(chainC.function() == "dummy");

        // Check function data
        std::vector<uint8_t> expected0 = {0, 1, 2};
        std::vector<uint8_t> expected1 = {1, 2, 3};
        std::vector<uint8_t> expected2 = {2, 3, 4};
        REQUIRE(util::stringToBytes(chainA.inputdata()) == expected0);
        REQUIRE(util::stringToBytes(chainB.inputdata()) == expected1);
        REQUIRE(util::stringToBytes(chainC.inputdata()) == expected2);

        tearDown();
    }
}