#include <catch2/catch.hpp>

#include "faabric/proto/faabric.pb.h"
#include "utils.h"

#include <faabric/util/func.h>
#include <faabric/util/macros.h>
#include <module_cache/WasmModuleCache.h>

namespace tests {
TEST_CASE("Test creating zygotes", "[zygote]")
{
    cleanSystem();

    std::shared_ptr<faabric::BatchExecuteRequest> req =
      faabric::util::batchExecFactory("demo", "chain", 2);
    faabric::Message& msgA = req->mutable_messages()->at(0);
    faabric::Message& msgB = req->mutable_messages()->at(1);

    // Want to check things with chained calls, so need to fake up input to a
    // chained func
    // NOTE: here we are hard-coding the function's position in the function
    // table
    int funcPtr = 2;
    msgA.set_funcptr(funcPtr);

    int input[3] = { 1, 2, 3 };
    msgA.set_inputdata(BYTES(input), 3 * sizeof(int));

    module_cache::WasmModuleCache& registry =
      module_cache::getWasmModuleCache();
    wasm::WasmModule& moduleA = registry.getCachedModule(msgA);
    wasm::WasmModule& moduleB = registry.getCachedModule(msgB);

    // Check modules are the same
    REQUIRE(std::addressof(moduleA) == std::addressof(moduleB));
    REQUIRE(moduleA.isBound());

    // Execute the function normally and make sure zygote is not used directly
    faaslet::Faaslet faaslet(msgA);
    int returnValue = faaslet.executeTask(0, 0, req);
    REQUIRE(returnvalue == 0);

    REQUIRE(std::addressof(moduleA) != std::addressof(*faaslet.module));
}
}
