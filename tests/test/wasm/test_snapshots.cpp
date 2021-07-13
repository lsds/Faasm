#include <catch2/catch.hpp>

#include "faabric_utils.h"
#include "utils.h"

#include <boost/filesystem.hpp>

#include <faabric/proto/faabric.pb.h>
#include <faabric/util/func.h>
#include <faabric/util/memory.h>
#include <faabric/util/snapshot.h>

#include <faaslet/Faaslet.h>
#include <wavm/WAVMWasmModule.h>

using namespace wasm;

namespace tests {

class WasmSnapTestFixture
  : public RedisTestFixture
  , public SchedulerTestFixture
  , public SnapshotTestFixture
{
  public:
    WasmSnapTestFixture() {}

    ~WasmSnapTestFixture() {}
};

TEST_CASE_METHOD(WasmSnapTestFixture,
                 "Test snapshot and restore for wasm module",
                 "[wasm][snapshot]")
{
    std::string user = "demo";
    std::string function = "zygote_check";
    faabric::Message m = faabric::util::messageFactory(user, function);

    // Create the full module
    wasm::WAVMWasmModule moduleA;
    moduleA.bindToFunction(m);

    // Modify the memory of the module to check changes are propagated
    uint32_t memSize = WASM_BYTES_PER_PAGE + GUARD_REGION_SIZE;
    uint32_t wasmPtr = moduleA.growMemory(memSize);
    uint8_t* nativePtr = moduleA.wasmPointerToNative(wasmPtr);
    nativePtr[0] = 0;
    nativePtr[1] = 1;
    nativePtr[2] = 2;
    nativePtr[3] = 3;
    nativePtr[4] = 4;

    // Add a guard region to make sure these can be propagated
    uint32_t guardRegionOffset =
      moduleA.createMemoryGuardRegion(wasmPtr + WASM_BYTES_PER_PAGE);
    REQUIRE(guardRegionOffset ==
            wasmPtr + WASM_BYTES_PER_PAGE + GUARD_REGION_SIZE);

    size_t expectedSizeBytes = moduleA.getMemorySizeBytes();

    // Serialise to state
    std::string stateKey = moduleA.snapshot();

    // Create the module to be restored but don't execute zygote
    wasm::WAVMWasmModule moduleB;
    moduleB.bindToFunctionNoZygote(m);

    // Restore from snapshot
    moduleB.restore(stateKey);

    // Check size of restored memory is as expected
    size_t actualSizeBytesB = moduleB.getMemorySizeBytes();
    REQUIRE(actualSizeBytesB == expectedSizeBytes);

    // Check writes to memory are visible in restored module
    uint8_t* nativePtrB = moduleB.wasmPointerToNative(wasmPtr);
    REQUIRE(nativePtrB[0] == 0);
    REQUIRE(nativePtrB[1] == 1);
    REQUIRE(nativePtrB[2] == 2);
    REQUIRE(nativePtrB[3] == 3);
    REQUIRE(nativePtrB[4] == 4);

    // Create a third module from the second one
    wasm::WAVMWasmModule moduleC;
    moduleC.bindToFunctionNoZygote(m);

    // Restore from snapshot
    moduleC.restore(stateKey);

    // Check size of restored memory is as expected
    size_t actualSizeBytesC = moduleB.getMemorySizeBytes();
    REQUIRE(actualSizeBytesC == expectedSizeBytes);

    // Check writes to memory are visible in restored module
    uint8_t* nativePtrC = moduleC.wasmPointerToNative(wasmPtr);
    REQUIRE(nativePtrC[0] == 0);
    REQUIRE(nativePtrC[1] == 1);
    REQUIRE(nativePtrC[2] == 2);
    REQUIRE(nativePtrC[3] == 3);
    REQUIRE(nativePtrC[4] == 4);

    // Execute all of them
    int returnValueA = moduleA.executeFunction(m);
    REQUIRE(returnValueA == 0);

    int returnValueB = moduleB.executeFunction(m);
    REQUIRE(returnValueB == 0);

    int returnValueC = moduleC.executeFunction(m);
    REQUIRE(returnValueC == 0);
}

TEST_CASE_METHOD(WasmSnapTestFixture,
                 "Test dirty page checks for wasm module",
                 "[wasm][snapshot]")
{
    std::string user = "demo";
    std::string function = "memcpy";
    faabric::Message m = faabric::util::messageFactory(user, function);

    wasm::WAVMWasmModule module;
    module.bindToFunction(m);

    // Reset dirty page tracking _after_ binding
    faabric::util::resetDirtyTracking();

    // Check no dirty pages initially
    faabric::util::SnapshotData snapBefore = module.getSnapshotData();
    REQUIRE(snapBefore.getDirtyPages().empty());

    // Execute the function
    module.executeFunction(m);

    // Check some dirty pages are registered
    faabric::util::SnapshotData snapAfter = module.getSnapshotData();
    std::vector<faabric::util::SnapshotDiff> actual = snapAfter.getDirtyPages();
    REQUIRE(actual.size() == 4);
}

TEST_CASE_METHOD(WasmSnapTestFixture,
                 "Test dirty page checks for faaslet",
                 "[wasm][snapshot]")
{
    std::string user = "demo";
    std::string function = "memcpy";
    std::shared_ptr<faabric::BatchExecuteRequest> req =
      faabric::util::batchExecFactory(user, function, 1);
    faabric::Message& m = req->mutable_messages()->at(0);
    faaslet::Faaslet f(m);

    // Reset dirty page tracking _after_ binding
    faabric::util::resetDirtyTracking();

    // Check no dirty pages initially
    faabric::util::SnapshotData snapBefore = f.snapshot();
    REQUIRE(snapBefore.getDirtyPages().empty());

    // Execute the function
    f.executeTask(0, 0, req);

    // Check some dirty pages are registered
    faabric::util::SnapshotData snapAfter = f.snapshot();
    std::vector<faabric::util::SnapshotDiff> actual = snapAfter.getDirtyPages();
    REQUIRE(actual.size() == 4);

    // Set up a snapshot with this data
    std::string snapKey = "dirty-check";
    reg.takeSnapshot(snapKey, snapAfter);

    // Restore a Faaslet with this snapshot
    std::shared_ptr<faabric::BatchExecuteRequest> reqSnap =
      faabric::util::batchExecFactory(user, function, 1);
    faabric::Message& mSnap = reqSnap->mutable_messages()->at(0);
    mSnap.set_snapshotkey(snapKey);

    faaslet::Faaslet fSnap(mSnap);
    faabric::util::resetDirtyTracking();

    // Execute and check again
    fSnap.executeTask(0, 0, reqSnap);

    // Check some dirty pages are registered
    faabric::util::SnapshotData afterSnap = fSnap.snapshot();
    std::vector<faabric::util::SnapshotDiff> actualSnap =
      afterSnap.getDirtyPages();
    REQUIRE(actualSnap.size() == 4);
}
}
