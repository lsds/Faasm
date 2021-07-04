#include <catch2/catch.hpp>

#include <faabric/util/config.h>
#include <faabric/util/files.h>
#include <faabric/util/func.h>

#include <conf/FaasmConfig.h>
#include <conf/function_utils.h>
#include <storage/FileLoader.h>
#include <storage/S3Wrapper.h>

namespace tests {

class S3TestFixture
{
  public:
    S3TestFixture()
      : conf(conf::getFaasmConfig())
    {
        // Make sure the bucket exists
        s3.createBucket(conf.bucketName);
    };

    ~S3TestFixture(){};

  protected:
    conf::FaasmConfig& conf;
    storage::S3Wrapper s3;
};

TEST_CASE_METHOD(S3TestFixture, "Test read/write keys in bucket", "[s3]")
{
    std::string dataA("£5^Itej__\n\tFoo");
    std::string dataB("ABCDEFGH123$$$&\r*");

    std::vector<uint8_t> byteDataA = { 0, 1, 2, 3, 'c', '\\', '@', '$', '%' };
    std::vector<uint8_t> byteDataB = { 11, 99, 123, '#', '\n', '\t' };

    SECTION("Test string read/ write")
    {
        s3.addKeyStr(conf.bucketName, "alpha", dataA);
        s3.addKeyStr(conf.bucketName, "beta", dataB);

        REQUIRE(s3.getKeyStr(conf.bucketName, "alpha") == dataA);
        REQUIRE(s3.getKeyStr(conf.bucketName, "beta") == dataB);
    }

    SECTION("Test listing keys")
    {
        s3.addKeyStr(conf.bucketName, "alpha", dataA);
        s3.addKeyStr(conf.bucketName, "beta", dataB);

        std::vector<std::string> actual = s3.listKeys(conf.bucketName);
        std::sort(actual.begin(), actual.end());
        std::vector<std::string> expected = { "alpha", "beta" };

        REQUIRE(actual == expected);
    }

    SECTION("Test byte read/write")
    {
        s3.addKeyBytes(conf.bucketName, "alpha", byteDataA);
        s3.addKeyBytes(conf.bucketName, "beta", byteDataB);

        const std::vector<uint8_t> actualA =
          s3.getKeyBytes(conf.bucketName, "alpha");
        const std::vector<uint8_t> actualB =
          s3.getKeyBytes(conf.bucketName, "beta");

        REQUIRE(actualA == byteDataA);
        REQUIRE(actualB == byteDataB);
    }

    s3.deleteKey(conf.bucketName, "alpha");
    s3.deleteKey(conf.bucketName, "beta");

    std::vector<std::string> actualEmpty = s3.listKeys(conf.bucketName);
    REQUIRE(actualEmpty.empty());
}

TEST_CASE_METHOD(S3TestFixture,
                 "Test read/write function data in bucket",
                 "[s3]")
{
    faabric::Message msg;
    msg.set_user("demo");
    msg.set_function("echo");

    // Wasm data is uploaded via the message input data
    const std::string& funcPath = conf::getFunctionFile(msg);
    const std::vector<uint8_t>& wasmBytes =
      faabric::util::readFileToBytes(funcPath);
    msg.set_inputdata(wasmBytes.data(), wasmBytes.size());

    // Object files are uploaded by passing bytes directly
    const std::string& objPath = conf::getFunctionObjectFile(msg);
    const std::vector<uint8_t>& objectBytes =
      faabric::util::readFileToBytes(objPath);

    storage::FileLoader& loader = storage::getFileLoader();

    // Do both uploads
    loader.uploadFunction(msg);

    // Download again
    const std::vector<uint8_t>& actualWasmBytes = loader.loadFunctionWasm(msg);
    const std::vector<uint8_t>& actualObjectBytes =
      loader.loadFunctionObjectFile(msg);
    REQUIRE(actualWasmBytes == wasmBytes);
    REQUIRE(actualObjectBytes == objectBytes);

    // Check 2 keys present
    std::vector<std::string> keys = s3.listKeys(conf.bucketName);
    REQUIRE(keys.size() == 2);

    // Download in a different thread and check for any thread-local issues
    std::thread t([&msg, &wasmBytes, &objectBytes] {
        storage::FileLoader& l = storage::getFileLoader();
        const std::vector<uint8_t>& actualWasmBytes2 = l.loadFunctionWasm(msg);
        const std::vector<uint8_t>& actualObjectBytes2 =
          l.loadFunctionObjectFile(msg);
        REQUIRE(actualWasmBytes2 == wasmBytes);
        REQUIRE(actualObjectBytes2 == objectBytes);
    });

    t.join();

    // Clear up
    const std::string& funcKey = conf::getFunctionKey(msg);
    const std::string& objKey = conf::getFunctionObjectKey(msg);
    s3.deleteKey(conf.bucketName, funcKey);
    s3.deleteKey(conf.bucketName, objKey);

    // Check no more keys
    std::vector<std::string> actualEmpty = s3.listKeys(conf.bucketName);
    REQUIRE(actualEmpty.empty());
}
}
