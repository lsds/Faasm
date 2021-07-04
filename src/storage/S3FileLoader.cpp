#include <storage/S3FileLoader.h>

#include <faabric/util/bytes.h>
#include <faabric/util/func.h>
#include <faabric/util/logging.h>

namespace storage {

const static std::string funcFile = "function.wasm";
const static std::string objFile = "function.wasm.o";

std::string getFunctionKey(const faabric::Message& msg)
{
    std::string key = "wasm";

    key += "/";
    key += msg.user();
    key += "/";
    key += msg.function();
    key += "/";
    key += funcFile;

    return key;
}

std::string getFunctionObjectKey(const faabric::Message& msg)
{
    std::string key = "wasm";

    key += "/";
    key += msg.user();
    key += "/";
    key += msg.function();
    key += "/";
    key += objFile;

    return key;
}

S3FileLoader::S3FileLoader()
  : conf(conf::getFaasmConfig())
{}

std::vector<uint8_t> S3FileLoader::loadFileBytes(const std::string& path)
{
    SPDLOG_DEBUG("Loading bytes from {}/{}", conf.bucketName, path);

    const std::vector<uint8_t> bytes = s3.getKeyBytes(conf.bucketName, path);

    return bytes;
}

std::vector<uint8_t> S3FileLoader::loadFunctionWasm(const faabric::Message& msg)
{
    const std::string key = getFunctionKey(msg);
    return this->loadFileBytes(key);
}

std::vector<uint8_t> S3FileLoader::loadSharedObjectWasm(const std::string& path)
{
    throw std::runtime_error("Not implemented for S3 function loader");
}

std::vector<uint8_t> S3FileLoader::loadFunctionObjectFile(
  const faabric::Message& msg)
{
    const std::string key = getFunctionObjectKey(msg);
    return this->loadFileBytes(key);
}

std::vector<uint8_t> S3FileLoader::loadSharedObjectObjectFile(
  const std::string& path)
{
    throw std::runtime_error("Not implemented for S3 function loader");
}

void S3FileLoader::uploadFunction(faabric::Message& msg)
{
    // Note, when uploading, the input data is the function body
    const std::string& inputBytes = msg.inputdata();

    const std::string key = getFunctionKey(msg);
    s3.addKeyStr(conf.bucketName, key, inputBytes);

    // Build the object file from the file we've just received
    this->codegenForFunction(msg);
}

void S3FileLoader::uploadPythonFunction(faabric::Message& msg)
{
    throw std::runtime_error("Not yet implemented Python upload on S3");
}

void S3FileLoader::uploadFunctionObjectFile(
  const faabric::Message& msg,
  const std::vector<uint8_t>& objBytes)
{
    const std::string key = getFunctionObjectKey(msg);

    SPDLOG_DEBUG(
      "Uploading function object bytes to {}/{}", conf.bucketName, key);

    s3.addKeyBytes(conf.bucketName, key, objBytes);
}

void S3FileLoader::uploadSharedObjectObjectFile(
  const std::string& path,
  const std::vector<uint8_t>& objBytes)
{
    SPDLOG_DEBUG(
      "Uploading shared object object bytes to {}/{}", conf.bucketName, path);

    s3.addKeyBytes(conf.bucketName, path, objBytes);
}
}
