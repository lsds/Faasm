#include "FileLoader.h"
#include <boost/filesystem/operations.hpp>
#include <stdexcept>

#include <openssl/md5.h>

#if (WAMR_EXECUTION_MODE_INTERP)
// Import for codegen not needed as it's not supported
#else
#include <wamr/WAMRWasmModule.h>
#endif

#include <wavm/WAVMWasmModule.h>

#include <faabric/util/config.h>
#include <faabric/util/files.h>
#include <faabric/util/func.h>
#include <faabric/util/logging.h>

#include <boost/filesystem.hpp>

namespace storage {

std::vector<uint8_t> FileLoader::hashBytes(const std::vector<uint8_t>& bytes)
{
    std::vector<uint8_t> result(MD5_DIGEST_LENGTH);
    MD5(reinterpret_cast<const unsigned char*>(bytes.data()),
        bytes.size(),
        result.data());

    return result;
}

std::string FileLoader::getHashFilePath(const std::string& path)
{
    return path + HASH_EXT;
}

std::vector<uint8_t> FileLoader::doCodegen(std::vector<uint8_t>& bytes,
                                           const std::string& fileName)
{
    faabric::util::SystemConfig& conf = faabric::util::getSystemConfig();
    if (conf.wasmVm == "wamr") {
#if (WAMR_EXECTION_MODE_INTERP)
        throw std::runtime_error(
          "WAMR codegen not supported with WAMR interp mode");
#else
        return wasm::wamrCodegen(bytes);
#endif
    } else {
        return wasm::wavmCodegen(bytes, fileName);
    }
}

void FileLoader::codegenForFunction(faabric::Message& msg)
{
    std::vector<uint8_t> bytes = loadFunctionWasm(msg);

    auto logger = faabric::util::getLogger();
    const std::string funcStr = faabric::util::funcToString(msg, false);

    if (bytes.empty()) {
        throw std::runtime_error("Loaded empty bytes for " + funcStr);
    }

    // Compare hashes
    std::vector<uint8_t> newHash = hashBytes(bytes);
    std::vector<uint8_t> oldHash;
    faabric::util::SystemConfig& conf = faabric::util::getSystemConfig();
    if (conf.wasmVm == "wamr") {
        oldHash = loadFunctionWamrAotHash(msg);
    } else {
        oldHash = loadFunctionObjectHash(msg);
    }

    if ((!oldHash.empty()) && newHash == oldHash) {
        logger->debug("Skipping codegen for {}", funcStr);
        return;
    } else if (oldHash.empty()) {
        logger->debug("No old hash found for {}", funcStr);
    } else {
        logger->debug("Hashes differ for {}", funcStr);
    }

    // Run the actual codegen
    std::vector<uint8_t> objBytes;
    try {
        objBytes = doCodegen(bytes, funcStr);
    } catch (std::runtime_error& ex) {
        logger->error("Codegen failed for " + funcStr);
        throw ex;
    }

    // Upload the file contents and the hash
    if (conf.wasmVm == "wamr") {
        uploadFunctionAotFile(msg, objBytes);
        uploadFunctionWamrAotHash(msg, newHash);
    } else {
        uploadFunctionObjectFile(msg, objBytes);
        uploadFunctionObjectHash(msg, newHash);
    }
}

void FileLoader::codegenForSharedObject(const std::string& inputPath)
{
    auto logger = faabric::util::getLogger();

    // Load the wasm
    std::vector<uint8_t> bytes = loadSharedObjectWasm(inputPath);

    // Check the hash
    std::vector<uint8_t> newHash = hashBytes(bytes);
    std::vector<uint8_t> oldHash = loadSharedObjectObjectHash(inputPath);

    if ((!oldHash.empty()) && newHash == oldHash) {
        logger->debug("Skipping codegen for {}", inputPath);
        return;
    }

    // Run the actual codegen
    std::vector<uint8_t> objBytes = doCodegen(bytes, inputPath);

    // Do the upload
    faabric::util::SystemConfig& conf = faabric::util::getSystemConfig();
    if (conf.wasmVm == "wamr") {
        uploadSharedObjectAotFile(inputPath, objBytes);
        uploadSharedObjectAotHash(inputPath, newHash);
    } else {
        uploadSharedObjectObjectFile(inputPath, objBytes);
        uploadSharedObjectObjectHash(inputPath, newHash);
    }
}

void checkFileExists(const std::string& path)
{
    if (!boost::filesystem::exists(path)) {
        const std::shared_ptr<spdlog::logger>& logger =
          faabric::util::getLogger();
        logger->error("File {} does not exist", path);
        throw std::runtime_error("Expected file does not exist");
    }
}

std::vector<uint8_t> loadFileBytes(const std::string& path)
{
    checkFileExists(path);
    return faabric::util::readFileToBytes(path);
}

// -----------------------------------------------------
// Subclass overrides
// -----------------------------------------------------

std::vector<uint8_t> FileLoader::loadFunctionWasm(const faabric::Message& msg)
{
    throw std::runtime_error("loadFunctionWasm not implemented");
}

std::vector<uint8_t> FileLoader::loadSharedObjectWasm(const std::string& path)
{
    throw std::runtime_error("loadSharedObjectWasm not implemented");
}

std::vector<uint8_t> FileLoader::loadFunctionObjectFile(
  const faabric::Message& msg)
{
    throw std::runtime_error("loadFunctionObjectFile not implemented");
}

std::vector<uint8_t> FileLoader::loadFunctionWamrAotFile(
  const faabric::Message& msg)
{
    throw std::runtime_error("loadFunctionWamrAotFile not implemented");
}

std::vector<uint8_t> FileLoader::loadSharedObjectObjectFile(
  const std::string& path)
{
    throw std::runtime_error("loadSharedObjectObjectFile not implemented");
}

std::vector<uint8_t> FileLoader::loadSharedFile(const std::string& path)
{
    throw std::runtime_error("loadSharedFile not implemented");
}

std::vector<uint8_t> FileLoader::loadFunctionObjectHash(
  const faabric::Message& msg)
{
    throw std::runtime_error("loadFunctionObjectHash not implemented");
}

std::vector<uint8_t> FileLoader::loadFunctionWamrAotHash(
  const faabric::Message& msg)
{
    throw std::runtime_error("loadFunctionWamrAotHash not implemented");
}

std::vector<uint8_t> FileLoader::loadSharedObjectObjectHash(
  const std::string& path)
{
    throw std::runtime_error("loadSharedObjectObjectHash not implemented");
}

void FileLoader::uploadFunctionObjectHash(const faabric::Message& msg,
                                          const std::vector<uint8_t>& hash)
{
    throw std::runtime_error("uploadFunctionObjectHash not implemented");
}

void FileLoader::uploadFunctionWamrAotHash(const faabric::Message& msg,
                                           const std::vector<uint8_t>& hash)
{
    throw std::runtime_error("uploadFunctionWamrAotHash not implemented");
}

void FileLoader::uploadSharedObjectObjectHash(const std::string& path,
                                              const std::vector<uint8_t>& hash)
{
    throw std::runtime_error("uploadSharedObjectObjectHash not implemented");
}

void FileLoader::uploadSharedObjectAotHash(const std::string& path,
                                           const std::vector<uint8_t>& hash)
{
    throw std::runtime_error("uploadSharedObjectAotHash not implemented");
}

void FileLoader::uploadFunction(faabric::Message& msg)
{
    throw std::runtime_error("uploadFunction not implemented");
}

void FileLoader::uploadPythonFunction(faabric::Message& msg)
{
    throw std::runtime_error("uploadPythonFunction not implemented");
}

void FileLoader::uploadFunctionObjectFile(const faabric::Message& msg,
                                          const std::vector<uint8_t>& objBytes)
{
    throw std::runtime_error("uploadFunctionObjectFile not implemented");
}

void FileLoader::uploadFunctionAotFile(const faabric::Message& msg,
                                       const std::vector<uint8_t>& objBytes)
{
    throw std::runtime_error("uploadFunctionAotFile not implemented");
}

void FileLoader::uploadSharedObjectObjectFile(
  const std::string& path,
  const std::vector<uint8_t>& objBytes)
{
    throw std::runtime_error("uploadSharedObjectObjectFile not implemented");
}

void FileLoader::uploadSharedObjectAotFile(const std::string& path,
                                           const std::vector<uint8_t>& objBytes)
{
    throw std::runtime_error("uplaodSharedObjectAotFile not implemented");
}

void FileLoader::uploadSharedFile(const std::string& path,
                                  const std::vector<uint8_t>& fileBytes)
{
    throw std::runtime_error("uploadSharedFile not implemented");
}

void FileLoader::flushFunctionFiles()
{
    throw std::runtime_error("flushFunctionFiles not implemented");
}

}
