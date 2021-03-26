#include "storage/LocalFileLoader.h"

#include <iostream>

#include <faabric/util/bytes.h>
#include <faabric/util/files.h>
#include <faabric/util/func.h>
#include <faabric/util/logging.h>

#include <boost/filesystem.hpp>

namespace storage {
std::vector<uint8_t> LocalFileLoader::loadFunctionWasm(
  const faabric::Message& msg)
{
    std::string filePath = faabric::util::getFunctionFile(msg);
    return loadFileBytes(filePath);
}

std::vector<uint8_t> LocalFileLoader::loadEncryptedFunctionWasm(
  const faabric::Message& msg)
{
    std::string filePath = faabric::util::getEncryptedFunctionFile(msg);
    return loadFileBytes(filePath);
}

std::vector<uint8_t> LocalFileLoader::loadFunctionObjectFile(
  const faabric::Message& msg)
{
    std::string objectFilePath = faabric::util::getFunctionObjectFile(msg);
    return loadFileBytes(objectFilePath);
}

std::vector<uint8_t> LocalFileLoader::loadFunctionWamrAotFile(
  const faabric::Message& msg)
{
    std::string objectFilePath = faabric::util::getFunctionAotFile(msg);
    return loadFileBytes(objectFilePath);
}

std::vector<uint8_t> LocalFileLoader::loadSharedObjectObjectFile(
  const std::string& path)
{
    std::string objFilePath = faabric::util::getSharedObjectObjectFile(path);
    return loadFileBytes(objFilePath);
}

std::vector<uint8_t> LocalFileLoader::loadSharedObjectWasm(
  const std::string& path)
{
    return loadFileBytes(path);
}

std::vector<uint8_t> LocalFileLoader::loadHashForPath(const std::string& path)
{
    std::string hashFile = getHashFilePath(path);
    if (boost::filesystem::exists(hashFile)) {
        return faabric::util::readFileToBytes(hashFile);
    } else {
        std::vector<uint8_t> empty;
        return empty;
    }
}

std::vector<uint8_t> LocalFileLoader::loadFunctionObjectHash(
  const faabric::Message& msg)
{
    std::string outputFile = faabric::util::getFunctionObjectFile(msg);
    return loadHashForPath(outputFile);
}

std::vector<uint8_t> LocalFileLoader::loadFunctionWamrAotHash(
  const faabric::Message& msg)
{
    std::string outputFile = faabric::util::getFunctionAotFile(msg);
    return loadHashForPath(outputFile);
}

std::vector<uint8_t> LocalFileLoader::loadSharedObjectObjectHash(
  const std::string& path)
{
    std::string outputFile = faabric::util::getSharedObjectObjectFile(path);
    return loadHashForPath(outputFile);
}

std::vector<uint8_t> LocalFileLoader::loadSharedFile(const std::string& path)
{
    const std::string fullPath = faabric::util::getSharedFileFile(path);

    if (!boost::filesystem::exists(fullPath)) {
        const std::shared_ptr<spdlog::logger>& logger =
          faabric::util::getLogger();
        logger->debug("Local file loader could not find file at {}", fullPath);
        std::vector<uint8_t> empty;
        return empty;
    }

    if (boost::filesystem::is_directory(fullPath)) {
        throw SharedFileIsDirectoryException(fullPath);
    }

    return loadFileBytes(fullPath);
}

void LocalFileLoader::uploadFunction(faabric::Message& msg)
{
    const std::shared_ptr<spdlog::logger>& logger = faabric::util::getLogger();
    const std::string funcStr = faabric::util::funcToString(msg, false);

    // Here the msg input data is actually the file
    const std::string& fileBody = msg.inputdata();
    if (fileBody.empty()) {
        logger->error("Uploaded empty file to {}", funcStr);
        throw std::runtime_error("Uploaded empty file");
    }

    logger->debug("Uploading wasm file {}", funcStr);
    std::string outputFile = faabric::util::getFunctionFile(msg);
    std::ofstream out(outputFile);
    out.write(fileBody.c_str(), fileBody.size());
    out.flush();
    out.close();

    // Build the object file from the file we've just received
    logger->debug("Generating object file for {}", funcStr);
    codegenForFunction(msg);
}

void LocalFileLoader::uploadPythonFunction(faabric::Message& msg)
{
    const std::string& fileBody = msg.inputdata();
    const std::shared_ptr<spdlog::logger>& logger = faabric::util::getLogger();

    // Message will have user/ function set as python user and python function
    faabric::util::convertMessageToPython(msg);

    std::string outputFile = faabric::util::getPythonFunctionFile(msg);
    logger->debug("Uploading python file {}/{} to {}",
                  msg.pythonuser(),
                  msg.pythonfunction(),
                  outputFile);

    std::ofstream out(outputFile);
    out.write(fileBody.c_str(), fileBody.size());
    out.flush();
    out.close();
}

void LocalFileLoader::uploadFunctionObjectFile(
  const faabric::Message& msg,
  const std::vector<uint8_t>& objBytes)
{
    // Write the file
    std::string objFilePath = faabric::util::getFunctionObjectFile(msg);
    faabric::util::writeBytesToFile(objFilePath, objBytes);
}

void LocalFileLoader::uploadFunctionAotFile(
  const faabric::Message& msg,
  const std::vector<uint8_t>& objBytes)
{
    std::string objFilePath = faabric::util::getFunctionAotFile(msg);
    faabric::util::writeBytesToFile(objFilePath, objBytes);
}

void LocalFileLoader::uploadSharedObjectObjectFile(
  const std::string& path,
  const std::vector<uint8_t>& objBytes)
{
    std::string outputPath = faabric::util::getSharedObjectObjectFile(path);
    faabric::util::writeBytesToFile(outputPath, objBytes);
}

void LocalFileLoader::uploadSharedObjectAotFile(
  const std::string& path,
  const std::vector<uint8_t>& objBytes)
{
    throw std::runtime_error("Not yet implemented WAMR shared objects");
}

void LocalFileLoader::uploadSharedFile(const std::string& path,
                                       const std::vector<uint8_t>& objBytes)
{
    const std::string fullPath = faabric::util::getSharedFileFile(path);
    faabric::util::writeBytesToFile(fullPath, objBytes);
}

void LocalFileLoader::flushFunctionFiles()
{
    // In local file mode, we do not need to flush anything as the files on this
    // host are the master copies.
}

void LocalFileLoader::writeHashForFile(const std::string& path,
                                       const std::vector<uint8_t>& hash)
{
    // Write the hash
    std::string hashPath = getHashFilePath(path);
    faabric::util::writeBytesToFile(hashPath, hash);
}

void LocalFileLoader::uploadFunctionObjectHash(const faabric::Message& msg,
                                               const std::vector<uint8_t>& hash)
{
    std::string objFilePath = faabric::util::getFunctionObjectFile(msg);
    writeHashForFile(objFilePath, hash);
}

void LocalFileLoader::uploadFunctionWamrAotHash(
  const faabric::Message& msg,
  const std::vector<uint8_t>& hash)
{
    std::string objFilePath = faabric::util::getFunctionAotFile(msg);
    writeHashForFile(objFilePath, hash);
}

void LocalFileLoader::uploadSharedObjectObjectHash(
  const std::string& path,
  const std::vector<uint8_t>& hash)
{
    std::string outputPath = faabric::util::getSharedObjectObjectFile(path);
    writeHashForFile(outputPath, hash);
}

void LocalFileLoader::uploadSharedObjectAotHash(
  const std::string& path,
  const std::vector<uint8_t>& hash)
{
    throw std::runtime_error("Not yet implemented WAMR shared objects");
}
}
