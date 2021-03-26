#pragma once

#include <faabric/proto/faabric.pb.h>

#include <faabric/util/exception.h>
#include <string>
#include <vector>

#define HASH_EXT ".md5"

#define EMPTY_FILE_RESPONSE "Empty response"
#define IS_DIR_RESPONSE "IS_DIR"
#define FILE_PATH_HEADER "FilePath"

namespace storage {
class FileLoader
{
  public:
    virtual std::vector<uint8_t> loadFunctionWasm(
      const faabric::Message& msg) = 0;

    virtual std::vector<uint8_t> loadEncryptedFunctionWasm(
      const faabric::Message& msg) = 0;

    virtual std::vector<uint8_t> loadSharedObjectWasm(
      const std::string& path) = 0;

    virtual std::vector<uint8_t> loadFunctionObjectFile(
      const faabric::Message& msg) = 0;

    virtual std::vector<uint8_t> loadFunctionWamrAotFile(
      const faabric::Message& msg) = 0;

    virtual std::vector<uint8_t> loadSharedObjectObjectFile(
      const std::string& path) = 0;

    virtual std::vector<uint8_t> loadSharedFile(const std::string& path) = 0;

    virtual std::vector<uint8_t> loadFunctionObjectHash(
      const faabric::Message& msg) = 0;

    virtual std::vector<uint8_t> loadFunctionWamrAotHash(
      const faabric::Message& msg) = 0;

    virtual std::vector<uint8_t> loadSharedObjectObjectHash(
      const std::string& path) = 0;

    virtual void uploadFunctionObjectHash(const faabric::Message& msg,
                                          const std::vector<uint8_t>& hash) = 0;

    virtual void uploadFunctionWamrAotHash(
      const faabric::Message& msg,
      const std::vector<uint8_t>& hash) = 0;

    virtual void uploadSharedObjectObjectHash(
      const std::string& path,
      const std::vector<uint8_t>& hash) = 0;

    virtual void uploadSharedObjectAotHash(
      const std::string& path,
      const std::vector<uint8_t>& hash) = 0;

    virtual void uploadFunction(faabric::Message& msg) = 0;

    virtual void uploadPythonFunction(faabric::Message& msg) = 0;

    virtual void uploadFunctionObjectFile(
      const faabric::Message& msg,
      const std::vector<uint8_t>& objBytes) = 0;

    virtual void uploadFunctionAotFile(
      const faabric::Message& msg,
      const std::vector<uint8_t>& objBytes) = 0;

    virtual void uploadSharedObjectObjectFile(
      const std::string& path,
      const std::vector<uint8_t>& objBytes) = 0;

    virtual void uploadSharedObjectAotFile(
      const std::string& path,
      const std::vector<uint8_t>& objBytes) = 0;

    virtual void uploadSharedFile(const std::string& path,
                                  const std::vector<uint8_t>& fileBytes) = 0;

    virtual void flushFunctionFiles() = 0;

    void codegenForFunction(faabric::Message& msg);

    void codegenForSharedObject(const std::string& inputPath);

  protected:
    std::vector<uint8_t> doCodegen(std::vector<uint8_t>& bytes,
                                   const std::string& fileName);

    std::vector<uint8_t> hashBytes(const std::vector<uint8_t>& bytes);

    std::string getHashFilePath(const std::string& path);
};

FileLoader& getFileLoader();

void checkFileExists(const std::string& path);

std::vector<uint8_t> loadFileBytes(const std::string& path);

class SharedFileIsDirectoryException : public faabric::util::FaabricException
{
  public:
    explicit SharedFileIsDirectoryException(const std::string& filePath)
      : faabric::util::FaabricException(filePath + " is a directory")
    {}
};
};
