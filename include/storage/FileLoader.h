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
      const faabric::Message& msg);

    virtual std::vector<uint8_t> loadSharedObjectWasm(
      const std::string& path);

    virtual std::vector<uint8_t> loadFunctionObjectFile(
      const faabric::Message& msg);

    virtual std::vector<uint8_t> loadFunctionWamrAotFile(
      const faabric::Message& msg);

    virtual std::vector<uint8_t> loadSharedObjectObjectFile(
      const std::string& path);

    virtual std::vector<uint8_t> loadSharedFile(const std::string& path);

    virtual std::vector<uint8_t> loadFunctionObjectHash(
      const faabric::Message& msg);

    virtual std::vector<uint8_t> loadFunctionWamrAotHash(
      const faabric::Message& msg);

    virtual std::vector<uint8_t> loadSharedObjectObjectHash(
      const std::string& path);

    virtual void uploadFunctionObjectHash(const faabric::Message& msg,
                                          const std::vector<uint8_t>& hash);

    virtual void uploadFunctionWamrAotHash(
      const faabric::Message& msg,
      const std::vector<uint8_t>& hash);

    virtual void uploadSharedObjectObjectHash(
      const std::string& path,
      const std::vector<uint8_t>& hash);

    virtual void uploadSharedObjectAotHash(
      const std::string& path,
      const std::vector<uint8_t>& hash);

    virtual void uploadFunction(faabric::Message& msg);

    virtual void uploadPythonFunction(faabric::Message& msg);

    virtual void uploadFunctionObjectFile(
      const faabric::Message& msg,
      const std::vector<uint8_t>& objBytes);

    virtual void uploadFunctionAotFile(
      const faabric::Message& msg,
      const std::vector<uint8_t>& objBytes);

    virtual void uploadSharedObjectObjectFile(
      const std::string& path,
      const std::vector<uint8_t>& objBytes);

    virtual void uploadSharedObjectAotFile(
      const std::string& path,
      const std::vector<uint8_t>& objBytes);

    virtual void uploadSharedFile(const std::string& path,
                                  const std::vector<uint8_t>& fileBytes);

    virtual void flushFunctionFiles();

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
