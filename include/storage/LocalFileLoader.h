#pragma once

#include "FileLoader.h"
#include <faabric/util/config.h>

namespace storage {
class LocalFileLoader : public FileLoader
{
  public:
    std::vector<uint8_t> loadFunctionWasm(const faabric::Message& msg) override;

    std::vector<uint8_t> loadEncryptedFunctionWasm(
      const faabric::Message& msg) override;

    std::vector<uint8_t> loadSharedObjectWasm(const std::string& path) override;

    std::vector<uint8_t> loadFunctionObjectFile(
      const faabric::Message& msg) override;

    std::vector<uint8_t> loadFunctionWamrAotFile(
      const faabric::Message& msg) override;

    std::vector<uint8_t> loadSharedObjectObjectFile(
      const std::string& path) override;

    std::vector<uint8_t> loadSharedFile(const std::string& path) override;

    std::vector<uint8_t> loadFunctionObjectHash(
      const faabric::Message& msg) override;

    std::vector<uint8_t> loadFunctionWamrAotHash(
      const faabric::Message& msg) override;

    std::vector<uint8_t> loadSharedObjectObjectHash(
      const std::string& path) override;

    void uploadFunctionObjectHash(const faabric::Message& msg,
                                  const std::vector<uint8_t>& hash) override;

    void uploadFunctionWamrAotHash(const faabric::Message& msg,
                                   const std::vector<uint8_t>& hash) override;

    void uploadSharedObjectObjectHash(
      const std::string& path,
      const std::vector<uint8_t>& hash) override;

    void uploadSharedObjectAotHash(const std::string& path,
                                   const std::vector<uint8_t>& hash) override;

    void uploadFunction(faabric::Message& msg) override;

    void uploadPythonFunction(faabric::Message& msg) override;

    void uploadFunctionObjectFile(
      const faabric::Message& msg,
      const std::vector<uint8_t>& objBytes) override;

    void uploadFunctionAotFile(const faabric::Message& msg,
                               const std::vector<uint8_t>& objBytes) override;

    void uploadSharedObjectObjectFile(
      const std::string& path,
      const std::vector<uint8_t>& objBytes) override;

    void uploadSharedObjectAotFile(
      const std::string& path,
      const std::vector<uint8_t>& objBytes) override;

    void uploadSharedFile(const std::string& path,
                          const std::vector<uint8_t>& fileBytes) override;

    void flushFunctionFiles() override;

  private:
    std::vector<uint8_t> loadHashForPath(const std::string& path);

    void writeHashForFile(const std::string& path,
                          const std::vector<uint8_t>& hash);
};
};
