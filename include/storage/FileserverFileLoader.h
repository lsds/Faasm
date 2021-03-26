#pragma once

#include "FileLoader.h"

/**
 * This is a class that overrides *only* the loading of wasm and object files.
 * Any write operations are disabled because they're not valid.
 *
 * It's a stop-gap for environments that don't have decent object stores
 * available.
 */
namespace storage {
class FileserverFileLoader : public FileLoader
{
  public:
    explicit FileserverFileLoader(bool useFilesystemCacheIn);

    std::string getFileserverUrl();

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

    void flushFunctionFiles() override;

    void uploadFunction(faabric::Message& msg) override
    {
        throw std::runtime_error(
          "Not implemented for fileserver function loader");
    }

    void uploadPythonFunction(faabric::Message& msg) override
    {
        throw std::runtime_error(
          "Not implemented for fileserver function loader");
    }

    void uploadFunctionObjectFile(const faabric::Message& msg,
                                  const std::vector<uint8_t>& objBytes) override
    {
        throw std::runtime_error(
          "Not implemented for fileserver function loader");
    }

    void uploadFunctionAotFile(const faabric::Message& msg,
                               const std::vector<uint8_t>& objBytes) override
    {
        throw std::runtime_error(
          "Not implemented for fileserver function loader");
    }

    void uploadSharedObjectObjectFile(
      const std::string& path,
      const std::vector<uint8_t>& objBytes) override
    {
        throw std::runtime_error(
          "Not implemented for fileserver function loader");
    }

    void uploadSharedObjectAotFile(
      const std::string& path,
      const std::vector<uint8_t>& objBytes) override
    {
        throw std::runtime_error(
          "Not implemented for fileserver function loader");
    }

    void uploadSharedFile(const std::string& path,
                          const std::vector<uint8_t>& fileBytes) override
    {
        throw std::runtime_error(
          "Not implemented for fileserver function loader");
    }

  private:
    bool useFilesystemCache = true;

    std::vector<uint8_t> doLoad(const std::string& urlPath,
                                const std::string& headerPath,
                                const std::string& storagePath);
};
};
