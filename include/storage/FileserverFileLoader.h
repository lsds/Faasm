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
class FileserverFileLoader final : public FileLoader
{
  public:
    explicit FileserverFileLoader(bool useFilesystemCacheIn);

    std::string getFileserverUrl();

    std::vector<uint8_t> loadFunctionWasm(const faabric::Message& msg) override;

    std::vector<uint8_t> loadSharedObjectWasm(const std::string& path) override;

    std::vector<uint8_t> loadFunctionObjectFile(
      const faabric::Message& msg) override;

    std::vector<uint8_t> loadSharedObjectObjectFile(
      const std::string& path) override;

    std::vector<uint8_t> loadSharedFile(const std::string& path) override;

    void flushFunctionFiles() override;

  private:
    bool useFilesystemCache = true;

    std::vector<uint8_t> doLoad(const std::string& urlPath,
                                const std::string& headerPath,
                                const std::string& storagePath);
};
};
