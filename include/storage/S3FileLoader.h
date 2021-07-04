#pragma once

#include <conf/FaasmConfig.h>
#include <faabric/util/config.h>
#include <faabric/util/func.h>
#include <storage/FileLoader.h>
#include <storage/S3Wrapper.h>

namespace storage {
class S3FileLoader : public FileLoader
{
  public:
    S3FileLoader();

    std::vector<uint8_t> loadFunctionWasm(const faabric::Message& msg) override;

    std::vector<uint8_t> loadSharedObjectWasm(const std::string& path) override;

    std::vector<uint8_t> loadFunctionObjectFile(
      const faabric::Message& msg) override;

    std::vector<uint8_t> loadSharedObjectObjectFile(
      const std::string& path) override;

    std::vector<uint8_t> loadSharedFile(const std::string& path) override
    {
        throw std::runtime_error("Not implemented for S3 function loader");
    }

    void uploadFunction(faabric::Message& msg) override;

    void uploadPythonFunction(faabric::Message& msg) override;

    void uploadFunctionObjectFile(
      const faabric::Message& msg,
      const std::vector<uint8_t>& objBytes) override;

    void uploadSharedObjectObjectFile(
      const std::string& path,
      const std::vector<uint8_t>& objBytes) override;

    void uploadSharedFile(const std::string& path,
                          const std::vector<uint8_t>& fileBytes) override
    {
        throw std::runtime_error("Not implemented for S3 function loader");
    }

  private:
    conf::FaasmConfig& conf;
    storage::S3Wrapper s3;

    std::vector<uint8_t> loadFileBytes(const std::string& path);
};
};
