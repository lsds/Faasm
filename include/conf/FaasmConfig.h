#pragma once

#include <string>

namespace conf {
class FaasmConfig
{
  public:
    std::string hostType;
    std::string functionStorage;
    std::string fileserverUrl;

    std::string cgroupMode;
    std::string netNsMode;

    std::string pythonPreload;
    std::string captureStdout;

    int chainedCallTimeout;

    std::string wasmVm;

    std::string functionDir;
    std::string objectFileDir;
    std::string runtimeFilesDir;
    std::string sharedFilesDir;
    std::string sharedFilesStorageDir;
    std::string bucketName;

    FaasmConfig();
    void reset();

  private:
    int getIntParam(const char* name, const char* defaultValue);

    void initialise();
};

FaasmConfig& getFaasmConfig();
}
