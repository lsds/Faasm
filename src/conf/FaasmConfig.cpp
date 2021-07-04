#include <conf/FaasmConfig.h>
#include <faabric/util/environment.h>
#include <faabric/util/logging.h>

using namespace faabric::util;

namespace conf {
FaasmConfig& getFaasmConfig()
{
    static FaasmConfig conf;
    return conf;
}

FaasmConfig::FaasmConfig()
{
    this->initialise();
}

void FaasmConfig::initialise()
{
    hostType = getEnvVar("HOST_TYPE", "default");
    functionStorage = getEnvVar("FUNCTION_STORAGE", "local");
    fileserverUrl = getEnvVar("FILESERVER_URL", "");

    cgroupMode = getEnvVar("CGROUP_MODE", "on");
    netNsMode = getEnvVar("NETNS_MODE", "off");

    pythonPreload = getEnvVar("PYTHON_PRELOAD", "off");
    captureStdout = getEnvVar("CAPTURE_STDOUT", "off");

    wasmVm = getEnvVar("WASM_VM", "wavm");
    chainedCallTimeout = this->getIntParam("CHAINED_CALL_TIMEOUT", "300000");

    std::string faasmLocalDir =
      getEnvVar("FAASM_LOCAL_DIR", "/usr/local/faasm");
    functionDir = fmt::format("{}/{}", faasmLocalDir, "wasm");
    objectFileDir = fmt::format("{}/{}", faasmLocalDir, "object");
    runtimeFilesDir = fmt::format("{}/{}", faasmLocalDir, "runtime_root");
    sharedFilesDir = fmt::format("{}/{}", faasmLocalDir, "shared");
    sharedFilesStorageDir = fmt::format("{}/{}", faasmLocalDir, "shared_store");

    bucketName = getEnvVar("BUCKET_NAME", "faasm");
}

int FaasmConfig::getIntParam(const char* name, const char* defaultValue)
{
    int value = stoi(faabric::util::getEnvVar(name, defaultValue));

    return value;
};

void FaasmConfig::reset()
{
    this->initialise();
}
}
