from os import makedirs, environ
from os.path import dirname, realpath, join, exists, expanduser

from faasmtools.build import FAASM_LOCAL_DIR


def _get_dir(variable, default):
    env_val = environ.get(variable)
    return env_val if env_val else default


FAABRIC_MSG_TYPE_CALL = 0
FAABRIC_MSG_TYPE_FLUSH = 4

HOME_DIR = expanduser("~")
PROJ_ROOT = dirname(dirname(dirname(dirname(realpath(__file__)))))
ANSIBLE_ROOT = join(PROJ_ROOT, "ansible")

PYTHON_USER = "python"
PYTHON_FUNC = "py_func"

FAASM_HOME = join(HOME_DIR, "faasm")
FAASM_DATA_DIR = join(HOME_DIR, "faasm", "data")
FAASM_MACHINE_CODE_DIR = join(FAASM_LOCAL_DIR, "object")
FAASM_RUNTIME_ROOT = join(FAASM_LOCAL_DIR, "runtime_root")
FAASM_SHARED_ROOT = join(FAASM_LOCAL_DIR, "shared")
FAASM_SHARED_STORAGE_ROOT = join(FAASM_LOCAL_DIR, "shared_store")
FAASM_SHARED_ROOT = join(FAASM_LOCAL_DIR, "shared")
FAASM_INSTALL_DIR = "/usr/local"
WASM_DIR = join(FAASM_LOCAL_DIR, "wasm")

FAASM_BUILD_DIR = _get_dir("FAASM_BUILD_DIR", "/build/faasm")

FAASM_CONFIG_FILE = join(PROJ_ROOT, "faasm.ini")

BENCHMARK_BUILD = join(HOME_DIR, "faasm", "bench")
RESULT_DIR = join(FAASM_HOME, "results")
BENCHMARK_ENV = {
    "CGROUP_MODE": "off",
    "NETNS_MODE": "off",
    "GLOBAL_MESSAGE_TIMEOUT": "120000",
    "LOG_LEVEL": "off",
}

RUNTIME_S3_BUCKET = "faasm-runtime"
MISC_S3_BUCKET = "faasm-misc"
DATA_S3_BUCKET = "faasm-data"
TEST_S3_BUCKET = "faasm-test"

# TODO - avoid hard-coding
AWS_ACCOUNT_ID = "733781933474"
AWS_REGION = "eu-west-1"

PY_RUNTIME_ROOT = join(FAASM_RUNTIME_ROOT, "lib", "python3.8")

LATEST_CMAKE = "/usr/local/lib/cmake-3.15/bin/cmake"

KEY_MANAGER_REGISTRY_IP = environ.get("KM_REGISTRY_HOST", "localhost")
KEY_MANAGER_REGISTRY_PORT = 5000
WASM_OPT_BIN = "wasm-opt"


def get_wasm_func_path(user, func_name):
    func_dir = join(WASM_DIR, user, func_name)

    if not exists(func_dir):
        makedirs(func_dir, exist_ok=True, mode=0o775)

    return join(func_dir, "function.wasm")


def set_benchmark_env():
    environ.update(BENCHMARK_ENV)
