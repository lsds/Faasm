#pragma once

#include "Faaslet.h"

#if FAASM_SGX
#include <sgx/faasm_sgx_system.h>
#endif

#include <faabric/executor/FaabricPool.h>

#if (FAASM_SGX)
#include <sgx/faasm_sgx_system.h>
#endif

using namespace faabric::executor;

namespace faaslet {
class FaasletPool : public FaabricPool
{
  public:
    explicit FaasletPool(int nThreads)
      : FaabricPool(nThreads)
    {
        // Create an enclave if necessary
#if FAASM_SGX
        sgx::checkSgxSetup();
#endif

        // Prepare the Python runtime up front
        preloadPythonRuntime();
    }

  protected:
    std::unique_ptr<FaabricExecutor> createExecutor(int threadIdx)
    {
        return std::make_unique<Faaslet>(threadIdx);
    }
};
}
