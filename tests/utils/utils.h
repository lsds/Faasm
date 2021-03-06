#pragma once

#include <faabric/util/func.h>
#include <faaslet/Faaslet.h>

namespace tests {
void cleanSystem();

void execFunction(faabric::Message& msg,
                  const std::string& expectedOutput = "");

std::string execFunctionWithStringResult(faabric::Message& msg);

void execBatchWithPool(std::shared_ptr<faabric::BatchExecuteRequest> req,
                       int nThreads,
                       bool clean);

void execFuncWithPool(faabric::Message& call,
                      bool clean = true,
                      int timeout = 1000);

void executeWithWamrPool(const std::string& user, const std::string& func);

void executeWithSGX(const std::string& user, const std::string& func);

void checkMultipleExecutions(faabric::Message& msg, int nExecs);

void checkCallingFunctionGivesBoolOutput(const std::string& user,
                                         const std::string& funcName,
                                         bool expected);
}
