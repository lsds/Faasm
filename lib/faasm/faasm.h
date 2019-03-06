#ifndef _FAASM_H
#define _FAASM_H

// For lambda builds we need to include the lambda function interface
// which defines its own main method etc.
#if AWS_LAMBDA == 1
#include <lambda_func/interface.h>
#else

#include "faasm/memory.h"

namespace faasm {
    /**
    * Function for faasm functions to implement
    */
    int exec(FaasmMemory *memory);
}

int main(int argc, char *argv[]) {
    faasm::FaasmMemory memory;
    faasm::exec(&memory);

    return 0;
}

#endif

#endif
