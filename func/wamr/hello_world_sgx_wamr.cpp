//
// Created by Joshua Heinemann on 09.07.20.
// TU-Braunschweig (heineman@ibr.cs.tu-bs.de)
//

#include <stdio.h>
#include <sgx/faasm_sgx_wamr.h>

void __attribute__((optnone)) FAASM_MAIN(main_){
    printf("[Info] Hello World from sgx_wamr\n");
}