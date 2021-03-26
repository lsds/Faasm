#!/bin/bash
set -e # fail on error

USER="demo"
UPLOAD_FUNCS="hello chain_named_a chain_named_b chain_named_c"
INVOKE_FUNCS="hello chain_named_a"
runner_pid=0

function kill_runner {
    #kill the pool runner:
    kill -9 $runner_pid
}
trap kill_runner EXIT
trap exit INT

function start_runner {
    OBJ_DIR="./wasm" FUNC_DIR="./wasm" WASM_VM="wamr" LOG_LEVEL="info" ./build/bin/pool_runner&
    runner_pid=$!
    echo "pool_runner has pid $runner_pid"
    sleep 1 # wait for pool_runner to be ready
    ps | grep $runner_pid # this lets the script fail if pool_runner is not running anymore
}


echo "################################################################################"
echo "# Test: Policy Generation ######################################################"
echo "################################################################################"

for f in $UPLOAD_FUNCS; do
    echo "- Function $f --------------------------------------------------------"
    inv -r faasmcli/faasmcli policy $USER $f
    echo -e "\n"
done

echo -e "\n"

echo "################################################################################"
echo "# Test: Function and Policy Upload #############################################"
echo "################################################################################"

for f in $UPLOAD_FUNCS; do
    echo "- Function $f --------------------------------------------------------"
    inv -r faasmcli/faasmcli upload $USER $f --sgx
    echo -e "\n"
done

echo -e "\n"

echo "################################################################################"
echo "# Test: Function Invocation ####################################################"
echo "################################################################################"

for f in $INVOKE_FUNCS; do
    echo "- Function $f --------------------------------------------------------"
    start_runner
    inv -r faasmcli/faasmcli invoke $USER $f --sgx
    kill_runner
done

# if we reach this withour error: nice!
echo "################################################################################"
echo "# ALL TESTS PASSED #############################################################"
echo "################################################################################"

