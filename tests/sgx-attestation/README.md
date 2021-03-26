SGX-Attestation Test
===================

The SGX-attestaion test is only partly based on `docker-compose`:
 - `docker-compose -f docker/docker-compose-sgx-attestation.yml up` starts the following containerized services: 
     - mongoDB
     - keymanager (in simulation mode, i.e. it does not contact the IAS)
     - upload
     - redis (queue and state)
 - Run tests: `./tests/sgx-attestation/sgx_integtration_test.sh`

*Important:* The test script restarts the  `pool_runner` after each test run because the WASM Module needs to be unloaded before re-registering the function. If the `pool_runner` is not restarted, the keymanger will print this error message: `ERROR: function hash 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' and sid 'yyyyyyyyyyyy' do not match`

The output should be something like this:
```
################################################################################
# Test: Policy Generation ######################################################
################################################################################
- Function hello --------------------------------------------------------
0 allowed functions found for function 'hello': {}
digraph cfg {
        szwfpnjo2 [label="start: hello:0"]
        szwfpnjo3 [label="end: hello:0"]
        szwfpnjo2 -> szwfpnjo3
        szwfpnjo3 [label="end: hello:0"]
}
policy file written to /opt/tmp/goltzsch/faasm/wasm/demo/hello/policy.json


- Function chain_named_a --------------------------------------------------------
2 allowed functions found for function 'chain_named_a': {'chain_named_c': '7338d09cca48f161359df07f91e2ef0963adb95208af7585c71600762c9127cf', 'chain_named_b': 806b7cd05120b321d50a03dc81b173e95894213587ba8800d7321d25d1e8b73c'}
digraph cfg {
        vdtbgjke2 [label="start: chain_named_a:0"]
        vdtbgjke3 [label="end: chain_named_a:0"]
        vdtbgjke2 -> vdtbgjke3
        vdtbgjke3 [label="end: chain_named_a:0"]
}
policy file written to /opt/tmp/goltzsch/faasm/wasm/demo/chain_named_a/policy.json


- Function chain_named_b --------------------------------------------------------
0 allowed functions found for function 'chain_named_b': {}
digraph cfg {
        apekdfbc2 [label="start: chain_named_b:0"]
        apekdfbc3 [label="end: chain_named_b:0"]
        apekdfbc2 -> apekdfbc3
        apekdfbc3 [label="end: chain_named_b:0"]
}
policy file written to /opt/tmp/goltzsch/faasm/wasm/demo/chain_named_b/policy.json


- Function chain_named_c --------------------------------------------------------
0 allowed functions found for function 'chain_named_c': {}
digraph cfg {
        kqpodlmz2 [label="start: chain_named_c:0"]
        kqpodlmz3 [label="end: chain_named_c:0"]
        kqpodlmz2 -> kqpodlmz3
        kqpodlmz3 [label="end: chain_named_c:0"]
}
policy file written to /opt/tmp/goltzsch/faasm/wasm/demo/chain_named_c/policy.json




################################################################################
# Test: Function and Policy Upload #############################################
################################################################################
- Function hello --------------------------------------------------------
Function upload complete
Registration was successful.
curl -X PUT http://127.0.0.1:8002/f/demo/hello -T /opt/tmp/goltzsch/faasm/wasm/demo/hello/function.wasm
Successfully PUT file /opt/tmp/goltzsch/faasm/wasm/demo/hello/function.wasm to http://127.0.0.1:8002/f/demo/hello


- Function chain_named_a --------------------------------------------------------
Function upload complete
Registration was successful.
curl -X PUT http://127.0.0.1:8002/f/demo/chain_named_a -T /opt/tmp/goltzsch/faasm/wasm/demo/chain_named_a/function.wasm
Successfully PUT file /opt/tmp/goltzsch/faasm/wasm/demo/chain_named_a/function.wasm to http://127.0.0.1:8002/f/demo/chain_named_a


- Function chain_named_b --------------------------------------------------------
Function upload complete
Registration was successful.
curl -X PUT http://127.0.0.1:8002/f/demo/chain_named_b -T /opt/tmp/goltzsch/faasm/wasm/demo/chain_named_b/function.wasm
Successfully PUT file /opt/tmp/goltzsch/faasm/wasm/demo/chain_named_b/function.wasm to http://127.0.0.1:8002/f/demo/chain_named_b


- Function chain_named_c --------------------------------------------------------
Function upload complete
Registration was successful.
curl -X PUT http://127.0.0.1:8002/f/demo/chain_named_c -T /opt/tmp/goltzsch/faasm/wasm/demo/chain_named_c/function.wasm
Successfully PUT file /opt/tmp/goltzsch/faasm/wasm/demo/chain_named_c/function.wasm to http://127.0.0.1:8002/f/demo/chain_named_c




################################################################################
# Test: Function Invocation ####################################################
################################################################################
- Function hello --------------------------------------------------------
Executing demo:hello with involved functions: {'hello': 'd85f51600ac9b9d1d17b6aba535e28ada934f3cfbac71a50e1b69b02db7a99ac'}
{"result":"xH9ZMU6S/6buFMxO+PCC8G1cYS2OSKkqmiPLPmoAAABV1FmtWuRZ7WYe0d1Mi7rgQA2FhpG1bVO/AwJPxgBbadtxev3Cv31aCKEF70kkeuG3z6PxLTvo4KsF0spaM3E7e8w5RO9l+sd6qie5Z5+YVyr/XwRc/NW0PiFF8N7Z2poK10QV/quCnd9F","output_data":"qmcTUP4mVSSQfyCup/UhrQznouYAAd4EbV1ODgwAAAD6YW+oiRknZjtc4H8="}
Verfication of the following execution stack was successful ✅ <hello:d85f51600ac9b9d1d17b6aba535e28ada934f3cfbac71a50e1b69b02db7a99ac:0>
Result: Hello Faasm!
- Function chain_named_a --------------------------------------------------------
Executing demo:chain_named_a with involved functions: {'chain_named_a': '95de67dd0ba9055e0ed978d338c601dee163ada9c5554a3b80fe688fa4566358', 'chain_named_b': '806b7cd05120b321d50a03dc81b173e95894213587ba8800d7321d25d1e8b73c'}
{"result":"Hd4l6qSfcZDCiT1he9VKBd39cmxhlu2xYnenh3IAAAD/QL8DHBAUWXLLpdWUThNAolfp5cOqBUcl30sKwG7MXVPfgu8ArH+ZGM9ddaj+biPmVxNsONNkb/BB6c2VuZKPXhHdR6dxq2BHYJ87P1w/rk3w59URXXD9X+m0Fz4rCxduzHHONRsweE0cbCdJKwQZQYM=","output_data":""}
Verfication of the following execution stack was successful ✅ <chain_named_a:95de67dd0ba9055e0ed978d338c601dee163ada9c5554a3b80fe688fa4566358:0>




################################################################################
# ALL TESTS PASSED #############################################################
################################################################################
