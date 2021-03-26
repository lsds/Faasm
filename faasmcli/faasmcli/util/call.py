from time import sleep
import base64
import json

from faasmcli.util.env import PYTHON_USER, PYTHON_FUNC, FAABRIC_MSG_TYPE_FLUSH
from faasmcli.util.http import do_post
from faasmcli.util.endpoints import get_invoke_host_port, get_knative_headers
from faasmcli.util.endpoints import get_invoke_host_port
from faasmcli.util.env import (
    PYTHON_USER,
    PYTHON_FUNC,
    KEY_MANAGER_REGISTRY_IP,
    KEY_MANAGER_REGISTRY_PORT,
)
from faasmcli.util.crypto import (
    encrypt_aes_gcm_128,
    decrypt_aes_gcm_128,
    get_random_string,
)
from faasmcli.util.sgx_wamr_types import (
    sgx_wamr_encrypted_data_blob_t_factory,
    sgx_wamr_result_t_factory,
)
from faasmcli.util.constants import NONCE_SIZE, AES_KEY_SIZE
from faasmcli.util.policy import Verifier

STATUS_SUCCESS = "SUCCESS"
STATUS_FAILED = "FAILED"
STATUS_RUNNING = "RUNNING"

POLL_INTERVAL_MS = 1000


def _do_invoke(user, func, host, port, func_type, input=None):
    url = "http://{}:{}/{}/{}/{}".format(host, port, func_type, user, func)
    print("Invoking {}".format(url))
    do_post(url, input, json=True)


def _async_invoke(url, msg, headers=None, poll=False, host=None, port=None):
    # Submit initial async call
    async_result = do_post(url, msg, headers=headers, quiet=True, json=True)

    try:
        call_id = int(async_result)
    except ValueError:
        raise RuntimeError(
            "Could not parse async response to int: {}".format(async_result)
        )

    # Return the call ID if we're not polling
    if not poll:
        return call_id

    print("\n---- Polling {} ----".format(call_id))

    # Poll status until we get success/ failure
    result = None
    output = None
    count = 0
    while result != STATUS_SUCCESS:
        count += 1

        interval = float(POLL_INTERVAL_MS) / 1000
        sleep(interval)

        result, output = status_call_impl(
            msg["user"], msg["function"], call_id, host, port, quiet=True
        )
        print("\nPOLL {} - {}".format(count, result))

    print("\n---- Finished {} ----\n".format(call_id))
    print(output)

    if result == STATUS_SUCCESS:
        prefix = "SUCCESS:"
    else:
        prefix = "FAILED:"

    output = output.replace(prefix, "")

    return call_id


def invoke_impl(
    user,
    func,
    sgx,
    input=None,
    py=False,
    asynch=False,
    knative=True,
    poll=False,
    cmdline=None,
    mpi_world_size=None,
    debug=False,
):
    host, port = get_invoke_host_port()

    # Polling always requires asynch
    if poll:
        asynch = True

    # Create URL and message
    url = "http://{}".format(host)
    if not port == "80":
        url += ":{}".format(port)

    if py:
        msg = {
            "user": PYTHON_USER,
            "function": PYTHON_FUNC,
            "async": asynch,
            "py_user": user,
            "py_func": func,
            "python": True,
        }
    else:
        msg = {
            "user": user,
            "function": func,
            "async": asynch,
        }

    if sgx:
        msg["sgx"] = sgx

        key = get_random_string(AES_KEY_SIZE)
        register_msg = {"key": key}
        response = json.loads(
            do_post(
                "http://{}:{}/api/v1/registry/pre-request/{}/{}".format(
                    KEY_MANAGER_REGISTRY_IP,
                    KEY_MANAGER_REGISTRY_PORT,
                    user,
                    func,
                ),
                register_msg,
                quiet=True,
                json=True,
            )
        )
        msg["sid"] = response["sid"]
        hash_list = response["hash-list"]
        verify = response["verify"]
        chain_verify = response["chain-verify"]
        verifier = Verifier(func, hash_list, verify, chain_verify)
        if not input:
            input = "PLACEHOLDER"
        ciphertext, nonce, tag = encrypt_aes_gcm_128(
            input.encode(), key.encode()
        )
        msg["input_data"] = base64.b64encode(
            nonce
            + tag
            + len(ciphertext).to_bytes(4, byteorder="little")
            + ciphertext
        ).decode("utf8")
        print(
            "Executing {}:{} with involved functions:".format(user, func),
            hash_list,
        )

    elif input:
        msg["input_data"] = input

    if cmdline:
        msg["cmdline"] = cmdline

    if mpi_world_size:
        msg["mpi_world_size"] = mpi_world_size

    # Knative must pass custom headers
    if knative:
        headers = get_knative_headers()
    else:
        headers = {}

    if asynch:
        return _async_invoke(
            url, msg, headers=headers, poll=poll, host=host, port=port
        )
    else:
        response = do_post(url, msg, headers=headers, json=True)
        if sgx:
            response_json = json.loads(response)
            if "result" not in response_json:
                raise RuntimeError("sgx flags needs result struct")
            encrypted_result_blob = base64.b64decode(response_json["result"])
            encrypted_result_blob = sgx_wamr_encrypted_data_blob_t_factory(
                len(encrypted_result_blob)
            ).from_buffer_copy(encrypted_result_blob)
            result_nonce = bytes(encrypted_result_blob.nonce)
            result_tag = bytes(encrypted_result_blob.tag)
            encryted_result = bytes(encrypted_result_blob.data)
            result_blob = decrypt_aes_gcm_128(
                encryted_result, result_nonce, result_tag, key.encode()
            )
            result = sgx_wamr_result_t_factory(
                len(result_blob)
            ).from_buffer_copy(result_blob)
            input_nonce = bytes(result.policy_nonce)
            if nonce != input_nonce:
                raise RuntimeError("result doesnt match call")
            output_nonce = bytes(result.output_nonce)
            encrypted_output_blob = response_json["output_data"]
            if len(encrypted_output_blob) == 0:
                if output_nonce != bytes([0] * NONCE_SIZE):
                    raise RuntimeError("output doesnt not match to result")
            execution_stack = bytes(result.attestation).decode("ascii")
            if not verifier.is_valid_execution(execution_stack):
                raise RuntimeError("verification failed.")
            else:
                print(
                    "Verfication of the following execution stack was successful ✅",
                    end=" ",
                )
                print(execution_stack)
            if len(encrypted_output_blob) == 0:
                return ""
            encrypted_output_blob = base64.b64decode(encrypted_output_blob)
            encrypted_output_blob = sgx_wamr_encrypted_data_blob_t_factory(
                len(encrypted_output_blob)
            ).from_buffer_copy(encrypted_output_blob)
            if output_nonce != bytes(encrypted_output_blob.nonce):
                raise RuntimeError("output doesnt not match to result")
            output_tag = bytes(encrypted_output_blob.tag)
            encrypted_output = bytes(encrypted_output_blob.data)
            output = decrypt_aes_gcm_128(
                encrypted_output, output_nonce, output_tag, key.encode()
            ).decode("utf8")
            print("Result:", output)
            return output
        else:
            return response


def flush_call_impl(host, port):
    msg = {
        "type": FAABRIC_MSG_TYPE_FLUSH,
    }
    return _do_single_call(host, port, msg, False)


def status_call_impl(user, func, call_id, host, port, quiet=False):
    msg = {
        "user": user,
        "function": func,
        "status": True,
        "id": int(call_id),
    }
    call_result = _do_single_call(host, port, msg, quiet)

    if call_result.startswith("SUCCESS"):
        return STATUS_SUCCESS, call_result
    elif call_result.startswith("FAILED"):
        return STATUS_FAILED, call_result
    else:
        return STATUS_RUNNING, call_result


def exec_graph_call_impl(user, func, call_id, host, port, quiet=False):
    msg = {
        "user": user,
        "function": func,
        "exec_graph": True,
        "id": int(call_id),
    }
    call_result = _do_single_call(host, port, msg, quiet)

    if not quiet:
        print(call_result)

    return call_result


def _do_single_call(host, port, msg, quiet):
    url = "http://{}".format(host)
    if port != 80:
        url += ":{}/".format(port)

    # If wasm, can always use the faasm worker for getting status
    headers = get_knative_headers()

    return do_post(url, msg, headers=headers, quiet=quiet, json=True)
