from faasmcli.util.constants import NONCE_SIZE, TAG_SIZE
import ctypes


def sgx_wamr_encrypted_data_blob_t_factory(msg_len):
    class sgx_wamr_encrypted_data_blob_t(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("nonce", NONCE_SIZE * ctypes.c_int8),
            ("tag", TAG_SIZE * ctypes.c_int8),
            ("data_len", ctypes.c_int32),
            ("data", (msg_len - NONCE_SIZE - TAG_SIZE - 4) * ctypes.c_int8),
        ]

    return sgx_wamr_encrypted_data_blob_t


def sgx_wamr_result_t_factory(msg_len):
    class sgx_wamr_result_t(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("return_value", ctypes.c_int32),
            ("output_nonce", NONCE_SIZE * ctypes.c_int8),
            ("policy_nonce", NONCE_SIZE * ctypes.c_int8),
            ("execution_stack_len", ctypes.c_int32),
            (
                "attestation",
                (msg_len - 4 - 2 * NONCE_SIZE - 4) * ctypes.c_int8,
            ),
        ]

    return sgx_wamr_result_t
