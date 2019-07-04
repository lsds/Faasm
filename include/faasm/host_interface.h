#ifndef FAASM_HOST_INTERFACE_H
#define FAASM_HOST_INTERFACE_H

// #define HOST_IFACE_FUNC __attribute__((weak))
#define HOST_IFACE_FUNC

// In a wasm build, these need to be C definitions to avoid the names getting mangled
#if WASM_BUILD == 1
extern "C" {
#endif

HOST_IFACE_FUNC
void __faasm_read_state(const char *key, unsigned char *buffer, long bufferLen, int async);

HOST_IFACE_FUNC
unsigned char *__faasm_read_state_ptr(const char *key, long totalLen, int async);

HOST_IFACE_FUNC
void __faasm_write_state(const char *key, const unsigned char *data, long dataLen, int async);

HOST_IFACE_FUNC
void __faasm_write_state_offset(const char *key, long totalLen, long offset, const unsigned char *data, long dataLen,
                                int async);

HOST_IFACE_FUNC
void __faasm_read_state_offset(const char *key, long totalLen, long offset, unsigned char *buffer, long bufferLen,
                               int async);

HOST_IFACE_FUNC
void __faasm_flag_state_dirty(const char *key, long totalLen);

HOST_IFACE_FUNC
void __faasm_flag_state_offset_dirty(const char *key, long totalLen, long offset, long dataLen);

HOST_IFACE_FUNC
unsigned char *__faasm_read_state_offset_ptr(const char *key, long totalLen, long offset, long len, int async);

HOST_IFACE_FUNC
void __faasm_push_state(const char *key);

HOST_IFACE_FUNC
void __faasm_push_state_partial(const char *key);

HOST_IFACE_FUNC
void __faasm_lock_state_read(const char *key);

HOST_IFACE_FUNC
void __faasm_unlock_state_read(const char *key);

HOST_IFACE_FUNC
void __faasm_lock_state_write(const char *key);

HOST_IFACE_FUNC
void __faasm_unlock_state_write(const char *key);

HOST_IFACE_FUNC
long __faasm_read_input(unsigned char *buffer, long bufferLen);

HOST_IFACE_FUNC
void __faasm_write_output(const unsigned char *output, long outputLen);

HOST_IFACE_FUNC
void __faasm_chain_function(const char *name, const unsigned char *inputData, long inputDataSize);

HOST_IFACE_FUNC
void __faasm_chain_this(int idx, const unsigned char *inputData, long inputDataSize);

HOST_IFACE_FUNC
int __faasm_get_idx();

HOST_IFACE_FUNC
void __faasm_snapshot_memory(const char *key);

HOST_IFACE_FUNC
void __faasm_restore_memory(const char *key);

HOST_IFACE_FUNC
void __faasm_read_config(const char *varName, char *buffer);

#if WASM_BUILD == 1
}
#endif

#endif
