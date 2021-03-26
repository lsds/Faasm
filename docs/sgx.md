# Faasm SGX Support

Faasm provides
[SGX](https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions.html)
support using [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime).

You can read the latest SGX Linux developer instructions 
[here](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_Developer_Guide.pdf).

[@J-Heinemann](https://github.com/J-Heinemann) is responsible for a lot of the
SGX work in Faasm, but some messy merges have mixed up ownership of a couple of
commits.

Credits for the work on SGX attestation go to [@golsch](https://github.com/golsch),
who implemented this as part of his Master's thesis.

## SGX Set-up

_Simulation Mode_

You'll need to install SGX. You can see how this is done by looking at the
[`faasm/sgx` dockerfile](../docker/sgx.dockerfile).

Simulation mode is the default for Faasm builds.

_Hardware mode_

Hardware Mode requires more SGX packages than Simulation Mode (e.g. SGX driver,
SGX LE etc.). The drive and prebuilt binaries can be downloaded from [the Intel
website](https://download.01.org/intel-sgx/sgx-linux/2.12/distro/ubuntu20.04-server/).

To run in Hardware Mode, you need to set `FAASM_SGX_SIM_MODE=OFF` (obviously
this is only possible with an SGX-enabled CPU).

## Building Faasm with SGX enabled

The Faasm build will automatically detect some properties of your SGX
installation with [SGX-CMake](https://github.com/xzhangxa/SGX-CMake).

High-level Faasm SGX support is configured with CMake options in the [main
`CMakeLists.txt`](../CMakeLists.txt). 

Low-level SGX-related customisation is found in [the SGX-specific
`CMakeLists.txt`](../src/sgx/CMakeLists.txt).

### General Options

- `FAASM_SGX_SIM_MODE` - Specifies the SGX execution mode whether the Simulation
  or Hardware mode is used.  Enabling this option chooses the Simulation mode.
  Default is on.
- `FAASM_SGX_WAMR_AOT_MODE` - Activates the Ahead of Time execution mode of
  WAMR.  If enabled, AoT is used. Otherwise the interpreter mode of WAMR is
  used. Default is on.
- `FAASM_SGX_WHITELISTING` - Enables the Whitelisting extension. This option is 
  only available if `FAASM_SGX_WAMR_AOT_MODE=OFF`.  Default is off.
- `FAASM_SGX_XRA` - Enables the eXtended Remote Attestation mechanism. Default 
  is off.

### Low-Level Options

- `FAASM_SGX_DEBUG`- Prints debug information messages.  Useful for development
  but slows down the execution.  Default is 1
- `FAASM_SGX_INIT_TCS_SLOTS` - Specifies the amount of Faasm-SGX TCS slots after
  initialization.  Its recommended (but not necessary) to use the same number as
  available SGX TCS.  Default is 2.
- `FAASM_SGX_WAMR_BUILDIN_LIBC` - This option enables the WAMR built-in libc.
  Default is 1 (enabled).
- `FAASM_SGX_WAMR_WASI_LIBC` - This option enables WASI support. If this option 
  is enabled, please set `#define FAASM_SGX_WAMR_WASI_LIBC 1` in 
  [faasm_sgx_enclave.edl](../src/sgx/faasm_sgx_enclave.edl). Default is 0 
  (disabled).
- `SGX_DEBUG_MODE` - This option enables or disables the SGX debug mode. 
  Default is 1 (enabled).
