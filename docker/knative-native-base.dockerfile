FROM faasm/base

# Install python lib for python functions
RUN apt-get install libpython3-dev

COPY . /usr/local/code/faasm

# Install native dependencies
WORKDIR /usr/local/code/faasm/ansible
RUN ansible-playbook pistache.yml
RUN ansible-playbook eigen.yml

# Nuke and recreate the build dir
WORKDIR /tmp
RUN rm -rf /faasm/build
WORKDIR /faasm/build

# Build the knative native runner
RUN cmake \
    -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
    -DCMAKE_C_COMPILER=/usr/bin/clang \
    -DFAASM_BUILD_TYPE=knative-native \
    -DCMAKE_BUILD_TYPE=Release \
    /usr/local/code/faasm

# Build the library
RUN cmake --build . --target knative_native -- -j

CMD "/bin/bash"