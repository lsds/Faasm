FROM faasm/http

# Build the edge binary
COPY . /usr/local/code/faasm
WORKDIR /faasm/build
RUN cmake --build . --target edge

CMD "/faasm/build/bin/edge"