FROM ubuntu:20.04

# System deps
RUN apt-get update
RUN apt-get install -y \
    python3-pip \
    git

# clone keymanager + install python deps
WORKDIR /usr/local/code
RUN git clone \
    https://github.com/faasm/keymanager
WORKDIR /usr/local/code/keymanager
RUN pip3 install -r requirements.txt

# run keymanager in sim mdoe
WORKDIR /usr/local/code/keymanager
CMD ./keymanager-sim.sh
