#!/bin/bash

set -e

THIS_DIR=$(dirname $(readlink -f $0))

ZIP_URL=http://data.mxnet.io/mxnet/data/mnist.zip

pushd ${THIS_DIR} > /dev/null

wget ${ZIP_URL}

unzip -o mnist.zip

rm mnist.zip*

popd > /dev/null

