#!/bin/bash

set -e 

# Camino-conduit root folder
CAMINO_CONDUIT_PATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )"; cd .. && pwd )
cd "${CAMINO_CONDUIT_PATH}"

# Check if Cargo is installed
if ! command -v cargo &> /dev/null; then
    echo -e "Cargo is not installed. Please install the necessary dependencies:"
    echo -e "$ sudo apt install libclang-dev build-essential"
    exit 1
fi

echo -e "Building camino-conduit"
cargo build --release

# copying binary to ${CAMINO_CONDUIT_PATH}/build/
mkdir -p "${CAMINO_CONDUIT_PATH}/build"
cp -a target/release/camino-conduit build/

cd -

echo "camino-conduit is built successfully"
echo "binary saved to ${CAMINO_CONDUIT_PATH}/build/camino-conduit"



