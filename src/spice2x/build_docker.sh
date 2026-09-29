#!/usr/bin/env bash

set -eu

docker build --pull "$PWD/external/docker" -t spicetools/deps --platform linux/x86_64
docker build --build-context gitroot="$PWD/../../.git" . -t spicetools/spice:latest

# Interactive TTY if available, so docker build can be Ctrl+C'd
DOCKER_FLAGS=""
[ -t 0 ] && DOCKER_FLAGS="-it"

# Forward CI narrowing flags into the container (env is not inherited by default)
DOCKER_ENV_FLAGS=""
if [ -n "${SPICE_CI:-}" ]; then
	DOCKER_ENV_FLAGS="$DOCKER_ENV_FLAGS -e SPICE_CI"
fi
if [ -n "${SPICE_H264:-}" ]; then
	DOCKER_ENV_FLAGS="$DOCKER_ENV_FLAGS -e SPICE_H264"
fi

docker run $DOCKER_FLAGS --rm $DOCKER_ENV_FLAGS -v "$PWD/dist:/src/src/spice2x/dist" -v "$PWD/bin:/src/src/spice2x/bin" -v "$PWD/.ccache:/src/src/spice2x/.ccache" spicetools/spice "$@"
