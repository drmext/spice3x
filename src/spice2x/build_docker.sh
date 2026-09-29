#!/usr/bin/env bash

set -eu

# CI skips the AUR x264 compile. The deps image is rebuilt on every Actions
# runner, so this is the step that was still compiling x264.
DEPS_BUILD_ARGS=""
if [ "${SPICE_CI:-}" = "1" ]; then
	DEPS_BUILD_ARGS="--build-arg INSTALL_X264=0"
fi

# Actions runners have an empty Docker cache. Buildx stores the deps image
# layers in the GitHub Actions cache so later runs skip pacman/yay.
if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
	docker buildx build --load --pull \
		--cache-from type=gha,scope=spice-deps \
		--cache-to type=gha,scope=spice-deps,mode=max \
		$DEPS_BUILD_ARGS \
		"$PWD/external/docker" -t spicetools/deps --platform linux/x86_64
else
	docker build --pull $DEPS_BUILD_ARGS "$PWD/external/docker" -t spicetools/deps --platform linux/x86_64
fi
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
