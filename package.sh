#!/usr/bin/sh

export DOCKER_BUILDKIT=1
docker run --rm -v "$(pwd)":/io "$(docker build -q .)"
