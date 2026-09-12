#!/usr/bin/env bash
# Build the agent and verifier images (pinned tamarin 1.12.0 from docker/bin/).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAG="${TAMARIN_IMAGE_TAG:-1.12.0}"
AGENT_TAG="${AGENT_IMAGE_TAG:-latest}"

docker build -f "${REPO_ROOT}/docker/agent.Dockerfile" \
    -t "protocolbench/agent:${AGENT_TAG}" \
    "${REPO_ROOT}/docker"

docker build -f "${REPO_ROOT}/docker/verifier.Dockerfile" \
    -t "tamaringym/verifier:${TAG}" \
    "${REPO_ROOT}/docker"

echo "Built protocolbench/agent:${AGENT_TAG} and tamaringym/verifier:${TAG}"
