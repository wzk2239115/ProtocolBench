#!/usr/bin/env bash
# Idempotent build of the NSPK 1978 live target image.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-protocolbench/nspk-target:latest}"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker not available; target runs as a local subprocess fallback" >&2
    exit 0
fi

if docker image inspect "${IMAGE}" >/dev/null 2>&1 && [ "${FORCE:-0}" != "1" ]; then
    echo "image ${IMAGE} already present (set FORCE=1 to rebuild)"
    exit 0
fi

docker build -t "${IMAGE}" "${HERE}/target"
echo "built ${IMAGE}"
