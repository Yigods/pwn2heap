#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Build the 32-bit glibc-2.27 classic notezpz1 in its native Ubuntu 18.04 environment.
docker run --rm -v "$PWD/notezpz1:/work" -w /work ubuntu:18.04 bash -lc '
  set -euo pipefail
  export DEBIAN_FRONTEND=noninteractive
  dpkg --add-architecture i386
  apt-get update >/dev/null
  apt-get install -y --no-install-recommends gcc gcc-multilib libc6-dev-i386 libc6:i386 make patchelf ca-certificates >/dev/null
  ldd --version | head -1
  ./build.sh
'

if [[ "${1:-}" == "--native" ]]; then
  make clean all
else
  docker run --rm -v "$PWD:/work" -w /work ubuntu:24.04 bash -lc '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    if ! command -v gcc >/dev/null; then
      apt-get update >/dev/null
      apt-get install -y --no-install-recommends gcc libc6-dev make patchelf ca-certificates >/dev/null
    fi
    ldd --version | head -1
    make clean all
  '
fi

# Keep the runtime libc name aligned with the patched RUNPATH/NEEDED entry.
cp ezpz2/libc6_2.39-0ubuntu8.6_amd64.so ezpz2/libc.so.6
cp ezpz2/libc6_2.39-0ubuntu8.6_amd64.so ezpz1/libc.so.6
cp notezpz1-plus/libc6_2.39-0ubuntu8.6_amd64.so notezpz1-plus/libc.so.6
cp notezpz2/libc6_2.39-0ubuntu8.6_amd64.so notezpz2/libc.so.6
cp applepie/libc6_2.39-0ubuntu8.6_amd64.so applepie/libc.so.6
cp darklamp/libc6_2.39-0ubuntu8.6_amd64.so darklamp/libc.so.6
make checksec
