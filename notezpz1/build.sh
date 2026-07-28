#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
gcc -m32 -O0 -g -fstack-protector-strong -fPIE -pie notezpz.c -o notezpz -Wl,-z,relro -Wl,-z,now
cp /lib/i386-linux-gnu/ld-2.27.so ./ld-linux.so.2
cp /lib/i386-linux-gnu/libc-2.27.so ./libc-2.27.so
cp ./libc-2.27.so ./libc.so.6
cp notezpz notezpz_patched
patchelf --set-interpreter ./ld-linux.so.2 --set-rpath . notezpz_patched
