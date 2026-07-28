#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <registry-prefix>"
  echo "Docker Hub example: $0 docker.io/yigod/hn2026"
  echo "  -> docker.io/yigod/hn2026-ezpz1:latest"
  echo "Generic registry example: $0 registry.example.com/hn2026"
  echo "  -> registry.example.com/hn2026/ezpz1:latest"
  exit 1
fi

prefix="${1%/}"

declare -A images=(
  [ezpz1]="pwn-ezpz1:latest"
  [ezpz2]="pwn-ezpz2:latest"
  [notezpz1]="pwn-notezpz1:latest"
  [notezpz1-plus]="pwn-notezpz1-plus:latest"
  [notezpz2]="pwn-notezpz2:latest"
  [applepie]="pwn-applepie:latest"
  [darklamp]="pwn-darklamp:latest"
)

make_dst() {
  local prefix="$1"
  local name="$2"

  # Docker Hub repository names are namespace/repository only; no nested path like user/a/b.
  # If user passes docker.io/yigod/hn2026, push as docker.io/yigod/hn2026-ezpz1:latest.
  if [[ "$prefix" =~ ^docker\.io/([^/]+)/([^/]+)$ ]]; then
    echo "docker.io/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}-${name}:latest"
  elif [[ "$prefix" =~ ^([^./][^/]*)/([^/]+)$ ]]; then
    # Also support Docker Hub shorthand: yigod/hn2026 -> yigod/hn2026-ezpz1:latest
    echo "${BASH_REMATCH[1]}/${BASH_REMATCH[2]}-${name}:latest"
  else
    # Generic registries usually allow nested paths.
    echo "$prefix/$name:latest"
  fi
}

for name in ezpz1 ezpz2 notezpz1 notezpz1-plus notezpz2 applepie darklamp; do
  src="${images[$name]}"
  dst="$(make_dst "$prefix" "$name")"
  echo "[*] tag $src -> $dst"
  docker tag "$src" "$dst"
  echo "[*] push $dst"
  docker push "$dst"
done

echo "[+] pushed all images"
