#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
run_and_check() {
  local name="$1" pattern="$2" attempts="$3"; shift 3
  local logfile="/tmp/${name}_test.log"
  echo "[*] testing ${name}"
  for i in $(seq 1 "$attempts"); do
    set +e
    "$@" >"$logfile" 2>&1
    local rc=$?
    set -e
    if grep -qaE "$pattern" "$logfile"; then
      echo "[+] ${name} verified (attempt ${i})"
      return 0
    fi
    echo "[!] ${name} attempt ${i} failed (rc=${rc}), retrying..."
    sleep 0.2
  done
  echo "[-] ${name} failed, see ${logfile}"
  tail -100 "$logfile"
  return 1
}
run_and_check ezpz1 'uid=' 2 bash -lc "cd ezpz1 && python3 solve.py L <<< 'id; exit'"
run_and_check ezpz2 'uid=' 2 bash -lc "cd ezpz2 && python3 solve.py L <<< 'id; exit'"
run_and_check notezpz1 'FLAG\{|flag\{|uid=' 4 bash -lc "cd notezpz1 && python3 solve.py L"
run_and_check notezpz1-plus 'uid=' 8 bash -lc "cd notezpz1-plus && python3 notezpz.py L <<< 'id; exit'"
run_and_check notezpz2 'uid=' 8 bash -lc "cd notezpz2 && python3 notezpz2.py <<< 'id; exit'"
run_and_check applepie 'FLAG\{|flag\{' 2 bash -lc "cd applepie && python3 solve.py L"
run_and_check darklamp 'FLAG\{|flag\{' 2 bash -lc "cd darklamp && python3 solve.py L"
echo '[+] all local exploits verified'
