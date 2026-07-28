#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker compose up -d >/dev/null
run_and_check() {
  local name="$1" expected="$2" attempts="$3"; shift 3
  local logfile="/tmp/${name}_docker_test.log"
  echo "[*] testing docker ${name}"
  for i in $(seq 1 "$attempts"); do
    set +e
    "$@" >"$logfile" 2>&1
    local rc=$?
    set -e
    if grep -q "$expected" "$logfile"; then
      echo "[+] ${name} flag verified (attempt ${i})"
      return 0
    fi
    echo "[!] ${name} attempt ${i} failed (rc=${rc}), retrying..."
    sleep 0.2
  done
  echo "[-] ${name} failed, see ${logfile}"
  tail -100 "$logfile"
  return 1
}
run_and_check ezpz1 'flag{test_ezpz1_glibc_239}' 2 bash -lc "cd ezpz1 && timeout 20 python3 solve.py <<< 'cat /flag; exit'"
run_and_check ezpz2 'flag{test_ezpz2_glibc_239}' 2 bash -lc "cd ezpz2 && timeout 20 python3 solve.py <<< 'cat /flag; exit'"
run_and_check notezpz1 'flag{test_notezpz1_classic_glibc_227}' 4 bash -lc "cd notezpz1 && timeout 20 python3 solve.py"
run_and_check notezpz1-plus 'flag{test_notezpz1_glibc_239}' 8 bash -lc "cd notezpz1-plus && timeout 30 python3 notezpz.py <<< 'cat /flag; exit'"
run_and_check notezpz2 'flag{test_notezpz2_glibc_239}' 8 bash -lc "cd notezpz2 && timeout 30 python3 notezpz2.py REMOTE <<< 'cat /flag; exit'"
run_and_check applepie 'flag{test_applepie_house_of_apple2_orw}' 4 bash -lc "cd applepie && timeout 30 python3 solve.py"
run_and_check darklamp 'flag{test_darklamp_oracle_state_machine_orw}' 4 bash -lc "cd darklamp && timeout 30 python3 solve.py"
echo '[+] all docker exploits recovered flags'
