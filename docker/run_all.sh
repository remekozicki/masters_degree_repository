#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-/opt/project}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$ROOT_DIR/workspace}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/results}"
RSA_BITS_LIST="${RSA_BITS_LIST:-2048 3072}"
RSA_PROVIDER="${RSA_PROVIDER:-default}"
CLEAN_RESULTS="${CLEAN_RESULTS:-1}"

if [[ ! -d "$WORKSPACE_DIR" ]]; then
  echo "Missing workspace directory: $WORKSPACE_DIR" >&2
  exit 1
fi

mkdir -p "$RESULTS_DIR"

if [[ "$CLEAN_RESULTS" == "1" ]]; then
  rm -f "$RESULTS_DIR"/result-*.csv
fi

cd "$WORKSPACE_DIR"

rm -f result-*.csv

echo "==> Toolchain"
echo "CC: ${CC:-gcc}"
"${CC:-gcc}" --version | head -n 1
make --version | head -n 1
openssl version
pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'

run_lightweight_suite() {
  local alg="$1"
  echo "==> Running lightweight suite for ALG=$alg"
  make clean
  make ALG="$alg" run-kat
  make ALG="$alg" run-func
  make ALG="$alg" run-random
  make ALG="$alg" run-api
  make ALG="$alg" run-throughput
  make ALG="$alg" run-latency
  make ALG="$alg" run-micro-internal
  make ALG="$alg" LIGHTWEIGHT_OUTPUT="result-${alg}-lightweight.csv" run-lightweight
}

for alg in ascon elephant gift; do
  run_lightweight_suite "$alg"
done

for bits in $RSA_BITS_LIST; do
  echo "==> Running RSA suite for RSA_BITS=$bits provider=$RSA_PROVIDER"
  make clean
  make run-rsa-tests \
    RSA_BITS="$bits" \
    RSA_PROVIDER="$RSA_PROVIDER" \
    RSA_OUTPUT_PREFIX="result-rsa-${bits}-${RSA_PROVIDER}"
done

make clean

echo "==> Copying CSV results to $RESULTS_DIR"
find "$WORKSPACE_DIR" -maxdepth 1 -type f -name 'result-*.csv' -exec cp {} "$RESULTS_DIR"/ \;

METADATA_FILE="$RESULTS_DIR/run-metadata.txt"
{
  echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname=$(uname -a)"
  echo "compiler=$("${CC:-gcc}" --version | head -n 1)"
  echo "openssl=$(openssl version)"
  echo "pwsh_version=$(pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')"
  echo "rsa_bits_list=$RSA_BITS_LIST"
  echo "rsa_provider=$RSA_PROVIDER"
} > "$METADATA_FILE"

echo "==> Completed. Files in $RESULTS_DIR:"
ls -1 "$RESULTS_DIR"
