#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="${1:-${ROOT_DIR}}"
NATIVE_DIR="${PLUGIN_DIR}/native"
PLUGIN_NAME="botkiller"
ZIP_OUT="${PLUGIN_DIR}/${PLUGIN_NAME}.zip"

if [[ ! -f "${NATIVE_DIR}/Cargo.toml" ]]; then
  echo "[error] native/Cargo.toml not found in ${NATIVE_DIR}" >&2
  exit 1
fi

# botkiller is Windows-only (x86_64-pc-windows-msvc cdylib).
BUILD_TARGETS="${BUILD_TARGETS:-windows-amd64}"

BUILT_FILES=()

for target in ${BUILD_TARGETS}; do
  os="${target%%-*}"
  arch="${target#*-}"

  if [[ "${os}" != "windows" ]]; then
    echo "[skip] botkiller is Windows-only: ${target}"
    continue
  fi

  rust_target="x86_64-pc-windows-msvc"
  [[ "${arch}" == "arm64" ]] && rust_target="aarch64-pc-windows-msvc"

  outfile="${PLUGIN_DIR}/${PLUGIN_NAME}-${os}-${arch}.dll"
  echo "[build] cargo build --release --target=${rust_target} in ${NATIVE_DIR}"
  (cd "${NATIVE_DIR}" && cargo build --release --target="${rust_target}")
  cp "${NATIVE_DIR}/target/${rust_target}/release/botkiller.dll" "${outfile}"
  BUILT_FILES+=("${PLUGIN_NAME}-${os}-${arch}.dll")
done

rm -f "${ZIP_OUT}"

ZIP_FILES=("config.json")
for bf in "${BUILT_FILES[@]}"; do
  ZIP_FILES+=("${bf}")
done
for asset in "${PLUGIN_NAME}.html" "${PLUGIN_NAME}.css" "${PLUGIN_NAME}.js"; do
  if [[ -f "${PLUGIN_DIR}/${asset}" ]]; then
    ZIP_FILES+=("${asset}")
  fi
done

if command -v zip >/dev/null 2>&1; then
  (cd "${PLUGIN_DIR}" && zip -q "${ZIP_OUT}" "${ZIP_FILES[@]}")
else
  echo "[error] zip not found. Please install zip." >&2
  exit 1
fi

echo "[ok] ${ZIP_OUT}"
