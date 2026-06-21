#!/usr/bin/env bash
# build_fidb.sh — Build esp32p4-idf6.fidb in three automated phases:
#
#   Phase 1: Build IDF stub for esp32p4  →  get all component .a archives
#   Phase 2: Import archives into a Ghidra project via analyzeHeadless
#   Phase 3: Run GenerateESP32P4FIDB.java to fingerprint and save .fidb
#
# Usage:
#   bash tools/build_fidb.sh [--idf-path PATH] [--ghidra PATH] [--out PATH]
#
# Defaults:
#   --idf-path   ~/.espressif/v6.0.1/esp-idf
#   --ghidra     /opt/ghidra_12.1.2_PUBLIC
#   --out        tools/esp32p4-idf6.fidb
#
# Requirements:
#   - ESP-IDF v6.0.1 installed (default: ~/.espressif/v6.0.1/esp-idf)
#   - Ghidra 12.x installed (default: /opt/ghidra_12.1.2_PUBLIC)
#   - riscv32-esp-elf toolchain installed
#   - At least 4 GB free disk space, ~20 min build time

set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

IDF_PATH_DEFAULT="$HOME/.espressif/v6.0.1/esp-idf"
GHIDRA_DEFAULT="/opt/ghidra_12.1.2_PUBLIC"
OUT_DEFAULT="$SCRIPT_DIR/esp32p4-idf6.fidb"

IDF_PATH_ARG=""
GHIDRA_ARG=""
OUT_ARG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --idf-path) IDF_PATH_ARG="$2"; shift 2 ;;
        --ghidra)   GHIDRA_ARG="$2";   shift 2 ;;
        --out)      OUT_ARG="$2";      shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

IDF_ROOT="${IDF_PATH_ARG:-$IDF_PATH_DEFAULT}"
GHIDRA_INSTALL="${GHIDRA_ARG:-$GHIDRA_DEFAULT}"
FIDB_OUT="${OUT_ARG:-$OUT_DEFAULT}"

ANALYZE_HEADLESS="$GHIDRA_INSTALL/support/analyzeHeadless"
STUB_DIR="$SCRIPT_DIR/idf_stub"
BUILD_DIR="$STUB_DIR/build"
GHIDRA_PROJ_DIR="/tmp/esp32p4-fidb-proj"
GHIDRA_PROJ_NAME="IDFLibs"
SCRIPTS_DIR="$REPO_ROOT/ghidra_scripts"

# ── sanity checks ─────────────────────────────────────────────────────────────
echo "═══ FIDB generation pipeline ═══"
echo "  IDF:    $IDF_ROOT"
echo "  Ghidra: $GHIDRA_INSTALL"
echo "  Output: $FIDB_OUT"
echo

[[ -d "$IDF_ROOT" ]] || { echo "ERROR: IDF not found at $IDF_ROOT"; exit 1; }
[[ -f "$ANALYZE_HEADLESS" ]] || { echo "ERROR: analyzeHeadless not found at $ANALYZE_HEADLESS"; exit 1; }
[[ -d "$STUB_DIR" ]] || { echo "ERROR: IDF stub project not found at $STUB_DIR"; exit 1; }

# Locate the Python env for IDF v6
IDF_PYTHON_ENV="$HOME/.espressif/python_env/idf6.0_py3.12_env"
[[ -d "$IDF_PYTHON_ENV" ]] || {
    # Fallback: try any idf6* env
    IDF_PYTHON_ENV=$(ls -d "$HOME/.espressif/python_env/idf6"*"_env" 2>/dev/null | head -1)
    [[ -n "$IDF_PYTHON_ENV" ]] || { echo "ERROR: No IDF v6 Python env found under ~/.espressif/python_env/"; exit 1; }
}
IDF_PY="$IDF_PYTHON_ENV/bin/python $IDF_ROOT/tools/idf.py"
echo "  IDF Python env: $IDF_PYTHON_ENV"

# Locate the RISC-V ESP toolchain matching IDF v6 (esp-15.2.0 required by IDF v6.0.1)
# Prefer the version IDF v6.0.1 declares in tools.json (esp-15.2.0_*), then fall back
RISCV_TOOLCHAIN=$(find "$HOME/.espressif/tools/riscv32-esp-elf" \
    -name "riscv32-esp-elf-gcc" -path "*esp-15*" 2>/dev/null | head -1 | xargs dirname || true)
# If no esp-15 version found, accept any version (user may have patched tools.json)
[[ -n "$RISCV_TOOLCHAIN" ]] || RISCV_TOOLCHAIN=$(find "$HOME/.espressif/tools/riscv32-esp-elf" \
    -name "riscv32-esp-elf-gcc" 2>/dev/null | head -1 | xargs dirname || true)
[[ -n "$RISCV_TOOLCHAIN" ]] || {
    echo "ERROR: riscv32-esp-elf toolchain not found under ~/.espressif/tools/"
    echo "  Install with: ~/.espressif/v6.0.1/esp-idf/install.sh esp32p4"
    exit 1
}
echo "  Toolchain:      $RISCV_TOOLCHAIN"
export PATH="$RISCV_TOOLCHAIN:$PATH"

# ── Phase 1: Build IDF stub ───────────────────────────────────────────────────
echo
echo "── Phase 1: Building IDF stub for esp32p4 ──"
echo "(This takes ~10–15 min on first run; subsequent runs use ccache)"

mkdir -p "$BUILD_DIR"

(
    export IDF_PATH="$IDF_ROOT"
    export IDF_PYTHON_ENV_PATH="$IDF_PYTHON_ENV"
    export ESP_IDF_VERSION="6.0.1"
    cd "$STUB_DIR"
    $IDF_PY set-target esp32p4 2>&1 | tail -5
    $IDF_PY build 2>&1 | tail -20
)

# Collect all component archives
ARCHIVE_LIST=$(find "$BUILD_DIR/esp-idf" -name "lib*.a" 2>/dev/null)
ARCHIVE_COUNT=$(echo "$ARCHIVE_LIST" | grep -c '\.a$' || true)

if [[ "$ARCHIVE_COUNT" -eq 0 ]]; then
    echo "ERROR: No .a archives found under $BUILD_DIR/esp-idf"
    echo "  Did the build succeed? Check output above."
    exit 1
fi
echo "  Found $ARCHIVE_COUNT component archives"

# ── Phase 2: Extract .o files and import into Ghidra project ─────────────────
echo
echo "── Phase 2: Extracting object files and importing into Ghidra ──"
echo "(Ghidra's ELF loader requires individual .o files, not .a archives)"

OBJ_DIR="/tmp/fidb-objs-$$"
rm -rf "$OBJ_DIR"
mkdir -p "$OBJ_DIR"

# Extract all .o from every archive into per-component subdirectories.
# Disambiguate name collisions (e.g. multiple init.c.obj) with component prefix.
OBJ_COUNT=0
while IFS= read -r arc; do
    [[ -z "$arc" ]] && continue
    # Component name = directory name (e.g. …/esp-idf/heap/libheap.a → heap)
    comp=$(basename "$(dirname "$arc")")
    dest="$OBJ_DIR/$comp"
    mkdir -p "$dest"
    (cd "$dest" && ar x "$arc" 2>/dev/null) || true
    n=$(ls "$dest"/*.obj "$dest"/*.o 2>/dev/null | wc -l)
    OBJ_COUNT=$((OBJ_COUNT + n))
done <<< "$ARCHIVE_LIST"
echo "  Extracted $OBJ_COUNT object files from $ARCHIVE_COUNT archives"

# Build import-args list
IMPORT_ARGS=()
while IFS= read -r obj; do
    [[ -n "$obj" ]] && IMPORT_ARGS+=(-import "$obj")
done < <(find "$OBJ_DIR" -name "*.obj" -o -name "*.o" | sort)

rm -rf "$GHIDRA_PROJ_DIR"
mkdir -p "$GHIDRA_PROJ_DIR"

echo "  Running analyzeHeadless -import ($OBJ_COUNT files)…"
"$ANALYZE_HEADLESS" \
    "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
    "${IMPORT_ARGS[@]}" \
    -processor "RISCV:LE:32:ESP32-P4" \
    -analysisTimeoutPerFile 60 \
    2>&1 | grep -E '(ERROR|WARN|Import succeeded|functions identified)' | tail -20

echo "  Import complete: project at $GHIDRA_PROJ_DIR/$GHIDRA_PROJ_NAME"
echo "  Removing extracted objects…"
rm -rf "$OBJ_DIR"

# ── Phase 3: Run GenerateESP32P4FIDB.java ────────────────────────────────────
echo
echo "── Phase 3: Generating FIDB ──"
echo "(Fingerprinting all functions in all imported programs)"

mkdir -p "$(dirname "$FIDB_OUT")"

"$ANALYZE_HEADLESS" \
    "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
    -process '*.obj' \
    -noanalysis \
    -scriptPath "$SCRIPTS_DIR" \
    -postScript GenerateESP32P4FIDB.java "$FIDB_OUT" \
    2>&1 | grep -E '(INFO|WARN|ERROR|FIDB|Populate|fingerprint|saved|pattern|result)' | tail -60

# ── Verify ────────────────────────────────────────────────────────────────────
if [[ -f "$FIDB_OUT" ]]; then
    FIDB_SIZE=$(du -sh "$FIDB_OUT" | cut -f1)
    echo
    echo "════════════════════════════════════════════════════════"
    echo "SUCCESS: $FIDB_OUT ($FIDB_SIZE)"
    echo "════════════════════════════════════════════════════════"
    echo
    echo "To apply in Ghidra:"
    echo "  Tools → Function ID → Apply Function ID Files"
    echo "  Select: $FIDB_OUT"
    echo
    echo "To ship as release artifact:"
    echo "  cp $FIDB_OUT tools/esp32p4-idf6.fidb"
    echo "  git add tools/esp32p4-idf6.fidb"
    echo "  git commit -m 'feat(fidb): ship ESP-IDF v6.0.1 FIDB for ESP32-P4'"
else
    echo
    echo "ERROR: FIDB file was not created at $FIDB_OUT"
    echo "  Check the Ghidra output above for errors."
    exit 1
fi

# ── Cleanup (optional) ────────────────────────────────────────────────────────
echo "Ghidra project left at: $GHIDRA_PROJ_DIR (delete manually when done)"
