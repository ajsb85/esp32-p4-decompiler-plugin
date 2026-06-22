#!/usr/bin/env bash
# build_fidb.sh — Build esp32p4-idf6.fidb in up to three automated phases:
#
#   Phase 1: Build IDF stub for esp32p4  →  get all component .a archives
#            (SKIPPED when --build-dir is supplied; libraries come from there)
#   Phase 2: Import archives into a Ghidra project via analyzeHeadless
#   Phase 3: Run GenerateESP32P4FIDB.java to fingerprint and save .fidb
#
# Usage:
#   bash tools/build_fidb.sh [--idf-path PATH] [--ghidra PATH] [--out PATH]
#   bash tools/build_fidb.sh --build-dir /path/to/idf-project/build [--ghidra PATH] [--out PATH]
#
# --build-dir   Skip Phase 1 entirely; use an already-built ESP-IDF project's
#               build/ directory.  The directory must contain build/esp-idf/
#               with lib*.a files for esp32p4 (RISC-V 32-bit).
#               Example: --build-dir /home/gbast/esp32-p4/my_esp32p4_app/build
#
# Defaults:
#   --idf-path   ~/.espressif/v6.0.1/esp-idf  (ignored when --build-dir given)
#   --ghidra     /opt/ghidra_12.1.2_PUBLIC
#   --out        tools/esp32p4-idf6.fidb
#
# Requirements:
#   - ESP-IDF v6.0.1 installed (default: ~/.espressif/v6.0.1/esp-idf)
#     (not required when --build-dir is used)
#   - Ghidra 12.x installed (default: /opt/ghidra_12.1.2_PUBLIC)
#   - riscv32-esp-elf toolchain installed (only required for Phase 1 build)
#   - At least 4 GB free disk space; ~20 min for a full build, <5 min with --build-dir

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
BUILD_DIR_ARG=""   # when set, skip Phase 1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --idf-path)  IDF_PATH_ARG="$2";  shift 2 ;;
        --ghidra)    GHIDRA_ARG="$2";    shift 2 ;;
        --out)       OUT_ARG="$2";       shift 2 ;;
        --build-dir) BUILD_DIR_ARG="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

IDF_ROOT="${IDF_PATH_ARG:-$IDF_PATH_DEFAULT}"
GHIDRA_INSTALL="${GHIDRA_ARG:-$GHIDRA_DEFAULT}"
FIDB_OUT="${OUT_ARG:-$OUT_DEFAULT}"

ANALYZE_HEADLESS="$GHIDRA_INSTALL/support/analyzeHeadless"
STUB_DIR="$SCRIPT_DIR/idf_stub"
GHIDRA_PROJ_DIR="/tmp/esp32p4-fidb-proj"
GHIDRA_PROJ_NAME="IDFLibs"
SCRIPTS_DIR="$REPO_ROOT/ghidra_scripts"

# ── sanity checks ─────────────────────────────────────────────────────────────
echo "═══ FIDB generation pipeline ═══"
if [[ -n "$BUILD_DIR_ARG" ]]; then
    echo "  Mode:   --build-dir (Phase 1 skipped)"
    echo "  Build:  $BUILD_DIR_ARG"
else
    echo "  Mode:   full build via idf_stub"
    echo "  IDF:    $IDF_ROOT"
fi
echo "  Ghidra: $GHIDRA_INSTALL"
echo "  Output: $FIDB_OUT"
echo

[[ -f "$ANALYZE_HEADLESS" ]] || { echo "ERROR: analyzeHeadless not found at $ANALYZE_HEADLESS"; exit 1; }

# ── Phase 1: Build IDF stub (or use existing build dir) ───────────────────────
if [[ -n "$BUILD_DIR_ARG" ]]; then
    # --build-dir path: validate and use the existing build directory directly
    BUILD_DIR="$BUILD_DIR_ARG"
    [[ -d "$BUILD_DIR" ]] || { echo "ERROR: --build-dir not found: $BUILD_DIR"; exit 1; }

    # Verify this looks like an esp32p4 RISC-V build
    SDKCONFIG_H="$BUILD_DIR/config/sdkconfig.h"
    if [[ -f "$SDKCONFIG_H" ]]; then
        if ! grep -q "CONFIG_IDF_TARGET_ARCH_RISCV\|CONFIG_IDF_TARGET_ESP32P4" "$SDKCONFIG_H" 2>/dev/null; then
            echo "WARNING: $SDKCONFIG_H does not mention RISCV or ESP32P4 — are you sure this is an esp32p4 build?"
        else
            TARGET=$(grep 'CONFIG_IDF_TARGET ' "$SDKCONFIG_H" 2>/dev/null | head -1 | grep -o '"[^"]*"' || echo unknown)
            echo "  Confirmed IDF_TARGET: $TARGET"
        fi
    fi

    echo "  Skipping Phase 1 — using pre-built libraries from: $BUILD_DIR"
else
    # Full build path: need IDF and toolchain
    [[ -d "$IDF_ROOT" ]] || { echo "ERROR: IDF not found at $IDF_ROOT"; echo "  Pass --build-dir to skip the build step."; exit 1; }
    [[ -d "$STUB_DIR" ]] || { echo "ERROR: IDF stub project not found at $STUB_DIR"; exit 1; }

    # Locate the Python env for IDF v6
    IDF_PYTHON_ENV="$HOME/.espressif/python_env/idf6.0_py3.12_env"
    [[ -d "$IDF_PYTHON_ENV" ]] || {
        IDF_PYTHON_ENV=$(ls -d "$HOME/.espressif/python_env/idf6"*"_env" 2>/dev/null | head -1)
        [[ -n "$IDF_PYTHON_ENV" ]] || { echo "ERROR: No IDF v6 Python env found under ~/.espressif/python_env/"; exit 1; }
    }
    IDF_PY="$IDF_PYTHON_ENV/bin/python $IDF_ROOT/tools/idf.py"
    echo "  IDF Python env: $IDF_PYTHON_ENV"

    # Locate the RISC-V ESP toolchain matching IDF v6 (esp-15.2.0 required by IDF v6.0.1)
    RISCV_TOOLCHAIN=$(find "$HOME/.espressif/tools/riscv32-esp-elf" \
        -name "riscv32-esp-elf-gcc" -path "*esp-15*" 2>/dev/null | head -1 | xargs dirname || true)
    [[ -n "$RISCV_TOOLCHAIN" ]] || RISCV_TOOLCHAIN=$(find "$HOME/.espressif/tools/riscv32-esp-elf" \
        -name "riscv32-esp-elf-gcc" 2>/dev/null | head -1 | xargs dirname || true)
    [[ -n "$RISCV_TOOLCHAIN" ]] || {
        echo "ERROR: riscv32-esp-elf toolchain not found under ~/.espressif/tools/"
        echo "  Install with: ~/.espressif/v6.0.1/esp-idf/install.sh esp32p4"
        echo "  Or pass --build-dir to skip the build step entirely."
        exit 1
    }
    echo "  Toolchain:      $RISCV_TOOLCHAIN"
    export PATH="$RISCV_TOOLCHAIN:$PATH"

    echo
    echo "── Phase 1: Building IDF stub for esp32p4 ──"
    echo "(This takes ~10–15 min on first run; subsequent runs use ccache)"

    BUILD_DIR="$STUB_DIR/build"
    mkdir -p "$BUILD_DIR"

    (
        export IDF_PATH="$IDF_ROOT"
        export IDF_PYTHON_ENV_PATH="$IDF_PYTHON_ENV"
        export ESP_IDF_VERSION="6.0.1"
        cd "$STUB_DIR"
        $IDF_PY set-target esp32p4 2>&1 | tail -5
        $IDF_PY build 2>&1 | tail -20
    )
fi

# Collect all component archives from whichever build dir we ended up with
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
    n=$(find "$dest" -maxdepth 1 \( -name "*.obj" -o -name "*.o" \) | wc -l)
    OBJ_COUNT=$((OBJ_COUNT + n))
done <<< "$ARCHIVE_LIST"
echo "  Extracted $OBJ_COUNT object files from $ARCHIVE_COUNT archives"

rm -rf "$GHIDRA_PROJ_DIR"
mkdir -p "$GHIDRA_PROJ_DIR"

# Use -recursive import on the whole OBJ_DIR — avoids ARG_MAX limits from
# passing thousands of individual -import flags on the command line.
echo "  Running analyzeHeadless -import $OBJ_DIR -recursive ($OBJ_COUNT files)…"
"$ANALYZE_HEADLESS" \
    "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
    -import "$OBJ_DIR" \
    -recursive \
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
    -process \
    -noanalysis \
    -scriptPath "$SCRIPTS_DIR" \
    -postScript GenerateESP32P4FIDB.java "$FIDB_OUT" "$OBJ_DIR" "-Os" \
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
