#!/usr/bin/env bash
# create_minimal_idf_fixture.sh — Create a minimal ESP-IDF project for esp32p4
# and build it so GenerateESP32P4FIDB.java has RISC-V static libraries to
# fingerprint.  Use this when you don't have an existing esp32p4 build directory.
#
# After this script completes, run:
#   tools/build_fidb.sh --build-dir <WORK_DIR>/build --out tools/esp32p4-idf6.fidb
#
# Usage:
#   bash tools/create_minimal_idf_fixture.sh [WORK_DIR]
#
# WORK_DIR defaults to /tmp/esp32p4_fidb_build
#
# Prerequisites:
#   - IDF_PATH set to your ESP-IDF checkout, OR the default ESP-IDF v6.0.1 at
#     ~/.espressif/v6.0.1/esp-idf is present.
#   - idf.py runnable (Python env activated, or IDF_PYTHON_ENV_PATH set).
#   - riscv32-esp-elf toolchain installed via idf_tools.py or manually.
#
# Tested with: ESP-IDF v6.0.1 targeting esp32p4

set -euo pipefail

WORK_DIR="${1:-/tmp/esp32p4_fidb_build}"

# ── Resolve IDF_PATH ──────────────────────────────────────────────────────────
if [[ -n "${IDF_PATH:-}" && -f "$IDF_PATH/tools/idf.py" ]]; then
    IDF_ROOT="$IDF_PATH"
elif [[ -f "$HOME/.espressif/v6.0.1/esp-idf/tools/idf.py" ]]; then
    IDF_ROOT="$HOME/.espressif/v6.0.1/esp-idf"
    echo "Note: IDF_PATH not set; using $IDF_ROOT"
else
    echo "ERROR: ESP-IDF not found."
    echo "  Set IDF_PATH to your esp-idf checkout, or install:"
    echo "    ~/.espressif/v6.0.1/esp-idf"
    exit 1
fi

# ── Resolve Python / idf.py invocation ───────────────────────────────────────
if command -v idf.py &>/dev/null; then
    IDF_CMD="idf.py"
else
    # Find the Python env for IDF v6
    IDF_PYTHON_ENV=$(ls -d "$HOME/.espressif/python_env/idf6"*"_env" 2>/dev/null | head -1 || true)
    if [[ -z "$IDF_PYTHON_ENV" ]]; then
        echo "ERROR: idf.py not in PATH and no IDF Python env found."
        echo "  Run: source $IDF_ROOT/export.sh"
        exit 1
    fi
    IDF_CMD="$IDF_PYTHON_ENV/bin/python $IDF_ROOT/tools/idf.py"
    echo "  Using IDF Python env: $IDF_PYTHON_ENV"
fi

echo "═══ Minimal ESP32-P4 IDF fixture builder ═══"
echo "  IDF:      $IDF_ROOT"
echo "  Work dir: $WORK_DIR"
echo

# ── Create project skeleton ───────────────────────────────────────────────────
mkdir -p "$WORK_DIR/main"

# Top-level CMakeLists.txt
cat > "$WORK_DIR/CMakeLists.txt" <<'HEREDOC'
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(fidb_fixture)
HEREDOC

# Component CMakeLists.txt
cat > "$WORK_DIR/main/CMakeLists.txt" <<'HEREDOC'
idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
)
HEREDOC

# Minimal app_main — exercises FreeRTOS, heap, and driver headers so those
# component libraries are pulled into the build.
cat > "$WORK_DIR/main/main.c" <<'HEREDOC'
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

void app_main(void) {
    /* Minimal stub — real logic intentionally omitted.
     * Purpose: produce lib*.a archives that cover the core IDF components
     * (freertos, heap, driver, hal, esp_hw_support) for FIDB fingerprinting.
     */
    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}
HEREDOC

echo "Project scaffold written to $WORK_DIR"

# ── Build ─────────────────────────────────────────────────────────────────────
echo
echo "── Running idf.py set-target esp32p4 ──"
(
    export IDF_PATH="$IDF_ROOT"
    cd "$WORK_DIR"
    $IDF_CMD set-target esp32p4 2>&1 | tail -5
)

echo
echo "── Running idf.py build (this takes ~10-15 min on first run) ──"
(
    export IDF_PATH="$IDF_ROOT"
    cd "$WORK_DIR"
    $IDF_CMD build 2>&1 | tail -30
)

# ── Verify output ─────────────────────────────────────────────────────────────
ARCHIVE_COUNT=$(find "$WORK_DIR/build/esp-idf" -name "lib*.a" 2>/dev/null | wc -l)
if [[ "$ARCHIVE_COUNT" -eq 0 ]]; then
    echo
    echo "ERROR: Build completed but no lib*.a archives found under $WORK_DIR/build/esp-idf"
    echo "  Check build output above for errors."
    exit 1
fi

# Spot-check: verify libfreertos.a contains RISC-V objects
FREERTOS_LIB="$WORK_DIR/build/esp-idf/freertos/libfreertos.a"
if [[ -f "$FREERTOS_LIB" ]]; then
    ARCH=$(ar p "$FREERTOS_LIB" tasks.c.obj 2>/dev/null | file - 2>/dev/null || true)
    if echo "$ARCH" | grep -q "RISC-V"; then
        echo "  Architecture check: RISC-V confirmed (libfreertos.a/tasks.c.obj)"
    else
        echo "  WARNING: Could not confirm RISC-V architecture in libfreertos.a"
    fi
fi

echo
echo "════════════════════════════════════════════════════════"
echo "SUCCESS: $ARCHIVE_COUNT component libraries built"
echo "  Build dir: $WORK_DIR/build"
echo "════════════════════════════════════════════════════════"
echo
echo "Next step — generate the FIDB:"
echo
echo "  SCRIPT_DIR=\"\$(dirname \"\$0\")\"  # or set manually"
echo "  bash tools/build_fidb.sh \\"
echo "    --build-dir $WORK_DIR/build \\"
echo "    --out tools/esp32p4-idf6.fidb"
echo
echo "This takes ~5 min and produces the .fidb ready to ship."
