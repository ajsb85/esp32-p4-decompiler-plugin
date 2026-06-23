#!/usr/bin/env bash
# RunFullPipeline.sh — Full ESP32-P4 firmware analysis pipeline
#
# Runs all 15 scripts in the correct order via analyzeHeadless to produce
# the most accurate decompiled C output from an ESP32-P4 firmware ELF.
#
# ── Usage ─────────────────────────────────────────────────────────────────────
#   bash tools/RunFullPipeline.sh <firmware.elf> [options]
#
# Options:
#   --ghidra PATH     Ghidra install dir  (default: /opt/ghidra_12.1.2_PUBLIC)
#   --out DIR         Output directory    (default: ./esp32p4_output)
#   --rom-elf PATH    ROM ELF for symbol loading
#                     (default: auto-detect ~/.espressif/tools/esp-rom-elfs/...)
#   --fidb PATH       FIDB file           (default: auto-detect tools/esp32p4-idf6.fidb)
#   --scripts DIR     ghidra_scripts/ dir (default: auto-detect from repo root)
#   --keep-project    Do not delete the Ghidra project after analysis
#   --project-dir DIR Ghidra project directory (default: /tmp/esp32p4_ghidra_proj)
#
# ── Output files ──────────────────────────────────────────────────────────────
#   <out>/firmware_decompiled.c   — main decompiled C source
#   <out>/firmware.h              — type definitions + function prototypes
#   <out>/globals.h               — extern declarations for all globals
#   <out>/firmware.dot            — Graphviz call graph
#   <out>/MODULES.md              — module table by connected component
#   <out>/semantic_hints.json     — pattern detection results (1,287 patterns)
#
# ── Pipeline phases ───────────────────────────────────────────────────────────
#   Phase 1 — Import + configure analyzers   (AnalyzeESP32P4Headless.py)
#   Phase 2 — Symbol enrichment              (FIDB → ROM symbols → SVD)
#   Phase 3 — Type enrichment                (FreeRTOS types → task extraction)
#   Phase 4 — Pattern detection              (DetectSemanticPatterns.java)
#   Phase 5 — Apply semantic hints           (ApplySemanticHints.java)
#   Phase 6 — Export                         (header → globals → C → call graph)
#
# Note: IdentifyReturnVariable.java is GUI-only (requires cursor position) and
# is not included in the headless pipeline.

set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

GHIDRA_DEFAULT="/opt/ghidra_12.1.2_PUBLIC"
OUT_DEFAULT="$PWD/esp32p4_output"
PROJ_DIR_DEFAULT="/tmp/esp32p4_ghidra_proj"
ROM_ELF_DEFAULT="$HOME/.espressif/tools/esp-rom-elfs/20241011/esp32p4_rev0_rom.elf"

FIRMWARE_ELF=""
GHIDRA_ARG=""
OUT_ARG=""
ROM_ELF_ARG=""
FIDB_ARG=""
SCRIPTS_ARG=""
PROJ_DIR_ARG=""
KEEP_PROJECT=0

# ── parse args ────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <firmware.elf> [--ghidra PATH] [--out DIR] [--rom-elf PATH] [--fidb PATH]"
    echo "       [--scripts DIR] [--project-dir DIR] [--keep-project]"
    exit 1
fi

FIRMWARE_ELF="$1"; shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ghidra)      GHIDRA_ARG="$2";    shift 2 ;;
        --out)         OUT_ARG="$2";       shift 2 ;;
        --rom-elf)     ROM_ELF_ARG="$2";   shift 2 ;;
        --fidb)        FIDB_ARG="$2";      shift 2 ;;
        --scripts)     SCRIPTS_ARG="$2";   shift 2 ;;
        --project-dir) PROJ_DIR_ARG="$2";  shift 2 ;;
        --keep-project) KEEP_PROJECT=1;    shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

GHIDRA_INSTALL="${GHIDRA_ARG:-$GHIDRA_DEFAULT}"
OUT_DIR="${OUT_ARG:-$OUT_DEFAULT}"
PROJ_DIR="${PROJ_DIR_ARG:-$PROJ_DIR_DEFAULT}"

# ── resolve optional paths ────────────────────────────────────────────────────

# FIDB: arg > repo tools/ > extension dir
if [[ -n "$FIDB_ARG" ]]; then
    FIDB_PATH="$FIDB_ARG"
elif [[ -f "$REPO_ROOT/tools/esp32p4-idf6.fidb" ]]; then
    FIDB_PATH="$REPO_ROOT/tools/esp32p4-idf6.fidb"
elif [[ -f "$HOME/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/esp32p4-ghidra-plugin/tools/esp32p4-idf6.fidb" ]]; then
    FIDB_PATH="$HOME/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/esp32p4-ghidra-plugin/tools/esp32p4-idf6.fidb"
else
    FIDB_PATH=""
fi

# ROM ELF: arg > default install location
if [[ -n "$ROM_ELF_ARG" ]]; then
    ROM_ELF_PATH="$ROM_ELF_ARG"
elif [[ -f "$ROM_ELF_DEFAULT" ]]; then
    ROM_ELF_PATH="$ROM_ELF_DEFAULT"
else
    ROM_ELF_PATH=""
fi

# Scripts directory: arg > repo ghidra_scripts/
if [[ -n "$SCRIPTS_ARG" ]]; then
    SCRIPTS_DIR="$SCRIPTS_ARG"
elif [[ -d "$REPO_ROOT/ghidra_scripts" ]]; then
    SCRIPTS_DIR="$REPO_ROOT/ghidra_scripts"
else
    echo "ERROR: Cannot locate ghidra_scripts/. Use --scripts to specify the path."
    exit 1
fi

ANALYZE_HEADLESS="$GHIDRA_INSTALL/support/analyzeHeadless"
HINTS_JSON="$OUT_DIR/semantic_hints.json"

# ── validate ──────────────────────────────────────────────────────────────────
if [[ ! -f "$FIRMWARE_ELF" ]]; then
    echo "ERROR: Firmware ELF not found: $FIRMWARE_ELF"
    exit 1
fi
if [[ ! -x "$ANALYZE_HEADLESS" ]]; then
    echo "ERROR: analyzeHeadless not found at: $ANALYZE_HEADLESS"
    echo "       Set --ghidra to your Ghidra installation directory."
    exit 1
fi

# ── prepare ───────────────────────────────────────────────────────────────────
mkdir -p "$OUT_DIR"
mkdir -p "$PROJ_DIR"

ELF_NAME="$(basename "$FIRMWARE_ELF" .elf)"
PROJ_NAME="esp32p4_${ELF_NAME}"

# Clean up any stale project files from a previous killed run.
# Ghidra leaves .gpr/.rep/.lock/.lock~ behind when killed; any leftover
# prevents the next run from acquiring the project lock.
rm -rf "${PROJ_DIR:?}/${PROJ_NAME}".* "${PROJ_DIR:?}/${PROJ_NAME}" 2>/dev/null || true

echo "============================================================"
echo "  ESP32-P4 Full Analysis Pipeline"
echo "============================================================"
echo "  Firmware:  $FIRMWARE_ELF"
echo "  Output:    $OUT_DIR"
echo "  Ghidra:    $GHIDRA_INSTALL"
echo "  FIDB:      ${FIDB_PATH:-'(not found, skipping)'}"
echo "  ROM ELF:   ${ROM_ELF_PATH:-'(not found, skipping)'}"
echo "  Scripts:   $SCRIPTS_DIR"
echo "============================================================"
echo ""

# ── build postScript list ─────────────────────────────────────────────────────
# Each phase is a separate -postScript invocation.
# Order is critical — do not reorder without understanding the dependencies.

POST_SCRIPTS=()

# Phase 2 — Symbol enrichment
# FIDB first: establishes named function boundaries before SVD struct application.
if [[ -n "$FIDB_PATH" ]]; then
    POST_SCRIPTS+=(-postScript "ApplyESP32P4FIDB.java"   "$FIDB_PATH")
else
    echo "WARN: No FIDB found — IDF function names will not be recovered."
fi
# ROM symbols: label ROM call targets so decompiler shows ets_printf instead of FUN_4fc0xxxx.
if [[ -n "$ROM_ELF_PATH" ]]; then
    POST_SCRIPTS+=(-postScript "LoadESP32P4RomSymbols.java" "$ROM_ELF_PATH")
else
    echo "WARN: No ROM ELF found — ROM API calls will remain unnamed."
fi
# SVD: creates peripheral structs. Must come after FIDB so function address space is settled.
POST_SCRIPTS+=(-postScript "LoadESP32P4SVD.java")

# Phase 3 — Type enrichment
# FreeRTOS types must be loaded before task extraction (ExtractFreeRTOSTasks relies on them).
POST_SCRIPTS+=(-postScript "LoadFreeRTOSTypes.java")
POST_SCRIPTS+=(-postScript "ExtractFreeRTOSTasks.java")

# Phase 4 — Pattern detection
# Must run after all enrichment so decompiled bodies already carry IDF/ROM names
# (which improves pattern signal-to-noise).
POST_SCRIPTS+=(-postScript "DetectSemanticPatterns.java" "$HINTS_JSON")

# Phase 5 — Apply hints
# Reads the JSON written by Phase 4 and renames FUN_* functions in the database.
# Must run before export so the recovered names appear in the decompiled output.
POST_SCRIPTS+=(-postScript "ApplySemanticHints.java" "$HINTS_JSON")

# Phase 6 — Export
# Header first: ExportDecompiledC.java may reference types defined there.
POST_SCRIPTS+=(-postScript "ExportFirmwareHeader.java" "$OUT_DIR/firmware.h")
POST_SCRIPTS+=(-postScript "ExportGlobalDecls.java"    "$OUT_DIR/globals.h")
POST_SCRIPTS+=(-postScript "ExportDecompiledC.java"    "$OUT_DIR/firmware_decompiled.c")
POST_SCRIPTS+=(-postScript "ExportCallGraph.java"      "$OUT_DIR")

# ── run ───────────────────────────────────────────────────────────────────────
echo "[1/7] Importing ELF + configuring analyzers..."
echo ""

"$ANALYZE_HEADLESS" \
    "$PROJ_DIR" "$PROJ_NAME" \
    -import "$FIRMWARE_ELF" \
    -processor "RISCV:LE:32:ESP32-P4" \
    -scriptPath "$SCRIPTS_DIR" \
    -preScript  "AnalyzeESP32P4Headless.py" \
    "${POST_SCRIPTS[@]}" \
    2>&1 | tee "$OUT_DIR/pipeline.log"

STATUS=${PIPESTATUS[0]}

# ── cleanup ───────────────────────────────────────────────────────────────────
if [[ $KEEP_PROJECT -eq 0 ]]; then
    rm -rf "$PROJ_DIR/$PROJ_NAME.gpr" "$PROJ_DIR/$PROJ_NAME.rep" 2>/dev/null || true
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
if [[ $STATUS -eq 0 ]]; then
    echo "  Pipeline complete. Output files:"
    for f in "$OUT_DIR/firmware.h" \
              "$OUT_DIR/globals.h" \
              "$OUT_DIR/firmware_decompiled.c" \
              "$OUT_DIR/firmware.dot" \
              "$OUT_DIR/MODULES.md" \
              "$OUT_DIR/semantic_hints.json"; do
        if [[ -f "$f" ]]; then
            SIZE=$(du -sh "$f" 2>/dev/null | cut -f1)
            printf "    %-40s %s\n" "$(basename "$f")" "$SIZE"
        else
            printf "    %-40s %s\n" "$(basename "$f")" "(not generated)"
        fi
    done
    echo ""
    echo "  Log: $OUT_DIR/pipeline.log"
    echo ""
    echo "  Next steps:"
    echo "    Render call graph:  dot -Tsvg $OUT_DIR/firmware.dot -o $OUT_DIR/firmware.svg"
    echo "    Recompile check:    riscv32-esp-elf-gcc -include tools/ghidra_types.h \\"
    echo "                          -include $OUT_DIR/firmware.h \\"
    echo "                          $OUT_DIR/firmware_decompiled.c -o /dev/null"
else
    echo "  Pipeline FAILED (exit $STATUS). Check: $OUT_DIR/pipeline.log"
fi
echo "============================================================"

exit $STATUS
