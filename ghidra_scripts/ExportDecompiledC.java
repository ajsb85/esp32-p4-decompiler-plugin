/* SPDX-License-Identifier: Apache-2.0
 *
 * ESP32-P4 Ghidra Plugin
 * Copyright 2026 Alexander Salas Bastidas <ajsb85@firechip.dev>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Exports decompiled C for every function in the current program.
//
// Three RISC-V / Ghidra artefacts are fixed automatically before writing:
//
//  1. GP-register lines  ("gp = 0x<hex>;")
//     The RISC-V global pointer is a fixed register set once by startup
//     code.  Ghidra emits it as a C assignment on every function entry,
//     which causes a compile error (undeclared identifier).  These lines
//     are stripped from the output.
//
//  2. Void return-type promotion
//     When Ghidra cannot prove a function's return value is consumed, it
//     declares the return type as void.  If the caller then assigns the
//     result to a variable, the emitted C is invalid.  This pass scans
//     for that pattern and promotes the return type to undefined4.
//
//  3. Bare return in promoted functions  ("return;")
//     After fix 2, a promoted function may still contain bare "return;"
//     statements in its body.  In the RISC-V ilp32 ABI the first
//     parameter (a0 = param_1) is also the return register, so a bare
//     return is semantically equivalent to "return param_1;".  These
//     bare returns are rewritten to "return param_1;" automatically.
//
// Semantic enrichments (Sprint 1):
//
//  - Functions are emitted sorted by entry-point address so that
//    consecutive re-runs produce stable output and git diff is meaningful.
//
//  - A block comment above each function records:
//      * the Ghidra-resolved symbol name (DWARF / FIDB / manual rename)
//      * the authoritative typed signature from fn.getReturnType() and
//        fn.getParameters() — useful when DWARF or FIDB provides real names
//      * the memory region (IRAM, Flash, ROM, ...) from the MemoryBlock name
//      * the list of calling functions (cross-reference)
//
//  - ROM functions (memory block named "ROM" or external functions) are
//    emitted as a single extern declaration; their bodies are skipped,
//    keeping the output focused on application code.
//
// The output file path can be passed as the first script argument when
// running headlessly (-postScript ExportDecompiledC.java /path/out.c).
// In GUI mode a save-file dialog is shown instead.
//
// Usage: Script Manager → ESP32-P4 → Export Decompiled C
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Export Decompiled C

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;

public class ExportDecompiledC extends GhidraScript {

    private static final int DECOMPILE_TIMEOUT_SECS = 30;

    // Maximum callers to list before abbreviating (keeps comments readable).
    private static final int MAX_CALLERS_SHOWN = 8;

    // Matches:  gp = 0x1a2b3c4d;   (with optional leading whitespace)
    private static final Pattern GP_ASSIGN =
            Pattern.compile("^\\s*gp\\s*=\\s*0x[0-9A-Fa-f]+\\s*;\\s*$");

    // Matches a void function signature:  void <name>(
    private static final Pattern VOID_SIG =
            Pattern.compile("^\\s*void\\s+(\\w+)\\s*\\(");

    // Matches an assignment whose RHS is a call:  <var> = <name>(
    private static final Pattern CALL_ASSIGN =
            Pattern.compile("\\w+\\s*=\\s*(\\w+)\\s*\\(");

    // Matches a bare return with no value (entire line, optional indent)
    private static final Pattern BARE_RETURN =
            Pattern.compile("^(\\s*)return\\s*;\\s*$");

    @Override
    public void run() throws Exception {

        // ── resolve output file ───────────────────────────────────────────────
        String defaultName =
                currentProgram.getName().replaceAll("[^\\w.-]", "_") + ".c";
        File outFile;
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            outFile = new File(args[0]);
        } else {
            outFile = askFile("Save decompiled C to", "Save");
            if (outFile == null) {
                outFile = new File(System.getProperty("user.home"), defaultName);
                println("No file chosen — writing to " + outFile.getAbsolutePath());
            }
        }

        // ── decompile all functions, sorted by entry-point address ────────────
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        decompiler.setOptions(opts);
        decompiler.toggleSyntaxTree(true);
        decompiler.toggleCCode(true);

        if (!decompiler.openProgram(currentProgram)) {
            printerr("Decompiler failed to open program: "
                    + decompiler.getLastMessage());
            return;
        }

        // TreeMap gives address-sorted iteration automatically.
        TreeMap<Address, Function> fnByAddr   = new TreeMap<>();
        TreeMap<Address, String>   rawByAddr  = new TreeMap<>();
        int failed = 0;

        try {
            FunctionIterator it =
                    currentProgram.getListing().getFunctions(true);
            while (it.hasNext()) {
                monitor.checkCancelled();
                Function fn = it.next();
                Address  addr = fn.getEntryPoint();

                DecompileResults res =
                        decompiler.decompileFunction(fn, DECOMPILE_TIMEOUT_SECS, monitor);

                fnByAddr.put(addr, fn);

                if (res != null && res.decompileCompleted()) {
                    DecompiledFunction df = res.getDecompiledFunction();
                    rawByAddr.put(addr, df != null ? df.getC() : null);
                    if (df == null) failed++;
                } else {
                    rawByAddr.put(addr, null);
                    failed++;
                }
            }
        } finally {
            decompiler.dispose();
        }

        // ── collect all void-declared function names ──────────────────────────
        Set<String> voidFunctions = new HashSet<>();
        for (String raw : rawByAddr.values()) {
            if (raw == null) continue;
            for (String line : raw.split("\n")) {
                Matcher m = VOID_SIG.matcher(line);
                if (m.find()) voidFunctions.add(m.group(1));
            }
        }

        // ── find void functions whose return value is actually used ───────────
        Set<String> promoteToUndefined4 = new HashSet<>();
        for (String raw : rawByAddr.values()) {
            if (raw == null) continue;
            for (String line : raw.split("\n")) {
                Matcher m = CALL_ASSIGN.matcher(line);
                if (m.find()) {
                    String callee = m.group(1);
                    if (voidFunctions.contains(callee)) {
                        promoteToUndefined4.add(callee);
                    }
                }
            }
        }

        if (!promoteToUndefined4.isEmpty()) {
            println("Return-type promotion (void → undefined4): "
                    + promoteToUndefined4);
        }

        // ── write fixed + enriched output ─────────────────────────────────────
        int exported     = 0;
        int gpStripped   = 0;
        int promoted     = 0;
        int bareReturnFixed = 0;
        int romSkipped   = 0;

        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
            pw.println("/* Auto-generated by Ghidra ExportDecompiledC script */");
            pw.println("/* Program : " + currentProgram.getName()  + " */");
            pw.println("/* Language: " + currentProgram.getLanguageID() + " */");
            pw.println("/* Fixes applied automatically:");
            pw.println(" *   - gp = 0x<hex>; lines stripped (RISC-V GP register artifact)");
            pw.println(" *   - void return promoted to undefined4 where caller uses result");
            pw.println(" *   - bare return; -> return param_1; in promoted functions");
            pw.println(" * Semantic enrichments:");
            pw.println(" *   - functions sorted by entry-point address");
            pw.println(" *   - typed signature, memory region, and caller list per function");
            pw.println(" *   - ROM functions emitted as extern declarations only");
            pw.println(" * Compile with:");
            pw.println(" *   riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei \\");
            pw.println(" *     -mabi=ilp32f -O0 -include ghidra_types.h -c "
                    + outFile.getName());
            pw.println(" */");
            pw.println();

            for (Map.Entry<Address, Function> e : fnByAddr.entrySet()) {
                Address  addr = e.getKey();
                Function fn   = e.getValue();
                String   raw  = rawByAddr.get(addr);

                // ── per-function metadata ─────────────────────────────────────

                // Memory region from the MemoryBlock name set by ESP32P4Analyzer.
                MemoryBlock block      = currentProgram.getMemory().getBlock(addr);
                String      regionName = (block != null) ? block.getName() : null;

                // ROM detection: external functions or blocks explicitly named ROM.
                boolean isRom = fn.isExternal() ||
                        (regionName != null &&
                         regionName.toUpperCase().contains("ROM"));

                // Caller list (sorted for stable output).
                Set<Function> callerSet = fn.getCallingFunctions(monitor);
                List<String> callerNames = callerSet.stream()
                        .map(Function::getName)
                        .sorted()
                        .collect(Collectors.toList());

                // Typed signature from Ghidra's function record.
                String typedSig = buildTypedSig(fn);

                // ── section comment ───────────────────────────────────────────
                pw.println("/* ═══════════════════════════════════════════════════ */");
                pw.println("/* " + fn.getName() + " @ " + addr);
                if (regionName != null)
                    pw.println(" * region  : " + regionName);
                pw.println(" * typed   : " + typedSig);
                if (!callerNames.isEmpty()) {
                    if (callerNames.size() <= MAX_CALLERS_SHOWN) {
                        pw.println(" * callers : " + String.join(", ", callerNames));
                    } else {
                        pw.println(" * callers : "
                                + String.join(", ",
                                    callerNames.subList(0, MAX_CALLERS_SHOWN))
                                + " (+" + (callerNames.size() - MAX_CALLERS_SHOWN)
                                + " more)");
                    }
                } else {
                    pw.println(" * callers : (none — possible root / ISR)");
                }
                pw.println(" */");

                // ── ROM short-circuit: extern only, no body ───────────────────
                if (isRom) {
                    pw.println("extern " + typedSig + "; /* ROM */");
                    pw.println();
                    romSkipped++;
                    continue;
                }

                // ── decompile failed ──────────────────────────────────────────
                if (raw == null) {
                    pw.println("/* decompile failed */");
                    pw.println();
                    continue;
                }

                // ── is this a void-promoted function? ─────────────────────────
                final String fnName = fn.getName();
                boolean isPromoted = promoteToUndefined4.contains(fnName);

                // ── apply fixes line-by-line ──────────────────────────────────
                StringBuilder fixed = new StringBuilder();
                for (String line : raw.split("\n", -1)) {

                    // fix 1: strip GP register assignments
                    if (GP_ASSIGN.matcher(line).matches()) {
                        gpStripped++;
                        continue;
                    }

                    // fix 2: promote void → undefined4 in the signature line
                    if (promoteToUndefined4.stream().anyMatch(name ->
                            line.matches("\\s*void\\s+" + Pattern.quote(name) + "\\s*\\(.*"))) {
                        String fixed2 = line.replaceFirst("\\bvoid\\b", "undefined4");
                        fixed.append(fixed2).append("\n");
                        promoted++;
                        continue;
                    }

                    // fix 3: bare return in promoted function → return param_1
                    if (isPromoted) {
                        Matcher brm = BARE_RETURN.matcher(line);
                        if (brm.matches()) {
                            fixed.append(brm.group(1))
                                 .append("return param_1;\n");
                            bareReturnFixed++;
                            continue;
                        }
                    }

                    fixed.append(line).append("\n");
                }

                pw.println(fixed.toString().stripTrailing());
                pw.println();
                exported++;
            }
        }

        println(String.format(
            "Export complete: %d written, %d ROM externs, %d failed | "
            + "%d gp lines stripped, %d return types promoted, "
            + "%d bare returns fixed → %s",
            exported, romSkipped, failed,
            gpStripped, promoted, bareReturnFixed,
            outFile.getAbsolutePath()));

        if (failed > 0)
            printerr(failed + " function(s) failed — "
                   + "check output for /* decompile failed */ markers.");
    }

    /**
     * Builds a typed C function signature from Ghidra's function record.
     * Uses fn.getReturnType() and fn.getParameters() — reflects DWARF debug
     * info, FIDB matches, and any manual type annotations made in Ghidra.
     * Falls back to "undefined4" for unknown/void types on promoted functions.
     */
    private String buildTypedSig(Function fn) {
        DataType retType = fn.getReturnType();
        String   retName = (retType != null)
                ? retType.getDisplayName()
                : "undefined4";

        StringBuilder sb = new StringBuilder();
        sb.append(retName).append(" ").append(fn.getName()).append("(");

        Parameter[] params = fn.getParameters();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) sb.append(", ");
            DataType dt = params[i].getDataType();
            String   dn = (dt != null) ? dt.getDisplayName() : "undefined4";
            sb.append(dn).append(" ").append(params[i].getName());
        }
        if (params.length == 0) sb.append("void");
        if (fn.hasVarArgs()) {
            if (params.length > 0) sb.append(", ");
            sb.append("...");
        }
        sb.append(")");
        return sb.toString();
    }
}
