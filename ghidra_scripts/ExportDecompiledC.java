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
// Two RISC-V / Ghidra artefacts are fixed automatically before writing:
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
import ghidra.program.model.listing.*;

import java.io.*;
import java.util.*;
import java.util.regex.*;

public class ExportDecompiledC extends GhidraScript {

    private static final int DECOMPILE_TIMEOUT_SECS = 30;

    // Matches:  gp = 0x1a2b3c4d;   (with optional leading whitespace)
    private static final Pattern GP_ASSIGN =
            Pattern.compile("^\\s*gp\\s*=\\s*0x[0-9A-Fa-f]+\\s*;\\s*$");

    // Matches a void function signature:  void <name>(
    private static final Pattern VOID_SIG =
            Pattern.compile("^\\s*void\\s+(\\w+)\\s*\\(");

    // Matches an assignment whose RHS is a call:  <var> = <name>(
    private static final Pattern CALL_ASSIGN =
            Pattern.compile("\\w+\\s*=\\s*(\\w+)\\s*\\(");

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

        // ── decompile all functions into memory ───────────────────────────────
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

        // name → raw C text (may be null on failure)
        Map<String, String> rawByName = new LinkedHashMap<>();
        int failed = 0;

        try {
            FunctionIterator it =
                    currentProgram.getListing().getFunctions(true);
            while (it.hasNext()) {
                monitor.checkCancelled();
                Function fn = it.next();
                String key = fn.getName() + "@" + fn.getEntryPoint();

                DecompileResults res =
                        decompiler.decompileFunction(fn, DECOMPILE_TIMEOUT_SECS, monitor);

                if (res != null && res.decompileCompleted()) {
                    DecompiledFunction df = res.getDecompiledFunction();
                    rawByName.put(key, df != null ? df.getC() : null);
                    if (df == null) failed++;
                } else {
                    rawByName.put(key, null);
                    failed++;
                }
            }
        } finally {
            decompiler.dispose();
        }

        // ── collect all void-declared function names ──────────────────────────
        Set<String> voidFunctions = new HashSet<>();
        for (String raw : rawByName.values()) {
            if (raw == null) continue;
            for (String line : raw.split("\n")) {
                Matcher m = VOID_SIG.matcher(line);
                if (m.find()) voidFunctions.add(m.group(1));
            }
        }

        // ── find void functions whose return value is actually used ───────────
        Set<String> promoteToUndefined4 = new HashSet<>();
        for (String raw : rawByName.values()) {
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

        // ── write fixed output ────────────────────────────────────────────────
        int exported = 0;
        int gpStripped = 0;
        int promoted = 0;

        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
            pw.println("/* Auto-generated by Ghidra ExportDecompiledC script */");
            pw.println("/* Program : " + currentProgram.getName()  + " */");
            pw.println("/* Language: " + currentProgram.getLanguageID() + " */");
            pw.println("/* Fixes applied automatically:");
            pw.println(" *   - gp = 0x<hex>; lines stripped (RISC-V GP register artifact)");
            pw.println(" *   - void return promoted to undefined4 where caller uses result");
            pw.println(" * Compile with:");
            pw.println(" *   riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei \\");
            pw.println(" *     -mabi=ilp32f -O0 -include ghidra_types.h -c "
                    + outFile.getName());
            pw.println(" */");
            pw.println();

            for (Map.Entry<String, String> e : rawByName.entrySet()) {
                pw.println("/* --- " + e.getKey() + " --- */");

                String raw = e.getValue();
                if (raw == null) {
                    pw.println("/* decompile failed */");
                    pw.println();
                    continue;
                }

                // apply fixes line-by-line
                StringBuilder fixed = new StringBuilder();
                for (String line : raw.split("\n", -1)) {

                    // fix 1: strip GP register assignments
                    if (GP_ASSIGN.matcher(line).matches()) {
                        gpStripped++;
                        continue;
                    }

                    // fix 2: promote void → undefined4 in the signature line
                    if (promoteToUndefined4.stream().anyMatch(name ->
                            line.matches("\\s*void\\s+" + name + "\\s*\\(.*"))) {
                        String fixed2 = line.replaceFirst(
                                "\\bvoid\\b", "undefined4");
                        fixed.append(fixed2).append("\n");
                        promoted++;
                        continue;
                    }

                    fixed.append(line).append("\n");
                }

                pw.println(fixed.toString().stripTrailing());
                pw.println();
                exported++;
            }
        }

        println(String.format(
            "Export complete: %d written, %d failed | "
            + "%d gp lines stripped, %d return types promoted → %s",
            exported, failed, gpStripped, promoted,
            outFile.getAbsolutePath()));

        if (failed > 0)
            printerr(failed + " function(s) failed — "
                   + "check output for /* decompile failed */ markers.");
    }
}
