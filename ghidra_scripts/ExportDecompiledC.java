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
// ── Automatic fixes ──────────────────────────────────────────────────────────
//
//  Fix 1: GP-register lines ("gp = 0x<hex>;")
//    The RISC-V global pointer is set once by startup code.  Ghidra emits it
//    as an assignment on every function entry, causing compile errors.
//    These lines are stripped.
//
//  Fix 2: Void return-type promotion
//    When Ghidra cannot prove a return value is consumed, it declares void.
//    If the caller assigns the result, the C is invalid.  A two-pass scan
//    detects this and promotes the return type to undefined4.
//
//  Fix 3 (improved in Sprint 7): Bare return in promoted functions
//    Bare "return;" in a promoted function is rewritten to "return <var>;"
//    where <var> is the last Ghidra-local variable (uVar*, iVar*, param_*)
//    assigned before the return.  Falls back to "return param_1;" if no
//    local assignment is found in scope.
//
// ── Semantic enrichments ─────────────────────────────────────────────────────
//
//  Sprint 1: Sorted output, per-function block comment (region, typed sig,
//            callers), ROM short-circuit (extern only).
//
//  Sprint 7: Smarter bare-return (backwards scan for last local assignment).
//
//  Sprint 8: Peripheral access annotation.
//    Scans raw decompiled text for DAT_<hex> where the address falls in a
//    known ESP32-P4 peripheral range (HP bus 0x400x–0x401x, HP_SYS 0x500x,
//    LP 0x501x).  Lists peripheral names in the block comment.
//    Also organises output into memory-region sections (IRAM / Flash / ROM)
//    with clear section headers.
//
//  Sprint 11: String constant extraction.
//    Collects all DAT_<hex> references from function bodies and checks whether
//    Ghidra has typed them as StringDataType.  Emits named constants
//    (static const char s_<hex>[] = "…") before the function block and
//    rewrites DAT_<hex> references in function bodies to use the name.
//
// ── Headless usage ───────────────────────────────────────────────────────────
//   analyzeHeadless /project Prog \
//     -postScript ExportDecompiledC.java /out/firmware.c
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
    private static final int MAX_CALLERS_SHOWN       = 8;

    // ── Fix 1: GP register artifact ──────────────────────────────────────────
    private static final Pattern GP_ASSIGN =
            Pattern.compile("^\\s*gp\\s*=\\s*0x[0-9A-Fa-f]+\\s*;\\s*$");

    // ── Fix 2: void return-type promotion ────────────────────────────────────
    private static final Pattern VOID_SIG =
            Pattern.compile("^\\s*void\\s+(\\w+)\\s*\\(");
    private static final Pattern CALL_ASSIGN =
            Pattern.compile("\\w+\\s*=\\s*(\\w+)\\s*\\(");

    // ── Fix 3 improved: bare return detection ─────────────────────────────────
    private static final Pattern BARE_RETURN =
            Pattern.compile("^(\\s*)return\\s*;\\s*$");

    // Matches Ghidra-generated local variable names on the LHS of an assignment.
    // Groups: (1) variable name  — only simple names, no arrow/dot/bracket.
    private static final Pattern LOCAL_ASSIGN =
            Pattern.compile("^\\s*((?:uVar|iVar|lVar|bVar|cVar|sVar|param_)\\d+)\\s*=(?!=)");

    // ── Sprint 11: string constant references ────────────────────────────────
    // DAT_ or PTR_DAT_ label in decompiled text.
    private static final Pattern DAT_REF =
            Pattern.compile("\\bDAT_([0-9A-Fa-f]{8})\\b");

    // ── Sprint 8: peripheral address ranges (ESP32-P4) ───────────────────────
    // [start, end_inclusive, name]
    private static final Object[][] PERIPH_RANGES = {
        // HP SYSTEM bus
        {0x40000000L, 0x4000FFFFL, "HP_SYS"},
        {0x40080000L, 0x40085FFFL, "UART0"},
        {0x40086000L, 0x4008BFFFL, "UART1"},
        {0x4008C000L, 0x40091FFFL, "UART2"},
        {0x40092000L, 0x40095FFFL, "SPI2"},
        {0x40096000L, 0x40099FFFL, "SPI3"},
        {0x4009A000L, 0x4009DFFFL, "I2C0"},
        {0x4009E000L, 0x400A1FFFL, "I2C1"},
        {0x400A2000L, 0x400A5FFFL, "GPIO"},
        {0x400A6000L, 0x400A9FFFL, "LEDC"},
        {0x400AA000L, 0x400ADFFFL, "TIMER_GROUP0"},
        {0x400AE000L, 0x400B1FFFL, "TIMER_GROUP1"},
        {0x400B0000L, 0x400BFFFFL, "HP_APM"},
        {0x400C0000L, 0x400CFFFFL, "HP_MATRIX"},
        {0x400D0000L, 0x400DFFFFL, "GDMA"},
        // HP_SYS extended
        {0x50000000L, 0x5001FFFFL, "HP_SYS_REGS"},
        {0x50020000L, 0x5003FFFFL, "I2S0"},
        {0x50040000L, 0x5005FFFFL, "I2S1"},
        {0x50060000L, 0x5007FFFFL, "I2S2"},
        {0x50080000L, 0x5009FFFFL, "I3C_MST"},
        {0x500A0000L, 0x500BFFFFL, "USB_SERIAL_JTAG"},
        {0x500C0000L, 0x500DFFFFL, "ADC"},
        {0x500E0000L, 0x500FFFFL,  "TOUCH"},
        // LP peripherals
        {0x50108000L, 0x50109FFFL, "LP_UART"},
        {0x5010A000L, 0x5010BFFFL, "LP_I2C"},
        {0x5010C000L, 0x5010DFFFL, "LP_SPI"},
        {0x5010E000L, 0x5010FFFFL, "LP_GPIO"},
    };

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
            printerr("Decompiler failed: " + decompiler.getLastMessage());
            return;
        }

        TreeMap<Address, Function> fnByAddr  = new TreeMap<>();
        TreeMap<Address, String>   rawByAddr = new TreeMap<>();
        int failed = 0;

        try {
            FunctionIterator it = currentProgram.getListing().getFunctions(true);
            while (it.hasNext()) {
                monitor.checkCancelled();
                Function fn   = it.next();
                Address  addr = fn.getEntryPoint();
                fnByAddr.put(addr, fn);

                DecompileResults res =
                        decompiler.decompileFunction(fn, DECOMPILE_TIMEOUT_SECS, monitor);
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

        // ── Fix 2: find void functions whose return value is used ─────────────
        Set<String> voidFunctions = new HashSet<>();
        for (String raw : rawByAddr.values()) {
            if (raw == null) continue;
            for (String line : raw.split("\n")) {
                Matcher m = VOID_SIG.matcher(line);
                if (m.find()) voidFunctions.add(m.group(1));
            }
        }
        Set<String> promoteToUndefined4 = new HashSet<>();
        for (String raw : rawByAddr.values()) {
            if (raw == null) continue;
            for (String line : raw.split("\n")) {
                Matcher m = CALL_ASSIGN.matcher(line);
                if (m.find()) {
                    String callee = m.group(1);
                    if (voidFunctions.contains(callee))
                        promoteToUndefined4.add(callee);
                }
            }
        }
        if (!promoteToUndefined4.isEmpty())
            println("Void→undefined4 promotion: " + promoteToUndefined4);

        // ── Sprint 11: collect string constants from all function bodies ───────
        // Map: "DAT_<hex>" → "s_<hex>"  (for substitution in body text)
        Map<String, String> stringConstants = new LinkedHashMap<>();
        // Map: "s_<hex>" → string value (for declaration)
        Map<String, String> stringDecls     = new LinkedHashMap<>();
        collectStringConstants(rawByAddr.values(), stringConstants, stringDecls);

        // ── write output ──────────────────────────────────────────────────────
        int exported        = 0;
        int gpStripped      = 0;
        int promoted        = 0;
        int bareReturnFixed = 0;
        int romSkipped      = 0;
        String prevRegion   = null;   // for section-header tracking

        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {

            pw.println("/* Auto-generated by Ghidra ExportDecompiledC script */");
            pw.println("/* Program : " + currentProgram.getName()   + " */");
            pw.println("/* Language: " + currentProgram.getLanguageID() + " */");
            pw.println("/* Fixes applied:");
            pw.println(" *   Fix 1 — gp = 0x<hex>; lines stripped");
            pw.println(" *   Fix 2 — void return promoted to undefined4 (caller-driven)");
            pw.println(" *   Fix 3 — bare return; -> return <last-local>; in promoted functions");
            pw.println(" * Semantic enrichments:");
            pw.println(" *   Sprint 1  — sorted output, typed sig, callers, ROM extern");
            pw.println(" *   Sprint 7  — smart bare-return (backwards local-var scan)");
            pw.println(" *   Sprint 8  — peripheral access annotation, region sections");
            pw.println(" *   Sprint 11 — string constants extracted from DAT_ references");
            pw.println(" * Compile with:");
            pw.println(" *   riscv32-esp-elf-gcc -march=rv32imafc_zicsr_zifencei \\");
            pw.println(" *     -mabi=ilp32f -O0 -include ghidra_types.h -c "
                    + outFile.getName());
            pw.println(" */");
            pw.println("#include \"ghidra_types.h\"");
            pw.println();

            // ── string constant block ─────────────────────────────────────────
            if (!stringDecls.isEmpty()) {
                pw.println("/* ─── String constants extracted from DAT_ references ─── */");
                for (Map.Entry<String, String> se : stringDecls.entrySet()) {
                    pw.println("static const char " + se.getKey()
                            + "[] = " + se.getValue() + ";");
                }
                pw.println();
            }

            for (Map.Entry<Address, Function> e : fnByAddr.entrySet()) {
                Address  addr = e.getKey();
                Function fn   = e.getValue();
                String   raw  = rawByAddr.get(addr);

                // ── per-function metadata ──────────────────────────────────────
                MemoryBlock block      = currentProgram.getMemory().getBlock(addr);
                String      regionName = (block != null) ? block.getName() : "?";
                boolean isRom = fn.isExternal() ||
                        regionName.toUpperCase().contains("ROM");

                // ── section header when region changes ────────────────────────
                if (!regionName.equals(prevRegion)) {
                    long blockStart = (block != null) ? block.getStart().getOffset() : 0;
                    long blockEnd   = (block != null) ? block.getEnd().getOffset()   : 0;
                    pw.println();
                    pw.println("/* ╔══════════════════════════════════════════════════════╗");
                    pw.printf(" * ║  SECTION: %-42s║%n", regionName);
                    pw.printf(" * ║  range:   0x%08X – 0x%08X                  ║%n",
                            blockStart, blockEnd);
                    pw.println(" * ╚══════════════════════════════════════════════════════╝");
                    pw.println(" */");
                    prevRegion = regionName;
                }

                // ── callers ────────────────────────────────────────────────────
                List<String> callerNames = fn.getCallingFunctions(monitor).stream()
                        .map(Function::getName).sorted()
                        .collect(Collectors.toList());

                // ── peripheral scan ───────────────────────────────────────────
                List<String> periphs = (raw != null)
                        ? detectPeripherals(raw)
                        : Collections.emptyList();

                String typedSig = buildTypedSig(fn);

                // ── block comment ─────────────────────────────────────────────
                pw.println("/* ─── " + fn.getName() + " @ 0x" + addr);
                pw.println(" * region  : " + regionName);
                pw.println(" * typed   : " + typedSig);
                if (!callerNames.isEmpty()) {
                    String callerStr = callerNames.size() <= MAX_CALLERS_SHOWN
                            ? String.join(", ", callerNames)
                            : String.join(", ", callerNames.subList(0, MAX_CALLERS_SHOWN))
                              + " (+" + (callerNames.size() - MAX_CALLERS_SHOWN) + " more)";
                    pw.println(" * callers : " + callerStr);
                } else {
                    pw.println(" * callers : (none — possible root / ISR)");
                }
                if (!periphs.isEmpty())
                    pw.println(" * periph  : " + String.join(", ", periphs));
                pw.println(" */");

                // ── ROM short-circuit ─────────────────────────────────────────
                if (isRom) {
                    pw.println("extern " + typedSig + "; /* ROM */");
                    pw.println();
                    romSkipped++;
                    continue;
                }

                if (raw == null) {
                    pw.println("/* decompile failed */");
                    pw.println();
                    continue;
                }

                // ── apply fixes ───────────────────────────────────────────────
                final String  fnName    = fn.getName();
                boolean       isPromoted = promoteToUndefined4.contains(fnName);
                StringBuilder fixed     = new StringBuilder();

                // For Fix 3 improved: track last Ghidra local var assigned per scope.
                // We use a simple stack: push null on '{', update on assignment, pop on '}'.
                // The "last" at the top of the stack when we hit bare return is our candidate.
                Deque<String> scopeStack    = new ArrayDeque<>();
                String        lastLocalVar  = null;  // running last across all scopes

                for (String line : raw.split("\n", -1)) {

                    // Fix 1: strip GP assignments.
                    if (GP_ASSIGN.matcher(line).matches()) {
                        gpStripped++;
                        continue;
                    }

                    // Fix 2: promote void → undefined4 in the signature.
                    if (promoteToUndefined4.stream().anyMatch(name ->
                            line.matches("\\s*void\\s+" + Pattern.quote(name) + "\\s*\\(.*"))) {
                        fixed.append(line.replaceFirst("\\bvoid\\b", "undefined4")).append("\n");
                        promoted++;
                        continue;
                    }

                    // Track scope depth for var lifetime (simple { } counting).
                    for (char c : line.toCharArray()) {
                        if (c == '{') scopeStack.push(lastLocalVar); // save on entry
                        else if (c == '}' && !scopeStack.isEmpty())
                            scopeStack.pop(); // restore on exit (but we keep the global lastLocalVar)
                    }

                    // Track last-assigned local variable (Fix 3 improved).
                    Matcher lam = LOCAL_ASSIGN.matcher(line);
                    if (lam.find()) lastLocalVar = lam.group(1);

                    // Fix 3: bare return → return <lastLocalVar or param_1>.
                    if (isPromoted) {
                        Matcher brm = BARE_RETURN.matcher(line);
                        if (brm.matches()) {
                            String retVar = (lastLocalVar != null) ? lastLocalVar : "param_1";
                            fixed.append(brm.group(1))
                                 .append("return ").append(retVar).append(";\n");
                            bareReturnFixed++;
                            continue;
                        }
                    }

                    // Sprint 11: substitute DAT_<hex> with string constant names.
                    String outLine = line;
                    for (Map.Entry<String, String> sc : stringConstants.entrySet()) {
                        outLine = outLine.replace(sc.getKey(), sc.getValue());
                    }

                    fixed.append(outLine).append("\n");
                }

                pw.println(fixed.toString().stripTrailing());
                pw.println();
                exported++;
            }
        }

        println(String.format(
            "Export: %d written, %d ROM externs, %d failed | "
            + "gp_stripped=%d promoted=%d bare_fixed=%d strings=%d → %s",
            exported, romSkipped, failed,
            gpStripped, promoted, bareReturnFixed,
            stringDecls.size(),
            outFile.getAbsolutePath()));

        if (failed > 0)
            printerr(failed + " function(s) failed — check /* decompile failed */ markers.");
    }

    // ── Sprint 8: peripheral detection ───────────────────────────────────────

    private List<String> detectPeripherals(String raw) {
        Set<String> found = new LinkedHashSet<>();
        Matcher m = DAT_REF.matcher(raw);
        while (m.find()) {
            long addr;
            try {
                addr = Long.parseUnsignedLong(m.group(1), 16);
            } catch (NumberFormatException ex) {
                continue;
            }
            for (Object[] range : PERIPH_RANGES) {
                long lo = (Long) range[0];
                long hi = (Long) range[1];
                if (addr >= lo && addr <= hi) {
                    found.add((String) range[2]);
                    break;
                }
            }
        }
        // Also check raw hex literals like (int *)0x40080000.
        Pattern HEX_LIT = Pattern.compile("0x([0-9A-Fa-f]{8})");
        Matcher hm = HEX_LIT.matcher(raw);
        while (hm.find()) {
            long addr;
            try {
                addr = Long.parseUnsignedLong(hm.group(1), 16);
            } catch (NumberFormatException ex) {
                continue;
            }
            for (Object[] range : PERIPH_RANGES) {
                long lo = (Long) range[0];
                long hi = (Long) range[1];
                if (addr >= lo && addr <= hi) {
                    found.add((String) range[2]);
                    break;
                }
            }
        }
        return new ArrayList<>(found);
    }

    // ── Sprint 11: string constant extraction ─────────────────────────────────

    private void collectStringConstants(
            Collection<String> rawBodies,
            Map<String, String> datToName,   // "DAT_400010ab" → "s_400010ab"
            Map<String, String> nameToDecl)  // "s_400010ab"   → "\"hello\""
            throws Exception {

        // Collect all unique DAT_ addresses referenced across all function bodies.
        Set<String> datAddrs = new LinkedHashSet<>();
        for (String raw : rawBodies) {
            if (raw == null) continue;
            Matcher m = DAT_REF.matcher(raw);
            while (m.find()) datAddrs.add(m.group(1).toLowerCase());
        }

        for (String hexAddr : datAddrs) {
            long offset;
            try {
                offset = Long.parseUnsignedLong(hexAddr, 16);
            } catch (NumberFormatException ex) {
                continue;
            }
            Address addr;
            try {
                addr = currentProgram.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(offset);
            } catch (Exception ex) {
                continue;
            }
            Data data = currentProgram.getListing().getDataAt(addr);
            if (data == null) continue;
            DataType dt = data.getDataType();
            if (!(dt instanceof StringDataType)
                    && !(dt instanceof TerminatedStringDataType)
                    && !(dt instanceof UnicodeDataType)) {
                continue;
            }
            Object val = data.getValue();
            if (val == null) continue;
            String strVal  = val.toString();
            String safeName = "s_" + hexAddr;
            String escaped  = escapeStringLiteral(strVal);
            datToName.put("DAT_" + hexAddr.toUpperCase(), safeName);
            nameToDecl.put(safeName, "\"" + escaped + "\"");
        }
    }

    private String escapeStringLiteral(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c >= 0x20 && c < 0x7F) sb.append(c);
                    else sb.append(String.format("\\x%02X", (int) c));
            }
        }
        return sb.toString();
    }

    // ── typed signature builder ────────────────────────────────────────────────

    private String buildTypedSig(Function fn) {
        DataType retType = fn.getReturnType();
        String   retName = (retType != null)
                ? retType.getDisplayName() : "undefined4";
        StringBuilder sb = new StringBuilder();
        sb.append(retName).append(" ").append(fn.getName()).append("(");
        Parameter[] params = fn.getParameters();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) sb.append(", ");
            DataType dt = params[i].getDataType();
            sb.append(dt != null ? dt.getDisplayName() : "undefined4")
              .append(" ").append(params[i].getName());
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
