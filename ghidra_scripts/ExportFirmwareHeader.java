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

// Generates firmware.h — a compilable C header for the current program.
//
// Emits three sections in dependency order:
//
//  1. User-defined type definitions
//     Iterates DataTypeManager for all Structure, Enum, and TypeDef types
//     that appear (transitively) in any function's return type or parameter
//     types.  Built-in Ghidra types (int, void, …) are excluded.
//     Types are emitted in topological dependency order to avoid forward-
//     reference errors.
//
//  2. Function prototypes
//     One extern declaration per non-ROM function, using the Ghidra-resolved
//     name and the typed signature from fn.getReturnType() / fn.getParameters().
//     ROM / external functions are emitted as-is (no "extern" prefix needed).
//
//  3. Global variable declarations
//     Iterates all symbols in non-executable memory blocks and emits
//     "extern <type> <name>;" for each that has a data type applied.
//     Volatile is added for symbols in the peripheral address range
//     (0x50000000–0x5FFFFFFF).
//
// Output path is taken from the first script argument in headless mode,
// or prompted via a save-file dialog in GUI mode.
//
// Usage: Script Manager → ESP32-P4 → Export Firmware Header
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Export Firmware Header

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.util.*;
import java.util.stream.*;

public class ExportFirmwareHeader extends GhidraScript {

    // HP peripheral bus — registers in this range should be volatile.
    private static final long PERIPH_BASE = 0x50000000L;
    private static final long PERIPH_END  = 0x60000000L;

    // C reserved words that must not appear as identifiers unmodified.
    private static final Set<String> C_RESERVED = new HashSet<>(Arrays.asList(
        "auto","break","case","char","const","continue","default","do","double",
        "else","enum","extern","float","for","goto","if","inline","int","long",
        "register","restrict","return","short","signed","sizeof","static",
        "struct","switch","typedef","union","unsigned","void","volatile","while",
        "_Bool","_Complex","_Imaginary"
    ));

    @Override
    public void run() throws Exception {
        String defaultName =
                currentProgram.getName().replaceAll("[^\\w.-]", "_") + ".h";
        File outFile;
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            outFile = new File(args[0]);
        } else {
            outFile = askFile("Save firmware header to", "Save");
            if (outFile == null) {
                outFile = new File(System.getProperty("user.home"), defaultName);
                println("No file chosen — writing to " + outFile.getAbsolutePath());
            }
        }

        // ── collect functions (sorted by address) ─────────────────────────────
        TreeMap<Address, Function> fnByAddr = new TreeMap<>();
        for (Function fn : currentProgram.getListing().getFunctions(true)) {
            fnByAddr.put(fn.getEntryPoint(), fn);
        }

        // ── collect referenced user types (transitively) ──────────────────────
        Set<DataType> usedTypes = new LinkedHashSet<>();
        for (Function fn : fnByAddr.values()) {
            collectType(fn.getReturnType(), usedTypes);
            for (Parameter p : fn.getParameters()) {
                collectType(p.getDataType(), usedTypes);
            }
        }

        // Topological emit order (DFS post-order = dependencies first).
        List<DataType> emitOrder = new ArrayList<>();
        Set<DataType> visited   = new HashSet<>();
        for (DataType dt : usedTypes) {
            topoVisit(dt, usedTypes, visited, emitOrder);
        }

        // ── collect globals ───────────────────────────────────────────────────
        // Walk non-executable memory blocks; emit every symbol that has a DataType.
        List<String> globalDecls = new ArrayList<>();
        SymbolIterator symIt =
                currentProgram.getSymbolTable().getAllSymbols(false);
        while (symIt.hasNext()) {
            monitor.checkCancelled();
            Symbol sym = symIt.next();
            if (!sym.isGlobal()) continue;
            Address addr = sym.getAddress();
            MemoryBlock block = currentProgram.getMemory().getBlock(addr);
            if (block == null || block.isExecute()) continue;
            Data data = currentProgram.getListing().getDataAt(addr);
            if (data == null) continue;
            DataType dt  = data.getDataType();
            String dtStr = cTypeName(dt);
            boolean vol  = isPeripheral(addr);
            String name  = safeName(sym.getName());
            globalDecls.add("extern " + (vol ? "volatile " : "") + dtStr
                    + " " + name + ";");
        }
        Collections.sort(globalDecls);

        // ── write header ──────────────────────────────────────────────────────
        int typesEmitted = 0, protosEmitted = 0, globalsEmitted = globalDecls.size();

        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
            pw.println("/* Auto-generated by Ghidra ExportFirmwareHeader script */");
            pw.println("/* Program : " + currentProgram.getName() + " */");
            pw.println("/* Language: " + currentProgram.getLanguageID() + " */");
            pw.println("#pragma once");
            pw.println("#include <stdint.h>");
            pw.println("#include \"ghidra_types.h\"");
            pw.println();

            // ─── section 1: type definitions ─────────────────────────────────
            pw.println("/* ═══ Type definitions ═══════════════════════════════ */");
            for (DataType dt : emitOrder) {
                String decl = emitTypeDecl(dt);
                if (decl != null) {
                    pw.println(decl);
                    typesEmitted++;
                }
            }
            pw.println();

            // ─── section 2: function prototypes ──────────────────────────────
            pw.println("/* ═══ Function prototypes ════════════════════════════ */");
            for (Function fn : fnByAddr.values()) {
                monitor.checkCancelled();
                MemoryBlock block = currentProgram.getMemory()
                        .getBlock(fn.getEntryPoint());
                boolean isRom = fn.isExternal() ||
                        (block != null &&
                         block.getName().toUpperCase().contains("ROM"));
                String sig = buildTypedSig(fn);
                pw.println((isRom ? "/* ROM */ " : "extern ") + sig + ";");
                protosEmitted++;
            }
            pw.println();

            // ─── section 3: global variables ─────────────────────────────────
            pw.println("/* ═══ Global variable declarations ══════════════════ */");
            for (String decl : globalDecls) pw.println(decl);
        }

        println(String.format(
            "Header written: %d types, %d prototypes, %d globals → %s",
            typesEmitted, protosEmitted, globalsEmitted,
            outFile.getAbsolutePath()));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /** Recursively collects all non-built-in types referenced by dt. */
    private void collectType(DataType dt, Set<DataType> out) {
        if (dt == null || out.contains(dt) || isBuiltIn(dt)) return;
        if (!(dt instanceof Structure) && !(dt instanceof ghidra.program.model.data.Enum) &&
            !(dt instanceof TypeDef) && !(dt instanceof Union)) {
            // For pointers/arrays, recurse into the base type but don't emit the container.
            if (dt instanceof Pointer)
                collectType(((Pointer) dt).getDataType(), out);
            else if (dt instanceof Array)
                collectType(((Array) dt).getDataType(), out);
            return;
        }
        out.add(dt);
        if (dt instanceof Structure) {
            for (DataTypeComponent c : ((Structure) dt).getComponents())
                collectType(c.getDataType(), out);
        } else if (dt instanceof Union) {
            for (DataTypeComponent c : ((Union) dt).getComponents())
                collectType(c.getDataType(), out);
        } else if (dt instanceof TypeDef) {
            collectType(((TypeDef) dt).getDataType(), out);
        }
    }

    /** DFS post-order topological sort: dependencies before the types that use them. */
    private void topoVisit(DataType dt, Set<DataType> all,
                           Set<DataType> visited, List<DataType> out) {
        if (!all.contains(dt) || visited.contains(dt)) return;
        visited.add(dt);
        if (dt instanceof Structure) {
            for (DataTypeComponent c : ((Structure) dt).getComponents())
                topoVisit(c.getDataType(), all, visited, out);
        } else if (dt instanceof Union) {
            for (DataTypeComponent c : ((Union) dt).getComponents())
                topoVisit(c.getDataType(), all, visited, out);
        } else if (dt instanceof TypeDef) {
            topoVisit(((TypeDef) dt).getDataType(), all, visited, out);
        }
        out.add(dt);
    }

    /** Emits a C type declaration, or null if not emittable. */
    private String emitTypeDecl(DataType dt) {
        if (dt instanceof Structure) {
            Structure s = (Structure) dt;
            String name = safeName(s.getName());
            StringBuilder sb = new StringBuilder();
            sb.append("typedef struct ").append(name).append(" {\n");
            for (DataTypeComponent c : s.getDefinedComponents()) {
                sb.append("    ").append(cTypeName(c.getDataType()))
                  .append(" ").append(safeName(c.getFieldName()))
                  .append(";\n");
            }
            sb.append("} ").append(name).append(";");
            return sb.toString();
        }
        if (dt instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum e = (ghidra.program.model.data.Enum) dt;
            String name = safeName(e.getName());
            StringBuilder sb = new StringBuilder();
            sb.append("typedef enum ").append(name).append(" {\n");
            for (String ename : e.getNames()) {
                sb.append("    ").append(safeName(ename))
                  .append(" = ").append(e.getValue(ename)).append(",\n");
            }
            sb.append("} ").append(name).append(";");
            return sb.toString();
        }
        if (dt instanceof TypeDef) {
            TypeDef td = (TypeDef) dt;
            String base = cTypeName(td.getDataType());
            String name = safeName(td.getName());
            if (base.equals(name)) return null; // trivial self-typedef
            return "typedef " + base + " " + name + ";";
        }
        return null;
    }

    private String buildTypedSig(Function fn) {
        DataType retType = fn.getReturnType();
        String retName = (retType != null) ? cTypeName(retType) : "undefined4";
        StringBuilder sb = new StringBuilder();
        sb.append(retName).append(" ").append(fn.getName()).append("(");
        Parameter[] params = fn.getParameters();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) sb.append(", ");
            DataType dt = params[i].getDataType();
            sb.append(dt != null ? cTypeName(dt) : "undefined4");
            sb.append(" ").append(safeName(params[i].getName()));
        }
        if (params.length == 0) sb.append("void");
        if (fn.hasVarArgs()) {
            if (params.length > 0) sb.append(", ");
            sb.append("...");
        }
        sb.append(")");
        return sb.toString();
    }

    private String cTypeName(DataType dt) {
        if (dt == null) return "undefined4";
        return dt.getDisplayName();
    }

    /** Sanitizes an identifier: replaces non-identifier chars and avoids C reserved words. */
    private String safeName(String name) {
        if (name == null || name.isEmpty()) return "_anon";
        // Replace non-identifier chars with underscore.
        String s = name.replaceAll("[^\\w]", "_");
        // Ensure doesn't start with digit.
        if (Character.isDigit(s.charAt(0))) s = "_" + s;
        // Avoid C reserved words.
        if (C_RESERVED.contains(s)) s = "_" + s;
        return s;
    }

    private boolean isBuiltIn(DataType dt) {
        if (dt == null) return true;
        // Ghidra built-in types typically live in the BuiltIn category or have
        // no category path. Composite/user types always have a non-empty path.
        CategoryPath cp = dt.getCategoryPath();
        return cp == null || cp.equals(CategoryPath.ROOT) ||
               cp.getPath().startsWith("/BuiltIn");
    }

    private boolean isPeripheral(Address addr) {
        long off = addr.getOffset();
        return off >= PERIPH_BASE && off < PERIPH_END;
    }
}
