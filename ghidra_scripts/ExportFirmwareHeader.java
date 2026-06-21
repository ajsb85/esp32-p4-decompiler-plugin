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
//     Walks program.getDataTypeManager().getAllDataTypes() to collect every
//     user-defined Structure, Union, Enum, and TypeDef (not just those
//     referenced by function signatures).  Built-in Ghidra types are excluded.
//
//     Emitted in two sub-passes:
//       a) Forward declarations  — "struct Foo;" for every named struct/union
//          that is referenced via pointer from another struct, preventing
//          "incomplete type" errors in mutual-reference and self-reference cases.
//       b) Full definitions      — topological DFS post-order so dependencies
//          are always defined before the types that use them.
//
//     Array fields are emitted as "int field[4]" not "int[4] field".
//     Union types are emitted as "typedef union Name { … } Name;".
//
//  2. Function prototypes
//     One extern declaration per non-ROM function, using the Ghidra-resolved
//     name and typed signature from fn.getReturnType() / fn.getParameters().
//     ROM / external functions are emitted with a /* ROM */ marker.
//
//  3. Global variable declarations
//     Iterates all symbols in non-executable memory blocks and emits
//     "extern <type> <name>;" for each that has a DataType applied.
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

        // ── collect ALL user-defined types from the DataTypeManager ──────────
        // Walk every type in the program's type manager (not just those in
        // function signatures) so structs that appear only in function bodies,
        // as global variable types, or as nested members are all captured.
        Set<DataType> usedTypes = new LinkedHashSet<>();
        // getAllDataTypes() returns Iterator, not Iterable — use while loop.
        java.util.Iterator<DataType> dtIter =
                currentProgram.getDataTypeManager().getAllDataTypes();
        while (dtIter.hasNext()) {
            monitor.checkCancelled();
            DataType dt = dtIter.next();
            if (isEmittable(dt)) {
                usedTypes.add(dt);
                collectNestedTypes(dt, usedTypes);
            }
        }

        // Topological emit order: DFS post-order so every dependency is
        // defined before the type that uses it.  Pointer fields do NOT create
        // dependency edges (a pointer only needs a forward declaration, not the
        // full struct definition), which breaks mutual-reference cycles.
        List<DataType> emitOrder = new ArrayList<>();
        Set<DataType> visited   = new HashSet<>();
        for (DataType dt : usedTypes) {
            topoVisit(dt, usedTypes, visited, emitOrder);
        }

        // Collect the set of struct/union names that are used via pointer from
        // any other struct/union field.  These need forward declarations.
        Set<String> needsForwardDecl = new LinkedHashSet<>();
        for (DataType dt : usedTypes) {
            if (dt instanceof Structure || dt instanceof Union) {
                DataTypeComponent[] comps = (dt instanceof Structure)
                        ? ((Structure) dt).getComponents()
                        : ((Union) dt).getComponents();
                for (DataTypeComponent c : comps) {
                    DataType ft = c.getDataType();
                    if (ft instanceof Pointer) {
                        DataType base = ((Pointer) ft).getDataType();
                        if (base instanceof Structure || base instanceof Union) {
                            needsForwardDecl.add(safeName(base.getName()));
                        }
                    }
                }
            }
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
        int typesEmitted = 0, fwdEmitted = 0, protosEmitted = 0,
            globalsEmitted = globalDecls.size();

        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
            pw.println("/* Auto-generated by Ghidra ExportFirmwareHeader script */");
            pw.println("/* Program : " + currentProgram.getName() + " */");
            pw.println("/* Language: " + currentProgram.getLanguageID() + " */");
            pw.println("#pragma once");
            pw.println("#include <stdint.h>");
            pw.println("#include \"ghidra_types.h\"");
            pw.println();

            // ─── section 1a: forward declarations ────────────────────────────
            if (!needsForwardDecl.isEmpty()) {
                pw.println("/* ═══ Forward declarations ══════════════════════════ */");
                for (String name : needsForwardDecl) {
                    pw.println("struct " + name + ";");
                    fwdEmitted++;
                }
                pw.println();
            }

            // ─── section 1b: type definitions ────────────────────────────────
            pw.println("/* ═══ Type definitions (" + emitOrder.size() + " types) ══════════ */");
            for (DataType dt : emitOrder) {
                String decl = emitTypeDecl(dt);
                if (decl != null) {
                    pw.println(decl);
                    pw.println();
                    typesEmitted++;
                }
            }

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
            "Header written: %d fwd-decls, %d types, %d prototypes, %d globals → %s",
            fwdEmitted, typesEmitted, protosEmitted, globalsEmitted,
            outFile.getAbsolutePath()));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /** Returns true for types we want to emit: struct, union, enum, typedef. */
    private boolean isEmittable(DataType dt) {
        if (dt == null || isBuiltIn(dt)) return false;
        return (dt instanceof Structure) || (dt instanceof Union) ||
               (dt instanceof ghidra.program.model.data.Enum) || (dt instanceof TypeDef);
    }

    /** Recursively adds nested emittable types from struct/union/typedef fields.
     *  Does NOT recurse through Pointer fields — pointers only need a forward
     *  declaration, not the full definition, so they don't create ordering deps. */
    private void collectNestedTypes(DataType dt, Set<DataType> out) {
        if (dt instanceof Structure) {
            for (DataTypeComponent c : ((Structure) dt).getComponents()) {
                DataType ft = stripArray(c.getDataType());
                if (isEmittable(ft) && !out.contains(ft)) {
                    out.add(ft);
                    collectNestedTypes(ft, out);
                }
            }
        } else if (dt instanceof Union) {
            for (DataTypeComponent c : ((Union) dt).getComponents()) {
                DataType ft = stripArray(c.getDataType());
                if (isEmittable(ft) && !out.contains(ft)) {
                    out.add(ft);
                    collectNestedTypes(ft, out);
                }
            }
        } else if (dt instanceof TypeDef) {
            DataType base = ((TypeDef) dt).getDataType();
            if (isEmittable(base) && !out.contains(base)) {
                out.add(base);
                collectNestedTypes(base, out);
            }
        }
    }

    /** Unwraps array wrappers to the element type (for dependency checking). */
    private DataType stripArray(DataType dt) {
        while (dt instanceof Array) dt = ((Array) dt).getDataType();
        return dt;
    }

    /** DFS post-order topological sort.
     *  Pointer fields do NOT create ordering edges (only forward-decl needed). */
    private void topoVisit(DataType dt, Set<DataType> all,
                           Set<DataType> visited, List<DataType> out) {
        if (!all.contains(dt) || visited.contains(dt)) return;
        visited.add(dt);
        if (dt instanceof Structure) {
            for (DataTypeComponent c : ((Structure) dt).getComponents()) {
                DataType ft = stripArray(c.getDataType());
                if (!(ft instanceof Pointer)) topoVisit(ft, all, visited, out);
            }
        } else if (dt instanceof Union) {
            for (DataTypeComponent c : ((Union) dt).getComponents()) {
                DataType ft = stripArray(c.getDataType());
                if (!(ft instanceof Pointer)) topoVisit(ft, all, visited, out);
            }
        } else if (dt instanceof TypeDef) {
            DataType base = ((TypeDef) dt).getDataType();
            if (!(base instanceof Pointer)) topoVisit(base, all, visited, out);
        }
        out.add(dt);
    }

    /** Emits a C type declaration, or null if not emittable. */
    private String emitTypeDecl(DataType dt) {
        if (dt instanceof Structure) return emitStruct((Structure) dt, "struct");
        if (dt instanceof Union)     return emitStruct((Union) dt,     "union");
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

    /** Emits a struct or union definition.  Handles array fields correctly
     *  ("int field[4]" not "int[4] field") and names missing fields "_field_N". */
    private String emitStruct(DataTypeComponent[] comps, String keyword, String name) {
        StringBuilder sb = new StringBuilder();
        sb.append("typedef ").append(keyword).append(" ").append(name).append(" {\n");
        int anonIdx = 0;
        for (DataTypeComponent c : comps) {
            DataType ft    = c.getDataType();
            String fldName = c.getFieldName();
            if (fldName == null || fldName.isEmpty())
                fldName = "_field_" + (anonIdx++);

            if (ft instanceof Array) {
                // Emit as "elemType fieldName[len];"
                Array arr  = (Array) ft;
                String elem = cTypeName(arr.getDataType());
                sb.append("    ").append(elem).append(" ")
                  .append(safeName(fldName))
                  .append("[").append(arr.getNumElements()).append("];\n");
            } else if (ft instanceof Pointer) {
                // Emit pointer with "*" attached to field name
                Pointer ptr  = (Pointer) ft;
                DataType base = ptr.getDataType();
                String baseName = (base != null) ? cTypeName(base) : "void";
                sb.append("    ").append(baseName).append(" *")
                  .append(safeName(fldName)).append(";\n");
            } else {
                sb.append("    ").append(cTypeName(ft))
                  .append(" ").append(safeName(fldName)).append(";\n");
            }
        }
        sb.append("} ").append(name).append(";");
        return sb.toString();
    }

    private String emitStruct(Structure s, String keyword) {
        return emitStruct(s.getDefinedComponents(), keyword, safeName(s.getName()));
    }

    private String emitStruct(Union u, String keyword) {
        return emitStruct(u.getComponents(), keyword, safeName(u.getName()));
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
        CategoryPath cp = dt.getCategoryPath();
        if (cp == null) return true;
        String path = cp.getPath();
        // Ghidra built-in types live under /BuiltIn, at the root /,
        // or under /ghidra_core (primitive aliases).  DWARF-recovered types
        // from the user's binary live under paths like "/my_file.c" — keep them.
        return path.equals("/") || path.startsWith("/BuiltIn") ||
               path.startsWith("/ghidra_core");
    }

    private boolean isPeripheral(Address addr) {
        long off = addr.getOffset();
        return off >= PERIPH_BASE && off < PERIPH_END;
    }
}
