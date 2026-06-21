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

// Research / prototype script: prints the ClangAST token tree for the
// function at the cursor (GUI mode) or for a named function (headless).
//
// Purpose: understand the ClangAST structure produced by Ghidra's
// DecompInterface so that future passes (Fix 4 — smarter bare-return
// detection, switch-table reconstruction, etc.) can walk the AST
// instead of using fragile regex on the printed C text.
//
// Output written to <program>_<funcname>_ast.txt (or to the path given
// as the first script argument).
//
// Key findings this script helps establish:
//  - Which ClangNode subclass represents a "return" statement
//  - Which ClangVariableToken holds the return value expression
//  - How parameters are represented vs local variables
//  - Where bare "return;" nodes differ from "return expr;" nodes
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Inspect ClangAST

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;

import java.util.Iterator;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

import java.io.*;

public class InspectClangAST extends GhidraScript {

    private static final int DECOMPILE_TIMEOUT_SECS = 30;

    @Override
    public void run() throws Exception {
        // ── resolve target function ───────────────────────────────────────────
        Function fn = null;
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            // headless: first arg = function name
            fn = findFunctionByName(args[0]);
            if (fn == null) {
                printerr("Function not found: " + args[0]);
                return;
            }
        } else {
            // GUI: use function at cursor
            Address cur = currentLocation != null ? currentLocation.getAddress() : null;
            fn = cur != null
                    ? currentProgram.getListing().getFunctionContaining(cur)
                    : null;
            if (fn == null) {
                fn = askChoice("InspectClangAST", "Select a function",
                        toList(currentProgram.getListing().getFunctions(true)), null);
            }
            if (fn == null) { println("No function selected."); return; }
        }

        // ── resolve output file ───────────────────────────────────────────────
        File outFile;
        if (args != null && args.length > 1 && !args[1].isEmpty()) {
            outFile = new File(args[1]);
        } else {
            String safeName = fn.getName().replaceAll("[^\\w.-]", "_");
            outFile = new File(System.getProperty("user.home"),
                    currentProgram.getName() + "_" + safeName + "_ast.txt");
        }

        // ── decompile ─────────────────────────────────────────────────────────
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        decompiler.setOptions(opts);
        decompiler.toggleSyntaxTree(true);
        decompiler.toggleCCode(true);
        if (!decompiler.openProgram(currentProgram)) {
            printerr("Decompiler failed: " + decompiler.getLastMessage());
            return;
        }

        DecompileResults res;
        try {
            res = decompiler.decompileFunction(fn, DECOMPILE_TIMEOUT_SECS, monitor);
        } finally {
            decompiler.dispose();
        }

        if (res == null || !res.decompileCompleted()) {
            printerr("Decompile failed for " + fn.getName());
            return;
        }

        // ── walk and print ClangAST ───────────────────────────────────────────
        ClangTokenGroup markup = res.getCCodeMarkup();
        int[] nodeCount    = {0};
        int[] returnCount  = {0};
        int[] bareReturns  = {0};

        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
            pw.println("=== ClangAST for " + fn.getName()
                    + " @ " + fn.getEntryPoint() + " ===");
            pw.println("Program : " + currentProgram.getName());
            pw.println("Language: " + currentProgram.getLanguageID());
            pw.println();

            walkNode(markup, 0, pw, nodeCount, returnCount, bareReturns);

            pw.println();
            pw.println("=== Summary ===");
            pw.println("Total nodes   : " + nodeCount[0]);
            pw.println("Return stmts  : " + returnCount[0]);
            pw.println("Bare returns  : " + bareReturns[0]
                    + " (return; with no value)");
            pw.println();
            pw.println("=== Decompiled C ===");
            DecompiledFunction df = res.getDecompiledFunction();
            if (df != null) pw.println(df.getC());
        }

        println("AST written to: " + outFile.getAbsolutePath());
        println("  Nodes: " + nodeCount[0] + " | Returns: " + returnCount[0]
                + " | Bare: " + bareReturns[0]);
    }

    // ── recursive AST walker ─────────────────────────────────────────────────

    private void walkNode(ClangNode node, int depth,
                          PrintWriter pw,
                          int[] nodeCount, int[] returnCount, int[] bareReturns) {
        if (node == null) return;
        nodeCount[0]++;

        String indent    = "  ".repeat(depth);
        String className = node.getClass().getSimpleName();

        // Truncate long text for readability.
        String text = node.toString();
        if (text.length() > 80) text = text.substring(0, 77) + "...";
        text = text.replace("\n", "\\n").replace("\r", "");

        // Annotate return statements.
        if (node instanceof ClangStatement) {
            ClangStatement stmt = (ClangStatement) node;
            // A return statement: ClangStatement whose first token text is "return"
            if (stmt.numChildren() > 0) {
                ClangNode first = stmt.Child(0);
                if ("return".equals(first.toString().trim())) {
                    returnCount[0]++;
                    boolean bare = (stmt.numChildren() <= 2); // "return" + ";" only
                    if (bare) bareReturns[0]++;
                    pw.println(indent + "★ " + className
                            + (bare ? " [BARE RETURN]" : " [RETURN " + text.trim() + "]"));
                    // Recurse into children.
                    for (int i = 0; i < node.numChildren(); i++)
                        walkNode(node.Child(i), depth + 1, pw, nodeCount, returnCount, bareReturns);
                    return;
                }
            }
        }

        // Annotate variable tokens (useful for return-value identification).
        String extra = "";
        if (node instanceof ClangVariableToken) {
            ClangVariableToken vt = (ClangVariableToken) node;
            extra = " [VAR: " + vt.toString() + "]";
        } else if (node instanceof ClangFuncNameToken) {
            extra = " [FUNC_NAME]";
        } else if (node instanceof ClangTypeToken) {
            extra = " [TYPE]";
        }

        pw.println(indent + className + extra + ": \"" + text + "\"");

        // Recurse.
        for (int i = 0; i < node.numChildren(); i++)
            walkNode(node.Child(i), depth + 1, pw, nodeCount, returnCount, bareReturns);
    }

    // ── utilities ─────────────────────────────────────────────────────────────

    private Function findFunctionByName(String name) {
        for (Function fn : currentProgram.getListing().getFunctions(true)) {
            if (name.equals(fn.getName())) return fn;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private <T> java.util.List<T> toList(Iterator<T> it) {
        java.util.List<T> list = new java.util.ArrayList<>();
        while (it.hasNext()) list.add(it.next());
        return list;
    }
}
