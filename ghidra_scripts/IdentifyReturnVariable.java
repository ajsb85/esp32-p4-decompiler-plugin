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

// Identifies the return variable for the current function by walking the ClangAST
// and locating RETURN PcodeOp nodes. Useful for verifying Fix 3 bare-return assignments
// and as a prototype for AST-driven ExportDecompiledC improvements.
//
// Output: prints the identified return Varnode + its definition chain.
// Also adds an EOL comment on the return statement with the resolved variable name.
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Identify Return Variable (ClangAST)

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.CommentType;

public class IdentifyReturnVariable extends GhidraScript {

    @Override
    public void run() throws Exception {
        Function func = getFunctionContaining(currentAddress);
        if (func == null) {
            printerr("Place cursor inside a function and run again.");
            return;
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        DecompileResults res = decomp.decompileFunction(func, 60, monitor);
        if (!res.decompileCompleted()) {
            printerr("Decompilation failed: " + res.getErrorMessage());
            return;
        }

        // Walk the ClangAST to find all RETURN statements
        ClangTokenGroup ast = res.getCCodeMarkup();
        HighFunction hf = res.getHighFunction();

        println("=== Return Variable Analysis: " + func.getName() + " ===");
        println("Declared return type: " + func.getReturnType().getDisplayName());
        println();

        walkAst(ast, hf, 0);

        decomp.closeProgram();
    }

    private void walkAst(ClangNode node, HighFunction hf, int depth) throws Exception {
        monitor.checkCancelled();

        if (node instanceof ClangStatement) {
            ClangStatement stmt = (ClangStatement) node;
            PcodeOp op = stmt.getPcodeOp();

            if (op != null && op.getOpcode() == PcodeOp.RETURN) {
                println("[RETURN stmt] at " + stmt.getMinAddress());

                // getInput(0) = return address (always); getInput(1) = return value
                if (op.getNumInputs() > 1) {
                    Varnode returnVal = op.getInput(1);
                    println("  Return varnode: " + returnVal.toString());
                    println("  Size: " + returnVal.getSize() + " bytes → " +
                            (returnVal.getSize() == 4 ? "a0 (int/ptr)" :
                             returnVal.getSize() == 0 ? "void" : "fa0 (float)"));

                    // Backward slice
                    println("  Definition chain:");
                    sliceBackward(returnVal, 6, "    ");

                    // Resolve high variable name
                    if (returnVal instanceof VarnodeAST) {
                        HighVariable hv = ((VarnodeAST) returnVal).getHigh();
                        if (hv != null) {
                            String varName = hv.getName();
                            println("  High variable name: " + varName);

                            // Add EOL comment at the return address
                            Address retAddr = stmt.getMinAddress();
                            if (retAddr != null) {
                                currentProgram.getListing().setComment(retAddr,
                                    CommentType.EOL,
                                    "returns: " + varName + " → a0");
                            }
                        }
                    }
                } else {
                    println("  Void return (no value)");
                }
                println();
            }
        }

        // Recurse into children — ClangStatement extends ClangTokenGroup, so
        // we use numChildren()/Child() which are defined on ClangNode itself.
        for (int i = 0; i < node.numChildren(); i++) {
            walkAst(node.Child(i), hf, depth + 1);
        }
    }

    private void sliceBackward(Varnode vn, int maxDepth, String indent) {
        if (maxDepth <= 0 || vn == null) return;
        if (vn.isConstant()) {
            println(indent + "CONST: 0x" + Long.toHexString(vn.getOffset()));
            return;
        }
        if (vn.isAddress()) {
            println(indent + "GLOBAL_ADDR: " + vn.getAddress());
            return;
        }

        PcodeOp def = vn.getDef();
        if (def == null) {
            println(indent + "INPUT (no def): " + vn.toString());
            return;
        }

        println(indent + PcodeOp.getMnemonic(def.getOpcode()) + " → " + vn.toString());

        // Follow inputs for common passthrough operations
        switch (def.getOpcode()) {
            case PcodeOp.COPY:
            case PcodeOp.CAST:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_SEXT:
                sliceBackward(def.getInput(0), maxDepth - 1, indent + "  ");
                break;
            case PcodeOp.PTRSUB:
            case PcodeOp.PTRADD:
                sliceBackward(def.getInput(0), maxDepth - 1, indent + "  base:");
                sliceBackward(def.getInput(1), maxDepth - 1, indent + "  offset:");
                break;
            case PcodeOp.LOAD:
                println(indent + "  from memory[" + def.getInput(1).toString() + "]");
                sliceBackward(def.getInput(1), maxDepth - 1, indent + "    addr:");
                break;
            default:
                // Stop at arithmetic, PHI, MULTIEQUAL, etc.
                break;
        }
    }
}
