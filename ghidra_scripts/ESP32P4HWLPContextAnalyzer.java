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

// Injects CONDITIONAL_JUMP flow references at hardware-loop tail instructions
// based on loop0_active/loop0_end/loop0_start SLEIGH context variables.
// Run AFTER auto-analysis completes to fix CFG back-edges for esp.lp.setup loops.
//
// Background
// ----------
// The ESP32-P4 RISC-V core has two hardware loop channels (HWLP0, HWLP1).
// The `esp.lp.setup` / `esp.lp.setupi` instructions arm a channel by writing:
//   - HWLP{n}_START  — first instruction of the loop body
//   - HWLP{n}_END    — first instruction AFTER the loop body (lp_end)
//   - HWLP{n}_COUNT  — number of iterations
//
// The SLEIGH spec propagates per-channel state into the context register via
// globalset() calls so that downstream instructions carry:
//   loop0_active  (bit 6)          — channel 0 is armed
//   loop0_start   (bits 7..38)     — loop body start PC
//   loop0_end     (bits 39..70)    — last instruction address (lp_end - 4 in RV32C terms,
//                                    or lp_end itself — exact semantics depends on the spec)
//   loop1_active  (bit 71)         — channel 1 is armed
//   loop1_start   (bits 72..103)   — loop body start PC (channel 1)
//   loop1_end     (bits 104..135)  — last instruction address (channel 1)
//
// When Ghidra processes the last instruction of a loop body its context register
// has loop{n}_active=1 and loop{n}_end == that instruction's address.
//
// What this script does
// ---------------------
// 1. Iterates all instructions in the program.
// 2. For each instruction reads the SLEIGH context fields loop0_active / loop1_active.
// 3. If a channel is active AND the instruction address matches loop{n}_end:
//    a. Reads loop{n}_start from the context.
//    b. Adds a CONDITIONAL_JUMP memory reference from the tail instruction to start.
//    c. Updates (or appends to) the POST comment on the tail instruction.
//    d. Ensures a label "HWLP{n}_BODY_<hex>" exists at the start address.
//
// The CONDITIONAL_JUMP reference is what Ghidra's CFG builder and the decompiler
// need to recognise the back-edge and reconstruct a for/do-while cycle instead of
// a sequence of GOTOs.  The existing ESP32P4Analyzer adds the same reference when
// it finds esp.lp.setup, but only when the lp_end address is statically visible in
// the setup instruction's pcode.  This script is the complementary second pass: it
// works from the context register (which is reliable even for indirect / register-
// based lp_end values) and runs after auto-analysis so the context is fully
// propagated.
//
// Usage
// -----
//   Ghidra Script Manager → Run Script → ESP32P4HWLPContextAnalyzer.java
//   (or: headless analyzeHeadless ... -postScript ESP32P4HWLPContextAnalyzer.java)
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Fix Hardware Loop CFG Back-edges

import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;

public class ESP32P4HWLPContextAnalyzer extends GhidraScript {

    // -------------------------------------------------------------------------
    // Script entry point
    // -------------------------------------------------------------------------

    @Override
    public void run() throws Exception {

        if (currentProgram == null) {
            printerr("ESP32P4HWLPContextAnalyzer: no program open.");
            return;
        }

        println("ESP32P4HWLPContextAnalyzer: starting hardware-loop CFG back-edge injection.");

        // Look up the SLEIGH context registers for both channels.
        // Names must match exactly what is declared in the SLEIGH .reg.sinc file.
        Register[] activeRegs = {
            lookupCtxReg("loop0_active"),
            lookupCtxReg("loop1_active"),
        };
        Register[] startRegs = {
            lookupCtxReg("loop0_start"),
            lookupCtxReg("loop1_start"),
        };
        Register[] endRegs = {
            lookupCtxReg("loop0_end"),
            lookupCtxReg("loop1_end"),
        };

        // Report which registers were resolved; abort if none found so the user
        // gets a clear error rather than a silent no-op.
        boolean anyFound = false;
        for (int ch = 0; ch < 2; ch++) {
            if (activeRegs[ch] != null && startRegs[ch] != null && endRegs[ch] != null) {
                println("  channel " + ch + ": registers resolved ("
                        + activeRegs[ch].getName() + ", "
                        + startRegs[ch].getName() + ", "
                        + endRegs[ch].getName() + ")");
                anyFound = true;
            } else {
                println("  channel " + ch + ": one or more context registers NOT FOUND — "
                        + "skipping channel " + ch + ". "
                        + "Check that loop" + ch + "_active/start/end are declared in the SLEIGH spec.");
            }
        }
        if (!anyFound) {
            printerr("ESP32P4HWLPContextAnalyzer: no SLEIGH context registers found. "
                    + "Has auto-analysis run with the ESP32-P4 language spec?");
            return;
        }

        ProgramContext     pctx    = currentProgram.getProgramContext();
        Listing            listing = currentProgram.getListing();
        ReferenceManager   refMgr  = currentProgram.getReferenceManager();
        SymbolTable        symTbl  = currentProgram.getSymbolTable();
        AddressSpace       defSpc  = currentProgram.getAddressFactory().getDefaultAddressSpace();

        int txId = currentProgram.startTransaction("ESP32P4 HWLP CFG back-edge injection");
        boolean success = false;
        int[] fixed = {0, 0};

        try {
            InstructionIterator it = listing.getInstructions(currentProgram.getMemory(), true);
            while (it.hasNext()) {
                monitor.checkCancelled();
                Instruction instr = it.next();
                if (instr == null) continue;

                Address addr = instr.getAddress();

                for (int ch = 0; ch < 2; ch++) {
                    if (activeRegs[ch] == null || startRegs[ch] == null || endRegs[ch] == null) {
                        continue;
                    }

                    // --- Is this channel active at this instruction? ---
                    RegisterValue rvActive = pctx.getRegisterValue(activeRegs[ch], addr);
                    if (rvActive == null) continue;
                    BigInteger activeVal = rvActive.getUnsignedValueIgnoreMask();
                    if (activeVal == null || activeVal.intValue() != 1) continue;

                    // --- Is this instruction the loop-tail? ---
                    RegisterValue rvEnd = pctx.getRegisterValue(endRegs[ch], addr);
                    if (rvEnd == null) continue;
                    BigInteger endVal = rvEnd.getUnsignedValueIgnoreMask();
                    if (endVal == null) continue;
                    long loopEndOffset = endVal.longValue();
                    if (addr.getOffset() != loopEndOffset) continue;

                    // --- Read loop-start address ---
                    RegisterValue rvStart = pctx.getRegisterValue(startRegs[ch], addr);
                    if (rvStart == null) continue;
                    BigInteger startVal = rvStart.getUnsignedValueIgnoreMask();
                    if (startVal == null) continue;
                    long loopStartOffset = startVal.longValue();

                    Address loopStartAddr;
                    try {
                        loopStartAddr = defSpc.getAddress(loopStartOffset);
                    } catch (Exception e) {
                        println("  WARN: channel " + ch + " loop_start=0x"
                                + Long.toHexString(loopStartOffset)
                                + " is not a valid address; skipping.");
                        continue;
                    }

                    // Sanity: start must precede tail.
                    if (loopStartOffset >= loopEndOffset) {
                        println("  WARN: channel " + ch
                                + " loop_start 0x" + Long.toHexString(loopStartOffset)
                                + " >= loop_end 0x" + Long.toHexString(loopEndOffset)
                                + " — skipping (degenerate / already-cleared context?).");
                        continue;
                    }

                    println("  HWLP" + ch
                            + ": tail @ 0x" + addr.toString()
                            + " -> start @ 0x" + loopStartAddr.toString());

                    // ---------------------------------------------------------
                    // 1. Ensure CONDITIONAL_JUMP reference exists (tail -> start)
                    // ---------------------------------------------------------
                    // Check whether a matching reference already exists to avoid
                    // duplicate entries in the reference table.
                    boolean refExists = false;
                    for (ghidra.program.model.symbol.Reference ref :
                            refMgr.getReferencesFrom(addr)) {
                        if (ref.getReferenceType() == RefType.CONDITIONAL_JUMP
                                && ref.getToAddress().equals(loopStartAddr)) {
                            refExists = true;
                            break;
                        }
                    }
                    if (!refExists) {
                        refMgr.addMemoryReference(
                            addr,
                            loopStartAddr,
                            RefType.CONDITIONAL_JUMP,
                            SourceType.ANALYSIS,
                            0 /* operand index */);
                    }

                    // ---------------------------------------------------------
                    // 2. Update POST comment on the tail instruction
                    // ---------------------------------------------------------
                    String tag = "[xesploop" + ch + "]";
                    String backEdgeComment = tag
                        + " HW loop back-edge -> 0x" + loopStartAddr.toString()
                        + " when HWLP" + ch + "_COUNT != 0"
                        + " (SLEIGH context injection via ESP32P4HWLPContextAnalyzer)";

                    String existing = instr.getComment(ghidra.program.model.listing.CommentType.POST);
                    if (existing == null || existing.isEmpty()) {
                        instr.setComment(ghidra.program.model.listing.CommentType.POST,
                                backEdgeComment);
                    } else if (!existing.contains(tag)) {
                        // Append rather than overwrite; the existing analyzer may have
                        // already added a comment from the setup-instruction side.
                        instr.setComment(ghidra.program.model.listing.CommentType.POST,
                                existing + "\n" + backEdgeComment);
                    }
                    // If `tag` is already present the comment is up-to-date; skip.

                    // ---------------------------------------------------------
                    // 3. Ensure a label exists at the loop body entry
                    // ---------------------------------------------------------
                    try {
                        String lblName = String.format("HWLP%d_BODY_%08x",
                                ch, loopStartOffset);
                        // Only create if no non-dynamic symbol exists there yet.
                        ghidra.program.model.symbol.Symbol sym =
                                symTbl.getPrimarySymbol(loopStartAddr);
                        if (sym == null || sym.isDynamic()) {
                            symTbl.createLabel(loopStartAddr, lblName, SourceType.ANALYSIS);
                        }
                    } catch (Exception e) {
                        // Label already exists with same name — harmless.
                    }

                    fixed[ch]++;
                }
            }

            success = true;
        } finally {
            currentProgram.endTransaction(txId, success);
        }

        println("ESP32P4HWLPContextAnalyzer: done."
                + " HWLP0=" + fixed[0] + " back-edge(s) injected,"
                + " HWLP1=" + fixed[1] + " back-edge(s) injected.");
        if (fixed[0] + fixed[1] == 0) {
            println("  (0 back-edges means the context registers held no active loop tails,"
                    + " or auto-analysis has not yet propagated the context values.)");
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Looks up a context register by name, returning null (with a warning) if
     * the register is not present in the current language.
     */
    private Register lookupCtxReg(String name) {
        Register reg = currentProgram.getLanguage().getRegister(name);
        if (reg == null) {
            println("  INFO: register '" + name + "' not found in language '"
                    + currentProgram.getLanguageID().getIdAsString() + "'.");
        }
        return reg;
    }
}
