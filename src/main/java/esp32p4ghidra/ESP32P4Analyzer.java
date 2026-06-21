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
package esp32p4ghidra;

import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Auto-analyzer for ESP32-P4 firmwares. Performs:
 * 1. Peripheral register block labeling (GPIO, UART, SPI, etc.)
 * 2. Memory region naming (IRAM, DRAM, SPM, Flash)
 * 3. ROM data section identification
 * 4. Hardware loop annotation
 * 5. PIE instruction flagging
 */
public class ESP32P4Analyzer extends AbstractAnalyzer {

    private static final String ANALYZER_NAME = "ESP32-P4 Firmware Analyzer";
    private static final String ANALYZER_DESC =
        "Labels ESP32-P4 peripheral registers, annotates memory regions, " +
        "and identifies hardware loop (xesploop) and PIE (xesppie) instructions.";

    private static final String OPT_LABEL_PERIPHERALS = "Label Peripheral Registers";
    private static final String OPT_LABEL_MEMORY      = "Label Memory Regions";
    private static final String OPT_ANNOTATE_HWLP     = "Annotate Hardware Loops";

    public ESP32P4Analyzer() {
        super(ANALYZER_NAME, ANALYZER_DESC, AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.FORMAT_ANALYSIS.after().after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return isESP32P4(program);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return isRiscV32(program);
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPT_LABEL_PERIPHERALS, true, null,
            "Create labeled memory blocks for ESP32-P4 peripheral registers");
        options.registerOption(OPT_LABEL_MEMORY, true, null,
            "Name IRAM, DRAM, Flash, SPM memory regions");
        options.registerOption(OPT_ANNOTATE_HWLP, true, null,
            "Add comments at hardware loop setup instructions (xesploop)");
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        boolean labelPeripherals = true;
        boolean labelMemory = true;
        boolean annotateHwlp = true;

        try {
            Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
            labelPeripherals = opts.getBoolean(ANALYZER_NAME + Options.DELIMITER + OPT_LABEL_PERIPHERALS, true);
            labelMemory = opts.getBoolean(ANALYZER_NAME + Options.DELIMITER + OPT_LABEL_MEMORY, true);
            annotateHwlp = opts.getBoolean(ANALYZER_NAME + Options.DELIMITER + OPT_ANNOTATE_HWLP, true);
        }
        catch (Exception e) {
            // Use defaults
        }

        int txId = program.startTransaction("ESP32-P4 Analysis");
        boolean success = false;
        try {
            if (labelMemory) {
                labelMemoryRegions(program, monitor, log);
            }
            if (labelPeripherals) {
                labelPeripheralBlocks(program, monitor, log);
            }
            if (annotateHwlp) {
                annotateHardwareLoops(program, set, monitor, log);
            }
            success = true;
        }
        catch (Exception e) {
            log.appendException(e);
            Msg.error(this, "ESP32-P4 analysis failed", e);
        }
        finally {
            program.endTransaction(txId, success);
        }

        return success;
    }

    // -------------------------------------------------------------------------
    // Memory region labeling
    // -------------------------------------------------------------------------

    private void labelMemoryRegions(Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        Memory mem = program.getMemory();
        AddressFactory af = program.getAddressFactory();
        AddressSpace space = af.getDefaultAddressSpace();

        // Name the memory blocks based on their address ranges
        for (MemoryBlock block : mem.getBlocks()) {
            monitor.checkCancelled();
            long start = block.getStart().getOffset();
            String suggestedName = suggestBlockName(start);
            if (suggestedName != null && !block.getName().equals(suggestedName)) {
                try {
                    block.setComment("ESP32-P4: " + suggestedName);
                }
                catch (Exception e) {
                    log.appendMsg("Could not set comment on block at 0x" + Long.toHexString(start));
                }
            }
        }
    }

    private String suggestBlockName(long addr) {
        if (addr >= 0x40000000L && addr < 0x42000000L) return "Flash_IROM";
        if (addr >= 0x42000000L && addr < 0x48000000L) return "Flash_DROM";
        if (addr >= 0x48000000L && addr < 0x4C000000L) return "PSRAM";
        if (addr >= 0x4FF00000L && addr < 0x4FFC0000L) return "IRAM";
        if (addr >= 0x30100000L && addr < 0x30102000L) return "SPM";
        if (addr >= 0x50108000L && addr < 0x50110000L) return "LP_RAM";
        if (addr >= 0x50000000L && addr < 0x60000000L) return "HP_PERIPH";
        if (addr >= 0x20000000L && addr < 0x20100000L) return "LP_PERIPH";
        return null;
    }

    // -------------------------------------------------------------------------
    // Peripheral labeling
    // -------------------------------------------------------------------------

    private void labelPeripheralBlocks(Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        Memory mem = program.getMemory();
        SymbolTable symTable = program.getSymbolTable();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Map<Long, String> periph = ESP32P4MemoryMap.getPeripheralMap();

        for (Map.Entry<Long, String> entry : periph.entrySet()) {
            monitor.checkCancelled();
            long addr = entry.getKey();
            String name = entry.getValue() + "_BASE";
            Address ghidraAddr;
            try {
                ghidraAddr = space.getAddress(addr);
            }
            catch (AddressOutOfBoundsException e) {
                continue;
            }

            // Create a memory block for the peripheral if it doesn't exist
            if (mem.getBlock(ghidraAddr) == null) {
                try {
                    MemoryBlock block = mem.createUninitializedBlock(
                        entry.getValue(), ghidraAddr, 0x1000, false);
                    block.setRead(true);
                    block.setWrite(true);
                    block.setExecute(false);
                    block.setVolatile(true);
                    block.setComment("ESP32-P4 peripheral: " + entry.getValue());
                }
                catch (Exception e) {
                    // Block may already exist or overlap; just add a symbol
                }
            }

            // Add a label at the peripheral base address
            try {
                Symbol existing = symTable.getPrimarySymbol(ghidraAddr);
                if (existing == null || existing.isDynamic()) {
                    symTable.createLabel(ghidraAddr, name, SourceType.ANALYSIS);
                }
            }
            catch (Exception e) {
                log.appendMsg("Could not label peripheral " + name);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Hardware loop annotation
    // -------------------------------------------------------------------------

    private void annotateHardwareLoops(Program program, AddressSetView set,
                                       TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        Listing listing = program.getListing();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

        InstructionIterator it = listing.getInstructions(set, true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Instruction instr = it.next();
            if (instr == null) continue;

            String mnem = instr.getMnemonicString();
            if (mnem != null && (mnem.startsWith("esp.lp.setup") || mnem.startsWith("esp.lp.setupi"))) {
                annotateLoopSetup(program, instr, log);
            }
        }
    }

    private void annotateLoopSetup(Program program, Instruction instr, MessageLog log) {
        try {
            // Loop body starts at the instruction immediately after esp.lp.setup
            Address loopStart = instr.getFallThrough();
            if (loopStart == null) return;

            // Loop ID encoded in rd field (op0711): 0 → loop0, 1 → loop1
            int loopId = 0;
            try {
                // rd=zero(0) → loop0, rd=ra(1) → loop1 per the Sleigh definition
                String rdStr = instr.getDefaultOperandRepresentation(0);
                if ("ra".equals(rdStr)) loopId = 1;
            } catch (Exception ignore) {}

            // Extract lp_end address from pcode: find COPY to HWLP_END virtual register
            Address loopEnd = extractLoopEndFromPcode(program, instr, loopId);

            // Annotate setup instruction
            String setupComment = (loopEnd != null)
                ? String.format("[xesploop%d] Hardware loop: body %s..%s, count=rs1",
                                loopId, loopStart, loopEnd)
                : String.format("[xesploop%d] Hardware loop setup (lp_end not resolved)", loopId);
            instr.setComment(CommentType.PLATE, setupComment);

            if (loopEnd == null) return;

            // Create a label at the loop body entry
            try {
                String lbl = String.format("HWLP%d_BODY_%s", loopId,
                        loopStart.toString().replaceFirst(".*:", ""));
                program.getSymbolTable().createLabel(loopStart, lbl, SourceType.ANALYSIS);
            } catch (Exception ignore) {}

            // Add a back-edge reference loopEnd → loopStart so the CFG shows the cycle.
            // CONDITIONAL_JUMP: the loop either falls through (count exhausted) or jumps back.
            program.getReferenceManager().addMemoryReference(
                loopEnd, loopStart, RefType.CONDITIONAL_JUMP, SourceType.ANALYSIS, 0);

            // Annotate the loop-end instruction
            Instruction lpEndInstr = program.getListing().getInstructionAt(loopEnd);
            if (lpEndInstr != null) {
                String backEdge = String.format(
                    "[xesploop%d] Hardware loop back-edge → %s (decrement count; jump if count≠0)",
                    loopId, loopStart);
                lpEndInstr.setComment(CommentType.POST, backEdge);
            }
        } catch (Exception e) {
            log.appendMsg("Could not annotate loop at " + instr.getAddress() + ": " + e.getMessage());
        }
    }

    private Address extractLoopEndFromPcode(Program program, Instruction instr, int loopId) {
        // HWLP0_END virtual register is at 0x5008, HWLP1_END at 0x5014.
        // The Sleigh constructor writes: HWLP_END = lp_end (COPY pcodeop).
        // We scan the instruction's pcode to find that COPY's input constant.
        long hwlpEndOffset = (loopId == 0) ? 0x5008L : 0x5014L;
        try {
            AddressSpace regSpace =
                program.getLanguage().getAddressFactory().getRegisterSpace();
            for (PcodeOp op : instr.getPcode()) {
                if (op.getOpcode() != PcodeOp.COPY) continue;
                Varnode out = op.getOutput();
                if (out == null) continue;
                if (!out.getAddress().getAddressSpace().equals(regSpace)) continue;
                if (out.getOffset() != hwlpEndOffset) continue;
                Varnode in0 = op.getInput(0);
                if (in0 == null || !in0.isConstant()) continue;
                return program.getAddressFactory().getDefaultAddressSpace()
                              .getAddress(in0.getOffset());
            }
        } catch (Exception ignore) {}

        // Fallback: parse operand 2 display string (lp_end is the 3rd operand)
        try {
            String opStr = instr.getDefaultOperandRepresentation(2);
            if (opStr != null) {
                opStr = opStr.trim().replaceFirst("^0[xX]", "");
                long addr = Long.parseUnsignedLong(opStr, 16);
                return program.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
            }
        } catch (Exception ignore) {}

        return null;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private boolean isRiscV32(Program program) {
        Language lang = program.getLanguage();
        if (lang == null) return false;
        LanguageDescription desc = lang.getLanguageDescription();
        return desc.getProcessor().toString().equalsIgnoreCase("RISCV") &&
               desc.getSize() == 32;
    }

    private boolean isESP32P4(Program program) {
        if (!isRiscV32(program)) return false;
        // Check if the program has ESP32-P4 characteristic memory sections
        Memory mem = program.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            long start = block.getStart().getOffset();
            // IRAM at 0x4FF00000 is characteristic of ESP32-P4
            if (start >= 0x4FF00000L && start < 0x50000000L) return true;
            // SPM at 0x30100000 is ESP32-P4 specific
            if (start >= 0x30100000L && start < 0x30200000L) return true;
        }
        return false;
    }
}
