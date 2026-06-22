// Recovers FreeRTOS task names, stack sizes, and priorities by backward
// data-flow slicing through P-code at xTaskCreate / xTaskCreatePinnedToCore call sites.
//
// For each call site found, resolves:
//   - pcName    (a1): string from .rodata
//   - ulStackDepth (a2): constant integer (stack words)
//   - uxPriority  (a4 for PinnedToCore): constant integer
//   - xCoreID     (a6 for PinnedToCore): 0, 1, or -1 (tskNO_AFFINITY)
//
// Output: table printed to console + plate comment added at each call site.
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Extract FreeRTOS Tasks

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import java.util.*;

public class ExtractFreeRTOSTasks extends GhidraScript {

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Find xTaskCreate and xTaskCreatePinnedToCore
        String[] targets = {"xTaskCreate", "xTaskCreatePinnedToCore"};

        println("=== ESP32-P4 FreeRTOS Task Recovery ===");
        println(String.format("%-30s %-12s %-8s %-8s", "Task Name", "Stack(words)", "Priority", "Core"));
        println("-".repeat(65));

        for (String funcName : targets) {
            boolean pinnedToCore = funcName.contains("PinnedToCore");

            // Look up by symbol name
            SymbolTable symTable = currentProgram.getSymbolTable();
            SymbolIterator syms = symTable.getSymbols(funcName);

            if (!syms.hasNext()) {
                println("  [" + funcName + " not found in symbol table]");
                continue;
            }

            Symbol sym = syms.next();
            Address targetAddr = sym.getAddress();

            // Iterate all call sites
            for (Reference ref : currentProgram.getReferenceManager()
                    .getReferencesTo(targetAddr)) {

                monitor.checkCancelled();
                Address callSite = ref.getFromAddress();
                Function caller = currentProgram.getListing()
                    .getFunctionContaining(callSite);
                if (caller == null) continue;

                // Decompile the calling function
                DecompileResults res = decomp.decompileFunction(caller, 60, monitor);
                HighFunction hf = res.getHighFunction();
                if (hf == null) continue;

                // Find the CALL PcodeOp at this address
                Iterator<PcodeOpAST> ops = hf.getPcodeOps(callSite);
                while (ops.hasNext()) {
                    PcodeOpAST op = ops.next();
                    if (op.getOpcode() != PcodeOp.CALL) continue;

                    // RISC-V: inputs are [target, a0, a1, a2, ...]
                    // xTaskCreate(pvTaskCode, pcName, ulStackDepth, pvParameters, uxPriority, pxCreatedTask)
                    // xTaskCreatePinnedToCore(pvTaskCode, pcName, ulStackDepth, pvParameters, uxPriority, pxCreatedTask, xCoreID)

                    String taskName = resolveStringParam(op, 2); // a1 = param index 2
                    long stackDepth = resolveConstParam(op, 3);   // a2 = param index 3
                    long priority   = resolveConstParam(op, 5);   // a4 = param index 5 (skip a3=pvParams)
                    long coreId     = pinnedToCore ? resolveConstParam(op, 7) : -2L; // a6

                    String coreStr = coreId == -2L ? "any" :
                                     coreId == -1L ? "any(tskNO_AFFINITY)" :
                                     String.valueOf(coreId);

                    println(String.format("%-30s %-12s %-8s %-8s  @ %s",
                        taskName, stackDepth < 0 ? "?" : String.valueOf(stackDepth),
                        priority < 0 ? "?" : String.valueOf(priority),
                        coreStr, callSite));

                    // Add plate comment at call site
                    String comment = String.format(
                        "[FreeRTOS Task] name=%s stack=%s words pri=%s core=%s",
                        taskName, stackDepth < 0 ? "?" : String.valueOf(stackDepth),
                        priority < 0 ? "?" : String.valueOf(priority), coreStr);
                    currentProgram.getListing().setComment(callSite,
                        ghidra.program.model.listing.CommentType.PLATE, comment);
                }
            }
        }

        decomp.closeProgram();
        println("\nDone. Call sites annotated with plate comments.");
    }

    private String resolveStringParam(PcodeOpAST callOp, int inputIndex) {
        if (callOp.getNumInputs() <= inputIndex) return "?";
        Varnode vn = callOp.getInput(inputIndex);
        if (vn == null) return "?";

        // Walk back through definitions to find a constant address
        vn = resolveVarnode(vn, 8);
        if (vn == null || !vn.isAddress()) return "?";

        // Read string from memory at that address
        try {
            Address addr = currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(vn.getOffset());
            Data d = currentProgram.getListing().getDataAt(addr);
            if (d != null && d.getValue() instanceof String) {
                return "\"" + d.getValue() + "\"";
            }
            // Try reading bytes directly
            byte[] buf = new byte[32];
            currentProgram.getMemory().getBytes(addr, buf);
            StringBuilder sb = new StringBuilder();
            for (byte b : buf) {
                if (b == 0) break;
                sb.append((char)(b & 0xFF));
            }
            return "\"" + sb + "\"";
        } catch (Exception e) {
            return "?";
        }
    }

    private long resolveConstParam(PcodeOpAST callOp, int inputIndex) {
        if (callOp.getNumInputs() <= inputIndex) return -1L;
        Varnode vn = callOp.getInput(inputIndex);
        if (vn == null) return -1L;
        vn = resolveVarnode(vn, 8);
        if (vn != null && vn.isConstant()) return vn.getOffset();
        return -1L;
    }

    private Varnode resolveVarnode(Varnode vn, int depth) {
        if (depth <= 0 || vn == null) return vn;
        if (vn.isConstant() || vn.isAddress()) return vn;
        PcodeOp def = vn.getDef();
        if (def == null) return vn;
        // COPY, CAST, PTRSUB — follow through
        if (def.getOpcode() == PcodeOp.COPY ||
            def.getOpcode() == PcodeOp.CAST ||
            def.getOpcode() == PcodeOp.INT_ZEXT ||
            def.getOpcode() == PcodeOp.INT_SEXT) {
            return resolveVarnode(def.getInput(0), depth - 1);
        }
        // PTRSUB / PTRADD for .rodata references
        if (def.getOpcode() == PcodeOp.PTRSUB ||
            def.getOpcode() == PcodeOp.PTRADD) {
            Varnode base = resolveVarnode(def.getInput(0), depth - 1);
            if (base != null && base.isAddress()) return base;
        }
        return vn;
    }
}
