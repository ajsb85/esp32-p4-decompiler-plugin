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
 */

// Sprint 26 — Fixed-point iterative FreeRTOS handle type promotion.
//
// Rounds run until convergence (no new promotions found), capped at MAX_ROUNDS.
//
// Round 1 (seed): decompiles every function that calls a known FreeRTOS API
//   (API_TABLE), traces the relevant argument/return Varnode to the backing
//   HighSymbol, records (HighSymbol, DataType) candidates, then commits.
//
// Rounds 2-N (propagation): after each commit, any promoted HighParam (formal
//   parameter) creates a new dynamic table entry for the callee function.
//   Similarly, if a promoted return-value Varnode flows directly into a RETURN
//   op, the callee itself is seeded as a return-value propagation source.
//   The next round decompiles callers of those callees and promotes their
//   variables one hop further up the call graph.
//
// This handles wrapper functions:
//   void delete_my_task(TaskHandle_t h) { vTaskDelete(h); }
//   // Round 1: h in delete_my_task → TaskHandle_t
//   // Round 2: callers of delete_my_task → their arg[0] → TaskHandle_t
//
// And factory wrappers:
//   TaskHandle_t create_sensor_task() { return xTaskCreate(...); }
//   // Round 1: local in create_sensor_task ← xTaskCreate return → TaskHandle_t
//   //          Varnode flows into RETURN → add return-propagation for create_sensor_task
//   // Round 2: callers of create_sensor_task → their lvalue → TaskHandle_t
//
// After all rounds, ExportDecompiledC.java re-decompiles from scratch and
// inherits the richer types, producing "tcb->uxPriority = 5;" instead of
// "*(uint *)(local_c + 0xc) = 5;".
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Apply Type Promotion

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import java.util.*;

public class ApplyTypePromotion extends GhidraScript {

    private static final int MAX_ROUNDS = 8;

    // API call-site seed table.
    // Columns: { functionName, argIdx, typeName }
    //   argIdx == "-1"  → promote the RETURN value (CALL output Varnode)
    //   argIdx >= "0"   → promote the logical argument at that 0-based index
    //                     (maps to CALL pcode input[argIdx+1]; input[0] = call target)
    //
    // Dynamic entries added during propagation use the prefix "addr:" followed
    // by the entry-point offset in hex, e.g. "addr:400A1234", so they can be
    // looked up by address even if the function has no stable export name.
    private static final String[][] API_TABLE = {
        // ── TaskHandle_t — return-value promotions ──
        {"xTaskGetCurrentTaskHandle",     "-1", "TaskHandle_t"},
        {"xTaskGetHandle",                "-1", "TaskHandle_t"},
        // ── TaskHandle_t — first-argument promotions ──
        {"vTaskDelete",                    "0", "TaskHandle_t"},
        {"vTaskPrioritySet",               "0", "TaskHandle_t"},
        {"uxTaskPriorityGet",              "0", "TaskHandle_t"},
        {"uxTaskPriorityGetFromISR",       "0", "TaskHandle_t"},
        {"vTaskSuspend",                   "0", "TaskHandle_t"},
        {"vTaskResume",                    "0", "TaskHandle_t"},
        {"xTaskResumeFromISR",             "0", "TaskHandle_t"},
        {"xTaskAbortDelay",                "0", "TaskHandle_t"},
        {"xTaskNotify",                    "0", "TaskHandle_t"},
        {"xTaskNotifyGive",                "0", "TaskHandle_t"},
        {"xTaskNotifyWait",                "0", "TaskHandle_t"},
        {"xTaskNotifyStateClear",          "0", "TaskHandle_t"},
        {"eTaskGetState",                  "0", "TaskHandle_t"},
        {"pcTaskGetName",                  "0", "TaskHandle_t"},
        // ── QueueHandle_t — return-value promotions ──
        {"xQueueCreate",                  "-1", "QueueHandle_t"},
        {"xQueueCreateStatic",            "-1", "QueueHandle_t"},
        {"xQueueGenericCreate",           "-1", "QueueHandle_t"},
        // ── QueueHandle_t — first-argument promotions ──
        {"xQueueSend",                     "0", "QueueHandle_t"},
        {"xQueueSendToBack",               "0", "QueueHandle_t"},
        {"xQueueSendToFront",              "0", "QueueHandle_t"},
        {"xQueueSendFromISR",              "0", "QueueHandle_t"},
        {"xQueueSendToBackFromISR",        "0", "QueueHandle_t"},
        {"xQueueSendToFrontFromISR",       "0", "QueueHandle_t"},
        {"xQueueReceive",                  "0", "QueueHandle_t"},
        {"xQueueReceiveFromISR",           "0", "QueueHandle_t"},
        {"xQueuePeek",                     "0", "QueueHandle_t"},
        {"xQueuePeekFromISR",              "0", "QueueHandle_t"},
        {"xQueueReset",                    "0", "QueueHandle_t"},
        {"xQueueOverwrite",                "0", "QueueHandle_t"},
        {"xQueueOverwriteFromISR",         "0", "QueueHandle_t"},
        {"uxQueueMessagesWaiting",         "0", "QueueHandle_t"},
        {"uxQueueMessagesWaitingFromISR",  "0", "QueueHandle_t"},
        {"uxQueueSpacesAvailable",         "0", "QueueHandle_t"},
        {"xQueueGenericSend",              "0", "QueueHandle_t"},
        {"xQueueGenericReceive",           "0", "QueueHandle_t"},
        // ── SemaphoreHandle_t — return-value promotions ──
        {"xSemaphoreCreateBinary",        "-1", "SemaphoreHandle_t"},
        {"xSemaphoreCreateCounting",      "-1", "SemaphoreHandle_t"},
        {"xSemaphoreCreateMutex",         "-1", "SemaphoreHandle_t"},
        {"xSemaphoreCreateRecursiveMutex","-1", "SemaphoreHandle_t"},
        // ── SemaphoreHandle_t — first-argument promotions ──
        {"xSemaphoreTake",                 "0", "SemaphoreHandle_t"},
        {"xSemaphoreTakeRecursive",        "0", "SemaphoreHandle_t"},
        {"xSemaphoreTakeFromISR",          "0", "SemaphoreHandle_t"},
        {"xSemaphoreGive",                 "0", "SemaphoreHandle_t"},
        {"xSemaphoreGiveRecursive",        "0", "SemaphoreHandle_t"},
        {"xSemaphoreGiveFromISR",          "0", "SemaphoreHandle_t"},
        {"xSemaphoreGetMutexHolder",       "0", "SemaphoreHandle_t"},
        // ── TimerHandle_t — return-value promotions ──
        {"xTimerCreate",                  "-1", "TimerHandle_t"},
        {"xTimerCreateStatic",            "-1", "TimerHandle_t"},
        // ── TimerHandle_t — first-argument promotions ──
        {"xTimerStart",                    "0", "TimerHandle_t"},
        {"xTimerStop",                     "0", "TimerHandle_t"},
        {"xTimerDelete",                   "0", "TimerHandle_t"},
        {"xTimerReset",                    "0", "TimerHandle_t"},
        {"xTimerChangePeriod",             "0", "TimerHandle_t"},
        {"pvTimerGetTimerID",              "0", "TimerHandle_t"},
        {"vTimerSetTimerID",               "0", "TimerHandle_t"},
        {"xTimerIsTimerActive",            "0", "TimerHandle_t"},
        {"pcTimerGetName",                 "0", "TimerHandle_t"},
        // ── EventGroupHandle_t — return-value promotions ──
        {"xEventGroupCreate",             "-1", "EventGroupHandle_t"},
        {"xEventGroupCreateStatic",       "-1", "EventGroupHandle_t"},
        // ── EventGroupHandle_t — first-argument promotions ──
        {"xEventGroupSetBits",             "0", "EventGroupHandle_t"},
        {"xEventGroupClearBits",           "0", "EventGroupHandle_t"},
        {"xEventGroupWaitBits",            "0", "EventGroupHandle_t"},
        {"xEventGroupGetBits",             "0", "EventGroupHandle_t"},
        {"xEventGroupGetBitsFromISR",      "0", "EventGroupHandle_t"},
        {"xEventGroupSetBitsFromISR",      "0", "EventGroupHandle_t"},
        {"xEventGroupSync",                "0", "EventGroupHandle_t"},
        {"vEventGroupDelete",              "0", "EventGroupHandle_t"},
        // ── StreamBufferHandle_t / MessageBufferHandle_t ──
        {"xStreamBufferCreate",           "-1", "StreamBufferHandle_t"},
        {"xStreamBufferSend",              "0", "StreamBufferHandle_t"},
        {"xStreamBufferReceive",           "0", "StreamBufferHandle_t"},
        {"xMessageBufferCreate",          "-1", "MessageBufferHandle_t"},
        {"xMessageBufferSend",             "0", "MessageBufferHandle_t"},
        {"xMessageBufferReceive",          "0", "MessageBufferHandle_t"},
    };

    @Override
    public void run() throws Exception {

        // ── Phase 0: resolve target types from DataTypeManager ────────────────
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Map<String, DataType> typeCache = new HashMap<>();
        Set<String> needed = new LinkedHashSet<>(Arrays.asList(
            "TaskHandle_t", "QueueHandle_t", "SemaphoreHandle_t",
            "TimerHandle_t", "EventGroupHandle_t",
            "StreamBufferHandle_t", "MessageBufferHandle_t"
        ));
        for (String tname : needed) {
            List<DataType> found = new ArrayList<>();
            dtm.findDataTypes(tname, found);
            if (!found.isEmpty()) {
                typeCache.put(tname, found.get(0));
            } else {
                println("[warn] type not in DTM: " + tname
                    + " — LoadFreeRTOSTypes.java must run before this script");
            }
        }
        if (typeCache.isEmpty()) {
            printerr("No FreeRTOS types found in DataTypeManager — aborting.");
            return;
        }
        println("Types resolved: " + typeCache.keySet());

        // ── Fixed-point loop ──────────────────────────────────────────────────
        //
        // dynamicTable: starts as API_TABLE, grows each round with propagation
        //   entries discovered from promoted HighParam / return-flowing Varnodes.
        //
        // seenKeys:  (callerAddr:varName:typeName) — persists across rounds so
        //   we never re-decompile a function just to skip its already-committed
        //   variables.  shouldSkip() is still checked per-candidate for safety.
        //
        // extKeys:   prevents adding the same propagation edge twice across rounds.
        List<String[]> dynamicTable = new ArrayList<>(Arrays.asList(API_TABLE));
        Set<String>    seenKeys     = new HashSet<>();
        Set<String>    extKeys      = new HashSet<>();
        int totalCommitted = 0, totalSkipped = 0, round = 0;

        DecompInterface decomp = new DecompInterface();
        decomp.setOptions(new DecompileOptions());
        decomp.toggleSyntaxTree(true);
        decomp.openProgram(currentProgram);

        SymbolTable     symTable = currentProgram.getSymbolTable();
        ReferenceManager refMgr  = currentProgram.getReferenceManager();
        AddressSpace    space    = currentProgram.getAddressFactory().getDefaultAddressSpace();

        try {
            while (round++ < MAX_ROUNDS) {

                // ── Discovery ────────────────────────────────────────────────
                Map<Function, List<Promotion>> pendingByFn = new LinkedHashMap<>();
                List<String[]> nextRows = new ArrayList<>();
                int discovered = 0;

                for (String[] row : dynamicTable) {
                    String   apiName  = row[0];
                    int      argIdx   = Integer.parseInt(row[1]);
                    String   typeName = row[2];
                    DataType newType  = typeCache.get(typeName);
                    if (newType == null) continue;

                    // Resolve the callee address.
                    Address apiAddr;
                    if (apiName.startsWith("addr:")) {
                        try {
                            apiAddr = space.getAddress(
                                Long.parseUnsignedLong(apiName.substring(5), 16));
                        } catch (NumberFormatException e) { continue; }
                    } else {
                        SymbolIterator syms = symTable.getSymbols(apiName);
                        if (!syms.hasNext()) continue;
                        apiAddr = syms.next().getAddress();
                    }

                    for (Reference ref : refMgr.getReferencesTo(apiAddr)) {
                        monitor.checkCancelled();
                        Address  callSite = ref.getFromAddress();
                        Function caller   = currentProgram.getListing()
                                                .getFunctionContaining(callSite);
                        if (caller == null) continue;

                        DecompileResults res = decomp.decompileFunction(caller, 30, monitor);
                        if (res == null || !res.decompileCompleted()) continue;
                        HighFunction hf = res.getHighFunction();
                        if (hf == null) continue;

                        Iterator<PcodeOpAST> ops = hf.getPcodeOps(callSite);
                        while (ops.hasNext()) {
                            PcodeOpAST op = ops.next();
                            if (op.getOpcode() != PcodeOp.CALL
                                    && op.getOpcode() != PcodeOp.CALLIND) continue;

                            Varnode targetVn;
                            if (argIdx < 0) {
                                targetVn = op.getOutput();
                            } else {
                                int inputIdx = argIdx + 1;
                                if (op.getNumInputs() <= inputIdx) continue;
                                targetVn = walkBack(op.getInput(inputIdx), 6);
                            }
                            if (targetVn == null) continue;

                            HighVariable hv = targetVn.getHigh();
                            if (hv == null) continue;
                            HighSymbol hvSym = hv.getSymbol();
                            if (hvSym == null) continue;
                            if (shouldSkip(hvSym.getDataType(), newType)) continue;

                            String dedupeKey = caller.getEntryPoint().toString()
                                + ":" + hvSym.getName() + ":" + typeName;
                            if (!seenKeys.add(dedupeKey)) continue;

                            boolean isParam = (hv instanceof HighParam);
                            pendingByFn.computeIfAbsent(caller, k -> new ArrayList<>())
                                .add(new Promotion(hvSym, newType, apiName, argIdx, isParam));
                            discovered++;

                            // ── Propagation edge: promoted parameter ──────────
                            // If the promoted variable is a formal parameter of
                            // `caller`, then callers of `caller` who pass a value
                            // at that parameter slot can be promoted in the next round.
                            if (isParam) {
                                int slot = ((HighParam) hv).getSlot();
                                String extKey = "param:"
                                    + caller.getEntryPoint().getOffset()
                                    + ":" + slot + ":" + typeName;
                                if (extKeys.add(extKey)) {
                                    nextRows.add(new String[]{
                                        "addr:" + Long.toHexString(
                                            caller.getEntryPoint().getOffset()),
                                        String.valueOf(slot),
                                        typeName
                                    });
                                }
                            }

                            // ── Propagation edge: return-flowing Varnode ──────
                            // If the promoted Varnode (e.g. the result of xQueueCreate)
                            // flows directly into a RETURN pcode op, `caller` itself
                            // acts as a factory and its callers should get the return
                            // value promoted.
                            if (argIdx < 0 && targetVn != null) {
                                Iterator<PcodeOp> uses = targetVn.getDescendants();
                                while (uses.hasNext()) {
                                    PcodeOp use = uses.next();
                                    if (use.getOpcode() == PcodeOp.RETURN) {
                                        String extKey = "ret:"
                                            + caller.getEntryPoint().getOffset()
                                            + ":-1:" + typeName;
                                        if (extKeys.add(extKey)) {
                                            nextRows.add(new String[]{
                                                "addr:" + Long.toHexString(
                                                    caller.getEntryPoint().getOffset()),
                                                "-1",
                                                typeName
                                            });
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                println("Round " + round + ": " + discovered + " candidate(s) in "
                    + pendingByFn.size() + " function(s), "
                    + nextRows.size() + " new propagation edge(s)");

                if (pendingByFn.isEmpty()) {
                    println("  → fixed point reached.");
                    break;
                }

                // ── Commit ───────────────────────────────────────────────────
                int roundCommitted = 0, roundSkipped = 0;
                for (Map.Entry<Function, List<Promotion>> entry : pendingByFn.entrySet()) {
                    Function        fn    = entry.getKey();
                    List<Promotion> plist = entry.getValue();

                    int txId = currentProgram.startTransaction(
                        "ApplyTypePromotion[" + fn.getName() + "]");
                    int fnCommitted = 0;
                    try {
                        for (Promotion p : plist) {
                            try {
                                HighFunctionDBUtil.updateDBVariable(
                                    p.sym, p.sym.getName(), p.newType, SourceType.ANALYSIS);
                                println("  [R" + round + "] +" + fn.getName()
                                    + "." + p.sym.getName()
                                    + " → " + p.newType.getName()
                                    + (p.isParam ? " (param)" : "")
                                    + "  via " + p.apiName
                                    + (p.argIdx < 0 ? " return" : " arg[" + p.argIdx + "]"));
                                fnCommitted++;
                                roundCommitted++;
                            } catch (Exception ex) {
                                println("  [skip] " + fn.getName()
                                    + "." + p.sym.getName() + ": " + ex.getMessage());
                                roundSkipped++;
                            }
                        }
                    } finally {
                        currentProgram.endTransaction(txId, fnCommitted > 0);
                    }
                }
                totalCommitted += roundCommitted;
                totalSkipped   += roundSkipped;
                println("  committed=" + roundCommitted + " skipped=" + roundSkipped);

                if (roundCommitted == 0) {
                    println("  → no successful commits this round — stopping.");
                    break;
                }

                // Extend dynamic table for the next round.
                dynamicTable.addAll(nextRows);
            }
        } finally {
            decomp.closeProgram();
        }

        println(String.format(
            "ApplyTypePromotion done: %d committed, %d skipped over %d round(s) — "
            + "ExportDecompiledC will re-decompile with promoted types.",
            totalCommitted, totalSkipped, round));
    }

    // Walk backward through COPY/CAST/INT_ZEXT/INT_SEXT/PTRSUB/PTRADD chains
    // to find the root Varnode (which is more likely to have a named HighVariable).
    private Varnode walkBack(Varnode vn, int depth) {
        if (vn == null || depth <= 0) return vn;
        if (vn.isConstant() || vn.isAddress()) return vn;
        PcodeOp def = vn.getDef();
        if (def == null) return vn;
        switch (def.getOpcode()) {
            case PcodeOp.COPY:
            case PcodeOp.CAST:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_SEXT:
                return walkBack(def.getInput(0), depth - 1);
            case PcodeOp.PTRSUB:
            case PcodeOp.PTRADD: {
                Varnode base = walkBack(def.getInput(0), depth - 1);
                if (base != null && base.isAddress()) return base;
                return vn;
            }
            default:
                return vn;
        }
    }

    // Returns true if the promotion should be skipped:
    //   - variable is already typed as the target type, OR
    //   - variable already has a specific non-generic type (don't override user work)
    private boolean shouldSkip(DataType existing, DataType target) {
        if (existing == null) return false;
        String name = existing.getName();
        if (name.equals(target.getName())) return true;
        if (name.startsWith("undefined")) return false;
        if (name.equals("void") || name.equals("uint") || name.equals("ulong")
                || name.equals("ushort") || name.equals("uchar")
                || name.equals("int")  || name.equals("long") || name.equals("bool")
                || name.equals("byte") || name.equals("word") || name.equals("dword")) return false;
        if (existing instanceof PointerDataType) {
            DataType inner = ((PointerDataType) existing).getDataType();
            return inner != null && !(inner instanceof VoidDataType);
        }
        return true;
    }

    private static class Promotion {
        final HighSymbol sym;
        final DataType   newType;
        final String     apiName;
        final int        argIdx;
        final boolean    isParam;

        Promotion(HighSymbol sym, DataType dt, String api, int arg, boolean isParam) {
            this.sym     = sym;
            this.newType = dt;
            this.apiName = api;
            this.argIdx  = arg;
            this.isParam = isParam;
        }
    }
}
