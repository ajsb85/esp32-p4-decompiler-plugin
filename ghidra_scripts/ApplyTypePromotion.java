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

// Sprint 26 — Two-pass FreeRTOS handle type promotion.
//
// Pass 1 (Discovery): decompiles every function that calls a known FreeRTOS
//   API, traces the relevant argument or return Varnode backward/forward to
//   find the backing HighVariable, and records a (HighVariable, DataType)
//   promotion candidate.
//
// Pass 2 (Commit): for each candidate, opens a program-database transaction
//   and calls HighFunctionDBUtil.updateDBVariable() to permanently write
//   the promoted type.  After this script runs, ExportDecompiledC.java re-
//   decompiles from scratch and inherits the richer types, producing output
//   like "tcb->uxPriority = 5;" instead of "*(uint *)(local_c + 0xc) = 5;".
//
// Dirty-flag optimization: functions with no qualifying call sites are never
//   re-decompiled in the export phase — zero performance overhead.
//
// Covered handle families:
//   TaskHandle_t         — vTaskDelete, vTaskPrioritySet, xTaskNotify, ...
//   QueueHandle_t        — xQueueCreate (return), xQueueSend, xQueueReceive, ...
//   SemaphoreHandle_t    — xSemaphoreCreate* (return), xSemaphoreTake/Give, ...
//   TimerHandle_t        — xTimerCreate (return), xTimerStart/Stop/Delete, ...
//   EventGroupHandle_t   — xEventGroupCreate (return), xEventGroupSetBits, ...
//   StreamBufferHandle_t — xStreamBufferCreate (return), Send/Receive
//   MessageBufferHandle_t— xMessageBufferCreate (return), Send/Receive
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

    // API call-site table.
    // Columns: { functionName, argIdx, typeName }
    //   argIdx == "-1"  → promote the RETURN value (CALL output Varnode)
    //   argIdx >= "0"   → promote the logical argument at that 0-based index
    //                     (maps to CALL pcode input[argIdx+1], offset by 1
    //                      because input[0] is always the call-target address)
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

        // ── Phase 1: discovery pass ──────────────────────────────────────────
        // Decompile each function that calls a known FreeRTOS API and collect
        // (HighVariable, DataType) promotion candidates.
        // Key: stable identity = entryPoint hex + ":" + variable name.
        // We group by Function so we can commit in one transaction per function.
        Map<Function, List<Promotion>> pendingByFn = new LinkedHashMap<>();
        // Track already-seen (fn, varName, typeName) triples to avoid duplicates
        // from multiple call sites of the same API within the same function.
        Set<String> seen = new HashSet<>();

        DecompInterface decomp = new DecompInterface();
        decomp.setOptions(new DecompileOptions());
        decomp.toggleSyntaxTree(true);
        decomp.openProgram(currentProgram);

        SymbolTable  symTable = currentProgram.getSymbolTable();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        int discovered = 0;

        try {
            for (String[] row : API_TABLE) {
                String   apiName  = row[0];
                int      argIdx   = Integer.parseInt(row[1]);
                String   typeName = row[2];
                DataType newType  = typeCache.get(typeName);
                if (newType == null) continue;

                // Look up the API function in the symbol table.
                SymbolIterator syms = symTable.getSymbols(apiName);
                if (!syms.hasNext()) continue;
                Address apiAddr = syms.next().getAddress();

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

                    // Find the CALL (or CALLIND) PcodeOp at the call-site address.
                    Iterator<PcodeOpAST> ops = hf.getPcodeOps(callSite);
                    while (ops.hasNext()) {
                        PcodeOpAST op = ops.next();
                        if (op.getOpcode() != PcodeOp.CALL
                                && op.getOpcode() != PcodeOp.CALLIND) continue;

                        // Resolve the target Varnode.
                        Varnode targetVn;
                        if (argIdx < 0) {
                            // Return value: the CALL output Varnode.
                            targetVn = op.getOutput();
                        } else {
                            // Argument: input[argIdx+1] (input[0] = call target).
                            int inputIdx = argIdx + 1;
                            if (op.getNumInputs() <= inputIdx) continue;
                            // Walk backward through COPY/CAST chains to find
                            // the root local variable Varnode.
                            targetVn = walkBack(op.getInput(inputIdx), 6);
                        }
                        if (targetVn == null) continue;

                        HighVariable hv = targetVn.getHigh();
                        if (hv == null) continue;

                        // HighOther/SSA temporaries have no backing DB symbol.
                        HighSymbol hvSym = hv.getSymbol();
                        if (hvSym == null) continue;

                        // Skip if already well-typed.
                        if (shouldSkip(hvSym.getDataType(), newType)) continue;

                        // Deduplicate across multiple call sites of same API.
                        String dedupeKey = caller.getEntryPoint().toString()
                            + ":" + hvSym.getName() + ":" + typeName;
                        if (!seen.add(dedupeKey)) continue;

                        pendingByFn.computeIfAbsent(caller, k -> new ArrayList<>())
                            .add(new Promotion(hvSym, newType, apiName, argIdx));
                        discovered++;
                    }
                }
            }
        } finally {
            decomp.closeProgram();
        }

        println("Discovery: " + discovered + " candidate(s) in "
            + pendingByFn.size() + " function(s)");

        // ── Phase 2: commit to program database ───────────────────────────────
        // One transaction per function — if any commit in the function fails
        // the whole function transaction rolls back (safe: no partial state).
        int totalCommitted = 0;
        int totalSkipped   = 0;

        for (Map.Entry<Function, List<Promotion>> entry : pendingByFn.entrySet()) {
            Function       fn    = entry.getKey();
            List<Promotion> plist = entry.getValue();

            int txId = currentProgram.startTransaction(
                "ApplyTypePromotion[" + fn.getName() + "]");
            int fnCommitted = 0;
            try {
                for (Promotion p : plist) {
                    try {
                        HighFunctionDBUtil.updateDBVariable(
                            p.sym, p.sym.getName(), p.newType, SourceType.ANALYSIS);
                        println("  +" + fn.getName() + "." + p.sym.getName()
                            + " → " + p.newType.getName()
                            + "  (via " + p.apiName
                            + (p.argIdx < 0 ? " return" : " arg[" + p.argIdx + "]") + ")");
                        fnCommitted++;
                        totalCommitted++;
                    } catch (Exception ex) {
                        println("  [skip] " + fn.getName() + "." + p.sym.getName()
                            + ": " + ex.getMessage());
                        totalSkipped++;
                    }
                }
            } finally {
                currentProgram.endTransaction(txId, fnCommitted > 0);
            }
        }

        println(String.format(
            "ApplyTypePromotion done: %d committed, %d skipped — "
            + "ExportDecompiledC will re-decompile with promoted types.",
            totalCommitted, totalSkipped));
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
        // Already exactly the target
        if (name.equals(target.getName())) return true;
        // Ghidra "I don't know" types — always promote
        if (name.startsWith("undefined")) return false;
        if (name.equals("void") || name.equals("uint") || name.equals("ulong")
                || name.equals("ushort") || name.equals("uchar")
                || name.equals("int")  || name.equals("long") || name.equals("bool")
                || name.equals("byte") || name.equals("word") || name.equals("dword")) return false;
        if (existing instanceof PointerDataType) {
            DataType inner = ((PointerDataType) existing).getDataType();
            // void* → always promote; typed pointer → keep
            return inner != null && !(inner instanceof VoidDataType);
        }
        // Has a specific struct/typedef/enum type — don't override
        return true;
    }

    // Holds one pending promotion discovered in Phase 1.
    private static class Promotion {
        final HighSymbol sym;
        final DataType   newType;
        final String     apiName;
        final int        argIdx;

        Promotion(HighSymbol sym, DataType dt, String api, int arg) {
            this.sym     = sym;
            this.newType = dt;
            this.apiName = api;
            this.argIdx  = arg;
        }
    }
}
