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
// Synthesizes ESP-IDF FreeRTOS data structures in the DataTypeManager.
//
// Creates precise byte-aligned replicas of:
//   - tskTaskControlBlock (TCB_t) — ESP-IDF SMP variant with xCoreID, pxEndOfStack
//   - QueueHandle_t / SemaphoreHandle_t opaque pointer types
//   - List_t and ListItem_t (FreeRTOS internal list primitives)
//   - StaticTask_t, StaticQueue_t (static allocation variants)
//
// Run AFTER auto-analysis. Types appear in Data Type Manager under /FreeRTOS/.
// Decompiled code will then show tcb->xCoreID instead of *(int *)(ptr + 0x58).
//
// Based on ESP-IDF v5.3+ SMP FreeRTOS TCB layout (rv32imafc ilp32f ABI).
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Load FreeRTOS Types

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.util.task.TaskMonitor;

import java.util.List;
import java.util.ArrayList;

public class LoadFreeRTOSTypes extends GhidraScript {

    private static final CategoryPath FREERTOS_CAT = new CategoryPath("/FreeRTOS");

    @Override
    public void run() throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        int typeCount = 0;
        int txId = dtm.startTransaction("Load FreeRTOS Types");
        try {
            // Ensure the /FreeRTOS category exists
            dtm.createCategory(FREERTOS_CAT);

            // ── 1. ListItem_t ────────────────────────────────────────────────
            // rv32 ilp32f: pointers are 4 bytes.  Typical ESP-IDF layout:
            //   0x00  xItemValue    uint32  tick count or priority
            //   0x04  pxNext        void*   next item
            //   0x08  pxPrevious    void*   previous item
            //   0x0C  pvOwner       void*   task/queue that owns this item
            //   0x10  pvContainer   void*   list this item is placed in
            // Total: 20 bytes (configUSE_LIST_DATA_INTEGRITY_CHECK_BYTES=0)
            StructureDataType listItem = new StructureDataType(FREERTOS_CAT, "ListItem_t", 0, dtm);
            listItem.add(new DWordDataType(),          4, "xItemValue",   "Tick count or priority value");
            listItem.add(new PointerDataType(dtm),     4, "pxNext",       "Pointer to next ListItem_t in list");
            listItem.add(new PointerDataType(dtm),     4, "pxPrevious",   "Pointer to previous ListItem_t in list");
            listItem.add(new PointerDataType(dtm),     4, "pvOwner",      "Task or queue that contains this list item");
            listItem.add(new PointerDataType(dtm),     4, "pvContainer",  "List this item is currently placed in");
            DataType listItemDT = dtm.addDataType(listItem, DataTypeConflictHandler.REPLACE_HANDLER);
            typeCount++;
            println("  Created: ListItem_t  (" + listItemDT.getLength() + " bytes)");

            // ── 2. List_t ────────────────────────────────────────────────────
            // rv32 layout:
            //   0x00  uxNumberOfItems  uint32       live count
            //   0x04  pxIndex          ListItem_t*  cursor (current item)
            //   0x08  xListEnd         ListItem_t   sentinel (20 bytes inline)
            // Total: 28 bytes
            StructureDataType list = new StructureDataType(FREERTOS_CAT, "List_t", 0, dtm);
            list.add(new DWordDataType(),                     4,  "uxNumberOfItems", "Number of items in the list");
            list.add(new PointerDataType(listItemDT, dtm),   4,  "pxIndex",         "Current list walk position");
            list.add(listItemDT,                              20, "xListEnd",        "Sentinel list item; marks end/start of list");
            DataType listDT = dtm.addDataType(list, DataTypeConflictHandler.REPLACE_HANDLER);
            typeCount++;
            println("  Created: List_t  (" + listDT.getLength() + " bytes)");

            // ── 3. tskTaskControlBlock (TCB_t) — ESP-IDF SMP rv32 layout ────
            //
            // Offsets verified against ESP-IDF v5.3 freertos/include/freertos/task.h
            // and portable/riscv/port.h for rv32imafc ilp32f (no MPU).
            //
            //   0x00  pxTopOfStack     void*       saved SP — MUST be first member
            //   0x04  xStateListItem   ListItem_t  20 bytes
            //   0x18  xEventListItem   ListItem_t  20 bytes
            //   0x2C  uxPriority       uint32
            //   0x30  pxStack          void*       bottom of allocated stack
            //   0x34  pcTaskName       char[16]    configMAX_TASK_NAME_LEN=16
            //   0x44  xCoreID          int32       0/1/−1(tskNO_AFFINITY) — SMP ext
            //   0x48  pxEndOfStack     void*       for stack-overflow detection
            //   0x4C  uxTCBNumber      uint32      unique task ID (trace tools)
            //   0x50  uxTaskNumber     uint32      task number for stats
            //   0x54  uxBasePriority   uint32      priority before mutation
            //   0x58  uxMutexesHeld    uint32      count of held mutexes
            StructureDataType tcb = new StructureDataType(FREERTOS_CAT, "tskTaskControlBlock", 0, dtm);
            tcb.add(new PointerDataType(dtm),          4,  "pxTopOfStack",    "Saved top-of-stack pointer (context switch); MUST be at offset 0");
            tcb.add(listItemDT,                        20, "xStateListItem",  "State list item: ready/blocked/suspended lists");
            tcb.add(listItemDT,                        20, "xEventListItem",  "Event list item: event/timeout list");
            tcb.add(new DWordDataType(),               4,  "uxPriority",      "Task priority (0 = lowest)");
            tcb.add(new PointerDataType(dtm),          4,  "pxStack",         "Pointer to bottom of task stack buffer");
            tcb.add(new ArrayDataType(new CharDataType(), 16, 1),
                                                       16, "pcTaskName",      "Human-readable task name (configMAX_TASK_NAME_LEN=16)");
            // ESP-IDF SMP extensions (not present in vanilla FreeRTOS)
            tcb.add(new DWordDataType(),               4,  "xCoreID",         "Core affinity: 0=Core0, 1=Core1, -1=tskNO_AFFINITY");
            tcb.add(new PointerDataType(dtm),          4,  "pxEndOfStack",    "Pointer to end of stack (for overflow detection)");
            tcb.add(new DWordDataType(),               4,  "uxTCBNumber",     "Unique TCB number assigned at creation (for trace tools)");
            tcb.add(new DWordDataType(),               4,  "uxTaskNumber",    "Task number assigned by vTaskSetTaskNumber()");
            tcb.add(new DWordDataType(),               4,  "uxBasePriority",  "Priority before any priority inheritance");
            tcb.add(new DWordDataType(),               4,  "uxMutexesHeld",   "Number of mutexes currently held by this task");
            DataType tcbDT = dtm.addDataType(tcb, DataTypeConflictHandler.REPLACE_HANDLER);
            typeCount++;
            println("  Created: tskTaskControlBlock  (" + tcbDT.getLength() + " bytes)");

            // Convenience typedef TCB_t → tskTaskControlBlock
            TypedefDataType tcbTypeDef = new TypedefDataType(FREERTOS_CAT, "TCB_t", tcbDT, dtm);
            dtm.addDataType(tcbTypeDef, DataTypeConflictHandler.REPLACE_HANDLER);
            typeCount++;
            println("  Created: TCB_t  (typedef → tskTaskControlBlock)");

            // ── 4. Opaque handle typedefs (void*) ───────────────────────────
            // FreeRTOS exposes these to application code; the pointed-to struct
            // varies by configuration so we model them as void*.
            String[] handleNames = {
                "TaskHandle_t",
                "QueueHandle_t",
                "SemaphoreHandle_t",
                "TimerHandle_t",
                "EventGroupHandle_t",
                "StreamBufferHandle_t",
                "MessageBufferHandle_t",
            };
            for (String name : handleNames) {
                TypedefDataType handle = new TypedefDataType(
                    FREERTOS_CAT, name,
                    new PointerDataType(new VoidDataType(), dtm),
                    dtm);
                dtm.addDataType(handle, DataTypeConflictHandler.REPLACE_HANDLER);
                typeCount++;
                println("  Created: " + name + "  (typedef → void*)");
            }

            // ── 5. StaticTask_t ─────────────────────────────────────────────
            // Used when configSUPPORT_STATIC_ALLOCATION=1.  The application
            // supplies storage of exactly sizeof(StaticTask_t) bytes; the
            // kernel casts it to TCB_t internally.  We model it as an opaque
            // byte array of the same size as tskTaskControlBlock so the
            // decompiler shows the correct allocation size.
            int tcbSize = tcbDT.getLength();
            StructureDataType staticTask = new StructureDataType(FREERTOS_CAT, "StaticTask_t", 0, dtm);
            staticTask.add(new ArrayDataType(new ByteDataType(), tcbSize, 1),
                           tcbSize, "ucDummy",
                           "Opaque storage; kernel casts to tskTaskControlBlock internally");
            dtm.addDataType(staticTask, DataTypeConflictHandler.REPLACE_HANDLER);
            typeCount++;
            println("  Created: StaticTask_t  (" + tcbSize + " bytes, opaque TCB storage)");

            // ── 6. Queue_t / QueueDefinition ────────────────────────────────
            // Minimal model covering the fields most useful for decompiler output.
            // Full upstream layout in queue.c (ESP-IDF v5.3):
            //   0x00  pcHead           int8_t*     start of queue storage area
            //   0x04  pcWriteTo        int8_t*     next write position
            //   0x08  u.pcReadFrom /   union       read pos or semaphore count
            //         u.uxRecursiveCallCount
            //   0x0C  xTasksWaitingToSend    List_t  28 bytes
            //   0x28  xTasksWaitingToReceive List_t  28 bytes
            //   0x44  uxMessagesWaiting      uint32
            //   0x48  uxLength               uint32  configured queue length
            //   0x4C  uxItemSize             uint32  size per item in bytes
            //   0x50  cRxLock                int8_t
            //   0x51  cTxLock                int8_t
            //   (optional fields for static alloc, trace, stats omitted)
            StructureDataType queue = new StructureDataType(FREERTOS_CAT, "QueueDefinition", 0, dtm);
            queue.add(new PointerDataType(new ByteDataType(), dtm),  4,  "pcHead",                   "Points to start of queue storage area");
            queue.add(new PointerDataType(new ByteDataType(), dtm),  4,  "pcWriteTo",                "Next free slot in storage area");
            queue.add(new PointerDataType(new ByteDataType(), dtm),  4,  "pcReadFrom_or_semCount",   "Read pointer (queue) or semaphore count (semaphore)");
            queue.add(listDT,                                         28, "xTasksWaitingToSend",      "Tasks blocked waiting to post to a full queue");
            queue.add(listDT,                                         28, "xTasksWaitingToReceive",   "Tasks blocked waiting to receive from an empty queue");
            queue.add(new DWordDataType(),                            4,  "uxMessagesWaiting",        "Current number of items in the queue");
            queue.add(new DWordDataType(),                            4,  "uxLength",                 "Configured maximum number of items");
            queue.add(new DWordDataType(),                            4,  "uxItemSize",               "Size of each item in bytes");
            queue.add(new ByteDataType(),                             1,  "cRxLock",                  "Counts items received from locked queue");
            queue.add(new ByteDataType(),                             1,  "cTxLock",                  "Counts items sent to locked queue");
            DataType queueDT = dtm.addDataType(queue, DataTypeConflictHandler.REPLACE_HANDLER);
            typeCount++;
            println("  Created: QueueDefinition  (" + queueDT.getLength() + " bytes)");

            // ── 7. StaticQueue_t ────────────────────────────────────────────
            int queueSize = queueDT.getLength();
            StructureDataType staticQueue = new StructureDataType(FREERTOS_CAT, "StaticQueue_t", 0, dtm);
            staticQueue.add(new ArrayDataType(new ByteDataType(), queueSize, 1),
                            queueSize, "ucDummy",
                            "Opaque storage; kernel casts to QueueDefinition internally");
            dtm.addDataType(staticQueue, DataTypeConflictHandler.REPLACE_HANDLER);
            typeCount++;
            println("  Created: StaticQueue_t  (" + queueSize + " bytes, opaque Queue storage)");

            // ── 8. Apply TCB pointer array to pxCurrentTCBs symbol ──────────
            applyCurrentTCBsType(dtm, tcbDT);

            // ── 9. Locate key FreeRTOS API functions ─────────────────────────
            locateFreeRTOSApiFunctions();

        } finally {
            dtm.endTransaction(txId, true);
        }

        println("──────────────────────────────────────────────────");
        println("Loaded " + typeCount + " FreeRTOS data types under /FreeRTOS/");
        println("Run 'Auto Create Structure' on suspected TCB pointers to refine offsets.");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /**
     * Find pxCurrentTCBs in the symbol table and apply tskTaskControlBlock*[2]
     * at its address so the decompiler shows the per-core current-task array.
     */
    private void applyCurrentTCBsType(DataTypeManager dtm, DataType tcbDT) {
        try {
            SymbolTable symTable = currentProgram.getSymbolTable();
            SymbolIterator it = symTable.getSymbols("pxCurrentTCBs");
            if (!it.hasNext()) {
                println("  [info] Symbol 'pxCurrentTCBs' not found — skipping type application.");
                return;
            }
            Symbol sym = it.next();
            Address addr = sym.getAddress();

            // Build tskTaskControlBlock*[2]
            DataType tcbPtr   = new PointerDataType(tcbDT, dtm);
            DataType tcbArr   = new ArrayDataType(tcbPtr, 2, tcbPtr.getLength());

            currentProgram.getListing().createData(addr, tcbArr);
            println("  Applied tskTaskControlBlock*[2] at pxCurrentTCBs (" + addr + ")");
        }
        catch (Exception e) {
            println("  [warn] Could not apply type at pxCurrentTCBs: " + e.getMessage());
        }
    }

    /**
     * Search the symbol table for common FreeRTOS task-creation functions and
     * print their addresses so the analyst knows where to set breakpoints /
     * rename stubs.
     */
    private void locateFreeRTOSApiFunctions() {
        String[] targets = {
            "xTaskCreate",
            "xTaskCreatePinnedToCore",
            "xTaskCreateStaticPinnedToCore",
            "xTaskCreateStatic",
            "vTaskDelete",
            "vTaskDelay",
            "xQueueCreate",
            "xQueueSend",
            "xQueueReceive",
            "xSemaphoreCreateMutex",
            "xSemaphoreCreateBinary",
        };

        println("  ── FreeRTOS API symbol search ──");
        SymbolTable symTable = currentProgram.getSymbolTable();
        int found = 0;
        for (String name : targets) {
            SymbolIterator it = symTable.getSymbols(name);
            if (it.hasNext()) {
                Symbol sym = it.next();
                println("  [found] " + name + " @ " + sym.getAddress());
                found++;
            }
        }
        if (found == 0) {
            println("  [info] No FreeRTOS API symbols found. Run 'Load ROM Symbols' first,");
            println("         or the firmware may statically link FreeRTOS without exports.");
        } else {
            println("  Tip: set data breakpoints on pxCurrentTCBs[0] and pxCurrentTCBs[1]");
            println("       to catch task context switches at runtime.");
        }
    }
}
