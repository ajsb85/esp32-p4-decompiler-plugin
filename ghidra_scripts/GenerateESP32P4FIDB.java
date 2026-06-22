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

// Generates an ESP-IDF v6 Function ID Database (FIDB) for the ESP32-P4 (RISC-V).
// Run headless or from Script Manager. Prompts for:
//   1. Output .fidb file path
//   2. ESP-IDF component ELF/object directory root
//   3. Optimization variant (-O0, -Os, -O2)
//
// Compiles against ESP-IDF freertos, heap, driver, hal, esp_hw_support components.
// Minimum function size: 5 instructions (to avoid hash collisions from tiny wrappers).
//
// Workflow:
//
//  Step 1 — Import ESP-IDF libraries into a Ghidra project (one-time setup):
//
//    analyzeHeadless /tmp/idf-fidb-project IDFLibs \
//      -import ~/.espressif/v6.0.1/esp-idf/build/esp-idf/*/lib*.a \
//      -processor "RISCV:LE:32:ESP32-P4"
//
//  Step 2 — Open any program in that project, then run this script:
//
//    analyzeHeadless /tmp/idf-fidb-project IDFLibs \
//      -process '*.a' \
//      -postScript GenerateESP32P4FIDB.java /tmp/esp32p4-idf6.fidb
//
//  Step 3 — Apply the FIDB to firmware analysis:
//    Tools → Function ID → Apply Function ID Files → select the .fidb
//
// Implementation notes:
//   - FidFileManager.createNewFidDatabase(File) creates the raw DB file.
//   - FidFile.getFidDB(true) opens it for writing.
//   - FidService.createNewLibraryFromPrograms() fingerprints domain files
//     in a single call; its predicate parameter accepts null (= all functions).
//   - If FID jars are not available at compile time, ClassNotFoundException is
//     caught at runtime and a helpful message is printed.
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Generate ESP-IDF FIDB

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.*;
import ghidra.program.model.lang.*;

import java.io.File;
import java.util.*;
import java.util.function.Predicate;

public class GenerateESP32P4FIDB extends GhidraScript {

    private static final String TARGET_LANG  = "RISCV:LE:32:ESP32-P4";
    private static final String LIB_FAMILY   = "ESP-IDF-v6";
    private static final String LIB_VERSION  = "6.0";

    /**
     * Minimum body size in code-units (roughly instructions) that a function
     * must have to be fingerprinted.  Tiny wrappers (thunks, stubs) produce
     * identical hashes across unrelated libraries, causing false positives.
     */
    private static final int MIN_FUNC_SIZE_CODE_UNITS = 5;

    @Override
    public void run() throws Exception {

        // ── Guard: verify FID classes are available ───────────────────────────
        try {
            Class.forName("ghidra.feature.fid.service.FidService");
        } catch (ClassNotFoundException e) {
            printerr("FID jars not found — run from inside Ghidra "
                    + "(not headless without FID support)");
            printerr("Expected jar: Ghidra/Features/FunctionID/lib/FunctionID.jar");
            return;
        }

        // ── 1. Resolve output .fidb path ──────────────────────────────────────
        File fidFile;
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            fidFile = new File(args[0]);
        } else {
            fidFile = askFile("Select output .fidb location", "Create");
            if (fidFile == null) {
                fidFile = new File(System.getProperty("user.home"), "esp32p4-idf6.fidb");
                println("No file chosen — writing to " + fidFile.getAbsolutePath());
            }
        }

        // ── 2. Ask for ESP-IDF build directory (informational / for logging) ──
        //    When running headless with -postScript, askDirectory() throws
        //    CancelledException if no GUI is present; catch it gracefully.
        File idfBuildDir = null;
        try {
            idfBuildDir = askDirectory(
                    "Select ESP-IDF build directory (contains .elf/.a files)", "Select");
        } catch (ghidra.util.exception.CancelledException ce) {
            // Headless mode or user cancelled — skip the directory prompt.
            println("No ESP-IDF build directory provided — using project programs only.");
        }
        if (idfBuildDir != null) {
            println("ESP-IDF build directory : " + idfBuildDir.getAbsolutePath());
        }

        // ── 3. Optimization variant ───────────────────────────────────────────
        String variant = "-Os";
        try {
            variant = askString("Library variant",
                    "Enter optimization variant (-Os, -O0, -O2):", "-Os");
        } catch (ghidra.util.exception.CancelledException ce) {
            println("No variant provided — defaulting to " + variant);
        }
        println("Library variant : " + variant);

        // ── 4. Scan current project for RISC-V / ESP32-P4 programs ───────────
        List<DomainFile> targets = new ArrayList<>();
        collectPrograms(state.getProject().getProjectData().getRootFolder(), targets);

        // Fallback: when called as -postScript during -import, the newly
        // imported program lives in currentProgram but may not yet be in the
        // project folder walk.  Add it directly so one-step import+fingerprint
        // works.
        if (targets.isEmpty() && currentProgram != null) {
            DomainFile df = currentProgram.getDomainFile();
            if (df != null) {
                println("Folder walk found nothing — using currentProgram: "
                        + currentProgram.getName());
                targets.add(df);
            }
        }

        if (targets.isEmpty()) {
            printerr("No RISC-V (ESP32-P4) programs found in the current project.");
            printerr("Import the IDF .a libraries first (see script header).");
            printManualInstructions(fidFile);
            return;
        }
        println("Found " + targets.size() + " program(s) to fingerprint.");

        // ── 5. Create the FID database via FidFileManager ─────────────────────
        FidFileManager fidMgr = FidFileManager.getInstance();

        // Remove stale file so createNewFidDatabase doesn't fail.
        if (fidFile.exists()) {
            fidFile.delete();
        }
        fidMgr.createNewFidDatabase(fidFile);

        FidFile wrappedFidFile = fidMgr.addUserFidFile(fidFile);
        if (wrappedFidFile == null) {
            printerr("FidFileManager could not register: " + fidFile.getAbsolutePath());
            printManualInstructions(fidFile);
            return;
        }

        // ── 6. Populate via FidService ────────────────────────────────────────
        FidDB fidDB = wrappedFidFile.getFidDB(true /* exclusive write */);
        try {
            FidService fidService = new FidService();
            LanguageID langId = new LanguageID(TARGET_LANG);

            // Predicate: skip functions whose body is below the minimum size
            // threshold to avoid hash collisions from HAL wrapper thunks.
            //
            // The predicate receives a generic.stl.Pair<Function, FidHashQuad>.
            // We cast to Object to keep this source file compilable without the
            // Generic.jar on the path at all times; inside Ghidra the correct
            // types are available and the lambda will execute correctly.
            @SuppressWarnings({"unchecked", "rawtypes"})
            Predicate predicate = (obj) -> {
                try {
                    // Pair.first is the Function
                    Object pair = obj;
                    java.lang.reflect.Method firstMethod =
                            pair.getClass().getMethod("first");
                    Object func = firstMethod.invoke(pair);
                    // Function.getBody().getNumAddresses() gives body size
                    java.lang.reflect.Method getBody =
                            func.getClass().getMethod("getBody");
                    Object addrSet = getBody.invoke(func);
                    java.lang.reflect.Method getNum =
                            addrSet.getClass().getMethod("getNumAddresses");
                    long numAddresses = (Long) getNum.invoke(addrSet);
                    return numAddresses >= MIN_FUNC_SIZE_CODE_UNITS;
                } catch (Exception ex) {
                    // If reflection fails, accept the function to be safe.
                    return true;
                }
            };

            List<String> ingestLog = new ArrayList<>();

            @SuppressWarnings("unchecked")
            FidPopulateResult result = fidService.createNewLibraryFromPrograms(
                    fidDB,
                    LIB_FAMILY,
                    LIB_VERSION,
                    variant,
                    targets,
                    predicate,
                    langId,
                    null /* no existing libs to relate */,
                    ingestLog,
                    monitor);

            if (!ingestLog.isEmpty()) {
                println("── Ingest log ──");
                for (String line : ingestLog) {
                    println("  " + line);
                }
            }

            if (result != null) {
                println("Functions attempted  : " + result.getTotalAttempted());
                println("Functions added      : " + result.getTotalAdded());
                println("Functions excluded   : " + result.getTotalExcluded());
                if (result.getFailures() != null && !result.getFailures().isEmpty()) {
                    println("Failure breakdown    : " + result.getFailures());
                }
            } else {
                println("No result returned from FidService (empty program set?).");
            }

            // MUST call saveDatabase before close to commit data to the packed format.
            fidDB.saveDatabase("Saving ESP-IDF FIDB", monitor);

        } finally {
            fidDB.close();
        }

        // Remove the temporary registration from FidFileManager.
        fidMgr.removeUserFile(wrappedFidFile);

        println("");
        println("FIDB saved → " + fidFile.getAbsolutePath());
        println("Apply with : Tools → Function ID → Apply Function ID Files");
        println("  Select   : " + fidFile.getAbsolutePath());
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * Recursively collects all DomainFiles in the project that are Programs.
     *
     * Language filter is best-effort: programs imported with {@code -noanalysis}
     * may not have metadata populated, so we accept any Program content type and
     * let FidService reject non-matching languages during ingest.  We do filter
     * on {@code RISCV:LE:32} prefix when language metadata is available.
     */
    private void collectPrograms(DomainFolder folder, List<DomainFile> out)
            throws Exception {
        monitor.checkCancelled();
        for (DomainFile df : folder.getFiles()) {
            if ("Program".equals(df.getContentType())) {
                Map<String, String> meta = df.getMetadata();
                String lang = meta != null ? meta.get("Language ID") : null;
                // Accept when:
                //   • no metadata yet (un-analysed import), OR
                //   • language starts with RISCV:LE:32 (covers the default
                //     variant and any ESP32-P4-specific compiler suffix), OR
                //   • exact TARGET_LANG match.
                if (lang == null
                        || lang.startsWith("RISCV:LE:32")
                        || TARGET_LANG.equals(lang)) {
                    out.add(df);
                }
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectPrograms(sub, out);
        }
    }

    private void printManualInstructions(File fidFile) {
        println("═══ Manual FIDB generation workflow ═══");
        println("");
        println("1. Import IDF libraries headlessly:");
        println("   analyzeHeadless /tmp/idf-proj IDFLibs \\");
        println("     -import ~/.espressif/v6.0.1/esp-idf/build/esp-idf/*/lib*.a \\");
        println("     -processor \"RISCV:LE:32:ESP32-P4\"");
        println("");
        println("2. Run this script against that project:");
        println("   analyzeHeadless /tmp/idf-proj IDFLibs \\");
        println("     -process '*.a' \\");
        println("     -postScript GenerateESP32P4FIDB.java \\");
        println("     " + fidFile.getAbsolutePath());
        println("");
        println("3. Apply: Tools → Function ID → Apply Function ID Files");
        println("   Select: " + fidFile.getAbsolutePath());
    }
}
