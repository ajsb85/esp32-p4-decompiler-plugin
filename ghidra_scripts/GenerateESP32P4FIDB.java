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

// Generates a Ghidra Function ID (FIDB) database from all ESP32-P4 programs
// in the current Ghidra project.
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

public class GenerateESP32P4FIDB extends GhidraScript {

    private static final String TARGET_LANG = "RISCV:LE:32:ESP32-P4";
    private static final String LIB_FAMILY  = "ESP-IDF";
    private static final String LIB_VERSION = "v6.0.1";

    @Override
    public void run() throws Exception {
        // ── resolve output .fidb path ─────────────────────────────────────────
        File fidFile;
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            fidFile = new File(args[0]);
        } else {
            fidFile = askFile("Save FIDB to", "Save");
            if (fidFile == null) {
                fidFile = new File(System.getProperty("user.home"),
                        "esp32p4-idf6.fidb");
                println("No file chosen — writing to " + fidFile.getAbsolutePath());
            }
        }

        // ── scan current project for ESP32-P4 programs ────────────────────────
        List<DomainFile> targets = new ArrayList<>();
        collectPrograms(state.getProject().getProjectData().getRootFolder(), targets);

        if (targets.isEmpty()) {
            printerr("No ESP32-P4 programs found in the current project.");
            printerr("Import the IDF .a libraries first (see script header).");
            printManualInstructions(fidFile);
            return;
        }
        println("Found " + targets.size() + " ESP32-P4 program(s) in project.");

        // ── create the FID database via FidFileManager ────────────────────────
        FidFileManager fidMgr = FidFileManager.getInstance();

        // Wipe any stale file so createNewFidDatabase doesn't fail.
        if (fidFile.exists()) fidFile.delete();
        fidMgr.createNewFidDatabase(fidFile);

        FidFile wrappedFidFile = fidMgr.addUserFidFile(fidFile);
        if (wrappedFidFile == null) {
            printerr("FidFileManager could not register: " + fidFile.getAbsolutePath());
            printManualInstructions(fidFile);
            return;
        }

        // ── populate via FidService ───────────────────────────────────────────
        FidDB fidDB = wrappedFidFile.getFidDB(true /* exclusive write */);
        try {
            FidService fidService = new FidService();
            LanguageID langId = new LanguageID(TARGET_LANG);

            // Predicate is null → accept all functions in all programs.
            @SuppressWarnings("unchecked")
            java.util.function.Predicate predicate = null;

            List<String> ingestLog = new ArrayList<>();

            @SuppressWarnings("unchecked")
            FidPopulateResult result = fidService.createNewLibraryFromPrograms(
                    fidDB,
                    LIB_FAMILY,
                    LIB_VERSION,
                    "" /* variant */,
                    targets,
                    predicate,
                    langId,
                    Collections.emptyList() /* no existing libs to relate */,
                    ingestLog,
                    monitor);

            if (!ingestLog.isEmpty()) {
                println("── Ingest log ──");
                for (String line : ingestLog) println("  " + line);
            }

            if (result != null) {
                println("Populate result: " + result);
            }

        } finally {
            fidDB.close();
        }

        // Remove the registration from FidFileManager (it was temporary).
        fidMgr.removeUserFile(wrappedFidFile);

        println(String.format("FIDB saved → %s", fidFile.getAbsolutePath()));
        println("Apply with: Tools → Function ID → Apply Function ID Files");
        println("  Select: " + fidFile.getAbsolutePath());
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /** Recursively collects all DomainFiles in the project that are ESP32-P4 Programs. */
    private void collectPrograms(DomainFolder folder, List<DomainFile> out)
            throws Exception {
        monitor.checkCancelled();
        for (DomainFile df : folder.getFiles()) {
            if ("Program".equals(df.getContentType())) {
                Map<String, String> meta = df.getMetadata();
                String lang = meta != null ? meta.get("Language ID") : null;
                if (TARGET_LANG.equals(lang)) out.add(df);
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectPrograms(sub, out);
        }
    }

    private void printManualInstructions(File fidFile) {
        println("═══ Manual FIDB generation workflow ═══");
        println();
        println("1. Import IDF libraries headlessly:");
        println("   analyzeHeadless /tmp/idf-proj IDFLibs \\");
        println("     -import ~/.espressif/v6.0.1/esp-idf/build/esp-idf/*/lib*.a \\");
        println("     -processor \"" + TARGET_LANG + "\"");
        println();
        println("2. Run this script against that project:");
        println("   analyzeHeadless /tmp/idf-proj IDFLibs \\");
        println("     -process '*.a' \\");
        println("     -postScript GenerateESP32P4FIDB.java \\");
        println("     " + fidFile.getAbsolutePath());
        println();
        println("3. Apply: Tools → Function ID → Apply Function ID Files");
        println("   Select: " + fidFile.getAbsolutePath());
    }
}
