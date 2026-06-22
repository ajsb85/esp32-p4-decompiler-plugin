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
// Applies tools/esp32p4-idf6.fidb to the current program.
//
// In headless mode pass the .fidb path as the first script argument:
//   -postScript ApplyESP32P4FIDB.java /path/to/tools/esp32p4-idf6.fidb
//
// When run from Script Manager (no args) the script auto-detects the bundled
// FIDB at tools/esp32p4-idf6.fidb relative to the plugin root.
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Apply ESP-IDF FIDB

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.cmd.ApplyFidEntriesCommand;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.program.model.address.AddressSetView;

import java.io.File;

public class ApplyESP32P4FIDB extends GhidraScript {

    @Override
    public void run() throws Exception {

        // ── Guard: verify FID classes are available ───────────────────────────
        try {
            Class.forName("ghidra.feature.fid.cmd.ApplyFidEntriesCommand");
        } catch (ClassNotFoundException e) {
            printerr("FID jars not found on classpath.");
            printerr("Expected: Ghidra/Features/FunctionID/lib/FunctionID.jar");
            return;
        }

        // ── Resolve FIDB file path ────────────────────────────────────────────
        File fidbFile = null;
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            fidbFile = new File(args[0]);
        } else {
            fidbFile = resolveBundledFidb();
        }

        if (fidbFile == null || !fidbFile.exists()) {
            printerr("FIDB not found. Pass path as script argument or place at tools/esp32p4-idf6.fidb");
            return;
        }
        println("Applying FIDB: " + fidbFile.getAbsolutePath()
                + " (" + (fidbFile.length() / 1024) + " KB)");

        // ── Register with FidFileManager ──────────────────────────────────────
        FidFileManager fidMgr = FidFileManager.getInstance();
        FidFile wrappedFile = fidMgr.addUserFidFile(fidbFile);
        if (wrappedFile == null) {
            printerr("FidFileManager could not register: " + fidbFile.getAbsolutePath());
            return;
        }

        try {
            // ── Apply to entire program ───────────────────────────────────────
            // Thresholds: 1.0f = full-hash match required, 0.5f = multi-name cutoff
            AddressSetView scope = currentProgram.getMemory()
                    .getLoadedAndInitializedAddressSet();

            ApplyFidEntriesCommand cmd = new ApplyFidEntriesCommand(
                    scope,
                    1.0f,   // scoreThreshold
                    0.5f,   // multiNameScoreThreshold
                    false,  // alwaysApplyFidLabels
                    false   // createBookmarksEnabled
            );

            boolean ok = runCommand(cmd);
            if (!ok) {
                printerr("ApplyFidEntriesCommand did not complete successfully.");
            } else {
                // Count renamed functions
                long renamedCount = 0;
                for (ghidra.program.model.listing.Function fn :
                        currentProgram.getFunctionManager().getFunctions(true)) {
                    // Functions renamed by FID have a source type of ANALYSIS
                    if (fn.getSymbol().getSource() ==
                            ghidra.program.model.symbol.SourceType.ANALYSIS) {
                        renamedCount++;
                    }
                }
                println("FIDB applied. Functions with ANALYSIS source: " + renamedCount);
                println("Re-run ExportDecompiledC.java to get named output.");
            }
        } finally {
            fidMgr.removeUserFile(wrappedFile);
        }
    }

    /** Auto-detect tools/esp32p4-idf6.fidb relative to script or extension dir. */
    private File resolveBundledFidb() {
        // 1. Via ResourceFile (filesystem script)
        try {
            generic.jar.ResourceFile rf = getSourceFile();
            java.io.File f = rf.getFile(false);
            if (f != null) {
                java.io.File toolsDir = new java.io.File(f.getParentFile().getParent(), "tools");
                java.io.File candidate = new java.io.File(toolsDir, "esp32p4-idf6.fidb");
                if (candidate.exists()) return candidate;
            }
        } catch (Exception ignore) {}

        // 2. Extension dir
        String[] extPaths = {
            System.getProperty("user.home")
                + "/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/esp32p4-ghidra-plugin/tools/esp32p4-idf6.fidb",
        };
        for (String p : extPaths) {
            java.io.File f = new java.io.File(p);
            if (f.exists()) return f;
        }

        // 3. Working directory
        java.io.File cwd = new java.io.File("tools/esp32p4-idf6.fidb");
        if (cwd.exists()) return cwd;

        return null;
    }
}
