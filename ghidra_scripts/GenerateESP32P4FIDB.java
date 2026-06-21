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
// Generates a Ghidra Function ID (FIDB) database from ESP-IDF compiled libraries.
// This enables automatic recognition of ESP-IDF framework functions in firmware.
//
// Requires: A completed ESP32-P4 hello_world build (or any ESP-IDF project build)
// so that the compiled .a static libraries are available for fingerprinting.
//
// Usage:
//  1. Build an ESP32-P4 project: idf.py set-target esp32p4 && idf.py build
//  2. Run this script and point it to the build directory
//  3. The script creates FIDB files in the specified output directory
//  4. Apply the FIDB via: Tools → Function ID → Apply Function ID Files
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Generate ESP-IDF FIDB

import java.io.File;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class GenerateESP32P4FIDB extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== ESP32-P4 FIDB Generator ===");
        println("");
        println("This script helps generate Function ID databases (FIDB) for ESP-IDF.");
        println("");
        println("FIDB generation requires using the full Ghidra FunctionID plugin workflow:");
        println("");
        println("Step 1: Build your ESP32-P4 project with debug info:");
        println("  cd /tmp/esp32p4-hello-build/hello_world");
        println("  idf.py set-target esp32p4 && idf.py build");
        println("");
        println("Step 2: Open Ghidra CodeBrowser with this firmware.");
        println("");
        println("Step 3: Use Tools → Function ID → Create new empty FidDb");
        println("  Name: ESP-IDF-v6.0.1-ESP32P4");
        println("");
        println("Step 4: Use Tools → Function ID → Populate FidDb from Programs");
        println("  - Select the ESP-IDF library ELF/object files");
        println("  - Common library objects are in your build directory:");
        println("    build/esp-idf/*/lib*.a");
        println("");
        println("Step 5: To apply the database:");
        println("  Tools → Function ID → Apply Function ID Files");
        println("");
        println("For command-line FIDB generation using Ghidra headless:");
        println("  analyzeHeadless <project-dir> <project-name> \\");
        println("    -import <lib.elf> \\");
        println("    -processor 'RISCV:LE:32:ESP32-P4' \\");
        println("    -postScript CreateFunctionIDDatabase.java <output.fidb>");
        println("");

        // Find ESP-IDF build directory
        File defaultBuild = new File("/tmp/esp32p4-hello-build/hello_world/build");
        if (defaultBuild.exists()) {
            println("Found ESP32-P4 hello_world build at: " + defaultBuild.getAbsolutePath());
            println("Library archives available:");
            listLibraries(defaultBuild, 0);
        }
        else {
            println("No default build found. Build an ESP32-P4 project first.");
            println("Using eim CLI: eim run v6.0.1 idf.py set-target esp32p4 && idf.py build");
        }

        println("");
        println("ROM ELF for direct ROM function FIDB:");
        File romElf = new File(System.getProperty("user.home") +
            "/.espressif/tools/esp-rom-elfs/20241011/esp32p4_rev0_rom.elf");
        if (romElf.exists()) {
            println("  Found: " + romElf.getAbsolutePath());
            println("  Use LoadESP32P4RomSymbols.java to label ROM calls directly.");
        }
        else {
            println("  Not found at: " + romElf.getAbsolutePath());
        }
    }

    private void listLibraries(File dir, int depth) throws Exception {
        if (depth > 3) return;
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            monitor.checkCancelled();
            if (f.isFile() && (f.getName().endsWith(".a") || f.getName().endsWith(".elf"))) {
                println("  " + "  ".repeat(depth) + f.getName() + " (" + f.length() + " bytes)");
            }
            else if (f.isDirectory() && !f.getName().startsWith(".")) {
                listLibraries(f, depth + 1);
            }
        }
    }
}
