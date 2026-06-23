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
// Reads semantic_hints.json (produced by DetectSemanticPatterns.java) and applies
// the suggested renames back to the current Ghidra program.
//
// Rules applied per function entry:
//   confidence=high   → rename if current name starts with FUN_ or thunk_FUN_
//   confidence=medium → add plate comment "Semantic hint: <name>" (no rename)
//
// FIDB/user names always win: the rename uses SourceType.ANALYSIS so any
// existing IMPORTED or USER_DEFINED label is left untouched.
//
// This script closes the feedback loop that DetectSemanticPatterns.java opens:
// instead of writing hints to a file and stopping, the analysis is pushed back
// into the Ghidra database so every subsequent decompiler view and export uses
// the recovered names.
//
// ── Arguments (headless) ─────────────────────────────────────────────────────
//   -postScript ApplySemanticHints.java /path/to/semantic_hints.json
//
// When no argument is given the script looks for
//   ~/<program_name>_semantic_hints.json
// which is the default output path of DetectSemanticPatterns.java.
//
// ── Typical pipeline position ─────────────────────────────────────────────────
//   DetectSemanticPatterns.java → (this script) → ExportDecompiledC.java
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Apply Semantic Hints

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.regex.*;

public class ApplySemanticHints extends GhidraScript {

    @Override
    public void run() throws Exception {
        File hintsFile = resolveHintsFile();
        if (hintsFile == null || !hintsFile.exists()) {
            printerr("semantic_hints.json not found. Run DetectSemanticPatterns.java first.");
            printerr("Expected: " + (hintsFile != null ? hintsFile.getAbsolutePath() : "unknown"));
            return;
        }

        println("Reading semantic hints from: " + hintsFile.getAbsolutePath());
        String json = new String(Files.readAllBytes(hintsFile.toPath()), StandardCharsets.UTF_8);

        // Each function block is a flat JSON object written by DetectSemanticPatterns.writeJson().
        // We match across the entire object including the evidence array (no nested objects).
        Pattern blockPat = Pattern.compile(
                "\\{[^{}]*\"address\"[^{}]*\\}", Pattern.DOTALL);
        Matcher blockMatcher = blockPat.matcher(json);

        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        FunctionManager fm  = currentProgram.getFunctionManager();

        int renamed   = 0;
        int commented = 0;
        int skipped   = 0;

        while (blockMatcher.find()) {
            monitor.checkCancelled();
            String block = blockMatcher.group();

            String addr          = extractField(block, "address");
            String suggestedName = extractField(block, "suggested_name");
            String confidence    = extractField(block, "confidence");

            // Skip entries without a match (pattern=null in JSON)
            if (addr == null) continue;
            if (suggestedName == null || "null".equals(suggestedName)) continue;
            if (confidence    == null || "null".equals(confidence))    continue;

            long offset;
            try {
                offset = Long.decode(addr);
            } catch (NumberFormatException e) {
                continue;
            }

            Address funcAddr = space.getAddress(offset);
            Function fn = fm.getFunctionAt(funcAddr);
            if (fn == null) { skipped++; continue; }

            // Only touch functions that Ghidra has not yet given a meaningful name.
            String currentName = fn.getName();
            boolean isUnresolved = currentName.startsWith("FUN_")
                                || currentName.startsWith("thunk_FUN_");

            if (!isUnresolved) {
                skipped++;
                continue;
            }

            if ("high".equals(confidence)) {
                try {
                    fn.setName(suggestedName, SourceType.ANALYSIS);
                    renamed++;
                } catch (Exception e) {
                    printerr("Rename failed at " + addr + ": " + e.getMessage());
                    skipped++;
                }
            } else if ("medium".equals(confidence)) {
                try {
                    currentProgram.getListing().setComment(
                            funcAddr,
                            ghidra.program.model.listing.CommentType.PLATE,
                            "Semantic hint: " + suggestedName + " (medium confidence)");
                    commented++;
                } catch (Exception e) {
                    skipped++;
                }
            } else {
                skipped++;
            }
        }

        println(String.format(
                "ApplySemanticHints: %d renamed (high), %d plate-commented (medium), %d skipped",
                renamed, commented, skipped));

        if (renamed > 0) {
            println("Re-run ExportDecompiledC.java to get output with recovered names.");
        }
    }

    /**
     * Extract a JSON string value (or the token "null") from a flat object block.
     * Returns null if the field is absent; returns "null" if the JSON value is null.
     */
    private String extractField(String block, String field) {
        Pattern p = Pattern.compile(
                "\"" + Pattern.quote(field) + "\"\\s*:\\s*(?:\"([^\"]*)\"|null)");
        Matcher m = p.matcher(block);
        if (!m.find()) return null;
        // group(1) is set for string values; null group means the JSON value was null
        return m.group(1) != null ? m.group(1) : "null";
    }

    /** Resolve semantic_hints.json from script arg or DetectSemanticPatterns default path. */
    private File resolveHintsFile() {
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            return new File(args[0]);
        }
        // Match the default path written by DetectSemanticPatterns.java
        String name = currentProgram.getName().replaceAll("[^\\w.-]", "_")
                    + "_semantic_hints.json";
        File homeFile = new File(System.getProperty("user.home"), name);
        if (homeFile.exists()) return homeFile;
        // Last resort: current working directory
        return new File(name);
    }
}
