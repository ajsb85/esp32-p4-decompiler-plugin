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

// Exports the firmware call graph in two formats:
//
//  1. firmware.dot — Graphviz DOT file
//     Each node is a function.  Nodes are colored by layer:
//       - green  : named IDF functions (FIDB-matched; name doesn't start with FUN_)
//       - yellow : application code (unmatched; all callers/callees are named)
//       - grey   : unknown (FUN_<addr> functions — still unresolved)
//     Edges are directed calls (caller → callee).
//     Render with: dot -Tsvg firmware.dot -o firmware.svg
//
//  2. MODULES.md — module map table
//     Functions are grouped by weakly-connected component (BFS over the
//     undirected call graph).  Each component is a "module".  The table
//     lists every function, its module index, memory region, and caller count.
//
// The script applies a heuristic inspired by the humanify project's
// "context-window" approach: for each function, its naming context is
// the union of its callers, callees, and any IDF names in its neighborhood.
// A function adjacent to only named IDF functions is tagged "app layer".
//
// Arguments (headless): <output-dir>
//   e.g.  -postScript ExportCallGraph.java /tmp/esp32p4-graph
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Export Call Graph

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.util.*;
import java.util.stream.*;

public class ExportCallGraph extends GhidraScript {

    @Override
    public void run() throws Exception {
        // ── resolve output directory ──────────────────────────────────────────
        File outDir;
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            outDir = new File(args[0]);
        } else {
            outDir = askDirectory("Select output directory for call graph", "Select");
            if (outDir == null) {
                outDir = new File(System.getProperty("java.io.tmpdir"),
                        currentProgram.getName() + "-graph");
            }
        }
        outDir.mkdirs();

        // ── build call graph ──────────────────────────────────────────────────
        // fnId: stable integer ID for Graphviz node names.
        Map<String, Integer> fnId     = new LinkedHashMap<>();
        // adjacency list (undirected BFS) and directed edges (DOT).
        Map<String, Set<String>> calls = new LinkedHashMap<>();  // caller → callees
        List<Function> allFns = new ArrayList<>();

        FunctionIterator it = currentProgram.getListing().getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function fn = it.next();
            String name = fn.getName();
            allFns.add(fn);
            fnId.put(name, fnId.size());
            calls.computeIfAbsent(name, k -> new LinkedHashSet<>());
        }

        // Fill edges (in a second pass so all nodes are registered).
        for (Function fn : allFns) {
            monitor.checkCancelled();
            String caller = fn.getName();
            Set<Function> callees = fn.getCalledFunctions(monitor);
            for (Function callee : callees) {
                calls.get(caller).add(callee.getName());
                // Ensure callee is registered (ROM / external functions may be absent).
                calls.computeIfAbsent(callee.getName(), k -> new LinkedHashSet<>());
                fnId.computeIfAbsent(callee.getName(), k -> fnId.size());
            }
        }

        // ── weakly connected components (BFS on undirected graph) ─────────────
        // Build undirected adjacency.
        Map<String, Set<String>> undirected = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> e : calls.entrySet()) {
            String u = e.getKey();
            undirected.computeIfAbsent(u, k -> new LinkedHashSet<>());
            for (String v : e.getValue()) {
                undirected.computeIfAbsent(v, k -> new LinkedHashSet<>());
                undirected.get(u).add(v);
                undirected.get(v).add(u);
            }
        }

        Map<String, Integer> component = new LinkedHashMap<>();
        int[] compId = {0};
        for (String start : fnId.keySet()) {
            if (component.containsKey(start)) continue;
            int cid = compId[0]++;
            Queue<String> queue = new ArrayDeque<>();
            queue.add(start);
            component.put(start, cid);
            while (!queue.isEmpty()) {
                String cur = queue.poll();
                for (String nb : undirected.getOrDefault(cur, Collections.emptySet())) {
                    if (!component.containsKey(nb)) {
                        component.put(nb, cid);
                        queue.add(nb);
                    }
                }
            }
        }
        int totalComponents = compId[0];

        // ── layer classification ───────────────────────────────────────────────
        // "named" = FIDB-matched or ROM — name does NOT look like FUN_<hex>.
        Set<String> namedFns = fnId.keySet().stream()
                .filter(n -> !n.matches("FUN_[0-9A-Fa-f]+"))
                .collect(Collectors.toSet());

        // layer: "idf", "app", or "unknown"
        Map<String, String> layer = new LinkedHashMap<>();
        for (String fn : fnId.keySet()) {
            if (namedFns.contains(fn)) {
                layer.put(fn, "idf");
            } else {
                // If ALL callees are named, this is application code calling IDF.
                Set<String> calleeSet = calls.getOrDefault(fn, Collections.emptySet());
                boolean allCalleeNamed = !calleeSet.isEmpty() &&
                        calleeSet.stream().allMatch(namedFns::contains);
                layer.put(fn, allCalleeNamed ? "app" : "unknown");
            }
        }

        // ── build component size map ──────────────────────────────────────────
        Map<Integer, Integer> compSize = new LinkedHashMap<>();
        for (int cid : component.values())
            compSize.merge(cid, 1, Integer::sum);

        // ── write firmware.dot ────────────────────────────────────────────────
        File dotFile = new File(outDir, "firmware.dot");
        int edgeCount = 0;
        try (PrintWriter pw = new PrintWriter(new FileWriter(dotFile))) {
            pw.println("/* Generated by Ghidra ExportCallGraph */");
            pw.println("/* Program: " + currentProgram.getName() + " */");
            pw.println("/* Render: dot -Tsvg firmware.dot -o firmware.svg */");
            pw.println("digraph firmware {");
            pw.println("  graph [rankdir=LR, fontname=\"monospace\", fontsize=9];");
            pw.println("  node  [shape=box, style=filled, fontname=\"monospace\", fontsize=8];");
            pw.println("  edge  [fontname=\"monospace\", fontsize=7];");
            pw.println();

            // Nodes — only emit if size of component <= 200 to keep DOT manageable.
            // Large programs can have thousands of IDF nodes.
            for (Map.Entry<String, Integer> e : fnId.entrySet()) {
                String fn = e.getKey();
                int id    = e.getValue();
                int cid   = component.getOrDefault(fn, -1);
                if (compSize.getOrDefault(cid, 0) > 200) continue; // skip huge IDF clusters
                String color = switch (layer.getOrDefault(fn, "unknown")) {
                    case "idf"  -> "\"#90ee90\""; // light green
                    case "app"  -> "\"#ffff99\""; // light yellow
                    default     -> "\"#d3d3d3\""; // light grey
                };
                pw.println("  n" + id + " [label=\"" + escape(fn) + "\""
                        + " fillcolor=" + color
                        + " cluster=" + cid + "];");
            }
            pw.println();

            // Edges.
            for (Map.Entry<String, Set<String>> e : calls.entrySet()) {
                String caller = e.getKey();
                int callerId  = fnId.getOrDefault(caller, -1);
                if (callerId < 0) continue;
                int callerCid = component.getOrDefault(caller, -1);
                if (compSize.getOrDefault(callerCid, 0) > 200) continue;
                for (String callee : e.getValue()) {
                    int calleeId = fnId.getOrDefault(callee, -1);
                    if (calleeId < 0) continue;
                    pw.println("  n" + callerId + " -> n" + calleeId + ";");
                    edgeCount++;
                }
            }
            pw.println("}");
        }

        // ── write MODULES.md ──────────────────────────────────────────────────
        // Sort functions by component size (desc) then by name.
        List<String> sorted = new ArrayList<>(fnId.keySet());
        sorted.sort(Comparator
                .<String>comparingInt(n -> -compSize.getOrDefault(component.get(n), 0))
                .thenComparing(n -> n));

        // Build caller-count map.
        Map<String, Integer> callerCount = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> e : calls.entrySet()) {
            for (String callee : e.getValue())
                callerCount.merge(callee, 1, Integer::sum);
        }

        // Memory region lookup.
        Map<String, String> region = new LinkedHashMap<>();
        for (Function fn : allFns) {
            MemoryBlock b = currentProgram.getMemory().getBlock(fn.getEntryPoint());
            region.put(fn.getName(), b != null ? b.getName() : "?");
        }

        File mdFile = new File(outDir, "MODULES.md");
        try (PrintWriter pw = new PrintWriter(new FileWriter(mdFile))) {
            pw.println("# Firmware Module Map");
            pw.println();
            pw.println("Generated from: `" + currentProgram.getName() + "`");
            pw.println("Components: " + totalComponents
                    + " | Functions: " + fnId.size()
                    + " | Named (IDF/ROM): " + namedFns.size());
            pw.println();
            pw.println("| Module | Size | Layer | Region | Callers | Function |");
            pw.println("|--------|------|-------|--------|---------|----------|");
            for (String fn : sorted) {
                int cid   = component.getOrDefault(fn, -1);
                int size  = compSize.getOrDefault(cid, 0);
                String lay = layer.getOrDefault(fn, "?");
                String reg = region.getOrDefault(fn, "?");
                int callers = callerCount.getOrDefault(fn, 0);
                pw.println("| " + cid + " | " + size + " | " + lay
                        + " | " + reg + " | " + callers + " | `" + fn + "` |");
            }
        }

        println(String.format(
            "Call graph: %d nodes, %d edges, %d components → %s",
            fnId.size(), edgeCount, totalComponents, outDir.getAbsolutePath()));
        println("  DOT file: " + dotFile.getAbsolutePath());
        println("  Modules:  " + mdFile.getAbsolutePath());
        println("Render with: dot -Tsvg firmware.dot -o firmware.svg");
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
