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
package esp32p4ghidra;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.io.File;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

/**
 * Main Ghidra plugin for ESP32-P4 firmware decompilation support.
 *
 * Provides a tool window with quick-access actions for:
 * - Loading ESP32-P4 ROM symbols from ROM ELF
 * - Applying ESP-IDF FIDB for function identification
 * - Re-running the ESP32-P4 analyzer
 * - Showing memory map reference
 */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "ESP32-P4",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "ESP32-P4 RISC-V Decompiler Support",
    description = "Supports decompilation of ESP32-P4 firmwares: memory map labeling, " +
                  "ROM symbol import, ESP-IDF FIDB, hardware loop and PIE SIMD annotation."
)
public class ESP32P4Plugin extends ProgramPlugin {

    private ESP32P4Provider provider;

    public ESP32P4Plugin(PluginTool tool) {
        super(tool);
        provider = new ESP32P4Provider(this, getName());
        String topicName = this.getClass().getPackage().getName();
        provider.setHelpLocation(new HelpLocation(topicName, "ESP32P4Plugin"));
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    protected void programActivated(Program program) {
        provider.setProgram(program);
    }

    @Override
    protected void programDeactivated(Program program) {
        provider.setProgram(null);
    }

    // -------------------------------------------------------------------------
    // Provider (UI panel)
    // -------------------------------------------------------------------------

    static class ESP32P4Provider extends ComponentProvider {

        private JPanel panel;
        private JTextArea statusArea;
        private Program currentProgram;
        private ESP32P4Plugin plugin;

        ESP32P4Provider(ESP32P4Plugin plugin, String owner) {
            super(plugin.getTool(), "ESP32-P4 Firmware", owner);
            this.plugin = plugin;
            buildPanel();
            createActions();
            setVisible(true);
        }

        void setProgram(Program program) {
            this.currentProgram = program;
            updateStatus();
        }

        private void buildPanel() {
            panel = new JPanel(new BorderLayout(5, 5));

            // Header
            JLabel header = new JLabel("ESP32-P4 Decompiler Plugin", JLabel.CENTER);
            header.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));
            panel.add(header, BorderLayout.NORTH);

            // Status area
            statusArea = new JTextArea(8, 40);
            statusArea.setEditable(false);
            statusArea.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 11));
            statusArea.setText("No program loaded.\n\nOpen an ESP32-P4 ELF binary to begin.");
            panel.add(new JScrollPane(statusArea), BorderLayout.CENTER);

            // Button panel
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
            buttons.add(makeButton("Load ROM Symbols", this::loadRomSymbols));
            buttons.add(makeButton("Re-Run Analysis", this::reRunAnalysis));
            buttons.add(makeButton("Show Memory Map", this::showMemoryMap));
            panel.add(buttons, BorderLayout.SOUTH);
        }

        private JButton makeButton(String label, Runnable action) {
            JButton btn = new JButton(label);
            btn.addActionListener(e -> action.run());
            return btn;
        }

        private void createActions() {
            DockingAction refreshAction = new DockingAction("Refresh ESP32-P4 Status", getOwner()) {
                @Override
                public void actionPerformed(ActionContext context) {
                    updateStatus();
                }
            };
            refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
            refreshAction.markHelpUnnecessary();
            dockingTool.addLocalAction(this, refreshAction);
        }

        private void updateStatus() {
            if (currentProgram == null) {
                statusArea.setText("No program loaded.");
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Program: ").append(currentProgram.getName()).append("\n");
            sb.append("Language: ").append(currentProgram.getLanguage().getLanguageID()).append("\n");
            sb.append("Entry: 0x").append(
                Long.toHexString(currentProgram.getMinAddress().getOffset())).append("\n\n");

            sb.append("Memory Blocks:\n");
            for (var block : currentProgram.getMemory().getBlocks()) {
                sb.append(String.format("  %-20s 0x%08X - 0x%08X (%s)\n",
                    block.getName(),
                    block.getStart().getOffset(),
                    block.getEnd().getOffset(),
                    block.isExecute() ? "X" : (block.isWrite() ? "W" : "R")));
            }
            statusArea.setText(sb.toString());
        }

        private void loadRomSymbols() {
            if (currentProgram == null) {
                Msg.showWarn(this, panel, "No Program", "Open an ESP32-P4 binary first.");
                return;
            }
            // Default ROM ELF path (from ESP-IDF tools)
            File defaultRomElf = new File(
                System.getProperty("user.home") +
                "/.espressif/tools/esp-rom-elfs/20241011/esp32p4_rev0_rom.elf");

            JFileChooser chooser = new JFileChooser(defaultRomElf.exists() ?
                defaultRomElf.getParentFile() : new File(System.getProperty("user.home")));
            chooser.setDialogTitle("Select ESP32-P4 ROM ELF");
            chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "ELF files (*.elf)", "elf"));
            if (defaultRomElf.exists()) {
                chooser.setSelectedFile(defaultRomElf);
            }

            int result = chooser.showOpenDialog(panel);
            if (result != JFileChooser.APPROVE_OPTION) return;

            File romElf = chooser.getSelectedFile();
            if (!romElf.exists()) {
                Msg.showError(this, panel, "File Not Found", "ROM ELF not found: " + romElf);
                return;
            }

            // Run the ROM symbol loading script
            Msg.showInfo(this, panel, "Load ROM Symbols",
                "ROM ELF: " + romElf.getAbsolutePath() + "\n\n" +
                "To load ROM symbols, run the Ghidra script:\n" +
                "  LoadESP32P4RomSymbols.java\n" +
                "and point it to this ROM ELF file.\n\n" +
                "Or use: File → Import File, then set Language to RISCV:LE:32:ESP32-P4\n" +
                "and use the 'Merge' option to import symbols into the current program.");
        }

        private void reRunAnalysis() {
            if (currentProgram == null) {
                Msg.showWarn(this, panel, "No Program", "Open an ESP32-P4 binary first.");
                return;
            }
            Msg.showInfo(this, panel, "Re-Run Analysis",
                "To re-run the ESP32-P4 analyzer:\n\n" +
                "1. Go to Analysis → Auto Analyze (or press 'A')\n" +
                "2. Ensure 'ESP32-P4 Firmware Analyzer' is checked\n" +
                "3. Click Analyze\n\n" +
                "This will re-label peripherals and annotate hardware loops.");
        }

        private void showMemoryMap() {
            StringBuilder sb = new StringBuilder("ESP32-P4 Memory Map Reference\n");
            sb.append("=".repeat(50)).append("\n\n");
            sb.append(String.format("%-30s  %s\n", "Region", "Address"));
            sb.append("-".repeat(50)).append("\n");
            sb.append(String.format("%-30s  0x%08X\n", "Flash IROM (virtual)",   0x40000000));
            sb.append(String.format("%-30s  0x%08X\n", "PSRAM (XIP virtual)",    0x48000000));
            sb.append(String.format("%-30s  0x%08X\n", "IRAM / TCM",             0x4FF00000));
            sb.append(String.format("%-30s  0x%08X\n", "SPM (Scratch Pad)",      0x30100000));
            sb.append(String.format("%-30s  0x%08X\n", "LP RAM / RTC",           0x50108000));
            sb.append(String.format("%-30s  0x%08X\n", "HP Periph base",         0x50000000));
            sb.append(String.format("%-30s  0x%08X\n", "LP Periph base",         0x50110000));
            sb.append("\n");
            sb.append("Key peripherals:\n");
            for (var e : ESP32P4MemoryMap.getPeripheralMap().entrySet()) {
                sb.append(String.format("  %-20s 0x%08X\n", e.getValue(), e.getKey()));
            }
            sb.append("\nHardware Loop CSRs:\n");
            sb.append(String.format("  LOOP0_START  CSR 0x%03X\n", ESP32P4MemoryMap.CSR_LOOP0_START));
            sb.append(String.format("  LOOP0_END    CSR 0x%03X\n", ESP32P4MemoryMap.CSR_LOOP0_END));
            sb.append(String.format("  LOOP0_COUNT  CSR 0x%03X\n", ESP32P4MemoryMap.CSR_LOOP0_COUNT));
            sb.append(String.format("  LOOP1_START  CSR 0x%03X\n", ESP32P4MemoryMap.CSR_LOOP1_START));
            sb.append(String.format("  LOOP1_END    CSR 0x%03X\n", ESP32P4MemoryMap.CSR_LOOP1_END));
            sb.append(String.format("  LOOP1_COUNT  CSR 0x%03X\n", ESP32P4MemoryMap.CSR_LOOP1_COUNT));
            sb.append(String.format("  HWLP_STATE   CSR 0x%03X\n", ESP32P4MemoryMap.CSR_HWLP_STATE));
            sb.append(String.format("  PIE_STATE    CSR 0x%03X\n", ESP32P4MemoryMap.CSR_PIE_STATE));

            JTextArea ta = new JTextArea(sb.toString());
            ta.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 11));
            ta.setEditable(false);
            JScrollPane sp = new JScrollPane(ta);
            sp.setPreferredSize(new java.awt.Dimension(600, 500));
            JOptionPane.showMessageDialog(panel, sp, "ESP32-P4 Memory Map",
                JOptionPane.INFORMATION_MESSAGE);
        }

        @Override
        public JComponent getComponent() {
            return panel;
        }
    }
}
