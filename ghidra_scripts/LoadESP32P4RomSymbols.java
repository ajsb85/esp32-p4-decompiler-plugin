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
// Loads ESP32-P4 ROM ELF symbols into the current program.
// This identifies ROM functions (e.g., ets_printf, uart_tx_one_char) that firmware
// calls via direct ROM addresses. The ROM ELF is at:
//   ~/.espressif/tools/esp-rom-elfs/20241011/esp32p4_rev0_rom.elf
//
// Usage:
//   GUI:     Script Manager → ESP32-P4 → Load ROM Symbols  (file chooser appears)
//   Headless: -postScript LoadESP32P4RomSymbols.java /path/to/esp32p4_rev0_rom.elf
//
// When no argument is given the default path is tried automatically:
//   ~/.espressif/tools/esp-rom-elfs/20241011/esp32p4_rev0_rom.elf
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Load ROM Symbols

import java.io.File;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class LoadESP32P4RomSymbols extends GhidraScript {

    // Default ROM ELF path
    private static final String DEFAULT_ROM_ELF =
        System.getProperty("user.home") +
        "/.espressif/tools/esp-rom-elfs/20241011/esp32p4_rev0_rom.elf";

    @Override
    public void run() throws Exception {
        File romElf = null;

        // 1. Script argument (headless: -postScript LoadESP32P4RomSymbols.java <path>)
        String[] scriptArgs = getScriptArgs();
        if (scriptArgs != null && scriptArgs.length > 0 && !scriptArgs[0].isEmpty()) {
            romElf = new File(scriptArgs[0]);
        }

        // 2. Auto-detect default installation path (works headless without a dialog)
        if (romElf == null || !romElf.exists()) {
            File def = new File(DEFAULT_ROM_ELF);
            if (def.exists()) {
                romElf = def;
                println("Auto-detected ROM ELF: " + romElf.getAbsolutePath());
            }
        }

        // 3. GUI file chooser (interactive only; returns null in headless mode)
        if (romElf == null || !romElf.exists()) {
            romElf = askFile("Select ESP32-P4 ROM ELF", "Load");
        }

        if (romElf == null || !romElf.exists()) {
            printerr("ROM ELF not found. Skipping ROM symbol loading.");
            printerr("Install esp-rom-elfs or pass the path as a script argument.");
            return;
        }

        println("Loading ROM symbols from: " + romElf.getAbsolutePath());

        ByteProvider provider = new RandomAccessByteProvider(romElf);
        ElfHeader elf;
        try {
            elf = new ElfHeader(provider, msg -> printerr("ELF: " + msg));
            elf.parse();
        }
        catch (Exception e) {
            printerr("Failed to parse ROM ELF: " + e.getMessage());
            provider.close();
            return;
        }

        SymbolTable symTable = currentProgram.getSymbolTable();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        int added = 0, skipped = 0;

        for (ElfSymbolTable symTab : elf.getSymbolTables()) {
            for (ElfSymbol sym : symTab.getSymbols()) {
                monitor.checkCancelled();

                String name = sym.getNameAsString();
                if (name == null || name.isEmpty() || name.startsWith("$")) continue;

                long value = sym.getValue();
                if (value == 0) {
                    skipped++;
                    continue;
                }

                // RISC-V: Thumb-like bit 0 set means compressed; clear it for address
                long addr = value & ~1L;

                if (!isValidESP32P4RomAddress(addr)) {
                    skipped++;
                    continue;
                }

                try {
                    Address ghidraAddr = space.getAddress(addr);
                    Symbol existing = symTable.getPrimarySymbol(ghidraAddr);
                    if (existing != null && !existing.isDynamic() &&
                        existing.getSource() != SourceType.DEFAULT) {
                        skipped++;
                        continue;
                    }

                    symTable.createLabel(ghidraAddr, name, SourceType.IMPORTED);
                    added++;

                    // If it's a function symbol, also create a function
                    if (sym.getType() == ElfSymbol.STT_FUNC) {
                        Function fn = currentProgram.getListing().getFunctionAt(ghidraAddr);
                        if (fn == null) {
                            createFunction(ghidraAddr, name);
                        }
                    }
                }
                catch (Exception e) {
                    // Skip problematic symbols
                }
            }
        }

        provider.close();
        println(String.format("ROM symbols loaded: %d added, %d skipped", added, skipped));
        println("Functions labeled from ROM ELF will help identify ROM API calls.");
    }

    private boolean isValidESP32P4RomAddress(long addr) {
        // ESP32-P4 ROM (HP ROM) physical address range: 0x4FC00000 - 0x4FD00000
        // (1541 symbols found in esp32p4_rev0_rom.elf in this range)
        // Also accept IRAM, Flash IROM/DROM, and SPM ranges
        return (addr >= 0x4FC00000L && addr < 0x4FD00000L) || // HP ROM
               (addr >= 0x40000000L && addr < 0x48000000L) || // Flash IROM/DROM
               (addr >= 0x4FF00000L && addr < 0x50000000L) || // IRAM/TCM
               (addr >= 0x30100000L && addr < 0x30200000L);   // SPM
    }
}
