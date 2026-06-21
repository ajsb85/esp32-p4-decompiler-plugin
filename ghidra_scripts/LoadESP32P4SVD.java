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
// Loads ESP32-P4 peripheral registers from an SVD (System View Description) file
// into the current Ghidra program.
//
// The SVD file defines all peripheral registers with names, offsets, and descriptions.
// This script creates memory blocks for each peripheral and labels every register.
//
// Default SVD path: ~/.espressif/tools/... (not bundled) OR
//   /mnt/c/Users/gbast/espressif-jtag/ghidra/esp32p4.svd
//
// Usage: Run via Script Manager while viewing an ESP32-P4 firmware.
//        Select the esp32p4.svd file when prompted.
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Load SVD Peripheral Registers

import java.io.File;
import java.util.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class LoadESP32P4SVD extends GhidraScript {

    private static final String DEFAULT_SVD =
        "/mnt/c/Users/gbast/espressif-jtag/ghidra/esp32p4.svd";

    @Override
    public void run() throws Exception {
        File svdFile = askFile("Select ESP32-P4 SVD file", "Load");
        if (svdFile == null) {
            File def = new File(DEFAULT_SVD);
            if (def.exists()) {
                int ans = askInt("Use default?",
                    "SVD found at: " + DEFAULT_SVD + "\n\nEnter 1 to use it, 0 to cancel:");
                if (ans == 1) svdFile = def;
            }
            if (svdFile == null) {
                printerr("No SVD file selected.");
                return;
            }
        }

        println("Loading ESP32-P4 SVD from: " + svdFile.getAbsolutePath());

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(svdFile);
        doc.getDocumentElement().normalize();

        NodeList peripheralList = doc.getElementsByTagName("peripheral");
        int periCount = 0, regCount = 0;

        Memory mem = currentProgram.getMemory();
        SymbolTable symTable = currentProgram.getSymbolTable();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        for (int i = 0; i < peripheralList.getLength(); i++) {
            monitor.checkCancelled();

            Element peripheral = (Element) peripheralList.item(i);
            String periName = getTagText(peripheral, "name");
            String periDesc = getTagText(peripheral, "description");
            String baseHex  = getTagText(peripheral, "baseAddress");

            if (periName == null || baseHex == null) continue;

            long baseAddr;
            try {
                baseAddr = Long.decode(baseHex);
            } catch (NumberFormatException e) {
                continue;
            }

            Address periBase = space.getAddress(baseAddr);

            // Determine peripheral size from registers
            long maxOffset = 0x100; // minimum 256 bytes
            NodeList regs = peripheral.getElementsByTagName("register");
            for (int r = 0; r < regs.getLength(); r++) {
                Element reg = (Element) regs.item(r);
                String offHex = getTagText(reg, "addressOffset");
                if (offHex != null) {
                    try {
                        long off = Long.decode(offHex);
                        if (off + 4 > maxOffset) maxOffset = off + 4;
                    } catch (NumberFormatException ignore) {}
                }
            }
            // Round up to 4K or next power of 2
            long periSize = Math.max(0x1000, Long.highestOneBit(maxOffset - 1) << 1);

            // Create or find memory block for this peripheral
            MemoryBlock block = mem.getBlock(periBase);
            if (block == null) {
                try {
                    block = mem.createUninitializedBlock(periName, periBase, periSize, false);
                    block.setVolatile(true);
                    block.setWrite(true);
                    block.setRead(true);
                    block.setComment(periDesc != null ? periDesc.trim() : periName);
                } catch (Exception e) {
                    // Block may already exist (overlapping peripherals)
                    block = mem.getBlock(periBase);
                }
            }

            // Label the peripheral base address
            try {
                symTable.createLabel(periBase, periName + "_BASE", SourceType.IMPORTED);
            } catch (Exception ignore) {}

            periCount++;

            // Label each register
            for (int r = 0; r < regs.getLength(); r++) {
                monitor.checkCancelled();
                Element reg = (Element) regs.item(r);
                String regName = getTagText(reg, "name");
                String regOff  = getTagText(reg, "addressOffset");
                String regDesc = getTagText(reg, "description");

                if (regName == null || regOff == null) continue;

                long offset;
                try {
                    offset = Long.decode(regOff);
                } catch (NumberFormatException e) {
                    continue;
                }

                Address regAddr = space.getAddress(baseAddr + offset);
                String label = periName + "_" + regName;

                try {
                    symTable.createLabel(regAddr, label, SourceType.IMPORTED);
                    if (regDesc != null && !regDesc.isEmpty()) {
                        setPlateComment(regAddr, regDesc.trim());
                    }
                    regCount++;
                } catch (Exception ignore) {}
            }
        }

        println(String.format("SVD loaded: %d peripherals, %d registers labeled.", periCount, regCount));
        println("Peripheral memory blocks created and labeled.");
        println("Register labels are searchable in the Symbol Table (Window > Symbol Table).");
    }

    private String getTagText(Element parent, String tagName) {
        NodeList nl = parent.getElementsByTagName(tagName);
        if (nl.getLength() == 0) return null;
        Node n = nl.item(0);
        // Only get direct children, not descendants
        if (n.getParentNode() != parent) {
            // Search direct children only
            NodeList children = parent.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                Node child = children.item(i);
                if (child instanceof Element && tagName.equals(child.getNodeName())) {
                    return child.getTextContent().trim();
                }
            }
            return null;
        }
        return n.getTextContent().trim();
    }

    private void setPlateComment(Address addr, String comment) {
        try {
            currentProgram.getListing().setComment(addr,
                CodeUnit.PLATE_COMMENT, comment);
        } catch (Exception ignore) {}
    }
}
