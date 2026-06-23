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
// Loads ESP32-P4 peripheral registers from the bundled SVD file (data/esp32p4.svd)
// into the current Ghidra program.
//
// For each peripheral the script:
//   1. Creates an uninitialized volatile memory block at the peripheral base address.
//   2. Builds a C-style Structure in the DataTypeManager with one uint32_t field per register.
//   3. Applies the structure at the base address so that decompiled code shows
//      UART0->FIFO instead of *(uint *)(0x500c0000 + 0).
//   4. Labels every register address in the Symbol Table for cross-reference.
//
// Usage: Run via Script Manager while viewing an ESP32-P4 firmware.
//        The bundled data/esp32p4.svd is used automatically; a file-chooser
//        dialog appears if the bundled file cannot be found.
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Load SVD Peripheral Registers

import java.io.File;
import java.util.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class LoadESP32P4SVD extends GhidraScript {

    @Override
    public void run() throws Exception {
        File svdFile = resolveBundledSvd();
        if (svdFile == null) {
            svdFile = askFile("Select ESP32-P4 SVD file", "Load");
        }
        if (svdFile == null || !svdFile.exists()) {
            printerr("No SVD file found. Place data/esp32p4.svd next to the ghidra_scripts/ directory.");
            return;
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
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        // Category in DataTypeManager for all generated structs
        CategoryPath svdCat = new CategoryPath("/ESP32P4_SVD");

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

            // Collect registers for this peripheral
            NodeList regs = peripheral.getElementsByTagName("register");
            List<long[]>   offsets   = new ArrayList<>();
            List<String>   regNames  = new ArrayList<>();
            List<String>   regDescs  = new ArrayList<>();

            long maxOffset = 0x100;
            for (int r = 0; r < regs.getLength(); r++) {
                Element reg = (Element) regs.item(r);
                String regName = getTagText(reg, "name");
                String offHex  = getTagText(reg, "addressOffset");
                String regDesc = getTagText(reg, "description");
                if (regName == null || offHex == null) continue;
                try {
                    long off = Long.decode(offHex);
                    if (off + 4 > maxOffset) maxOffset = off + 4;
                    offsets.add(new long[]{off});
                    regNames.add(regName);
                    regDescs.add(regDesc != null ? regDesc.trim() : "");
                } catch (NumberFormatException ignore) {}
            }

            long periSize = Math.max(0x1000, Long.highestOneBit(maxOffset - 1) << 1);

            // ------------------------------------------------------------------
            // 1. Memory block
            // ------------------------------------------------------------------
            MemoryBlock block = mem.getBlock(periBase);
            // Skip any peripheral whose base address falls inside an existing
            // executable block (IRAM/ROM code) — applying a struct there would
            // corrupt disassembly and hang the decompiler indefinitely.
            if (block != null && block.isExecute()) {
                continue;
            }
            if (block == null) {
                try {
                    block = mem.createUninitializedBlock(periName, periBase, periSize, false);
                    block.setVolatile(true);
                    block.setWrite(true);
                    block.setRead(true);
                    block.setExecute(false);
                    block.setComment(periDesc != null ? periDesc.trim() : periName);
                } catch (Exception e) {
                    block = mem.getBlock(periBase);
                    // Re-check after exception: skip if it turned out executable
                    if (block != null && block.isExecute()) continue;
                }
            }

            // ------------------------------------------------------------------
            // 2. DataTypeManager struct: one uint32_t field per register + padding
            // ------------------------------------------------------------------
            StructureDataType struct = new StructureDataType(svdCat, periName + "_t",
                (int) periSize, dtm);
            DataType u32 = dtm.getDataType(new CategoryPath("/"), "uint");
            if (u32 == null) u32 = new DWordDataType();

            // Fill the struct at exact offsets; gaps become padding arrays
            long cursor = 0;
            for (int r = 0; r < offsets.size(); r++) {
                long off = offsets.get(r)[0];
                if (off > cursor) {
                    // insert padding
                    ArrayDataType pad = new ArrayDataType(new ByteDataType(), (int)(off - cursor), 1);
                    struct.insertAtOffset((int) cursor, pad, (int)(off - cursor),
                        "_pad_" + Long.toHexString(cursor), "");
                }
                String fieldComment = regDescs.get(r);
                struct.insertAtOffset((int) off, u32, 4, regNames.get(r),
                    fieldComment.length() > 120 ? fieldComment.substring(0, 120) : fieldComment);
                cursor = off + 4;
            }

            // Commit struct to DataTypeManager
            try {
                DataType existing = dtm.getDataType(svdCat, periName + "_t");
                if (existing != null) {
                    dtm.remove(existing, monitor);
                }
                dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
            } catch (Exception ignore) {}

            // ------------------------------------------------------------------
            // 3. Apply struct at base address
            // ------------------------------------------------------------------
            try {
                if (block != null) {
                    DataType committed = dtm.getDataType(svdCat, periName + "_t");
                    if (committed != null) {
                        currentProgram.getListing().createData(periBase, committed);
                    }
                }
            } catch (Exception ignore) {}

            // ------------------------------------------------------------------
            // 4. Symbol table labels
            // ------------------------------------------------------------------
            try {
                symTable.createLabel(periBase, periName + "_BASE", SourceType.IMPORTED);
            } catch (Exception ignore) {}

            for (int r = 0; r < regNames.size(); r++) {
                monitor.checkCancelled();
                Address regAddr = space.getAddress(baseAddr + offsets.get(r)[0]);
                String label = periName + "_" + regNames.get(r);
                try {
                    symTable.createLabel(regAddr, label, SourceType.IMPORTED);
                    String desc = regDescs.get(r);
                    if (!desc.isEmpty()) applyPlateComment(regAddr, desc);
                    regCount++;
                } catch (Exception ignore) {}
            }

            periCount++;
        }

        println(String.format(
            "SVD loaded: %d peripherals, %d registers. Structs added to DataTypeManager under /ESP32P4_SVD.",
            periCount, regCount));
        println("Peripheral structs are now visible in the Data Type Manager (Window > Data Type Manager).");
        println("Decompiled code will show PERIPHERAL->REGISTER instead of raw pointer arithmetic.");
    }

    /** Resolves data/esp32p4.svd — checks script dir, extension dir, and home. */
    private File resolveBundledSvd() {
        // 1. Via ResourceFile (works when script is on filesystem, not in JAR)
        try {
            generic.jar.ResourceFile rf = getSourceFile();
            java.io.File f = rf.getFile(false);
            if (f != null) {
                java.io.File bundled = new java.io.File(f.getParentFile().getParent(), "data/esp32p4.svd");
                if (bundled.exists()) return bundled;
            }
        } catch (Exception ignore) {}

        // 2. Relative to Ghidra user extension dir
        String[] extCandidates = {
            System.getProperty("user.home") + "/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/esp32p4-ghidra-plugin/data/esp32p4.svd",
            System.getProperty("user.home") + "/.ghidra/.ghidra_12.1.2_PUBLIC/Extensions/esp32p4-ghidra-plugin/data/esp32p4.svd",
        };
        for (String path : extCandidates) {
            java.io.File f = new java.io.File(path);
            if (f.exists()) return f;
        }

        // 3. Working directory (useful for headless runs from repo root)
        java.io.File cwd = new java.io.File("data/esp32p4.svd");
        if (cwd.exists()) return cwd;

        return null;
    }

    private String getTagText(Element parent, String tagName) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child instanceof Element && tagName.equals(child.getNodeName())) {
                return child.getTextContent().trim();
            }
        }
        return null;
    }

    private void applyPlateComment(Address addr, String comment) {
        try {
            currentProgram.getListing().setComment(addr, ghidra.program.model.listing.CommentType.PLATE, comment);
        } catch (Exception ignore) {}
    }
}
