# SPDX-License-Identifier: Apache-2.0
#
# ESP32-P4 Ghidra Plugin
# Copyright 2026 Alexander Salas Bastidas <ajsb85@firechip.dev>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Headless analysis pre-script for ESP32-P4 firmware.
# Run via: analyzeHeadless <proj> <name> -import <elf> -preScript AnalyzeESP32P4Headless.py
#
# Sets up the analysis environment for best ESP32-P4 decompilation results:
# - Configures analysis options
# - Disables analyzers that produce noise for bare-metal RISC-V
# - Enables the ESP32-P4 custom analyzer
#
# @category ESP32-P4
# @menupath Analysis.ESP32-P4.Configure Headless Analysis

from ghidra.program.model.address import AddressSet
from ghidra.app.util.opinion import LoaderService
from ghidra.framework.options import Options

# Analyzer names to disable (produce noise on bare-metal)
DISABLE_ANALYZERS = [
    "Windows x86 PE RTTI Analyzer",
    "Windows x86 PE Exception Handling",
    "Decompiler Switch Analysis",  # Can be slow; re-enable manually
]

# Analyzer names to enable
ENABLE_ANALYZERS = [
    "ESP32-P4 Firmware Analyzer",
    "RISC-V RVC Compressed Instruction Handler",
    "Non-Returning Functions - Discovered",
    "Non-Returning Functions - Known",
    "Stack",
    "Embedded Media",
    "Data Reference",
    "Function Start Search",
    "Create Address Tables",
]

def configureAnalyzers():
    options = currentProgram.getOptions("Analyzers")
    for name in DISABLE_ANALYZERS:
        try:
            options.setBoolean(name, False)
        except:
            pass  # Not present in this Ghidra version
    for name in ENABLE_ANALYZERS:
        try:
            options.setBoolean(name, True)
        except:
            pass


def main():
    print("ESP32-P4 headless pre-script running...")
    configureAnalyzers()

    lang = currentProgram.getLanguage()
    print("Language: " + str(lang.getLanguageID()))
    print("Program: " + currentProgram.getName())

    mem = currentProgram.getMemory()
    print("Memory blocks:")
    for block in mem.getBlocks():
        print("  %s: 0x%08X - 0x%08X" % (
            block.getName(),
            block.getStart().getOffset(),
            block.getEnd().getOffset()))

    print("Pre-script complete. Analysis will begin.")


main()
