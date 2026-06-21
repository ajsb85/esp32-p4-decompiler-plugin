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

/*
 * ghidra_types.h — type stubs for recompiling Ghidra decompiler output.
 *
 * Ghidra's DecompInterface emits C using its own type aliases that are
 * not part of any standard header.  Include this file (via -include or
 * #include) when recompiling exported decompiled C:
 *
 *   riscv32-esp-elf-gcc -include ghidra_types.h decompiled.c ...
 *
 * Global variables referenced in decompiled function bodies but not
 * declared there must be declared manually before the first use.
 */

#pragma once
#include <stdint.h>

/* Ghidra undefined-size placeholders */
typedef uint8_t  undefined;
typedef uint8_t  undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined4;
typedef uint64_t undefined8;

/* Ghidra short aliases for unsigned types */
typedef unsigned char  uchar;
typedef unsigned short ushort;
typedef unsigned int   uint;
typedef unsigned long  ulong;

/* Ghidra short alias for signed char */
typedef signed char schar;
