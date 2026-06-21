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

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * ESP32-P4 memory map constants derived from ESP-IDF soc/esp32p4/include/soc/*.h
 * and the technical reference manual.
 */
public class ESP32P4MemoryMap {

    // Flash (MMU-mapped virtual addresses)
    public static final long IROM_BASE        = 0x40000000L; // Instruction ROM (flash mapped)
    public static final long IROM_SIZE        = 0x02000000L; // 32 MB window
    public static final long DROM_BASE        = 0x40000000L; // Data ROM (flash mapped rodata)
    public static final long PSRAM_BASE       = 0x48000000L; // PSRAM XIP

    // Internal SRAM (TCM - Tightly Coupled Memory)
    public static final long IRAM_BASE        = 0x4FF00000L; // Internal RAM (code)
    public static final long IRAM_SIZE        = 0x000C0000L; // 768 KB
    public static final long DRAM_BASE        = 0x4FF00000L; // DRAM alias of IRAM
    public static final long DRAM_SIZE        = 0x000C0000L;

    // Scratch Pad Memory
    public static final long SPM_BASE         = 0x30100000L; // Scratch Pad Memory
    public static final long SPM_SIZE         = 0x00002000L; // 8 KB

    // LP (Low Power) / RTC Memory
    public static final long LP_RAM_BASE      = 0x50108000L; // LP SRAM
    public static final long LP_RAM_SIZE      = 0x00008000L; // 32 KB

    // HP Peripheral Bus 0 (0x50000000)
    public static final long DR_REG_FLASH_SPI0_BASE     = 0x5008C000L;
    public static final long DR_REG_TIMERG0_BASE        = 0x500C2000L;
    public static final long DR_REG_TIMERG1_BASE        = 0x500C3000L;
    public static final long DR_REG_I2C0_BASE           = 0x500C4000L;
    public static final long DR_REG_I2C1_BASE           = 0x500C5000L;
    public static final long DR_REG_UHCI0_BASE          = 0x500C6000L;
    public static final long DR_REG_UART0_BASE          = 0x500CA000L;
    public static final long DR_REG_UART1_BASE          = 0x500CB000L;
    public static final long DR_REG_UART2_BASE          = 0x500CC000L;
    public static final long DR_REG_UART3_BASE          = 0x500CD000L;
    public static final long DR_REG_UART4_BASE          = 0x500CE000L;
    public static final long DR_REG_GPSPI2_BASE         = 0x500D0000L;
    public static final long DR_REG_GPSPI3_BASE         = 0x500D1000L;
    public static final long DR_REG_LEDC_BASE           = 0x500D6000L;
    public static final long DR_REG_TWAI0_BASE          = 0x500D8000L;
    public static final long DR_REG_TWAI1_BASE          = 0x500D9000L;
    public static final long DR_REG_TWAI2_BASE          = 0x500DA000L;
    public static final long DR_REG_I2S0_BASE           = 0x500DC000L;
    public static final long DR_REG_I2S1_BASE           = 0x500DD000L;
    public static final long DR_REG_I2S2_BASE           = 0x500DE000L;
    public static final long DR_REG_GPIO_BASE           = 0x500E0000L;
    public static final long DR_REG_IO_MUX_BASE         = 0x500E1000L;
    public static final long DR_REG_SYSTIMER_BASE       = 0x500E2000L;
    public static final long DR_REG_MIPI_CSI_BASE       = 0x500E7000L;
    public static final long DR_REG_ISP_BASE            = 0x500E8000L;
    public static final long DR_REG_CAM_BASE            = 0x500EA000L;
    public static final long DR_REG_DMA2D_BASE          = 0x500EB000L;
    public static final long DR_REG_HP_SYSTEM_BASE      = 0x500E5000L;
    public static final long DR_REG_HP_SYS_CLKRST_BASE = 0x500E6000L;

    // Security peripherals
    public static final long DR_REG_AES_BASE            = 0x50090000L;
    public static final long DR_REG_SHA_BASE            = 0x50092000L;
    public static final long DR_REG_RSA_BASE            = 0x50094000L;
    public static final long DR_REG_ECC_BASE            = 0x50096000L;
    public static final long DR_REG_ECDSA_BASE          = 0x50097000L;
    public static final long DR_REG_DS_BASE             = 0x50099000L;
    public static final long DR_REG_HMAC_BASE           = 0x5009B000L;

    // LP (Low-Power) peripherals
    public static final long DR_REG_PMU_BASE            = 0x50115000L;
    public static final long DR_REG_LP_SYS_BASE         = 0x50110000L;
    public static final long DR_REG_LP_TIMER_BASE       = 0x50118000L;
    public static final long DR_REG_LP_WDT_BASE         = 0x50116000L;
    public static final long DR_REG_LP_GPIO_BASE        = 0x5012A000L;
    public static final long DR_REG_LP_IO_MUX_BASE      = 0x5012B000L;
    public static final long DR_REG_LP_UART_BASE        = 0x50124000L;
    public static final long DR_REG_LP_I2C0_BASE        = 0x50125000L;
    public static final long DR_REG_EFUSE_BASE          = 0x5012D000L;
    public static final long DR_REG_LP_CLKRST_BASE      = 0x50112000L;
    public static final long DR_REG_LP_AON_BASE         = 0x50110000L;

    // CPU-specific / intc
    public static final long DR_REG_INTMTX_BASE         = 0x500F0000L;
    public static final long DR_REG_PLIC_BASE           = 0x20000000L; // PLIC for LP core

    /**
     * Returns a map of address → peripheral name for labeling in Ghidra.
     * Peripheral addresses are taken directly from the esp32p4.svd System View Description file.
     * SVD source: /mnt/c/Users/gbast/espressif-jtag/ghidra/esp32p4.svd (89 peripherals)
     */
    public static Map<Long, String> getPeripheralMap() {
        Map<Long, String> map = new LinkedHashMap<>();

        // Debug / Trace (low address range)
        map.put(0x3FF04000L, "TRACE0");
        map.put(0x3FF05000L, "TRACE1");
        map.put(0x3FF06000L, "ASSIST_DEBUG");
        map.put(0x3FF10000L, "CACHE");

        // HP USB / DMA / Media subsystem
        map.put(0x50080000L, "USB_WRAP");
        map.put(0x50081000L, "DMA");
        map.put(0x50083000L, "SDHOST");
        map.put(0x50084000L, "H264");
        map.put(0x50085000L, "AHB_DMA");
        map.put(0x50086000L, "JPEG");
        map.put(0x50087000L, "PPA");
        map.put(0x5008A000L, "AXI_DMA");

        // SPI controllers
        map.put(0x5008C000L, "SPI0");
        map.put(0x5008D000L, "SPI1");

        // Security accelerators
        map.put(0x50090000L, "AES");
        map.put(0x50091000L, "SHA");
        map.put(0x50092000L, "RSA");
        map.put(0x50093000L, "ECC");
        map.put(0x50094000L, "DS");
        map.put(0x50095000L, "HMAC");
        map.put(0x50096000L, "ECDSA");

        // Camera / display / vision processing
        map.put(0x5009E000L, "PVT");
        map.put(0x5009F000L, "MIPI_CSI_HOST");
        map.put(0x5009F800L, "MIPI_CSI_BRIDGE");
        map.put(0x500A0000L, "MIPI_DSI_HOST");
        map.put(0x500A0800L, "MIPI_DSI_BRIDGE");
        map.put(0x500A1000L, "ISP");
        map.put(0x500A3000L, "BITSCRAMBLER");
        map.put(0x500A4000L, "AXI_ICM");
        map.put(0x500A7000L, "H264_DMA");

        // Motor control / timers
        map.put(0x500C0000L, "MCPWM0");
        map.put(0x500C1000L, "MCPWM1");
        map.put(0x500C2000L, "TIMG0");
        map.put(0x500C3000L, "TIMG1");

        // I2C / I2S / audio
        map.put(0x500C4000L, "I2C0");
        map.put(0x500C5000L, "I2C1");
        map.put(0x500C6000L, "I2S0");
        map.put(0x500C7000L, "I2S1");
        map.put(0x500C8000L, "I2S2");
        map.put(0x500C9000L, "PCNT");

        // UART controllers
        map.put(0x500CA000L, "UART0");
        map.put(0x500CB000L, "UART1");
        map.put(0x500CC000L, "UART2");
        map.put(0x500CD000L, "UART3");
        map.put(0x500CE000L, "UART4");

        // Parallel IO / SPI / USB / LEDs / RMT
        map.put(0x500CF000L, "PARL_IO");
        map.put(0x500D0000L, "SPI2");
        map.put(0x500D1000L, "SPI3");
        map.put(0x500D2000L, "USB_DEVICE");
        map.put(0x500D3000L, "LEDC");
        map.put(0x500D4000L, "RMT");
        map.put(0x500D5000L, "SOC_ETM");

        // Interrupt controllers
        map.put(0x500D6000L, "INTERRUPT_CORE0");
        map.put(0x500D6800L, "INTERRUPT_CORE1");

        // CAN / I3C / LCD
        map.put(0x500D7000L, "TWAI0");
        map.put(0x500D8000L, "TWAI1");
        map.put(0x500D9000L, "TWAI2");
        map.put(0x500DA000L, "I3C_MST");
        map.put(0x500DB000L, "I3C_SLV");
        map.put(0x500DC000L, "LCD_CAM");
        map.put(0x500DE000L, "ADC");
        map.put(0x500DF000L, "UHCI0");

        // GPIO / IO_MUX / timers / HP system
        map.put(0x500E0000L, "GPIO");
        map.put(0x500E0F00L, "GPIO_SD");
        map.put(0x500E1000L, "IO_MUX");
        map.put(0x500E2000L, "SYSTIMER");
        map.put(0x500E5000L, "HP_SYS");
        map.put(0x500E6000L, "HP_SYS_CLKRST");

        // LP (Low-Power) subsystem
        map.put(0x50110000L, "LP_SYS");
        map.put(0x50111000L, "LP_AON_CLKRST");
        map.put(0x50112000L, "LP_TIMER");
        map.put(0x50113000L, "LP_ANA_PERI");
        map.put(0x50114000L, "LP_HUK");
        map.put(0x50115000L, "PMU");
        map.put(0x50116000L, "LP_WDT");
        map.put(0x50120000L, "LP_PERI");
        map.put(0x50121000L, "LP_UART");
        map.put(0x50122000L, "LP_I2C0");
        map.put(0x50124000L, "LP_I2C_ANA_MST");
        map.put(0x50125000L, "LP_I2S0");
        map.put(0x50127000L, "LP_ADC");
        map.put(0x50128000L, "LP_TOUCH");
        map.put(0x5012A000L, "LP_GPIO");
        map.put(0x5012B000L, "LP_IO_MUX");
        map.put(0x5012C000L, "LP_INTR");
        map.put(0x5012D000L, "EFUSE");
        map.put(0x5012F000L, "LP_TSENS");

        // PAU (Power Management Unit Assist)
        map.put(0x60093000L, "PAU");

        return map;
    }

    /**
     * Returns true if the address falls within the ESP32-P4 peripheral address space.
     */
    public static boolean isPeripheralAddress(long addr) {
        // HP peripherals: 0x50000000 - 0x5FFFFFFF
        // LP peripherals/AON: 0x50100000 - 0x5013FFFF
        // LP CPU PLIC: 0x20000000
        return (addr >= 0x50000000L && addr < 0x60000000L) ||
               (addr >= 0x20000000L && addr < 0x20100000L);
    }

    /**
     * Returns the peripheral name for an address, or null if not a known peripheral.
     */
    public static String getPeripheralName(long addr) {
        Map<Long, String> periph = getPeripheralMap();
        // Check if addr falls in any peripheral block (1 page = 0x1000 bytes)
        long page = addr & ~0xFFFL;
        return periph.get(page);
    }

    // CSR addresses for hardware loop extension (xesploop)
    public static final int CSR_LOOP0_START = 0x7C6;
    public static final int CSR_LOOP0_END   = 0x7C7;
    public static final int CSR_LOOP0_COUNT = 0x7C8;
    public static final int CSR_LOOP1_START = 0x7C9;
    public static final int CSR_LOOP1_END   = 0x7CA;
    public static final int CSR_LOOP1_COUNT = 0x7CB;
    public static final int CSR_HWLP_STATE  = 0x7F1;

    // CSR addresses for PIE extension (xesppie)
    public static final int CSR_PIE_STATE   = 0x7F2;

    // CSR addresses for DSP/V2 extension (related to xespv2)
    public static final int CSR_DSP_XACC_L = 0x806;
    public static final int CSR_DSP_XACC_H = 0x807;
    public static final int CSR_DSP_SAR     = 0x809;
    public static final int CSR_DSP_STATUS  = 0x80A;
    public static final int CSR_DSP_STATE   = 0x7F3;
}
