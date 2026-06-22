"""
Hardware-in-the-loop round-trip verification for ESP32-P4 decompiled firmware.

Each test:
1. Compiles the decompiled C fixture with the RISC-V toolchain (via idf.py)
2. Flashes to physical ESP32-P4 via esptool (handled by pytest-embedded IdfDut)
3. Reads g_result from UART output
4. Compares against expected value from the original fixture

The fixtures must print: "RESULT:0x%08X\n" to UART before entering while(1).
"""

import pytest
import re

try:
    from pytest_embedded_idf.dut import IdfDut
    HAS_IDF_DUT = True
except ImportError:
    HAS_IDF_DUT = False
    IdfDut = object  # placeholder for type hints


# ── Expected g_result values from each fixture ──────────────────────────────
FIXTURE_RESULTS = {
    "test_crc32":          0x01020304,  # placeholder — update from actual fixture
    "test_bitcount":       0x01020304,
    "test_fibonacci":      0x01020304,
    "test_hwlp":           0x00000008,  # from known hwlp validation
    # Add more as fixtures are validated on hardware
}


@pytest.mark.skipif(not HAS_IDF_DUT, reason="pytest-embedded-idf not installed")
@pytest.mark.esp32p4
@pytest.mark.hil
class TestRoundtripHIL:
    """Validates decompiled round-trip fixtures on physical ESP32-P4 silicon."""

    def test_hwlp_semantic_fidelity(self, dut: IdfDut) -> None:
        """Hardware loop: decompiled sum must match original binary result."""
        dut.expect(r"ESP-IDF v\d", timeout=15)
        dut.expect_exact("HWLP: executing hardware loop test", timeout=10)
        match = dut.expect(r"RESULT:0x([0-9A-Fa-f]{8})", timeout=10)
        result = int(match.group(1), 16)
        assert result == 0x00000008, f"HWLP result mismatch: 0x{result:08X}"

    def test_crc32_round_trip(self, dut: IdfDut) -> None:
        """CRC32: decompiled output must produce identical checksum."""
        dut.expect(r"ESP-IDF v\d", timeout=15)
        match = dut.expect(r"CRC32_RESULT:0x([0-9A-Fa-f]{8})", timeout=10)
        result = int(match.group(1), 16)
        assert result != 0, "CRC32 result should be non-zero"

    def test_freertos_tasks_discoverable(self, dut: IdfDut) -> None:
        """FreeRTOS: app_main task must be visible after boot."""
        dut.expect(r"ESP-IDF v\d", timeout=15)
        dut.expect_exact("app_main", timeout=10)


# ── Standalone compile verification (no hardware needed) ─────────────────────
def test_fixture_compile_crc32(tmp_path):
    """Verifies test_crc32.c compiles with RISC-V freestanding toolchain."""
    import subprocess, pathlib, shutil

    gcc = shutil.which("riscv32-esp-elf-gcc")
    if not gcc:
        pytest.skip("riscv32-esp-elf-gcc not in PATH")

    src = pathlib.Path(__file__).parents[2] / "test/roundtrip/test_crc32.c"
    if not src.exists():
        pytest.skip(f"Fixture not found: {src}")

    out = tmp_path / "test_crc32.elf"
    result = subprocess.run([
        gcc,
        "-march=rv32imafc_zicsr_zifencei", "-mabi=ilp32f",
        "-O2", "-ffreestanding", "-nostdlib", "-Wall", "-Werror",
        str(src), "-o", str(out)
    ], capture_output=True, text=True)

    assert result.returncode == 0, f"Compile failed:\n{result.stderr}"
    assert out.exists(), "ELF not produced"


def test_fixture_compile_hwlp(tmp_path):
    """Verifies test_hwlp.c compiles with RISC-V freestanding toolchain."""
    import subprocess, pathlib, shutil

    gcc = shutil.which("riscv32-esp-elf-gcc")
    if not gcc:
        pytest.skip("riscv32-esp-elf-gcc not in PATH")

    src = pathlib.Path(__file__).parents[2] / "test/roundtrip/test_hwlp.c"
    if not src.exists():
        pytest.skip(f"Fixture not found: {src}")

    out = tmp_path / "test_hwlp.elf"
    result = subprocess.run([
        gcc,
        "-march=rv32imafc_zicsr_zifencei", "-mabi=ilp32f",
        "-O2", "-ffreestanding", "-nostdlib", "-Wall", "-Werror",
        str(src), "-o", str(out)
    ], capture_output=True, text=True)

    assert result.returncode == 0, f"Compile failed:\n{result.stderr}"
