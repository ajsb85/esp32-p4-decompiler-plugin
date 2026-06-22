"""
pytest-embedded integration tests for ESP32-P4 number theory round-trips.

Demonstrates how a bare-metal fixture (test/roundtrip/test_twin_primes.c)
becomes a pytest-embedded test via IdfDut capture of UART RESULT lines.

Run with:
    cd test/idf_examples/esp32p4_number_theory
    idf.py build flash
    pytest --embedded-services esp,idf --target esp32p4 -v
"""
import pytest

try:
    from pytest_embedded_idf.dut import IdfDut
    HAS_IDF_DUT = True
except ImportError:
    HAS_IDF_DUT = False


@pytest.mark.skipif(not HAS_IDF_DUT, reason="pytest-embedded-idf not installed")
@pytest.mark.esp32p4
class TestNumberTheoryRoundTrips:

    def test_twin_primes_result(self, dut: 'IdfDut') -> None:
        """Twin primes below 100: 8 pairs, first_sum mod 256 = 0xEC.

        Expected g_result = 0x006408EC
          high byte  (0x64 = 100) : TP_UPPER
          middle byte (0x08 = 8)  : pair_count
          low byte   (0xEC = 236) : first_sum mod 256
        """
        dut.expect("ESP32-P4 Number Theory Round-Trip Tests starting", timeout=15)
        match = dut.expect(r"RESULT:0x([0-9A-Fa-f]{8})", timeout=10)
        result = int(match.group(1), 16)

        assert result == 0x006408EC, (
            f"Expected 0x006408EC, got 0x{result:08X}\n"
            f"  pair_count = {(result >> 8) & 0xFF} (expected 8)\n"
            f"  first_sum_mod = 0x{result & 0xFF:02X} (expected 0xEC)"
        )

    def test_all_passed(self, dut: 'IdfDut') -> None:
        """All Unity tests must pass (0 failures)."""
        match = dut.expect(r"ALL_TESTS_DONE failed=(\d+)", timeout=30)
        failed = int(match.group(1))
        assert failed == 0, f"{failed} test(s) failed on device"
