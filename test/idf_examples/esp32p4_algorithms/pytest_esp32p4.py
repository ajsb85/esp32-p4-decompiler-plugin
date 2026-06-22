"""
pytest-embedded integration tests for ESP32-P4 algorithm round-trips.

Run with:
    cd test/idf_examples/esp32p4_algorithms
    idf.py build flash
    pytest --embedded-services esp,idf --target esp32p4 -v
"""
import pytest
import re

try:
    from pytest_embedded_idf.dut import IdfDut
    HAS_IDF_DUT = True
except ImportError:
    HAS_IDF_DUT = False


@pytest.mark.skipif(not HAS_IDF_DUT, reason="pytest-embedded-idf not installed")
@pytest.mark.esp32p4
class TestAlgorithmRoundTrips:

    def test_crc32_round_trip(self, dut: 'IdfDut') -> None:
        """CRC32 of 'ESP32P4' produces deterministic result."""
        dut.expect("ESP32-P4 Algorithm Round-Trip Tests starting", timeout=15)
        match = dut.expect(r"CRC32_RESULT:0x([0-9A-Fa-f]{8})", timeout=10)
        result = int(match.group(1), 16)
        assert result != 0, "CRC32 result must be non-zero"
        # Verify count byte (high byte) = 7 (length of "ESP32P4")
        assert (result >> 16) & 0xFF == 7, f"Unexpected count byte: 0x{result:08X}"

    def test_fibonacci_round_trip(self, dut: 'IdfDut') -> None:
        """Fibonacci counter produces exactly 19 values below 10000."""
        match = dut.expect(r"FIBONACCI_RESULT:0x([0-9A-Fa-f]{8})", timeout=10)
        result = int(match.group(1), 16)
        count = (result >> 16) & 0xFF
        assert count == 19, f"Expected 19 Fibonacci values, got {count}"

    def test_primes_round_trip(self, dut: 'IdfDut') -> None:
        """Sieve finds exactly 25 primes below 100."""
        match = dut.expect(r"PRIMES_RESULT:0x([0-9A-Fa-f]{8})", timeout=10)
        result = int(match.group(1), 16)
        count = (result >> 16) & 0xFF
        assert count == 25, f"Expected 25 primes < 100, got {count}"

    def test_all_passed(self, dut: 'IdfDut') -> None:
        """All Unity tests must pass."""
        match = dut.expect(r"ALL_TESTS_DONE failed=(\d+)", timeout=30)
        failed = int(match.group(1))
        assert failed == 0, f"{failed} test(s) failed"
