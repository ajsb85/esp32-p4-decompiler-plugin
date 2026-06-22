# Hardware-in-the-loop test configuration for ESP32-P4
# Uses pytest-embedded with IDF service to flash and verify on physical hardware.
#
# Usage:
#   cd test/hil
#   pip install pytest pytest-embedded pytest-embedded-idf pytest-embedded-serial-esp
#   pytest --embedded-services esp,idf --target esp32p4 -v
#
# Environment variables:
#   IDF_PATH     — path to ESP-IDF installation
#   ESPPORT      — serial port (default: auto-detect)
#   ESPBAUD      — baud rate (default: 115200)

import pytest

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "esp32p4: mark test as requiring ESP32-P4 hardware"
    )
    config.addinivalue_line(
        "markers", "hil: hardware-in-the-loop test requiring physical device"
    )
