# ESP-IDF Unity test component for hardware-in-the-loop round-trip testing.
# Build: idf.py -C test/hil build
# Flash: idf.py -C test/hil flash monitor

cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS "$ENV{IDF_PATH}/components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32p4_hil_tests)

idf_component_register(
    SRCS "unity_test_runner.c"
    INCLUDE_DIRS "."
    REQUIRES unity freertos esp_hw_support driver
)
