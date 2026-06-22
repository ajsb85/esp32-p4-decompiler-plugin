# IDF Examples for ESP32-P4

Test fixtures built with ESP-IDF targeting the ESP32-P4 (RISC-V, `esp32p4`).

## Examples in this directory

| Directory | Description | IDF Version |
|-----------|-------------|-------------|
| `esp32p4_algorithms/` | CRC32, Fibonacci, prime sieve — core algorithm patterns | v6.0.1 |
| `esp32p4_number_theory/` | Twin prime search — number-theory patterns | v6.0.1 |

## IDF versions in use

### v6.0.1 — examples here (`test/idf_examples/`)

- **IDF path:** `/home/gbast/.espressif/v6.0.1/esp-idf` (or wherever `IDF_PATH` points)
- **Source:** `my_esp32p4_app` project in `/mnt/c/Users/gbast/espressif-jtag/my_esp32p4_app`
- **Build:** `idf.py -p <PORT> build flash monitor`

### v5.5.4 — official dev-kit examples

Pre-built archives and full source are available at:

```
/mnt/c/Users/gbast/espressif-jtag/esp-dev-kits/examples/esp32-p4-function-ev-board/examples/
    esp_brookesia_phone/      (80 archives)
    esp_brookesia_phone_v2/   (127 archives)
    lvgl_demo_v8/             (121 archives)
    lvgl_demo_v9/             (121 archives)

/mnt/c/Users/gbast/espressif-jtag/esp-dev-kits/examples/esp32-p4-eye/examples/
    factory_demo/
```

- **IDF path:** `/home/gbast/.espressif/v5.5.4/esp-idf`
- **eim_config.toml:** `/mnt/c/Users/gbast/espressif-jtag/eim_config.toml`

## CMakeLists.txt patterns

### Minimal project root (v6.0.1 style, used here)

```cmake
cmake_minimum_required(VERSION 3.22)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(my_example)
```

### Dev-kit project root (v5.5.4 style, lvgl_demo_v9)

```cmake
cmake_minimum_required(VERSION 3.5)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
set(EXTRA_COMPONENT_DIRS ../common_components)
add_compile_options(-Wno-format -Wno-ignored-qualifiers)
project(lvgl_demo_v9)
```

### Component CMakeLists.txt

```cmake
idf_component_register(
    SRCS "app_main.c"
    INCLUDE_DIRS ".")
```

## sdkconfig.defaults essentials for ESP32-P4 v3.x silicon

```ini
CONFIG_IDF_TARGET="esp32p4"
CONFIG_FREERTOS_HZ=1000
# Required for v3.x silicon (avoid bootloader rejection):
CONFIG_ESP32P4_SELECTS_REV_LESS_V3=n
CONFIG_ESP32P4_REV_MIN_301=y
# PSRAM (if used):
CONFIG_SPIRAM=y
CONFIG_SPIRAM_SPEED_250M=y
```

## Partition table (dev-kit baseline)

```
# Name,   Type, SubType, Offset,  Size
nvs,      data, nvs,     0x11000, 0x6000
phy_init, data, phy,     0x17000, 0x1000
factory,  app,  factory, ,        8M
storage,  data, spiffs,  ,        7M
```

Set `CONFIG_PARTITION_TABLE_CUSTOM=y` and `CONFIG_PARTITION_TABLE_OFFSET=0x10000` in sdkconfig.defaults when using a custom `partitions.csv`.
