idf_component_register(
    SRCS
        "app_main.c"
        "test_crc32_idf.c"
        "test_fibonacci_idf.c"
        "test_primes_idf.c"
    INCLUDE_DIRS "."
    REQUIRES unity freertos esp_hw_support driver
)
