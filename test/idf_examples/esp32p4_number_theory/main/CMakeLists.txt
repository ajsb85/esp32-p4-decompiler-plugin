idf_component_register(
    SRCS
        "app_main.c"
        "test_twin_primes_idf.c"
    INCLUDE_DIRS "."
    REQUIRES unity freertos esp_hw_support driver
)
