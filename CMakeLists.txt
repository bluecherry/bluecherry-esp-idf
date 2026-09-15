idf_component_register(
    SRCS "src/bluecherry.c"
    INCLUDE_DIRS "src"
    REQUIRES bootloader_support spi_flash esp_partition app_update esp_timer lwip mbedtls
)