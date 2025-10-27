idf_component_register(
    SRCS "src/bluecherry.c"
        "src/bc_ztp_cbor.c"
    INCLUDE_DIRS "src"
    REQUIRES bootloader_support spi_flash app_update fatfs vfs
    PRIV_REQUIRES esp_netif mbedtls esp_partition
)