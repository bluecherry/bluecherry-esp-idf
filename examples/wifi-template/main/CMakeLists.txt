idf_component_register(SRCS "main.c" "wifi.c"
                    PRIV_REQUIRES esp_event esp_netif esp_wifi nvs_flash mbedtls
                    INCLUDE_DIRS "." "includes")

target_add_binary_data(${COMPONENT_TARGET} "credentials/devcert.pem" TEXT)
target_add_binary_data(${COMPONENT_TARGET} "credentials/devkey.pem" TEXT)
