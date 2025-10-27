/**
 * @file bluecherry.c
 * @author Daan Pape (daan@dptechnics.com)
 * @brief This code connects to the BlueCherry platform.
 * @version 1.2.0
 * @date 2025-07-25
 * @copyright Copyright (c) 2025 DPTechnics BV
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU Lesser General Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.
 */

#include <bluecherry.h>
#include <bc_ztp_cbor.h>

/**
 * @brief The operational data used by the BlueCherry cloud  connection.
 */
static _bluecherry_t _bluecherry_opdata = { 0 };

/**
 * @brief The logging tag for this BlueCherry module.
 */
static const char* TAG = "[BlueCherry]";

static bool _watchdog = false;
/**
 * @brief Tickle the task watchdog if enabled.
 *
 * This function tickles the task watchdog if it is enabled.
 */
static void _tickleWatchdog(void)
{
  if(_watchdog) {
    esp_task_wdt_reset();
  }
}

/**
 * @brief The entrypoint of the automatic BlueCherry synchronisation task.
 *
 * This function implements the automatic BlueCherry syncronisation.
 *
 * @param args A NULL pointer.
 *
 * @return None.
 */
static void _bluecherry_sync_task(void* args)
{
  if(_watchdog) {
    esp_task_wdt_add(NULL);
  }

  bool block = true;

  while(true) {
    _tickleWatchdog();
    if(bluecherry_sync(block) == BLUECHERRY_SYNC_CONTINUE) {
      block = false;
    } else {
      block = true;
    }
  }
}

#pragma region OTA FUNCTIONS

/**
 * @brief Get the current OTA progress.
 *
 * This function returns the current OTA progress. If no OTA is in progress, 0 is returned.
 *
 * @return The current OTA progress.
 */
static float blueCherryGetOtaProgressPercent(void)
{
  if(_bluecherry_opdata.otaSize == 0) {
    return 0.0f;
  }

  return ((float) _bluecherry_opdata.otaProgress / (float) _bluecherry_opdata.otaSize) * 100.0f;
}

/**
 * @brief Process OTA init event
 *
 * This function prepares a OTA update and checks the announced update image size against
 * the update partition size.
 *
 * @param data The event data, being the announced size of the image
 * @param len The length of the update data.
 *
 * @return Whether we should emit an error BC event on next sync, in case announced size is
 * too large for partitioning.
 */
static bool _processOtaInitializeEvent(uint8_t* data, uint16_t len)
{
  if(len != sizeof(uint32_t)) {
    return true;
  }

  _bluecherry_opdata.otaSize = *((uint32_t*) data);

  /* check if there is enough space on the update partition */
  _bluecherry_opdata.otaPartition = esp_ota_get_next_update_partition(NULL);
  if(!_bluecherry_opdata.otaPartition ||
     _bluecherry_opdata.otaSize > _bluecherry_opdata.otaPartition->size ||
     _bluecherry_opdata.otaSize == 0) {
    ESP_LOGE(TAG, "OTA init: no OTA partition or size 0 or %lu > %lu", _bluecherry_opdata.otaSize,
             _bluecherry_opdata.otaPartition->size);
    return true;
  }

  /* initialize buffer and state */
  _bluecherry_opdata.otaBufferPos = 0;
  _bluecherry_opdata.otaProgress = 0;

  ESP_LOGD(TAG, "OTA init: size %lu <= partition size %lu", _bluecherry_opdata.otaSize,
           _bluecherry_opdata.otaPartition->size);

  return false;
}

/**
 * @brief Write a flash sector to flash, erasing the block first if on an as of yet
 * uninitialized block
 *
 * @param None.
 *
 * @return True if succeeded, false if not.
 */
static bool _otaBufferToFlash(void)
{
  /* first bytes of new firmware must be postponed so
   * partially written firmware is not bootable just yet
   */
  uint8_t skip = 0;

  if(!_bluecherry_opdata.otaProgress) {
    /* meanwhile check for the magic byte */
    if(_bluecherry_opdata.otaBuffer[0] != ESP_IMAGE_HEADER_MAGIC) {
      ESP_LOGD(TAG, "OTA chunk: magic header not found");
      return false;
    }

    skip = ENCRYPTED_BLOCK_SIZE;
    memcpy(_bluecherry_opdata.otaSkipBuffer, _bluecherry_opdata.otaBuffer, skip);
  }

  size_t flashOffset = _bluecherry_opdata.otaPartition->address + _bluecherry_opdata.otaProgress;

  // if it's the block boundary, than erase the whole block from here
  bool blockErase =
      (_bluecherry_opdata.otaSize - _bluecherry_opdata.otaProgress >= SPI_FLASH_BLOCK_SIZE) &&
      (flashOffset % SPI_FLASH_BLOCK_SIZE == 0);

  // sector belong to unaligned partition heading block
  bool partitionHeadSectors =
      _bluecherry_opdata.otaPartition->address % SPI_FLASH_BLOCK_SIZE &&
      flashOffset < (_bluecherry_opdata.otaPartition->address / SPI_FLASH_BLOCK_SIZE + 1) *
                        SPI_FLASH_BLOCK_SIZE;

  // sector belong to unaligned partition tailing block
  bool partitionTailSectors =
      flashOffset >= (_bluecherry_opdata.otaPartition->address + _bluecherry_opdata.otaSize) /
                         SPI_FLASH_BLOCK_SIZE * SPI_FLASH_BLOCK_SIZE;

  if(blockErase || partitionHeadSectors || partitionTailSectors) {
    if(esp_partition_erase_range(_bluecherry_opdata.otaPartition, _bluecherry_opdata.otaProgress,
                                 blockErase ? SPI_FLASH_BLOCK_SIZE : SPI_FLASH_SEC_SIZE) !=
       ESP_OK) {
      ESP_LOGE(TAG, "OTA chunk: could not erase partition");
      return false;
    }
  }

  if(esp_partition_write(_bluecherry_opdata.otaPartition, _bluecherry_opdata.otaProgress + skip,
                         (uint32_t*) _bluecherry_opdata.otaBuffer + skip / sizeof(uint32_t),
                         _bluecherry_opdata.otaBufferPos - skip) != ESP_OK) {
    ESP_LOGE(TAG, "OTA chunk: could not write data to partition");
    return false;
  }

  _bluecherry_opdata.otaProgress += _bluecherry_opdata.otaBufferPos;
  _bluecherry_opdata.otaBufferPos = 0;

  return true;
}

/**
 * @brief Process OTA chunk event
 *
 * This function accepts a chunk of the OTA update binary image. If the chunk is empty, the
 * BlueCherry cloud server signals a cancel of the upload in progress.
 *
 * @param data The chunk data
 * @param len The length of the chunk data
 *
 * @return Whether we should emit an error BC event on next sync, in case size so far
 * exceeds announced size, or if it is an empty chunk.
 */
static bool _processOtaChunkEvent(uint8_t* data, uint16_t len)
{
  if(!_bluecherry_opdata.otaSize || len == 0 ||
     _bluecherry_opdata.otaProgress + len > _bluecherry_opdata.otaSize) {
    ESP_LOGW(TAG, "OTA: cancelled because empty chunk or chunk beyond update size");
    /**
     * TODO: Replace hard reset with immediate response to bluecherry that OTA was aborted.
     *
     * Reason for hard reset: The cloud will continue to send OTA data and assume it
     * completes successfully unless the connection is aborted.
     */
    // vTaskDelay(5000);
    // esp_restart();
    return true;
  }

  size_t left = len;

  while((_bluecherry_opdata.otaBufferPos + left) > SPI_FLASH_SEC_SIZE) {
    size_t toBuff = SPI_FLASH_SEC_SIZE - _bluecherry_opdata.otaBufferPos;

    memcpy(_bluecherry_opdata.otaBuffer + _bluecherry_opdata.otaBufferPos, data + (len - left),
           toBuff);
    _bluecherry_opdata.otaBufferPos += toBuff;

    if(!_otaBufferToFlash()) {
      ESP_LOGE(TAG, "OTA chunk: failed to write to flash (within loop)");
      return true;
    } else {
      ESP_LOGI(TAG, "OTA chunk written to flash; progress = %lu / %lu (%.2f%%)",
               _bluecherry_opdata.otaProgress, _bluecherry_opdata.otaSize,
               blueCherryGetOtaProgressPercent());
    }

    left -= toBuff;
  }

  memcpy(_bluecherry_opdata.otaBuffer + _bluecherry_opdata.otaBufferPos, data + (len - left), left);
  _bluecherry_opdata.otaBufferPos += left;

  if(_bluecherry_opdata.otaProgress + _bluecherry_opdata.otaBufferPos ==
     _bluecherry_opdata.otaSize) {
    if(!_otaBufferToFlash()) {
      ESP_LOGE(TAG, "OTA chunk: failed to write to flash (remainder)");
      return true;
    } else {
      ESP_LOGD(TAG, "OTA remainder written to flash; progress = %lu / %lu (%.2f%%)",
               _bluecherry_opdata.otaProgress, _bluecherry_opdata.otaSize,
               blueCherryGetOtaProgressPercent());
    }
  }

  return false;
}

/**
 * @brief Process an OTA finish event.
 *
 * This function verifies the exact announced size has been flashed, could verify the
 * optional included SHA256.
 *
 * @return Whether we should emit an error BC event on next sync, in case the size
 * mismatches the announced size, or the optional included SHA256 digest mismatches the
 * corresponding image.
 */
static bool _processOtaFinishEvent(void)
{
  if(!_bluecherry_opdata.otaSize || _bluecherry_opdata.otaProgress != _bluecherry_opdata.otaSize) {
    return true;
  }

  /* enable partition: write the stashed first bytes */
  if(esp_partition_write(_bluecherry_opdata.otaPartition, 0,
                         (uint32_t*) _bluecherry_opdata.otaSkipBuffer,
                         ENCRYPTED_BLOCK_SIZE) != ESP_OK) {
    ESP_LOGE(TAG, "OTA Finish: Could not write start of boot sector to partition");
    return true;
  }

  /* check if partition is bootable */
  if(esp_partition_read(_bluecherry_opdata.otaPartition, 0,
                        (uint32_t*) _bluecherry_opdata.otaSkipBuffer,
                        ENCRYPTED_BLOCK_SIZE) != ESP_OK) {
    ESP_LOGE(TAG, "OTA Finish: Could not read boot partition");
    return true;
  }
  if(_bluecherry_opdata.otaSkipBuffer[0] != ESP_IMAGE_HEADER_MAGIC) {
    ESP_LOGE(TAG, "OTA Finish: Magic header is missing on partition");
    return true;
  }

  if(esp_ota_set_boot_partition(_bluecherry_opdata.otaPartition)) {
    ESP_LOGE(TAG, "OTA Finish: Could not set boot partition");
    return true;
  }

  ESP_LOGI(TAG, "OTA Finish: set boot partition. Booting in new firmware.");
  esp_restart();

  return false;
}

/**
 * @brief Process an incoming BlueCherry event.
 *
 * This function is called when blueCherryDidRing encounters a BlueCherry management packet,
 * eg for OTA updates.
 *
 * @param data The event data.
 * @param len The length of the data block.
 *
 * @return Whether we should emit an error BC event on next sync.
 */
static bool _blueCherryProcessEvent(uint8_t* data, uint8_t len)
{
  switch(data[0]) {
  case BLUECHERRY_EVENT_TYPE_OTA_INITIALIZE:
    return _processOtaInitializeEvent(data + 1, len - 1);

  case BLUECHERRY_EVENT_TYPE_OTA_CHUNK:
    return _processOtaChunkEvent(data + 1, len - 1);

  case BLUECHERRY_EVENT_TYPE_OTA_FINISH:
    return _processOtaFinishEvent();

  default:
    ESP_LOGE(TAG, "Error: invalid BlueCherry event type 0x%x from cloud server", data[0]);
    return true;
  }

  return true;
}

#pragma endregion
#pragma region MBEDTLS NET SOCKET CALLBACKS
/**
 * @brief Send DTLS data over a socket.
 *
 * This function is called by Mbed TLS to send encrypted data over the underlying socket.
 *
 * @param ctx Pointer to the socket descriptor.
 * @param buf Pointer to the buffer containing the data to send.
 * @param len Length of the data to send, in bytes.
 *
 * @return The number of bytes sent on success, MBEDTLS error code on failure.
 */
static int _bluecherry_dtls_send(void* ctx, const unsigned char* buf, size_t len)
{
  int sock = *(int*) ctx;
  int ret = send(sock, buf, len, 0);

  if(ret < 0) {
    if(errno == EAGAIN || errno == EWOULDBLOCK) {
      return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }

  return ret;
}

/**
 * @brief Receive DTLS data from a socket.
 *
 * This function is called by Mbed TLS when a read is required from the underlying socket.
 *
 * @param ctx Pointer to the socket descriptor.
 * @param buf Pointer to the buffer where the received data will be stored.
 * @param len Maximum number of bytes to read into the buffer.
 *
 * @return int Number of bytes received on success, MBEDTLS error code on failure.
 */
static int _bluecherry_dtls_recv(void* ctx, unsigned char* buf, size_t len)
{
  int sock = *(int*) ctx;
  int ret = recv(sock, buf, len, 0);

  if(ret < 0) {
    if(errno == EWOULDBLOCK || errno == EAGAIN) {
      return MBEDTLS_ERR_SSL_WANT_READ;
    }
    if(errno == ETIMEDOUT) {
      return MBEDTLS_ERR_SSL_TIMEOUT;
    }
    return MBEDTLS_ERR_NET_RECV_FAILED;
  }

  return ret;
}

#pragma endregion
#pragma region MBEDTLS NET SOCKET

/**
 * @brief Read up to len bytes from the DTLS socket.
 *
 * This function will read up to len bytes from the DTLS socket. The function will handle session
 * re-negotiations and retries autonomously. This function will block for a maximum of
 * BLUECHERRY_SSL_READ_TIMEOUT milliseconds.
 *
 * @param buf Pointer to a buffer to read the results in.
 * @param len The maximum number of bytes to read.
 *
 * @return The number of bytes read from the socket.
 */
static int _bluecherry_mbed_dtls_read(unsigned char* buf, size_t len)
{
  int ret;

  while(true) {
    ret = mbedtls_ssl_read(&_bluecherry_opdata.ssl, buf, len);
    if(ret > 0) {
      return ret;
    }

    if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      _tickleWatchdog();
      vTaskDelay(pdMS_TO_TICKS(10));
      continue;
    }

    if(ret == MBEDTLS_ERR_SSL_TIMEOUT) {
      return ret;
    }

    ESP_LOGE(TAG, "Could not read from the BlueCherry cloud connection: -%04X", -ret);
    return ret;
  }
}

/**
 * @brief Write a buffer to the DTLS socket.
 *
 * This function will write a buffer to the DTLS socket. This function will handle session
 * re-negotiations and retries autonomously.
 *
 * @param buf Pointer to a buffer write to the network.
 * @param len The length of the data to write to the network.
 *
 * @return The Mbed TLS result code.
 */
static int _bluecherry_mbed_dtls_write(const unsigned char* buf, size_t len)
{
  int ret;

  do {
    ret = mbedtls_ssl_write(&_bluecherry_opdata.ssl, buf, len);
    if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      _tickleWatchdog();
      vTaskDelay(pdMS_TO_TICKS(10));
      continue;
    }

    if(ret < 0) {
      ESP_LOGE(TAG, "Could not write to the BlueCherry cloud connection: -%04X", -ret);
      return ret;
    }

    return ret;
  } while(true);
}

/**
 * @brief Finalize the CSR generation process.
 *
 * This function cleans up the resources used during the CSR generation process.
 *
 * @param result The result of the CSR generation process.
 *
 * @return true if the cleanup was successful, false otherwise.
 */
static bool _ztp_finish_csr_gen(bool result)
{
  mbedtls_pk_free(&_bluecherry_opdata.devkey);
  mbedtls_entropy_free(&_bluecherry_opdata.entropy);
  mbedtls_ctr_drbg_free(&_bluecherry_opdata.ctr_drbg);
  mbedtls_x509write_csr_free(&_bluecherry_opdata.ztp_mbCsr);

  if(!result) {
    ztp_pkeyBuf[0] = '\0';
    ztp_certBuf[0] = '\0';
  }

  return result;
}

/**
 * @brief Cleanup the Mbed TLS resources.
 *
 * This function cleans up the Mbed TLS resources used by the BlueCherry connection.
 *
 * @return None.
 */
static void _bluecherry_cleanup_mbedtls()
{
  mbedtls_ssl_free(&_bluecherry_opdata.ssl);
  mbedtls_ssl_config_free(&_bluecherry_opdata.ssl_conf);
  mbedtls_ctr_drbg_free(&_bluecherry_opdata.ctr_drbg);
  mbedtls_entropy_free(&_bluecherry_opdata.entropy);
  mbedtls_x509_crt_free(&_bluecherry_opdata.cacert);
  mbedtls_x509_crt_free(&_bluecherry_opdata.devcert);
  mbedtls_pk_free(&_bluecherry_opdata.devkey);
}

/**
 * @brief Cleanup the network resources.
 *
 * This function cleans up the network resources used by the BlueCherry connection.
 *
 * @return None.
 */
static void _bluecherry_cleanup_network()
{
  if(_bluecherry_opdata.sock > 0) {
    shutdown(_bluecherry_opdata.sock, 0);
    close(_bluecherry_opdata.sock);
    _bluecherry_opdata.sock = -1;
  }
}

/**
 * @brief Setup the Mbed TLS resources.
 *
 * This function sets up the Mbed TLS resources used by the BlueCherry connection.
 *
 * @param mac Pointer to the MAC address used for seeding the RNG.
 *
 * @return true if the setup was successful, false otherwise.
 */
static bool _bluecherry_setup_mbedtls(const uint8_t* mac)
{
  mbedtls_ssl_init(&_bluecherry_opdata.ssl);
  mbedtls_ssl_config_init(&_bluecherry_opdata.ssl_conf);
  mbedtls_ctr_drbg_init(&_bluecherry_opdata.ctr_drbg);
  mbedtls_entropy_init(&_bluecherry_opdata.entropy);
  mbedtls_x509_crt_init(&_bluecherry_opdata.cacert);
  mbedtls_x509_crt_init(&_bluecherry_opdata.devcert);
  mbedtls_pk_init(&_bluecherry_opdata.devkey);
  _bluecherry_opdata.sock = -1;

  int ret = mbedtls_ctr_drbg_seed(&_bluecherry_opdata.ctr_drbg, mbedtls_entropy_func,
                                  &_bluecherry_opdata.entropy, mac, 6);
  if(ret != 0) {
    ESP_LOGE(TAG, "Could not seed RNG: -%04X", -ret);
    return false;
  }

  ret = mbedtls_ssl_config_defaults(&_bluecherry_opdata.ssl_conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if(ret != 0) {
    ESP_LOGE(TAG, "Could not configure DTLS defaults: -%04X", -ret);
    return false;
  }

  mbedtls_ssl_conf_read_timeout(&_bluecherry_opdata.ssl_conf, BLUECHERRY_SSL_READ_TIMEOUT);
  mbedtls_ssl_conf_authmode(&_bluecherry_opdata.ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(&_bluecherry_opdata.ssl_conf, mbedtls_ctr_drbg_random,
                       &_bluecherry_opdata.ctr_drbg);
  return true;
}

/**
 * @brief Configure the Mbed TLS credentials.
 *
 * This function configures the Mbed TLS credentials used by the BlueCherry connection.
 *
 * @param caCert Pointer to the CA certificate in PEM format.
 * @param devCert Pointer to the device certificate in PEM format, or NULL if not used.
 * @param devKey Pointer to the device private key in PEM format, or NULL if not used.
 *
 * @return true if the configuration was successful, false otherwise.
 */
static bool _bluecherry_configure_credentials(const char* caCert, const char* devCert,
                                              const char* devKey)
{
  int ret = mbedtls_x509_crt_parse(&_bluecherry_opdata.cacert, (const uint8_t*) caCert,
                                   strlen(caCert) + 1);
  if(ret != 0) {
    ESP_LOGE(TAG, "Could not parse CA certificate: -%04X", -ret);
    return false;
  }

  if(devCert && devKey) {
    ret = mbedtls_x509_crt_parse(&_bluecherry_opdata.devcert, (const uint8_t*) devCert,
                                 strlen(devCert) + 1);
    if(ret != 0) {
      ESP_LOGE(TAG, "Could not parse device certificate: -%04X", -ret);
      return false;
    }

    ret = mbedtls_pk_parse_key(&_bluecherry_opdata.devkey, (const uint8_t*) devKey,
                               strlen(devKey) + 1, NULL, 0, mbedtls_entropy_func,
                               &_bluecherry_opdata.ctr_drbg);
    if(ret != 0) {
      ESP_LOGE(TAG, "Could not parse device key: -%04X", -ret);
      return false;
    }

    ret = mbedtls_ssl_conf_own_cert(&_bluecherry_opdata.ssl_conf, &_bluecherry_opdata.devcert,
                                    &_bluecherry_opdata.devkey);
    if(ret != 0) {
      ESP_LOGE(TAG, "Could not configure device cert/key in context: -%04X", -ret);
      return false;
    }
  }

  mbedtls_ssl_conf_ca_chain(&_bluecherry_opdata.ssl_conf, &_bluecherry_opdata.cacert, NULL);
  return true;
}

/**
 * @brief Connect to the BlueCherry DTLS server.
 *
 * This function connects to the BlueCherry DTLS server using the provided host and port.
 *
 * @param host The hostname or IP address of the BlueCherry server.
 * @param port The port number of the BlueCherry server.
 *
 * @return true if the connection was successful, false otherwise.
 */
static bool _bluecherry_dtls_connect(const char* host, const char* port)
{
  struct addrinfo hints = { 0 };
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  struct addrinfo* res = NULL;
  int ret = getaddrinfo(host, port, &hints, &res);
  if(ret != 0 || res == NULL) {
    ESP_LOGE(TAG, "DNS lookup failed: %d", ret);
    if(res)
      freeaddrinfo(res);
    return false;
  }

  _bluecherry_opdata.sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if(_bluecherry_opdata.sock < 0) {
    ESP_LOGE(TAG, "socket() failed: %s", strerror(errno));
    freeaddrinfo(res);
    return false;
  }

  struct timeval timeout = { .tv_sec = 3, .tv_usec = 0 };
  setsockopt(_bluecherry_opdata.sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  ret = connect(_bluecherry_opdata.sock, res->ai_addr, res->ai_addrlen);
  freeaddrinfo(res);
  if(ret != 0) {
    ESP_LOGE(TAG, "connect() failed: %s", strerror(errno));
    _bluecherry_cleanup_network();
    return false;
  }

  ret = mbedtls_ssl_setup(&_bluecherry_opdata.ssl, &_bluecherry_opdata.ssl_conf);
  if(ret != 0) {
    ESP_LOGE(TAG, "Could not setup SSL context: -%04X", -ret);
    return false;
  }

  mbedtls_ssl_set_timer_cb(&_bluecherry_opdata.ssl, &_bluecherry_opdata.timer,
                           mbedtls_timing_set_delay, mbedtls_timing_get_delay);

  ret = mbedtls_ssl_set_hostname(&_bluecherry_opdata.ssl, host);
  if(ret != 0) {
    ESP_LOGE(TAG, "Could not set hostname: -%04X", -ret);
    return false;
  }

  mbedtls_ssl_set_bio(&_bluecherry_opdata.ssl, &_bluecherry_opdata.sock, _bluecherry_dtls_send,
                      _bluecherry_dtls_recv, NULL);

  time_t start = time(NULL);
  while((ret = mbedtls_ssl_handshake(&_bluecherry_opdata.ssl)) != 0) {
    if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
       ret == MBEDTLS_ERR_SSL_TIMEOUT) {
      if(difftime(time(NULL), start) >= 30) {
        ESP_LOGE(TAG, "DTLS handshake timeout");
        return false;
      }
      vTaskDelay(pdMS_TO_TICKS(10));
      continue;
    }
    ESP_LOGE(TAG, "DTLS handshake failed: -%04X", -ret);
    return false;
  }

  return true;
}

#pragma endregion
#pragma region CoAP RXTX

/**
 * @brief Perform CoAP transmit and receive operations with the BlueCherry cloud.
 *
 * This function will calculate and add the correct CoAP header to the message buffer and transmit
 * the data over the the Mbed TLS DTLS socket. The message buffer must have a free space of
 * BLUECHERRY_COAP_HEADER_SIZE preceeding the valid data. After the buffer is transmitted the
 * function will try to read the acknowledgement and new data coming from the cloud.
 *
 * @param msg The message to send or NULL to send empty sync packet.
 *
 * @return ESP_OK on success.
 */
static esp_err_t _bluecherry_coap_rxtx(_bluecherry_msg_t* msg)
{
  uint8_t no_payload_hdr[BLUECHERRY_COAP_HEADER_SIZE];
  uint8_t* data = msg == NULL ? no_payload_hdr : msg->data;
  size_t data_len = msg == NULL ? BLUECHERRY_COAP_HEADER_SIZE : msg->len;

  if(data_len < BLUECHERRY_COAP_HEADER_SIZE) {
    ESP_LOGE(TAG, "Cannot send CoAP message smaller than %dB", BLUECHERRY_COAP_HEADER_SIZE);
    return ESP_ERR_NO_MEM;
  }

  _bluecherry_opdata.cur_message_id += 1;
  if(_bluecherry_opdata.cur_message_id == 0) {
    _bluecherry_opdata.cur_message_id = 1;
  }

  int32_t last_acked_message_id = _bluecherry_opdata.last_acked_message_id;
  if(last_acked_message_id > _bluecherry_opdata.cur_message_id) {
    last_acked_message_id -= 0xffff;
  }
  uint8_t missed_msg_count = _bluecherry_opdata.cur_message_id - last_acked_message_id - 1;

  data[0] = 0x40;
  data[1] = missed_msg_count;
  data[2] = _bluecherry_opdata.cur_message_id >> 8;
  data[3] = _bluecherry_opdata.cur_message_id & 0xFF;
  data[4] = 0xFF;

  double timeout = BLUECHERRY_ACK_TIMEOUT *
                   (1 + (rand() / (RAND_MAX + 1.0)) * (BLUECHERRY_ACK_RANDOM_FACTOR - 1));

  for(uint8_t attempt = 1; attempt <= BLUECHERRY_MAX_RETRANSMITS; ++attempt) {
    _bluecherry_opdata.last_tx_time = time(NULL);
    _tickleWatchdog();

    if(_bluecherry_mbed_dtls_write(data, data_len) < 0) {
      return ESP_FAIL;
    }

    _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_AWAITING_RESPONSE;

    while(true) {
      int ret = _bluecherry_mbed_dtls_read(_bluecherry_opdata.in_buf, BLUECHERRY_MAX_MESSAGE_LEN);
      if(ret > 0) {
        _bluecherry_opdata.in_buf_len = ret;
        _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_RECEIVED_ACK;
        return ESP_OK;
      } else if(ret != MBEDTLS_ERR_SSL_TIMEOUT) {
        return ESP_FAIL;
      }

      if(difftime(time(NULL), _bluecherry_opdata.last_tx_time) >= timeout) {
        break;
      }
    }

    timeout *= 2;
  }

  _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_TIMED_OUT;
  return ESP_ERR_TIMEOUT;
}

/**
 * @brief Common CoAP transmit and receive function for ZTP operations.
 *
 * This function handles the common logic for transmitting and receiving CoAP messages
 * during the Zero Touch Provisioning (ZTP) process. It constructs the CoAP message with
 * the provided header and payload, sends it over the DTLS connection, and waits for
 * a response.
 *
 * @param tx_buf Pointer to the buffer containing the payload to transmit.
 * @param tx_len Length of the payload to transmit.
 * @param rx_buf Pointer to the buffer where the received data will be stored.
 * @param rx_len Pointer to a variable where the length of the received data will be stored.
 * @param header Pointer to the CoAP header to be used for the message.
 * @param header_len Length of the CoAP header.
 *
 * @return true if the transmission and reception were successful, false otherwise.
 */
static bool _bluecherry_ztp_coap_rxtx_common(uint8_t* tx_buf, uint16_t tx_len, uint8_t* rx_buf,
                                             uint16_t* rx_len, const uint8_t* header,
                                             size_t header_len)
{
  static time_t last_tx_time = 0;

  _bluecherry_opdata.cur_message_id += 1;
  if(_bluecherry_opdata.cur_message_id == 0) {
    _bluecherry_opdata.cur_message_id = 1;
  }

  size_t data_len = header_len;
  uint8_t data[header_len + 1 + tx_len];

  memcpy(data, header, header_len);

  if(tx_len > 0) {
    data[header_len] = 0xFF;
    memcpy(data + header_len + 1, tx_buf, tx_len);
    data_len = header_len + 1 + tx_len;
  }

  double timeout = 2.0 * (1 + (rand() / (RAND_MAX + 1.0)) * (1.5 - 1));

  for(uint8_t attempt = 1; attempt <= 4; ++attempt) {
    last_tx_time = time(NULL);

    if(_bluecherry_mbed_dtls_write(data, data_len) < 0)
      return false;

    while(true) {
      uint8_t temp_buf[1024];
      int ret = _bluecherry_mbed_dtls_read(temp_buf, sizeof(temp_buf));

      if(ret > 0) {
        if(ret > 7) {
          memcpy(rx_buf, temp_buf + 7, ret - 7);
          *rx_len = (uint16_t) (ret - 7);
        } else {
          *rx_len = 0;
        }
        return true;
      } else if(ret != MBEDTLS_ERR_SSL_TIMEOUT) {
        return false;
      }

      if(difftime(time(NULL), last_tx_time) >= timeout)
        break;
    }

    timeout *= 2;
  }

  return false;
}

/**
 * @brief CoAP transmit and receive function for requesting device ID.
 *
 * This function constructs and sends a CoAP message to request the device ID
 * from the BlueCherry cloud server. It uses a predefined CoAP header for the
 * device ID request and handles the transmission and reception of the message.
 *
 * @param tx_buf Pointer to the buffer containing the payload to transmit.
 * @param tx_len Length of the payload to transmit.
 * @param rx_buf Pointer to the buffer where the received data will be stored.
 * @param rx_len Pointer to a variable where the length of the received data will be stored.
 *
 * @return true if the transmission and reception were successful, false otherwise.
 */
static bool _bluecherry_ztp_coap_rxtx_devid(uint8_t* tx_buf, uint16_t tx_len, uint8_t* rx_buf,
                                            uint16_t* rx_len)
{
  const uint8_t header[] = { 0x40,
                             0x01,
                             _bluecherry_opdata.cur_message_id >> 8,
                             _bluecherry_opdata.cur_message_id & 0xFF,
                             0xB2,
                             0x76,
                             0x31,
                             0x05,
                             0x64,
                             0x65,
                             0x76,
                             0x69,
                             0x64 };

  return _bluecherry_ztp_coap_rxtx_common(tx_buf, tx_len, rx_buf, rx_len, header, sizeof(header));
}

/**
 * @brief CoAP transmit and receive function for signing operations.
 *
 * This function constructs and sends a CoAP message to perform signing operations
 * with the BlueCherry cloud server. It uses a predefined CoAP header for the
 * signing request and handles the transmission and reception of the message.
 *
 * @param tx_buf Pointer to the buffer containing the payload to transmit.
 * @param tx_len Length of the payload to transmit.
 * @param rx_buf Pointer to the buffer where the received data will be stored.
 * @param rx_len Pointer to a variable where the length of the received data will be stored.
 *
 * @return true if the transmission and reception were successful, false otherwise.
 */
static bool _bluecherry_ztp_coap_rxtx_sign(uint8_t* tx_buf, uint16_t tx_len, uint8_t* rx_buf,
                                           uint16_t* rx_len)
{
  const uint8_t header[] = { 0x40,
                             0x01,
                             _bluecherry_opdata.cur_message_id >> 8,
                             _bluecherry_opdata.cur_message_id & 0xFF,
                             0xB2,
                             0x76,
                             0x31,
                             0x04,
                             0x73,
                             0x69,
                             0x67,
                             0x6E };

  return _bluecherry_ztp_coap_rxtx_common(tx_buf, tx_len, rx_buf, rx_len, header, sizeof(header));
}

#pragma endregion
#pragma region ZTP

/**
 * @brief Add a device ID parameter of string type.
 *
 * This function adds a device ID parameter of string type to the ZTP device ID parameters list.
 *
 * @param type The type of the device ID parameter.
 * @param str The string value of the device ID parameter.
 *
 * @return true if the parameter was added successfully, false otherwise.
 */
static bool _ztp_add_device_id_parameter_string(bluecherry_ztp_device_id_type type, const char* str)
{
  if(str == NULL ||
     _bluecherry_opdata.ztp_devIdParams.count >= BLUECHERRY_ZTP_MAX_DEVICE_ID_PARAMS) {
    return false;
  }

  switch(type) {
  case BLUECHERRY_ZTP_DEVICE_ID_TYPE_IMEI:
    _bluecherry_opdata.ztp_devIdParams.param[_bluecherry_opdata.ztp_devIdParams.count].type =
        BLUECHERRY_ZTP_DEVICE_ID_TYPE_IMEI;
    strncpy(_bluecherry_opdata.ztp_devIdParams.param[_bluecherry_opdata.ztp_devIdParams.count]
                .value.imei,
            str, BLUECHERRY_ZTP_IMEI_LEN);
    _bluecherry_opdata.ztp_devIdParams.param[_bluecherry_opdata.ztp_devIdParams.count]
        .value.imei[BLUECHERRY_ZTP_IMEI_LEN] = '\0';
    _bluecherry_opdata.ztp_devIdParams.count += 1;
    break;

  default:
    return false;
  }

  return true;
}

/**
 * @brief Add a device ID parameter of blob type.
 *
 * This function adds a device ID parameter of blob type to the ZTP device ID parameters list
 * (e.g., MAC address).
 *
 * @param type The type of the device ID parameter.
 * @param blob The blob value of the device ID parameter.
 *
 * @return true if the parameter was added successfully, false otherwise.
 */
static bool _ztp_add_device_id_parameter_blob(bluecherry_ztp_device_id_type type,
                                              const unsigned char* blob)
{
  if(blob == NULL ||
     _bluecherry_opdata.ztp_devIdParams.count >= BLUECHERRY_ZTP_MAX_DEVICE_ID_PARAMS) {
    return false;
  }

  switch(type) {
  case BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC:
    _bluecherry_opdata.ztp_devIdParams.param[_bluecherry_opdata.ztp_devIdParams.count].type =
        BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC;
    memcpy(_bluecherry_opdata.ztp_devIdParams.param[_bluecherry_opdata.ztp_devIdParams.count]
               .value.mac,
           blob, BLUECHERRY_ZTP_MAC_LEN);
    _bluecherry_opdata.ztp_devIdParams.count += 1;
    break;

  default:
    return false;
  }

  return true;
}

/**
 * @brief Add a device ID parameter of number type.
 *
 * This function adds a device ID parameter of number type to the ZTP device ID parameters list
 * (e.g., OOB challenge).
 *
 * @param type The type of the device ID parameter.
 * @param number The number value of the device ID parameter.
 *
 * @return true if the parameter was added successfully, false otherwise.
 */
static bool _ztp_add_device_id_parameter_number(bluecherry_ztp_device_id_type type,
                                                unsigned long long number)
{
  if(_bluecherry_opdata.ztp_devIdParams.count >= BLUECHERRY_ZTP_MAX_DEVICE_ID_PARAMS) {
    return false;
  }

  switch(type) {
  case BLUECHERRY_ZTP_DEVICE_ID_TYPE_OOB_CHALLENGE:
    _bluecherry_opdata.ztp_devIdParams.param[_bluecherry_opdata.ztp_devIdParams.count].type =
        BLUECHERRY_ZTP_DEVICE_ID_TYPE_OOB_CHALLENGE;
    _bluecherry_opdata.ztp_devIdParams.param[_bluecherry_opdata.ztp_devIdParams.count]
        .value.oobChallenge = number;
    _bluecherry_opdata.ztp_devIdParams.count += 1;
    break;

  default:
    return false;
  }

  return true;
}

/**
 * @brief Request the device ID from the BlueCherry ZTP server.
 *
 * This function constructs a CBOR-encoded request containing the device type ID and
 * device ID parameters, sends it to the BlueCherry ZTP server via CoAP,
 * and decodes the received device ID.
 *
 * @return true if the device ID was successfully requested and decoded, false otherwise.
 */
static bool _ztp_request_device_id()
{
  int ret;
  uint8_t cborBuf[256];
  ZTP_CBOR cbor;

  if(ztp_cbor_init(&cbor, cborBuf, sizeof(cborBuf)) < 0) {
    printf("Failed to init CBOR buffer\n");
    return false;
  };

  // Start the CBOR array
  if(ztp_cbor_start_array(&cbor, 2) < 0) {
    printf("Failed to start CBOR array\n");
    return false;
  }

  // Encode type ID value
  if(ztp_cbor_encode_string(&cbor, bcTypeId) < 0) {
    printf("Failed to encode typeId value\n");
    return false;
  }

  // Start the CBOR map (key-value pairs)
  if(ztp_cbor_start_map(&cbor, _bluecherry_opdata.ztp_devIdParams.count) < 0) {
    printf("Failed to start CBOR map\n");
    return false;
  }

  for(size_t i = 0; i < _bluecherry_opdata.ztp_devIdParams.count; i++) {

    int type = (int) _bluecherry_opdata.ztp_devIdParams.param[i].type;
    if(ztp_cbor_encode_int(&cbor, type) < 0) {
      printf("Failed to encode param type (%u)\n", type);
      return false;
    }

    switch(_bluecherry_opdata.ztp_devIdParams.param[i].type) {
    case BLUECHERRY_ZTP_DEVICE_ID_TYPE_IMEI: {
      // Encode IMEI number (15 characters)
      uint64_t imei = strtoull(_bluecherry_opdata.ztp_devIdParams.param[i].value.imei, NULL, 10);
      if(ztp_cbor_encode_uint64(&cbor, imei) < 0) {
        printf("Failed to encode IMEI number\n");
        return false;
      }
    } break;

    case BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC: {
      // Encode MAC address (6 bytes)
      if(ztp_cbor_encode_bytes(
             &cbor, (uint8_t*) _bluecherry_opdata.ztp_devIdParams.param[i].value.mac, 6) < 0) {
        printf("Failed to encode MAC address\n");
        return false;
      }
    } break;

    case BLUECHERRY_ZTP_DEVICE_ID_TYPE_OOB_CHALLENGE: {
      // Encode OOB challenge (64 bit unsigned int)
      uint64_t oobChallenge = _bluecherry_opdata.ztp_devIdParams.param[0].value.oobChallenge;
      if(ztp_cbor_encode_uint64(&cbor, oobChallenge) < 0) {
        printf("Failed to encode OOB challenge\n");
        return false;
      }
    } break;

    default:
      break;
    }
  }

  uint8_t in_buf[16];
  uint16_t in_len = 0;
  if(!_bluecherry_ztp_coap_rxtx_devid(cborBuf, ztp_cbor_size(&cbor), in_buf, &in_len)) {
    ESP_LOGE("ZTP", "Failed to sync with ZTP COAP server");
    return false;
  }

  ret = ztp_cbor_decode_device_id(in_buf, in_len, ztp_bcDevId, sizeof(ztp_bcDevId));
  if(ret < 0) {
    printf("Failed to decode device id: %d\n", ret);
    return false;
  }

  return true;
}

/**
 * @brief Generate a key pair and CSR for ZTP.
 *
 * This function generates an EC key pair and creates a Certificate Signing Request (CSR)
 * using the provided device type ID and device ID. The generated private key is stored
 * in PEM format in the global ztp_pkeyBuf, and the CSR is stored in the _bluecherry_opdata
 * structure.
 *
 * @param rfEnabled A boolean indicating whether RF is enabled (not used in this function).
 *
 * @return true if the key pair and CSR were generated successfully, false otherwise.
 */
static bool _ztp_generate_key_and_csr(bool rfEnabled)
{
  int ret;
  uint8_t csrBuf[BLUECHERRY_ZTP_CERT_BUF_SIZE];

  if(bcTypeId == NULL || strlen(bcTypeId) != BLUECHERRY_ZTP_ID_LEN ||
     strlen(ztp_bcDevId) != BLUECHERRY_ZTP_ID_LEN) {
    return false;
  }

  mbedtls_pk_init(&_bluecherry_opdata.devkey);
  mbedtls_x509write_csr_init(&_bluecherry_opdata.ztp_mbCsr);

  if(mbedtls_pk_setup(&_bluecherry_opdata.devkey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) !=
     0) {
    return _ztp_finish_csr_gen(false);
  }

  if(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(_bluecherry_opdata.devkey),
                         mbedtls_ctr_drbg_random, &_bluecherry_opdata.ctr_drbg) != 0) {
    return _ztp_finish_csr_gen(false);
  }

  if(mbedtls_pk_write_key_pem(&_bluecherry_opdata.devkey, (unsigned char*) ztp_pkeyBuf,
                              BLUECHERRY_ZTP_PKEY_BUF_SIZE) != 0) {
    return _ztp_finish_csr_gen(false);
  }

  mbedtls_x509write_csr_set_md_alg(&_bluecherry_opdata.ztp_mbCsr, MBEDTLS_MD_SHA256);
  mbedtls_x509write_csr_set_key(&_bluecherry_opdata.ztp_mbCsr, &_bluecherry_opdata.devkey);

  snprintf(ztp_subjBuf, BLUECHERRY_ZTP_SUBJ_BUF_SIZE, "C=BE,CN=%s.%s", bcTypeId, ztp_bcDevId);
  if(mbedtls_x509write_csr_set_subject_name(&_bluecherry_opdata.ztp_mbCsr, ztp_subjBuf) != 0) {
    return _ztp_finish_csr_gen(false);
  }

  ret =
      mbedtls_x509write_csr_der(&_bluecherry_opdata.ztp_mbCsr, csrBuf, BLUECHERRY_ZTP_CERT_BUF_SIZE,
                                mbedtls_ctr_drbg_random, &_bluecherry_opdata.ctr_drbg);
  if(ret < 0) {
    printf("Failed to write CSR: -0x%04X\n", -ret);
    return _ztp_finish_csr_gen(false);
  }

  size_t offset = BLUECHERRY_ZTP_CERT_BUF_SIZE - ret;
  _bluecherry_opdata.ztp_csr.length = ret;
  memcpy(_bluecherry_opdata.ztp_csr.buffer, csrBuf + offset, _bluecherry_opdata.ztp_csr.length);

  return _ztp_finish_csr_gen(true);
}

/**
 * @brief Request a signed certificate from the BlueCherry ZTP server.
 *
 * This function sends the previously generated CSR to the BlueCherry ZTP server
 * via CoAP, receives the signed certificate in DER format, converts it to PEM format,
 * and stores it in the global ztp_certBuf.
 *
 * @return true if the signed certificate was successfully requested and stored, false otherwise.
 */
static bool _ztp_request_signed_certificate()
{
  int ret;
  uint8_t cborBuf[BLUECHERRY_ZTP_CERT_BUF_SIZE];
  uint8_t coapData[BLUECHERRY_ZTP_CERT_BUF_SIZE];
  ZTP_CBOR cbor;

  ztp_cbor_init(&cbor, cborBuf, BLUECHERRY_ZTP_CERT_BUF_SIZE);
  mbedtls_x509_crt_init(&_bluecherry_opdata.devcert);

  if(ztp_cbor_encode_bytes(&cbor, _bluecherry_opdata.ztp_csr.buffer,
                           _bluecherry_opdata.ztp_csr.length) < 0) {
    printf("Failed to encode CSR\n");
    return false;
  }

  uint16_t in_len = 0;
  if(!_bluecherry_ztp_coap_rxtx_sign(cborBuf, ztp_cbor_size(&cbor), coapData, &in_len)) {
    ESP_LOGE("ZTP", "Failed to receive response from ZTP COAP server");
    return false;
  }

  size_t decodedSize;
  ret = ztp_cbor_decode_certificate(coapData, in_len, cborBuf, &decodedSize);
  if(ret < 0) {
    printf("Failed to decode certificate: %d\n", ret);
    return false;
  }

  // Parse the DER-encoded certificate
  ret = mbedtls_x509_crt_parse_der(&_bluecherry_opdata.devcert, cborBuf, decodedSize);
  if(ret < 0) {
    printf("Failed to parse DER certificate, error code: -0x%x\n", -ret);
    mbedtls_x509_crt_free(&_bluecherry_opdata.devcert);
    return false;
  }

  // Convert the certificate to PEM format
  size_t pemLen;
  ret =
      mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
                               _bluecherry_opdata.devcert.raw.p, _bluecherry_opdata.devcert.raw.len,
                               cborBuf, BLUECHERRY_ZTP_CERT_BUF_SIZE, &pemLen);
  if(ret < 0) {
    printf("Failed to write PEM: -0x%04X\n", -ret);
    mbedtls_x509_crt_free(&_bluecherry_opdata.devcert);
    return false;
  }

  memcpy(ztp_certBuf, cborBuf, pemLen);
  ztp_certBuf[pemLen] = '\0';

  mbedtls_x509_crt_free(&_bluecherry_opdata.devcert);
  return true;
}

#pragma endregion
#pragma region PUBLIC

esp_err_t bluecherry_init(const char* device_cert, const char* device_key,
                          bluecherry_msg_handler_t msg_handler, void* msg_handler_args,
                          bool auto_sync, uint16_t watchdog_timeout_seconds)
{
  if(_bluecherry_opdata.state != BLUECHERRY_STATE_UNINITIALIZED)
    return ESP_OK;

  _bluecherry_opdata.msg_handler = msg_handler;
  _bluecherry_opdata.msg_handler_args = msg_handler_args;

  uint8_t mac[6];
  esp_err_t eret = esp_read_mac(mac, ESP_MAC_WIFI_STA);
  if(eret != ESP_OK) {
    ESP_LOGE(TAG, "Could not read MAC: %s", esp_err_to_name(eret));
    return ESP_FAIL;
  }

  _bluecherry_opdata.out_queue =
      xQueueCreate(BLUECHERRY_MAX_PENDING_OUTGOING_MESSAGES, sizeof(_bluecherry_msg_t));
  if(_bluecherry_opdata.out_queue == NULL) {
    ESP_LOGE(TAG, "Unable to create outgoing message queue");
    return ESP_FAIL;
  }

  if(!_bluecherry_setup_mbedtls(mac)) {
    ESP_LOGE(TAG, "Could not setup Mbed TLS context");
    goto fail;
  }
  if(!_bluecherry_configure_credentials(BLUECHERRY_CA, device_cert, device_key)) {
    ESP_LOGE(TAG, "Could not configure credentials");
    goto fail;
  }

  _bluecherry_opdata.state = BLUECHERRY_STATE_AWAIT_CONNECTION;
  if(!_bluecherry_dtls_connect(BLUECHERRY_HOST, BLUECHERRY_PORT)) {
    ESP_LOGE(TAG, "Could not connect to BlueCherry server");
    goto fail;
  }

  _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_IDLE;
  ESP_LOGI(TAG, "BlueCherry DTLS session established");

  if(watchdog_timeout_seconds > 0) {
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 0, 0)
    esp_task_wdt_init(watchdog_timeout_seconds, true);
#else
    esp_task_wdt_config_t twdt_config = { .timeout_ms =
                                              (uint32_t) (watchdog_timeout_seconds * 1000UL),
                                          .idle_core_mask = (1 << portNUM_PROCESSORS) - 1,
                                          .trigger_panic = true };
#if CONFIG_ESP_TASK_WDT_INIT
    esp_task_wdt_reconfigure(&twdt_config);
#else
    esp_task_wdt_init(&twdt_config);
#endif
#endif
    esp_task_wdt_add(NULL);
    _watchdog = true;
  }

  if(auto_sync) {
    BaseType_t ret = xTaskCreate(_bluecherry_sync_task, "bc_sync", 4096, NULL, BLUECHERRY_SP, NULL);
    if(ret != pdPASS) {
      vQueueDelete(_bluecherry_opdata.out_queue);
      _bluecherry_opdata.out_queue = NULL;
      goto fail;
    }
  }

  return ESP_OK;

fail:
  _bluecherry_cleanup_network();
  _bluecherry_cleanup_mbedtls();
  _bluecherry_opdata.state = BLUECHERRY_STATE_UNINITIALIZED;
  return ESP_FAIL;
}

esp_err_t bluecherry_init_ztp(bluecherry_ztp_bio_handler_t ztp_bio_handler,
                              void* ztp_bio_handler_args, const char* bc_device_type,
                              bluecherry_msg_handler_t msg_handler, void* msg_handler_args,
                              bool auto_sync, uint16_t watchdog_timeout_seconds)
{
  if(_bluecherry_opdata.state != BLUECHERRY_STATE_UNINITIALIZED) {
    return ESP_OK;
  }

  bcTypeId = bc_device_type;

  // Get existing device credentials using the provided BIO handler
  const char* device_cert = ztp_bio_handler(true, false, NULL);
  const char* device_key = ztp_bio_handler(true, true, NULL);

  if(device_cert == NULL || device_key == NULL) {
    ESP_LOGW(TAG, "Device is not provisioned for BlueCherry communication, starting ZTP...");

    uint8_t mac[8] = { 0 };
    esp_read_mac(mac, ESP_MAC_WIFI_STA);

    if(!_bluecherry_setup_mbedtls(mac)) {
      ESP_LOGE(TAG, "(ZTP) Could not setup Mbed TLS context");
      goto fail;
    }
    if(!_bluecherry_configure_credentials(BLUECHERRY_CA, NULL, NULL)) {
      ESP_LOGE(TAG, "(ZTP) Could not configure credentials");
      goto fail;
    }
    if(!_bluecherry_dtls_connect(BLUECHERRY_HOST, BLUECHERRY_ZTP_PORT)) {
      ESP_LOGE(TAG, "(ZTP) Could not connect to BlueCherry server");
      goto fail;
    }

    ESP_LOGI(TAG, "Connected to ZTP server");

    if(!_ztp_add_device_id_parameter_blob(BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC, mac)) {
      ESP_LOGE(TAG, "(ZTP) Could not add MAC address as ZTP device ID parameter");
      goto fail;
    }

    if(!_ztp_request_device_id()) {
      ESP_LOGE(TAG, "(ZTP) Could not request device ID");
      goto fail;
    }

    if(!_ztp_generate_key_and_csr(false)) {
      ESP_LOGE(TAG, "(ZTP) Could not generate private key");
      goto fail;
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    if(!_ztp_request_signed_certificate()) {
      ESP_LOGE(TAG, "(ZTP) Could not request signed certificate");
      goto fail;
    }

    const char* new_cert = ztp_certBuf;
    const char* new_key = ztp_pkeyBuf;

    // Store the new credentials using the provided BIO handler
    ztp_bio_handler(false, false, (void*) new_cert);
    ztp_bio_handler(false, true, (void*) new_key);

    device_cert = new_cert;
    device_key = new_key;
  }

  return bluecherry_init(device_cert, device_key, msg_handler, msg_handler_args, auto_sync,
                         watchdog_timeout_seconds);

fail:
  _bluecherry_cleanup_network();
  _bluecherry_cleanup_mbedtls();
  return false;
}

esp_err_t bluecherry_sync(bool blocking)
{
  if(_bluecherry_opdata.state == BLUECHERRY_STATE_AWAIT_CONNECTION) {
    if(!_bluecherry_dtls_connect(BLUECHERRY_HOST, BLUECHERRY_PORT)) {
      ESP_LOGE(TAG, "Could not connect to BlueCherry server");
      return ESP_ERR_NOT_FINISHED;
    }
    _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_IDLE;
  }

  if(_bluecherry_opdata.state == BLUECHERRY_STATE_UNINITIALIZED ||
     _bluecherry_opdata.state == BLUECHERRY_STATE_CONNECTED_AWAITING_RESPONSE) {
    ESP_LOGE(TAG, "Cannot sync in the current state");
    return ESP_ERR_INVALID_STATE;
  }

  int blocktime = blocking ? BLUECHERRY_AUTO_SYNC_SECONDS : 0;
  _bluecherry_msg_t out_msg;
  if(xQueuePeek(_bluecherry_opdata.out_queue, &out_msg, pdMS_TO_TICKS(blocktime * 1000)) ==
     pdPASS) {
    if(_bluecherry_coap_rxtx(&out_msg) == ESP_OK) {
      if(xQueueReceive(_bluecherry_opdata.out_queue, &out_msg, 0) == pdPASS) {
        ESP_LOGD(TAG, "Synchronized messages with cloud");
        free(out_msg.data);
      } else {
        ESP_LOGD(TAG, "Could not remove transmitted message from queue");
        return ESP_FAIL;
      }
    } else {
      ESP_LOGE(TAG, "Could not sync payload with cloud");
      _bluecherry_opdata.state = BLUECHERRY_STATE_AWAIT_CONNECTION;
      return ESP_ERR_NOT_FINISHED;
    }
  } else {
    if(_bluecherry_coap_rxtx(NULL) != ESP_OK) {
      ESP_LOGE(TAG, "Could not sync with cloud");
      _bluecherry_opdata.state = BLUECHERRY_STATE_AWAIT_CONNECTION;
      return ESP_ERR_NOT_FINISHED;
    }
  }

  bool want_resync = false;

  uint16_t offset = 0;

  uint8_t header = _bluecherry_opdata.in_buf[offset++];
  uint8_t version = (header >> 6) & 0x03;
  if(version != 1) {
    ESP_LOGE(TAG, "Received CoAP packet with version %d, expeced 1", version);
    return ESP_ERR_INVALID_VERSION;
  }

  uint8_t type = (header >> 4) & 0x03;
  uint8_t token_len = header & 0x0F;
  offset += token_len;
  uint8_t code = _bluecherry_opdata.in_buf[offset++];
  uint16_t msg_id = _bluecherry_opdata.in_buf[offset++];
  msg_id <<= 8;
  msg_id |= _bluecherry_opdata.in_buf[offset++];
  offset++;

  if(type == BLUECHERRY_COAP_TYPE_ACK) {
    if(msg_id != _bluecherry_opdata.cur_message_id) {
      ESP_LOGE(TAG, "Received ACK for %" PRIu16 " instead of %" PRIu32 "", msg_id,
               _bluecherry_opdata.cur_message_id);
      return ESP_ERR_INVALID_STATE;
    }

    _bluecherry_opdata.last_acked_message_id = msg_id;
  }

  switch(code) {
  case BLUECHERRY_COAP_RSP_VALID:
    want_resync = false;
    break;

  case BLUECHERRY_COAP_RSP_CONTINUE:
    want_resync = true;
    break;

  default:
    ESP_LOGE(TAG, "Received invalid CoAP code %02X", code);
    return ESP_ERR_INVALID_RESPONSE;
  }

  while(offset < _bluecherry_opdata.in_buf_len) {
    uint8_t topic = _bluecherry_opdata.in_buf[offset++];
    uint8_t data_len = _bluecherry_opdata.in_buf[offset++];

    if(topic == 0x00) {
      want_resync = true;

      if(_blueCherryProcessEvent(_bluecherry_opdata.in_buf + offset, data_len)) {
        _bluecherry_opdata.emitErrorEvent = true;
        _bluecherry_opdata.otaSize = 0;
      }
    } else if(_bluecherry_opdata.msg_handler != NULL) {
      _bluecherry_opdata.msg_handler(topic, data_len, _bluecherry_opdata.in_buf + offset,
                                     _bluecherry_opdata.msg_handler_args);
    }

    offset += data_len;
  }

  if(want_resync) {
    _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_PENDING_MESSAGES;
    return BLUECHERRY_SYNC_CONTINUE;
  }

  _bluecherry_opdata.state = BLUECHERRY_STATE_CONNECTED_IDLE;
  return ESP_OK;
}

esp_err_t bluecherry_publish(uint8_t topic, uint16_t len, const uint8_t* data)
{
  ESP_LOGD(TAG, "Scheduling publish on topic 0x%02X with %dB of data", topic, len);
  if(len >
     (BLUECHERRY_MAX_MESSAGE_LEN - (BLUECHERRY_COAP_HEADER_SIZE + BLUECHERRY_MQTT_HEADER_SIZE))) {
    ESP_LOGE(TAG, "The message exceeds the maximum allowed size");
    return ESP_ERR_INVALID_SIZE;
  }

  size_t total_len = BLUECHERRY_COAP_HEADER_SIZE + BLUECHERRY_MQTT_HEADER_SIZE + len;

  uint8_t* data_cpy = malloc(total_len);
  if(data_cpy == NULL) {
    ESP_LOGE(TAG, "Could not allocate publish buffer: %s", strerror(errno));
    return ESP_ERR_NO_MEM;
  }

  (data_cpy + BLUECHERRY_COAP_HEADER_SIZE)[0] = topic;
  (data_cpy + BLUECHERRY_COAP_HEADER_SIZE)[1] = len & 0xFF;
  memcpy(data_cpy + BLUECHERRY_COAP_HEADER_SIZE + BLUECHERRY_MQTT_HEADER_SIZE, data, len);

  _bluecherry_msg_t msg = { .len = total_len, .data = data_cpy };

  if(xQueueSendToBack(_bluecherry_opdata.out_queue, &msg, 0) != pdTRUE) {
    free(data_cpy);
    return ESP_ERR_NO_MEM;
  }

  return ESP_OK;
}

#pragma endregion