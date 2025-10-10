/**
 * @file bluecherry.h
 * @author Daan Pape (daan@dptechnics.com)
 * @brief This code connects to the BlueCherry platform.
 * @version 1.1.0
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

#include <mbedtls/net_sockets.h>
#include <freertos/FreeRTOS.h>
#include <mbedtls/platform.h>
#include <mbedtls/ctr_drbg.h>
#include <esp_image_format.h>
#include <mbedtls/entropy.h>
#include <spi_flash_mmap.h>
#include <mbedtls/timing.h>
#include <freertos/queue.h>
#include <mbedtls/error.h>
#include <esp_partition.h>
#include <freertos/task.h>
#include <esp_task_wdt.h>
#include <lwip/sockets.h>
#include <esp_ota_ops.h>
#include <esp_vfs_fat.h>
#include <esp_vfs.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>

#ifndef BLUECHERRY_H
#define BLUECHERRY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief This return code is used by BlueCherry sync to signal if it want's to continue syncing.
 */
#define BLUECHERRY_SYNC_CONTINUE 0x100

/**
 * @brief The maximum size of a BlueCherry message payload.
 */
#define BLUECHERRY_MAX_MESSAGE_LEN 1024

/*
 * @brief The timeout in seconds for a SSL handshake to complete.
 */
#define SSL_HANDSHAKE_TIMEOUT_SEC 30

/**
 * @brief Encrypted block size within flash.
 */
#define ENCRYPTED_BLOCK_SIZE 16

/**
 * @brief SPI flash sectors per erase block, usually large erase block is 32k/64k.
 */
#define SPI_SECTORS_PER_BLOCK 16

/**
 * @brief SPI flash erase block size
 */
#define SPI_FLASH_BLOCK_SIZE (SPI_SECTORS_PER_BLOCK * SPI_FLASH_SEC_SIZE)

/**
 * @brief The maximum number of pending outgoing messages.
 */
static const UBaseType_t BLUECHERRY_MAX_PENDING_OUTGOING_MESSAGES = 32;

/**
 * @brief Header of the function that handles incoming MQTT messages.
 *
 * This is the header of the function that is called when a new incoming MQTT message has arrived
 * from the BlueCherry cloud.
 *
 * @param topic The topic as the topic index.
 * @param len The length of the incoming data.
 * @param data The incoming data buffer.
 * @param args Optional user arguments, passed when the handler was installed.
 *
 * @return None
 */
typedef void (*bluecherry_msg_handler_t)(uint8_t topic, uint16_t len, const uint8_t* data,
                                         void* args);

/**
 * @brief The different states the BlueCherry connection can be in.
 */
typedef enum {
  BLUECHERRY_STATE_UNINITIALIZED = 0,
  BLUECHERRY_STATE_AWAIT_CONNECTION,
  BLUECHERRY_STATE_CONNECTED_IDLE,
  BLUECHERRY_STATE_CONNECTED_AWAITING_RESPONSE,
  BLUECHERRY_STATE_CONNECTED_TIMED_OUT,
  BLUECHERRY_STATE_CONNECTED_RECEIVED_ACK,
  BLUECHERRY_STATE_CONNECTED_PENDING_MESSAGES,
} bluecherry_state;

/**
 * @brief The types of CoAP packets.
 */
typedef enum {
  BLUECHERRY_COAP_TYPE_CON = 0,
  BLUECHERRY_COAP_TYPE_NON = 1,
  BLUECHERRY_COAP_TYPE_ACK = 2,
  BLUECHERRY_COAP_TYPE_RST = 3
} _bluecherry_coap_type;

/**
 * @brief The types of CoAP responses.
 */
typedef enum {
  BLUECHERRY_COAP_RSP_VALID = 0x43,
  BLUECHERRY_COAP_RSP_CONTINUE = 0x61
} _bluecherry_coap_response;

/**
 * @brief The possible types of BlueCherry events.
 */
typedef enum {
  BLUECHERRY_EVENT_TYPE_OTA_INITIALIZE = 1,
  BLUECHERRY_EVENT_TYPE_OTA_CHUNK = 2,
  BLUECHERRY_EVENT_TYPE_OTA_FINISH = 3,
  BLUECHERRY_EVENT_TYPE_OTA_ERROR = 4
} _bluecherry_event_type;

/**
 * @brief The hostname of the BlueCherry cloud.
 */
static const char* BLUECHERRY_HOST = "coap.bluecherry.io";

/**
 * @brief The port of the BlueCherry cloud.
 */
static const char* BLUECHERRY_PORT = "5684";

/**
 * @brief The priority used for automatically syncing with BlueCherry.
 */
static const UBaseType_t BLUECHERRY_SP = 10;

/**
 * @brief The period in seconds between automatic BlueCherry syncs.
 */
static const uint8_t BLUECHERRY_AUTO_SYNC_SECONDS = 10;

/**
 * @brief The size of the BlueCherry CoAP header.
 */
static const size_t BLUECHERRY_COAP_HEADER_SIZE = 5;

/**
 * @brief The size the the BlueCherry MQTT header.
 */
static const size_t BLUECHERRY_MQTT_HEADER_SIZE = 2;

/**
 * @brief The maximum number of CoAP retransmits.
 */
static const uint8_t BLUECHERRY_MAX_RETRANSMITS = 4;

/**
 * @brief The CoAP acknowledgement base timeout period.
 */
static const double BLUECHERRY_ACK_TIMEOUT = 2.0;

/**
 * @brief The CoAP acknowledgement timeout period randomness factor.
 */
static const double BLUECHERRY_ACK_RANDOM_FACTOR = 1.5;

/**
 * @brief The maximum number of milliseconds to wait for a datagram to arrive on a socket.
 */
static const uint32_t BLUECHERRY_SSL_READ_TIMEOUT = 100;

/**
 * @brief The BlueCherry CA root + intermediate certificate used for CoAP DTLS
 * communication.
 */
static const char* BLUECHERRY_CA = "-----BEGIN CERTIFICATE-----\r\n\
MIIBlTCCATqgAwIBAgICEAAwCgYIKoZIzj0EAwMwGjELMAkGA1UEBhMCQkUxCzAJ\r\n\
BgNVBAMMAmNhMB4XDTI0MDMyNDEzMzM1NFoXDTQ0MDQwODEzMzM1NFowJDELMAkG\r\n\
A1UEBhMCQkUxFTATBgNVBAMMDGludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqG\r\n\
SM49AwEHA0IABJGFt28UrHlbPZEjzf4CbkvRaIjxDRGoeHIy5ynfbOHJ5xgBl4XX\r\n\
hp/r8zOBLqSbu6iXGwgjp+wZJe1GCDi6D1KjZjBkMB0GA1UdDgQWBBR/rtuEomoy\r\n\
49ovMAnj5Hpmk2gTGjAfBgNVHSMEGDAWgBR3Vw0Y1sUvMhkX7xySsX55tvsu8TAS\r\n\
BgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAwNJ\r\n\
ADBGAiEApN7DmuufC/aqyt6g2Y8qOWg6AXFUyTcub8/Y28XY3KgCIQCs2VUXCPwn\r\n\
k8jR22wsqNvZfbndpHthtnPqI5+yFXrY4A==\r\n\
-----END CERTIFICATE-----\r\n\
-----BEGIN CERTIFICATE-----\r\n\
MIIBmDCCAT+gAwIBAgIUDjfXeosg0fphnshZoXgQez0vO5UwCgYIKoZIzj0EAwMw\r\n\
GjELMAkGA1UEBhMCQkUxCzAJBgNVBAMMAmNhMB4XDTI0MDMyMzE3MzU1MloXDTQ0\r\n\
MDQwNzE3MzU1MlowGjELMAkGA1UEBhMCQkUxCzAJBgNVBAMMAmNhMFkwEwYHKoZI\r\n\
zj0CAQYIKoZIzj0DAQcDQgAEB00rHNthOOYyKj80cd/DHQRBGSbJmIRW7rZBNA6g\r\n\
fbEUrY9NbuhGS6zKo3K59zYc5R1U4oBM3bj6Q7LJfTu7JqNjMGEwHQYDVR0OBBYE\r\n\
FHdXDRjWxS8yGRfvHJKxfnm2+y7xMB8GA1UdIwQYMBaAFHdXDRjWxS8yGRfvHJKx\r\n\
fnm2+y7xMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49\r\n\
BAMDA0cAMEQCID7AcgACnXWzZDLYEainxVDxEJTUJFBhcItO77gcHPZUAiAu/ZMO\r\n\
VYg4UI2D74WfVxn+NyVd2/aXTvSBp8VgyV3odA==\r\n\
-----END CERTIFICATE-----\r\n";

/**
 * @brief This structure represents a scheduled BlueCherry message.
 */
typedef struct {
  /**
   * @brief The length of the data
   */
  size_t len;

  /**
   * @brief A pointer to the data.
   */
  uint8_t* data;
} _bluecherry_msg_t;

/**
 * @brief The operational data used by the BlueCherry cloud connection.
 */
typedef struct {
  /**
   * @brief The current state of the BlueCherry cloud connection.
   */
  bluecherry_state state;

  /**
   * @brief The Mbed TLS SSL context.
   */
  mbedtls_ssl_context ssl;

  /**
   * @brief The Mbed TLS SSL configuration.
   */
  mbedtls_ssl_config ssl_conf;

  /**
   * @brief The Mbed TLS random number generator context and state.
   */
  mbedtls_ctr_drbg_context ctr_drbg;

  /**
   * @brief The Mbed TLS entropy context.
   */
  mbedtls_entropy_context entropy;

  /**
   * @brief The server certificate.
   */
  mbedtls_x509_crt cacert;

  /**
   * @brief The device certificate.
   */
  mbedtls_x509_crt devcert;

  /**
   * @brief The device key.
   */
  mbedtls_pk_context devkey;

  /**
   * @brief The Mbed TLS delay context timer.
   */
  mbedtls_timing_delay_context timer;

  /**
   * @brief The socket used to communicate with the BlueCherry cloud.
   */
  int sock;

  /**
   * @brief The outgoing message queue.
   */
  QueueHandle_t out_queue;

  /**
   * @brief The message handler or NULL to ignore incoming messages.
   */
  bluecherry_msg_handler_t msg_handler;

  /**
   * @brief Optional user arguments to pass to the incoming message handler.
   */
  void* msg_handler_args;

  /**
   * @brief The current CoAP message id that is used.
   */
  int32_t cur_message_id;

  /**
   * @brief The last CoAP message id that was acknowledged from the cloud.
   */
  int32_t last_acked_message_id;

  /**
   * @brief The last CoAP transmission time.
   */
  time_t last_tx_time;

  /**
   * @brief The length of the last incoming buffer data.
   */
  size_t in_buf_len;

  /**
   * @brief The buffer to receive incoming server data in.
   */
  uint8_t in_buf[BLUECHERRY_MAX_MESSAGE_LEN];

  /**
   * @brief Pointer to where the incoming OTA data should be saved.
   */
  uint8_t otaBuffer[SPI_FLASH_SEC_SIZE];

  /**
   * @brief The current position in the OTA buffer.
   */
  uint32_t otaBufferPos;

  /**
   * @brief A buffer used to store the start of an OTA file, this is metadata and not actual
   * firmware data.
   */
  uint8_t otaSkipBuffer[ENCRYPTED_BLOCK_SIZE];

  /**
   * @brief Flag used to signal an error.
   */
  bool emitErrorEvent;

  /**
   * @brief The total size of the OTA image.
   */
  uint32_t otaSize;

  /**
   * @brief The OTA progress in percent, 0 means that the OTA is not currently running.
   */
  uint32_t otaProgress;

  /**
   * @brief The current OTA partition.
   */
  const esp_partition_t* otaPartition;
} _bluecherry_t;

/**
 * @brief Initialize the BlueCherry subsystem without ZTP.
 *
 * This function will initialize the BlueCherry IoT module without zero-touch provisioning enabled.
 *
 * @param device_cert The BlueCherry device certificate in PEM format.
 * @param device_key The BlueCherry device certificate's key in PEM format.
 * @param msg_handler The handler used for incoming messages or NULL to ignore them.
 * @param msg_handler_args Optional user pointer which is passed to the message handler.
 * @param auto_sync When set to true, the library will atomatically perform syncs in the background.
 * @param watchdog_timeout_seconds The timeout in seconds for the task watchdog. If not 0, your
 * application should ensure that `esp_task_wdt_reset()` is repeatedly called within this time.
 * Should be more than 30 seconds
 *
 * @return ESP_OK on success.
 */
esp_err_t bluecherry_init(const char* device_cert, const char* device_key,
                          bluecherry_msg_handler_t msg_handler, void* msg_handler_args,
                          bool auto_sync, uint16_t watchdog_timeout_seconds);

/**
 * @brief Synchronize incoming and outgoing BlueCherry messages and perform OTA.
 *
 * This function will communicate with the BlueCherry cloud and send any enqueued MQTT messages,
 * check if there are any incoming MQTT messages and check for OTA updates.
 *
 * @param blocking When true, the function will block until a message is sent or received, or the
 *                  BLUECHERRY_AUTO_SYNC_SECONDS timeout expires.
 *
 * @return ESP_OK when finished, BLUECHERRY_SYNC_CONTINUE when more messages are pending.
 */
esp_err_t bluecherry_sync(bool blocking);

/**
 * @brief Enqueue an MQTT message for publishing.
 *
 * This function will add the MQTT message to the outgoing message queue. After bluecherry_sync, the
 * messages will be forwarded to the designated broker.
 *
 * @param topic The topic of the message, passed as the topic index.
 * @param len The length of the topic payload data.
 * @param data The topic payload data.
 * @param copy True when the data must be copied.
 *
 * @return ESP_OK on success.
 */
esp_err_t bluecherry_publish(uint8_t topic, uint16_t len, const uint8_t* data);

#ifdef __cplusplus
};
#endif

#endif