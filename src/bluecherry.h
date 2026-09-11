/**
 * @file bluecherry.h
 * @author Daan Pape <daan@dptechnics.com>
 * @author Thibo Verheyde <thibo@dptechnics.com>
 * @author Arnoud Devoogdt <arnoud@dptechnics.com>
 * @brief This code connects to the BlueCherry platform.
 * @version 1.3.4
 * @date 2025-10-27
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
#include <bootloader_random.h>
#include <freertos/FreeRTOS.h>
#include <mbedtls/platform.h>
#include <mbedtls/ctr_drbg.h>
#include <esp_image_format.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/entropy.h>
#include <spi_flash_mmap.h>
#include <mbedtls/timing.h>
#include <freertos/queue.h>
#include <mbedtls/error.h>
#include <esp_partition.h>
#include <freertos/task.h>
#include <esp_heap_caps.h>
#include <esp_task_wdt.h>
#include <lwip/sockets.h>
#include <esp_ota_ops.h>
#include <esp_vfs_fat.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <esp_random.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <esp_vfs.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
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

/**
 * @brief The timeout in seconds for a SSL handshake to complete.
 */
#define SSL_HANDSHAKE_TIMEOUT_SEC 30

/**
 * @brief Encrypted block size within flash.
 */
#define ENCRYPTED_BLOCK_SIZE 16

/**
 * @brief Size of the priority slot holding one outgoing internal-channel frame.
 *
 * A macro, not the sum of BLUECHERRY_COAP_HEADER_SIZE and
 * BLUECHERRY_MQTT_HEADER_SIZE below: those are `static const size_t`, which is
 * not a constant expression in C and cannot size a struct member. Same reason
 * every other array size in this header is a #define.
 *
 * 5 header + 2 framing + 128 payload. The largest internal event is INIT_INFO,
 * which runs to about 84 bytes in practice. Its absolute worst case — three
 * BLUECHERRY_INFO_STR_MAX strings — is 153 and does NOT fit; that is safe only
 * because _bluecherry_info_add_str drops a field it cannot fit rather than
 * writing half of one. See the _Static_assert in _bluecherry_send_init_info for
 * the part that must fit unconditionally.
 */
#define BLUECHERRY_EVENT_PAYLOAD_MAX 128
#define BLUECHERRY_PENDING_EVENT_SIZE (5 + 2 + BLUECHERRY_EVENT_PAYLOAD_MAX)

/**
 * @brief SPI flash sectors per erase block, usually large erase block is 32k/64k.
 */
#define SPI_SECTORS_PER_BLOCK 16

/**
 * @brief SPI flash erase block size
 */
#define SPI_FLASH_BLOCK_SIZE (SPI_SECTORS_PER_BLOCK * SPI_FLASH_SEC_SIZE)

/**
 * @brief The size of the private key buffer.
 */
#define BLUECHERRY_ZTP_PKEY_BUF_SIZE 256

/**
 * @brief The size of the CSR/certificate buffer.
 */
#define BLUECHERRY_ZTP_CERT_BUF_SIZE 576

/**
 * @brief The number of characters in a BlueCherry Type ID or Device ID.
 */
#define BLUECHERRY_ZTP_ID_LEN 8

/**
 * @brief The size of the CSR subject buffer.
 */
#define BLUECHERRY_ZTP_SUBJ_BUF_SIZE 32

/**
 * @brief The length of a MAC address in bytes.
 */
#define BLUECHERRY_ZTP_MAC_LEN 6

/**
 * @brief The length of an IMEI number.
 */
#define BLUECHERRY_ZTP_IMEI_LEN 15

/**
 * @brief The maximum number of device identification parameters.
 */
#define BLUECHERRY_ZTP_MAX_DEVICE_ID_PARAMS 3

/**
 * @brief Bytes skipped at the head of a ZTP CoAP response.
 *
 * The ZTP exchange does not parse its responses; it skips a fixed header and treats the
 * remainder as the CBOR payload. Any change to the server's response header silently
 * corrupts the payload, so this constant is a contract with the ZTP service.
 */
#define BLUECHERRY_ZTP_RSP_HEADER_LEN 7

/**
 * @brief The size of the ZTP transmit buffer.
 *
 * Sized to hold the largest ZTP request, which is the CSR: a CoAP header, the payload
 * marker and BLUECHERRY_ZTP_CERT_BUF_SIZE bytes of DER, with room to spare. A fixed buffer
 * rather than a VLA, so the stack cost is visible at compile time instead of depending on a
 * length computed at run time.
 */
#define BLUECHERRY_ZTP_TX_BUF_SIZE (BLUECHERRY_ZTP_CERT_BUF_SIZE + 64)

/**
 * @brief Header of the function that handles reading/writing of certificates and keys
 * for zero-touch provisioning.
 *
 * @param read True when reading, false when writing.
 * @param secure True when handling the private key, false when handling the certificate.
 * @param args Optional user arguments, key or certificate passed as arguments when writing.
 *
 * @return The certificate or key when reading, NULL when writing.
 */
typedef const char* (*bluecherry_ztp_bio_handler_t)(bool read, bool secure, void* args);

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
 * @brief This enumeration list all different types of device identification
 * parameters.
 */
typedef enum {
  BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC = 0,
  BLUECHERRY_ZTP_DEVICE_ID_TYPE_IMEI,
  BLUECHERRY_ZTP_DEVICE_ID_TYPE_OOB_CHALLENGE
} bluecherry_ztp_device_id_type;

/**
 * @brief The different states the BlueCherry connection can be in.
 *
 * The progression is linear: nothing allocated, no credentials, credentials but no session,
 * session up. Only bluecherry_sync moves between them, and it is the only thing that touches
 * the network — bluecherry_init allocates and never connects.
 */
typedef enum {
  /**
   * @brief Nothing has been allocated yet.
   */
  BLUECHERRY_STATE_UNINITIALIZED = 0,

  /**
   * @brief Allocated, but no device credentials are available yet.
   *
   * The next bluecherry_sync reads them through the storage handler and, if they are absent,
   * provisions this device before going on to connect.
   */
  BLUECHERRY_STATE_NOT_PROVISIONED,

  /**
   * @brief Credentials are loaded but there is no live session.
   */
  BLUECHERRY_STATE_AWAIT_CONNECTION,

  /**
   * @brief Session up, nothing outstanding.
   */
  BLUECHERRY_STATE_IDLE,

  /**
   * @brief A confirmable message is on the wire.
   *
   * Set for the duration of a request/response exchange so a second, concurrent call to
   * bluecherry_sync is rejected rather than corrupting the exchange.
   */
  BLUECHERRY_STATE_AWAITING_RESPONSE,

  /**
   * @brief The server signalled that it still has data queued for this device.
   */
  BLUECHERRY_STATE_PENDING_MESSAGES
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
  // 1..3 are the OTA messages the cloud sends before it knows what this client
  // speaks. It implements none of them: 1 is answered with the probe reply (see
  // BLUECHERRY_OTA_ERROR_UNSUPPORTED_PROTOCOL) and 2 and 3 are discarded.
  BLUECHERRY_EVENT_TYPE_OTA_PROBE = 1, // Server -> Client: the cloud's opening OTA message, which
                                       // this client answers to announce the protocol it speaks.
  BLUECHERRY_EVENT_TYPE_OTA_UNSUPPORTED_CHUNK =
      2, // Server -> Client: image data in a form this client does not accept. Discarded.
  BLUECHERRY_EVENT_TYPE_OTA_UNSUPPORTED_FINISH =
      3, // Server -> Client: end of an image this client never accepted. Discarded.
  BLUECHERRY_EVENT_TYPE_ERROR =
      4, // Client -> Server: a topic 0x00 handler failed. Historically payload-less; a reason byte
         // may be appended, see BLUECHERRY_OTA_ERROR_*.
  // MOTA 5..8: modem firmware update. Not implemented here, but reserved by the
  // protocol and in use elsewhere, where it shares its transfer state with the
  // application OTA path. Never reuse these.
  // MOTA RESERVED, 5
  // MOTA RESERVED, 6
  // MOTA RESERVED, 7
  // MOTA RESERVED, 8
  BLUECHERRY_EVENT_TYPE_PARTITION_HASH =
      9, // Client -> Server: Sends the currently running partition hash to the server. Server can
         // use this to verify if an OTA was received.
  BLUECHERRY_EVENT_TYPE_OTA_INITIALIZE =
      10, // Server -> Client: Informs the client an OTA update is available. Server reports the
          // total size, hash, and version number
  BLUECHERRY_EVENT_TYPE_OTA_START =
      11, // Client -> Server: Requests the start of the OTA update. Echoes back the version number
          // so the server can verify it matches the intended update.
  BLUECHERRY_EVENT_TYPE_OTA_CHUNK = 12, // Server -> Client: Sends a chunk of the OTA update
  BLUECHERRY_EVENT_TYPE_OTA_VERIFIED =
      13, // Client -> Server: Informs the server that the OTA update has been fully received and
          // checksum has been verified. (ready for reboot)
  BLUECHERRY_EVENT_TYPE_OTA_ERROR =
      14, // Client -> Server: Informs the Server that an error occurred during the OTA update, and
          // that the update should stop. Can be thrown at any time during the download, or at the
          // verification step. (Server will re-try ota up until max 3 times)
  BLUECHERRY_EVENT_TYPE_INIT_INFO =
      15 // Client -> Server: Sends initial information about the client to the server.
} _bluecherry_event_type;

/**
 * @brief Reason byte appended to BLUECHERRY_EVENT_TYPE_ERROR: the probe reply.
 *
 * The cloud opens every OTA with BLUECHERRY_EVENT_TYPE_OTA_PROBE and sends
 * nothing this client accepts until it is answered with [4][0xB2].
 *
 * The reply must be EXACTLY those two bytes. A one-byte [4] is the historic
 * payload-less error reported on any topic 0x00 failure, and the length is all
 * that keeps the two apart.
 */
#define BLUECHERRY_OTA_ERROR_UNSUPPORTED_PROTOCOL 0xB2

/**
 * @brief OTA error codes, sent as BLUECHERRY_EVENT_TYPE_OTA_ERROR.
 */
typedef enum {
  BLUECHERRY_OTA_ERR_NO_PARTITION = 1,
  BLUECHERRY_OTA_ERR_TOO_LARGE = 2,
  BLUECHERRY_OTA_ERR_ERASE_FAILED = 3,
  BLUECHERRY_OTA_ERR_WRITE_FAILED = 4,
  BLUECHERRY_OTA_ERR_HASH_MISMATCH = 5,
  BLUECHERRY_OTA_ERR_BAD_MAGIC = 6,
  BLUECHERRY_OTA_ERR_SET_BOOT_FAILED = 7,
  BLUECHERRY_OTA_ERR_APP_ABORTED = 8,
  BLUECHERRY_OTA_ERR_CHUNK_OVERRUN = 9
} bluecherry_ota_error_t;

/**
 * @brief Length of an image SHA-256, as reported in INIT_INFO and as carried by
 * BLUECHERRY_EVENT_TYPE_OTA_INITIALIZE and _VERIFIED.
 */
#define BLUECHERRY_PARTITION_HASH_LEN 32

/**
 * @brief INIT_INFO payload layout.
 *
 * Mandatory core, 36 bytes:
 *   [0]       event type = 15
 *   [1]       schema version = 1
 *   [2..33]   running partition SHA-256
 *   [34..35]  presence bitmap, uint16 little endian
 *
 * Optional fields follow in ascending bit order. Fixed-width fields carry their
 * value directly; a string field is [1B length][that many UTF-8 bytes], with a
 * zero length legal and meaning "empty", not "absent".
 *
 * They are PURELY INFORMATIONAL: the server logs them and never makes a
 * decision on them. Only the hash is acted upon.
 *
 * Changing the list: a field may be repurposed in place only if its width is
 * unchanged. A width change must RETIRE the bit and use the next free one, or a
 * stale peer misparses every field after it.
 */
#define BLUECHERRY_INIT_INFO_SCHEMA 1

#define BLUECHERRY_INFO_BIT_PLATFORM (1 << 0)    /* 1B  toolchain enum */
#define BLUECHERRY_INFO_BIT_LIB_VERSION (1 << 1) /* 3B  major, minor, patch */
/* Bit 2 is RETIRED (was a 1B esp_reset_reason()). Never reassign it. */
#define BLUECHERRY_INFO_BIT_OTA_SLOT_SIZE (1 << 3) /* 4B  usable slot size, LE */
#define BLUECHERRY_INFO_BIT_UPTIME (1 << 4)        /* 4B  seconds since boot, LE */
#define BLUECHERRY_INFO_BIT_TOTAL_HEAP (1 << 5)    /* 4B  total heap bytes, LE */
#define BLUECHERRY_INFO_BIT_APP_VERSION (1 << 6)   /* 1B len + UTF-8 */
#define BLUECHERRY_INFO_BIT_LIB_NAME (1 << 7)      /* 1B len + UTF-8 */
#define BLUECHERRY_INFO_BIT_MCU (1 << 8)           /* 1B len + UTF-8 */
#define BLUECHERRY_INFO_BIT_OTA_SLOT (1 << 9)      /* 2B  running slot, target slot */
#define BLUECHERRY_INFO_BIT_RESET_REASON (1 << 10) /* 1B len + UTF-8 */

/**
 * @brief Longest string this client will put in one INIT_INFO field.
 *
 * A field that does not fit the remaining buffer is dropped rather than
 * truncated — a cleared presence bit is something the server renders correctly,
 * whereas a half-written string would misalign every field after it.
 */
#define BLUECHERRY_INFO_STR_MAX 32

/**
 * @brief Which BlueCherry library this is, and its version.
 *
 * The name is the point: more than one client library can be built for the same
 * toolchain, so the platform enum cannot identify the sender and a bare version
 * number means nothing without it. A different library changes this one string.
 */
#define BLUECHERRY_LIB_NAME "BlueCherry"
#define BLUECHERRY_LIB_VERSION_MAJOR 1
#define BLUECHERRY_LIB_VERSION_MINOR 3
#define BLUECHERRY_LIB_VERSION_PATCH 4

/**
 * @brief The MCU this was built for, as a string.
 *
 * ESP-IDF already defines CONFIG_IDF_TARGET as e.g. "esp32s3" in the
 * force-included sdkconfig.h, so this needs no lookup table and resolves at
 * compile time. A build without it simply omits the field.
 */
#ifdef CONFIG_IDF_TARGET
#define BLUECHERRY_MCU CONFIG_IDF_TARGET
#endif

/**
 * @brief ota_slot value meaning "not an OTA slot" — a factory boot, or a
 * platform with no such concept.
 *
 * The field carries a platform-neutral slot index rather than an ESP partition
 * subtype, so that a platform with a different flash layout does not have to
 * fake an ESP encoding to report it.
 */
#define BLUECHERRY_OTA_SLOT_NONE 0xFF

/**
 * @brief Client toolchain reported in INIT_INFO.
 *
 * The toolchain, not the board — a board built on ESP-IDF reports ESP-IDF
 * whatever else is on it. ARDUINO is reported when that macro is defined, which
 * is technically still an ESP-IDF wrapper but is the useful thing to know.
 */
typedef enum {
  BLUECHERRY_PLATFORM_UNKNOWN = 0,
  BLUECHERRY_PLATFORM_ESP_IDF = 1,
  BLUECHERRY_PLATFORM_ARDUINO = 2,
  BLUECHERRY_PLATFORM_NORDIC = 3,
  BLUECHERRY_PLATFORM_ZEPHYR = 4,
  BLUECHERRY_PLATFORM_LINUX = 5
} bluecherry_platform_t;

/**
 * @brief Internal OTA state.
 */
typedef enum {
  BLUECHERRY_OTA_STATE_IDLE = 0,
  BLUECHERRY_OTA_STATE_OFFERED,           /* INITIALIZE received, waiting on the application */
  BLUECHERRY_OTA_STATE_DOWNLOADING,       /* START sent, chunks arriving */
  BLUECHERRY_OTA_STATE_AWAITING_VERIFIED, /* image written and hashed, VERIFIED queued */
  BLUECHERRY_OTA_STATE_COMPLETE           /* verified, acked, boot partition set */
} _bluecherry_ota_state;

/**
 * @brief OTA events reported to the application.
 */
typedef enum {
  /**
   * @brief An update is available; details are in bluecherry_ota_info_t.
   *
   * Carries a decision: the download. Return true and nothing happens until
   * bluecherry_ota_start() is called — there is no timeout, so waiting until
   * 3am is fine.
   */
  BLUECHERRY_OTA_EVENT_AVAILABLE,

  /** @brief The download has begun. Carries no decision. */
  BLUECHERRY_OTA_EVENT_STARTED,

  /**
   * @brief Progress: bytes_received of size written so far. Carries no
   * decision.
   *
   * Emitted once per batch that reaches flash, not once per received chunk —
   * see bytes_received.
   */
  BLUECHERRY_OTA_EVENT_PROGRESS,

  /**
   * @brief The image is written, checked, acknowledged by the server, and the
   * boot partition is set. The device keeps running the OLD firmware until it
   * restarts.
   *
   * Carries a decision: the reboot. Return true and it is yours — finish what
   * you are doing, then call esp_restart(). Nothing else from this library is
   * needed. Runs on the bc_sync task, so it must not block.
   */
  BLUECHERRY_OTA_EVENT_COMPLETE,

  /** @brief The update failed; error_code says why. Carries no decision. */
  BLUECHERRY_OTA_EVENT_FAILED
} bluecherry_ota_event_t;

/**
 * @brief Details accompanying a bluecherry_ota_event_t.
 */
typedef struct {
  /** @brief BlueCherry firmware version being offered or installed. */
  int8_t version;

  /** @brief Total image size in bytes. */
  uint32_t size;

  /**
   * @brief Expected image SHA-256, or all zeroes.
   *
   * All zeroes means the cloud holds no fingerprint for this build, so the
   * download cannot be checked against one. The client still computes and
   * reports the hash it ends up with, which is the value an operator would use
   * to populate it.
   */
  uint8_t sha256[BLUECHERRY_PARTITION_HASH_LEN];

  /**
   * @brief Bytes written to flash so far, for BLUECHERRY_OTA_EVENT_PROGRESS.
   *
   * Advances a flash sector at a time, because that is when bytes actually
   * reach the partition. Received chunks are an order of magnitude smaller and
   * stage in RAM first, so this number moves once per flush and reaches size on
   * the last one.
   */
  uint32_t bytes_received;

  /** @brief A bluecherry_ota_error_t, for BLUECHERRY_OTA_EVENT_FAILED. */
  uint8_t error_code;
} bluecherry_ota_info_t;

/**
 * @brief Handler for OTA events.
 *
 * Return true when this call took the decision the event carries, false to
 * leave it to the library. Two events carry one: BLUECHERRY_OTA_EVENT_AVAILABLE
 * (start the download) and BLUECHERRY_OTA_EVENT_COMPLETE (reboot). For the
 * other three the return value is ignored, so returning false there is the
 * normal answer and means nothing is wrong.
 *
 * A handler that returns false everywhere is therefore equivalent to
 * registering none at all: the library downloads on offer and reboots on
 * install, and the handler is pure observation. That is deliberate — watching
 * an update must not be able to stop one.
 *
 * @param event The event that occurred.
 * @param info Details for the event, valid only for the duration of the call.
 * @param args The argument given to bluecherry_ota_set_handler.
 *
 * @return True if the application took this event's decision, false to let the
 * library apply its default.
 */
typedef bool (*bluecherry_ota_handler_t)(bluecherry_ota_event_t event,
                                         const bluecherry_ota_info_t* info, void* args);

/**
 * @brief The priority used for automatically syncing with BlueCherry.
 */
static const UBaseType_t BLUECHERRY_SP = 10;

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

typedef union {
  /**
   * @brief Pointer to the BlueCherry Type ID, as this is always programmed in
   * the application, no extra memory is required.
   */
  const char* bcTypeId;

  /**
   * @brief A MAC address used for authentication.
   */
  unsigned char mac[BLUECHERRY_ZTP_MAC_LEN];

  /**
   * @brief An IMEI number in ASCII format + 0-terminator.
   */
  char imei[BLUECHERRY_ZTP_IMEI_LEN + 1];

  /**
   * @brief A 64-bit OOB challenge.
   */
  unsigned long long oobChallenge;
} _bluecherry_ztp_device_id_value_t;

/**
 * @brief This structure represents a device identifier.
 */
typedef struct {
  /**
   * @brief The type of device identifier.
   */
  bluecherry_ztp_device_id_type type;

  /**
   * @brief The value of the device identifier.
   */
  _bluecherry_ztp_device_id_value_t value;
} _bluecherry_ztp_device_id_param_t;

/**
 * @brief This structure represents a buffer and length of a CSR stored in PEM
 * format.
 */
typedef struct {
  /**
   * @brief The buffer used to store a CSR.
   */
  unsigned char buffer[BLUECHERRY_ZTP_CERT_BUF_SIZE];

  /**
   * @brief The data length of the CSR.
   */
  size_t length;
} _bluecherry_ztp_csr_t;

/**
 * @brief This structure represents the device identification parameters.
 */
typedef struct {
  /**
   * @brief The array of device identification parameters.
   */
  _bluecherry_ztp_device_id_param_t param[BLUECHERRY_ZTP_MAX_DEVICE_ID_PARAMS];

  /**
   * @brief The number of parameters in the list.
   */
  int count;
} _bluecherry_ztp_device_id_t;

/**
 * @brief The CBOR context structure.
 */
typedef struct {
  /**
   * @brief Output buffer pointer.
   */
  uint8_t* buffer;

  /**
   * @brief Maximum size of the buffer.
   */
  size_t capacity;

  /**
   * @brief Current write position in the buffer.
   */
  size_t position;
} _ztp_cbor_t;

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
   * @brief Mbed TLS CSR creation object.
   */
  mbedtls_x509write_csr ztp_mbCsr;

  /**
   * @brief The device key.
   */
  mbedtls_pk_context devkey;

  /**
   * @brief The Mbed TLS delay context timer.
   */
  mbedtls_timing_delay_context timer;

  /**
   * @brief The device ZTP identification data.
   */
  _bluecherry_ztp_device_id_t ztp_devIdParams;

  /**
   * @brief The CSR context.
   */
  _bluecherry_ztp_csr_t ztp_csr;

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
   * @brief The credential storage handler, or NULL when not using provisioning.
   *
   * Retained after init because provisioning now happens in bluecherry_sync, which needs to
   * read the stored credentials and write back the ones it is issued.
   */
  bluecherry_ztp_bio_handler_t ztp_bio_handler;

  /**
   * @brief Optional user arguments to pass to the credential storage handler.
   */
  void* ztp_bio_handler_args;

  /**
   * @brief The current CoAP message id that is used.
   */
  uint16_t cur_message_id;

  /**
   * @brief The last CoAP message id that was acknowledged from the cloud.
   */
  uint16_t last_acked_message_id;

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

  /**
   * @brief OTA state.
   */
  _bluecherry_ota_state otaState;

  /**
   * @brief The image SHA-256 the cloud says this update should have.
   *
   * All zeroes means no fingerprint is on record, so the download cannot be
   * checked against one. The hash is still computed and reported either way.
   */
  uint8_t otaExpectedHash[BLUECHERRY_PARTITION_HASH_LEN];

  /**
   * @brief True when otaExpectedHash is the all-zero "no fingerprint" sentinel.
   */
  bool otaUnverified;

  /**
   * @brief The BlueCherry firmware version being installed, echoed back to the
   * server in START, VERIFIED and ERROR so it can tell which update we mean.
   */
  int8_t otaTargetVersion;

  /**
   * @brief Priority slot for one outgoing internal-channel (topic 0x00) frame.
   *
   * Checked BEFORE out_queue in the send step — see bluecherry_sync for why.
   * One slot suffices because every internal event is a reply the server then
   * responds to, so only one is ever outstanding.
   */
  uint8_t pending_event[BLUECHERRY_PENDING_EVENT_SIZE];

  /**
   * @brief Length of the framed message in pending_event, 0 when empty.
   */
  size_t pending_event_len;

  /**
   * @brief The application's OTA handler, or NULL.
   *
   * NULL means the library decides for itself: start on offer, reboot on
   * completion. So does a handler that returns false — the pointer says whether
   * anyone is watching, the return value says who decides, and only the second
   * of those can differ per event.
   */
  bluecherry_ota_handler_t ota_handler;

  /**
   * @brief Optional user pointer passed to the OTA handler.
   */
  void* ota_handler_args;
} _bluecherry_t;

/**
 * @brief Initialize the BlueCherry subsystem with an existing device certificate.
 *
 * Reserves the outgoing queue, the TLS contexts and — when auto_sync is set — the
 * synchronisation task. It does not touch the network: the connection is established by the
 * first bluecherry_sync, so this call cannot fail because the cloud is unreachable.
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
 * @brief Initialize the BlueCherry subsystem with zero-touch provisioning.
 *
 * Reserves the same resources as bluecherry_init and returns immediately. Reading the stored
 * credentials, and provisioning this device when there are none, both happen on the first
 * bluecherry_sync — so this call does not touch the network and does not need to be retried
 * in a loop. A provisioning failure is reported by bluecherry_sync instead, which keeps
 * trying with a growing back-off.
 *
 * @param ztp_bio_handler The handler used for reading/writing keys and certificates. This must be
 * implemented by the application.
 * @param ztp_bio_handler_args Optional user pointer which is passed to the ZTP bio handler.
 * @param bc_device_type The BlueCherry device type string.
 * @param msg_handler The handler used for incoming messages or NULL to ignore them.
 * @param msg_handler_args Optional user pointer which is passed to the message handler.
 * @param auto_sync When set to true, the library will atomatically perform syncs in the background.
 * @param watchdog_timeout_seconds The timeout in seconds for the task watchdog. If not 0, your
 * application should ensure that `esp_task_wdt_reset()` is repeatedly called within this time.
 * Should be more than 30 seconds
 *
 * @return ESP_OK once initialized, ESP_ERR_INVALID_ARG on a missing handler or device type.
 */
esp_err_t bluecherry_init_ztp(bluecherry_ztp_bio_handler_t ztp_bio_handler,
                              void* ztp_bio_handler_args, const char* bc_device_type,
                              bluecherry_msg_handler_t msg_handler, void* msg_handler_args,
                              bool auto_sync, uint16_t watchdog_timeout_seconds);

/**
 * @brief Synchronize incoming and outgoing BlueCherry messages and perform OTA.
 *
 * This is the only function that uses the network. In order, it provisions the device when it
 * has no credentials yet, opens the connection when there is none, sends one enqueued message,
 * and dispatches whatever came back — incoming messages to the message handler and firmware
 * updates to the OTA machinery.
 *
 * It works the same whether the application calls it itself or the automatic synchronisation
 * task does. Each step is back-off gated and returns ESP_ERR_NOT_FINISHED rather than blocking
 * until it succeeds, so calling this in a loop is what drives a device from freshly booted to
 * connected.
 *
 * @param blocking When true, the function will block until a message is sent or received, or the
 *                  BLUECHERRY_AUTO_SYNC_SECONDS timeout expires.
 *
 * @return ESP_OK when finished, BLUECHERRY_SYNC_CONTINUE when more messages are pending,
 * ESP_ERR_NOT_FINISHED while still provisioning or connecting.
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
 *
 * @return ESP_OK on success.
 */
esp_err_t bluecherry_publish(uint8_t topic, uint16_t len, const uint8_t* data);

/**
 * @brief Register a handler for OTA events.
 *
 * Entirely optional. With no handler the library starts a download as soon as
 * one is offered and reboots as soon as it is installed, so an application that
 * never calls this still receives updates.
 *
 * The two decisions are independently deferrable — see
 * bluecherry_ota_handler_t. The handler runs on the bc_sync task and must not
 * block.
 *
 * @param handler The handler, or NULL to hand control back to the library.
 * @param args Optional user pointer passed to the handler.
 *
 * @return ESP_OK on success.
 */
esp_err_t bluecherry_ota_set_handler(bluecherry_ota_handler_t handler, void* args);

/**
 * @brief Accept an offered update and begin the download.
 *
 * Only needed by a handler that returned true from
 * BLUECHERRY_OTA_EVENT_AVAILABLE, which is what stops the library starting the
 * download itself. Call it from that handler or long afterwards — the offer does
 * not expire, so an application is free to wait for a quiet moment. If the cloud
 * has withdrawn the update in the meantime the request simply goes unanswered.
 *
 * @return ESP_OK when the request was queued, ESP_ERR_INVALID_STATE when no
 * update is currently on offer.
 */
esp_err_t bluecherry_ota_start(void);

/**
 * @brief Abandon the update in progress and tell the cloud why.
 *
 * The server counts this as one of three attempts and stops offering the update
 * after the third.
 *
 * @param error_code A bluecherry_ota_error_t. Use
 * BLUECHERRY_OTA_ERR_APP_ABORTED when the application is the one giving up.
 *
 * @return ESP_OK when the report was queued.
 */
esp_err_t bluecherry_ota_abort(uint8_t error_code);

#ifdef __cplusplus
};
#endif

#endif