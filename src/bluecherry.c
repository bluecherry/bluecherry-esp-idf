/**
 * @file bluecherry.c
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

#include <bluecherry.h>

/**
 * @brief The operational data used by the BlueCherry cloud  connection.
 */
static _bluecherry_t _bluecherry_opdata = { 0 };

/**
 * @brief The logging tag for this BlueCherry module.
 */
static const char* TAG = "[BlueCherry]";

/**
 * @brief The hostname of the BlueCherry cloud.
 */
static const char* BLUECHERRY_HOST = "coap.bluecherry.io";

/**
 * @brief The port of the BlueCherry cloud.
 */
static const char* BLUECHERRY_PORT = "5684";

/**
 * @brief The port of the BlueCherry ZTP server.
 */
static const char* BLUECHERRY_ZTP_PORT = "5688";

/**
 * @brief The buffer used to store a private key.
 */
static char ztp_pkey_buf[BLUECHERRY_ZTP_PKEY_BUF_SIZE];

/**
 * @brief The buffer used to store a certificate.
 */
static char ztp_cert_buf[BLUECHERRY_ZTP_CERT_BUF_SIZE];

/**
 * @brief The BlueCherry device ID received from the server.
 */
static char ztp_bc_dev_id[BLUECHERRY_ZTP_ID_LEN + 1];

/**
 * @brief The size of the buffer used for the CSR subject.
 */
static char ztp_subj_buf[BLUECHERRY_ZTP_SUBJ_BUF_SIZE];

/**
 * @brief The BlueCherry type ID associated with this firmware.
 */
static const char* bc_type_id;

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
 * @brief Whether the task watchdog is enabled.
 */
static bool _watchdog = false;

/**
 * @brief When the next provisioning attempt is due, or 0 for "due now".
 *
 * At file scope because the task reads it to decide how long it can wait.
 */
static int64_t _next_provision_us = 0;

/**
 * @brief The synchronisation task, or NULL before bluecherry_init.
 *
 * Signalled by bluecherry_sync, and what stops a second init spawning a second task.
 */
static TaskHandle_t _sync_task = NULL;

/**
 * @brief Seconds between automatic synchronisations, or 0 when they are off.
 */
static uint32_t _auto_sync_interval_sec = 0;

/**
 * @brief When the last synchronisation cycle ran.
 *
 * The interval is measured from here rather than from when it was set, so changing it re-dates
 * the next synchronisation against the last one instead of restarting the clock.
 */
static int64_t _last_sync_us = 0;

/**
 * @brief When the next automatic synchronisation is due. Unused while the interval is 0.
 */
static int64_t _next_auto_sync_us = 0;

/**
 * @brief Update requests raised by the application, carried out on the sync task.
 *
 * The work they ask for writes the priority slot the task transmits out of, so the caller only
 * raises a flag: that keeps every write to that slot on one thread.
 */
static volatile bool _ota_start_req = false;
static volatile bool _ota_abort_req = false;
static volatile uint8_t _ota_abort_code = 0;

/**
 * @brief Tickle the task watchdog if enabled.
 *
 * This function tickles the task watchdog if it is enabled.
 */
static void _bluecherry_tickle_watchdog(void)
{
  if(_watchdog) {
    esp_task_wdt_reset();
  }
}

/**
 * @brief Move to a new connection state and tell the application, if it asked.
 *
 * The single place the state is written, so the handler cannot miss a transition.
 *
 * @param next The state to enter.
 */
static void _bluecherry_set_state(bluecherry_state next)
{
  if(_bluecherry_opdata.state == next) {
    return;
  }

  _bluecherry_opdata.state = next;

  if(_bluecherry_opdata.state_handler != NULL) {
    _bluecherry_opdata.state_handler(next, _bluecherry_opdata.state_handler_args);
  }
}

/**
 * @brief Release the publish buffer, freeing it only if it was not the application's.
 */
static void _bluecherry_ring_deinit(void)
{
  _bluecherry_ring_t* ring = &_bluecherry_opdata.out_ring;

  if(ring->lock != NULL) {
    vSemaphoreDelete(ring->lock);
  }
  if(ring->owned) {
    free(ring->buf);
  }

  memset(ring, 0, sizeof(*ring));
}

/**
 * @brief Reserve the publish buffer.
 *
 * @param cfg The application's buffer, or NULL to allocate one here.
 *
 * @return ESP_OK on success.
 */
static esp_err_t _bluecherry_ring_init(const bluecherry_publish_buffer_t* cfg)
{
  _bluecherry_ring_t* ring = &_bluecherry_opdata.out_ring;

  /* Idempotent: an init retried after a failed one would otherwise strand the previous buffer
   * and its lock. Safe because the synchronisation task does not touch the buffer while the
   * state is UNINITIALIZED. */
  _bluecherry_ring_deinit();

  if(cfg != NULL && cfg->buffer != NULL) {
    if(cfg->size < BLUECHERRY_MIN_PUBLISH_BUFFER) {
      ESP_LOGE(TAG, "The publish buffer must be at least %uB", BLUECHERRY_MIN_PUBLISH_BUFFER);
      return ESP_ERR_INVALID_ARG;
    }
    ring->buf = cfg->buffer;
    ring->size = cfg->size;
    ring->owned = false;
  } else {
    ring->size = CONFIG_BLUECHERRY_PUBLISH_BUFFER_SIZE;
    ring->buf = malloc(ring->size);
    if(ring->buf == NULL) {
      ESP_LOGE(TAG, "Could not allocate the %uB publish buffer", (unsigned) ring->size);
      return ESP_ERR_NO_MEM;
    }
    ring->owned = true;
  }

  ring->lock = xSemaphoreCreateMutex();
  if(ring->lock == NULL) {
    ESP_LOGE(TAG, "Could not create the publish buffer lock");
    if(ring->owned) {
      free(ring->buf);
    }
    ring->buf = NULL;
    return ESP_FAIL;
  }

  ring->head = 0;
  ring->tail = 0;
  ring->wrap = ring->size;
  ring->count = 0;

  if(ring->size < BLUECHERRY_MAX_MESSAGE_LEN + 2U) {
    ESP_LOGW(TAG, "Publish buffer of %uB limits a message to %uB", (unsigned) ring->size,
             (unsigned) (ring->size - BLUECHERRY_PUBLISH_RECORD_OVERHEAD));
  }

  return ESP_OK;
}

/**
 * @brief How many messages are waiting to be published.
 */
static size_t _bluecherry_ring_count(void)
{
  _bluecherry_ring_t* ring = &_bluecherry_opdata.out_ring;

  if(ring->lock == NULL) {
    return 0;
  }

  xSemaphoreTake(ring->lock, portMAX_DELAY);
  size_t count = ring->count;
  xSemaphoreGive(ring->lock);

  return count;
}

/**
 * @brief Frame one message into the publish buffer.
 *
 * @param topic The topic of the message, passed as the topic index.
 * @param len The length of the topic payload data.
 * @param data The topic payload data.
 *
 * @return ESP_OK on success, ESP_ERR_NO_MEM when the buffer is full.
 */
static esp_err_t _bluecherry_ring_push(uint8_t topic, uint16_t len, const uint8_t* data)
{
  _bluecherry_ring_t* ring = &_bluecherry_opdata.out_ring;
  const size_t rec = BLUECHERRY_COAP_HEADER_SIZE + BLUECHERRY_MQTT_HEADER_SIZE + len;
  const size_t need = 2 + rec;

  if(ring->lock == NULL) {
    return ESP_ERR_INVALID_STATE;
  }
  if(need > ring->size) {
    ESP_LOGE(TAG, "The message does not fit in the %uB publish buffer", (unsigned) ring->size);
    return ESP_ERR_INVALID_SIZE;
  }

  xSemaphoreTake(ring->lock, portMAX_DELAY);

  if(ring->count == 0) {
    /* Nothing is held, so start over and give the message the whole buffer to fit in. */
    ring->head = 0;
    ring->tail = 0;
    ring->wrap = ring->size;
  }

  size_t room = ring->count == 0          ? ring->size
                : ring->head > ring->tail ? ring->size - ring->head
                                          : ring->tail - ring->head;
  size_t at;

  if(room >= need) {
    at = ring->head;
    ring->head += need;
  } else if(ring->head > ring->tail && ring->tail >= need) {
    /* Out of room at the end, but the records have moved on far enough to start again in front
     * of them. wrap is where the reader has to turn around. */
    ring->wrap = ring->head;
    at = 0;
    ring->head = need;
  } else {
    xSemaphoreGive(ring->lock);
    return ESP_ERR_NO_MEM;
  }

  uint8_t* p = ring->buf + at;
  p[0] = (uint8_t) (rec & 0xFF);
  p[1] = (uint8_t) (rec >> 8);
  p += 2;

  /* The CoAP header is left as it is: it carries the message id, which the transmit path only
   * knows once it is about to send, and writes into the record then. */
  p[BLUECHERRY_COAP_HEADER_SIZE] = topic;
  p[BLUECHERRY_COAP_HEADER_SIZE + 1] = (uint8_t) (len & 0xFF);
  memcpy(p + BLUECHERRY_COAP_HEADER_SIZE + BLUECHERRY_MQTT_HEADER_SIZE, data, len);

  ring->count += 1;
  xSemaphoreGive(ring->lock);

  return ESP_OK;
}

/**
 * @brief Point at the oldest message without removing it.
 *
 * The pointer stays valid until _bluecherry_ring_pop, which is what lets the message be
 * transmitted, and retransmitted, while other tasks keep publishing: a publish only ever writes
 * from head onwards, which never reaches into the record being sent.
 *
 * @param out Filled in with the message.
 *
 * @return True when there was one.
 */
static bool _bluecherry_ring_peek(_bluecherry_msg_t* out)
{
  _bluecherry_ring_t* ring = &_bluecherry_opdata.out_ring;

  if(ring->lock == NULL) {
    return false;
  }

  xSemaphoreTake(ring->lock, portMAX_DELAY);

  bool found = ring->count > 0;
  if(found) {
    out->len = (size_t) ring->buf[ring->tail] | ((size_t) ring->buf[ring->tail + 1] << 8);
    out->data = ring->buf + ring->tail + 2;
  }

  xSemaphoreGive(ring->lock);

  return found;
}

/**
 * @brief Drop the oldest message, which is only correct once the cloud has acknowledged it.
 */
static void _bluecherry_ring_pop(void)
{
  _bluecherry_ring_t* ring = &_bluecherry_opdata.out_ring;

  if(ring->lock == NULL) {
    return;
  }

  xSemaphoreTake(ring->lock, portMAX_DELAY);

  if(ring->count > 0) {
    size_t len = (size_t) ring->buf[ring->tail] | ((size_t) ring->buf[ring->tail + 1] << 8);
    ring->tail += 2 + len;
    ring->count -= 1;

    if(ring->tail >= ring->wrap) {
      /* The records tile the buffer exactly, so this lands on wrap rather than past it. */
      ring->tail = 0;
      ring->wrap = ring->size;
    }
    if(ring->count == 0) {
      ring->head = 0;
      ring->tail = 0;
      ring->wrap = ring->size;
    }
  }

  xSemaphoreGive(ring->lock);
}

/**
 * @brief Whether anything is still outstanding in either direction.
 *
 * The publish buffer counts because a cycle sends one message: without it the state would
 * settle to IDLE with publishes still waiting.
 *
 * @param want_resync Whether the server asked for another round.
 *
 * @return True while there is more to do.
 */
static bool _bluecherry_work_pending(bool want_resync)
{
  return want_resync || _bluecherry_opdata.pending_event_len > 0 || _bluecherry_ring_count() > 0;
}

/**
 * @brief Settle the state after a cycle that returned before it could do so itself.
 *
 * A cycle that reaches the end settles itself. One that returns early leaves AWAITING_RESPONSE
 * behind, which is the only case this cleans up - testing for exactly that is what stops it
 * overwriting a PENDING_MESSAGES the server asked for.
 */
static void _bluecherry_settle_state(void)
{
  if(_bluecherry_opdata.state != BLUECHERRY_STATE_AWAITING_RESPONSE) {
    return;
  }

  _bluecherry_set_state(_bluecherry_work_pending(false) ? BLUECHERRY_STATE_PENDING_MESSAGES
                                                        : BLUECHERRY_STATE_IDLE);
}

/**
 * @brief How long the synchronisation task may wait before running the next cycle.
 *
 * The next deadline it knows about: a provisioning retry or the auto-sync interval. Capped at
 * BLUECHERRY_SYNC_IDLE_MAX_MS so the watchdog cannot be starved. A trigger cuts the wait short.
 *
 * @return The number of milliseconds to wait.
 */
static uint32_t _bluecherry_sync_wait_ms(void)
{
  int64_t deadline_us = 0;

  if(_bluecherry_opdata.state == BLUECHERRY_STATE_NOT_PROVISIONED) {
    deadline_us = _next_provision_us;
  } else if(_auto_sync_interval_sec > 0) {
    deadline_us = _next_auto_sync_us;
  }

  if(deadline_us == 0) {
    return BLUECHERRY_SYNC_IDLE_MAX_MS;
  }

  int64_t remaining_us = deadline_us - esp_timer_get_time();
  if(remaining_us <= 0) {
    return 0;
  }

  uint64_t remaining_ms = (uint64_t) remaining_us / 1000;
  return remaining_ms > BLUECHERRY_SYNC_IDLE_MAX_MS ? BLUECHERRY_SYNC_IDLE_MAX_MS
                                                    : (uint32_t) remaining_ms;
}

/**
 * @brief Whether a cycle is due without anything having asked for one.
 *
 * The wait is capped so the watchdog stays fed, so it expiring says nothing about whether
 * there is work: this is the actual test. Provisioning and connecting are always due, because
 * their own backoff gates decide whether the cycle does anything.
 *
 * @return True when the task should run a cycle of its own accord.
 */
static bool _bluecherry_sync_due(void)
{
  switch(_bluecherry_opdata.state) {
  case BLUECHERRY_STATE_UNINITIALIZED:
    return false;

  case BLUECHERRY_STATE_NOT_PROVISIONED:
    return esp_timer_get_time() >= _next_provision_us;

  case BLUECHERRY_STATE_AWAIT_CONNECTION:
    return true;

  default:
    break;
  }

  return _auto_sync_interval_sec > 0 && esp_timer_get_time() >= _next_auto_sync_us;
}

/**
 * @brief Arm the next automatic synchronisation, or clear it when they are off.
 *
 * Counted from the last synchronisation, not from now, so that changing the interval asks
 * "how long since the last one" rather than restarting the wait. Shortening it below the time
 * already elapsed therefore leaves the next one due immediately, which is the point.
 */
static void _bluecherry_arm_auto_sync(void)
{
  _next_auto_sync_us =
      _auto_sync_interval_sec > 0 ? _last_sync_us + (int64_t) _auto_sync_interval_sec * 1000000 : 0;
}

/* Defined further down, but the task is the only caller of both. */
static esp_err_t _bluecherry_sync_once(void);
static void _bluecherry_ota_service_requests(void);

/**
 * @brief The entrypoint of the BlueCherry synchronisation task.
 *
 * Owns every network operation the library performs, and all the timing around them. It runs a
 * cycle when something triggers one, when an automatic synchronisation falls due, or when the
 * previous cycle finished with work still outstanding; otherwise it waits.
 *
 * @param args A NULL pointer.
 */
static void _bluecherry_sync_task(void* args)
{
  if(_watchdog) {
    esp_task_wdt_add(NULL);
  }

  while(true) {
    _bluecherry_tickle_watchdog();

    /* Clearing on take is what makes bluecherry_sync a trigger rather than a queue: any number
     * of calls collapse into one cycle, and one raised mid-cycle is still pending here. */
    uint32_t triggered = ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(_bluecherry_sync_wait_ms()));

    _bluecherry_tickle_watchdog();

    /* The task starts before init finishes, and init can still fail after that. */
    if(_bluecherry_opdata.state == BLUECHERRY_STATE_UNINITIALIZED) {
      continue;
    }

    /* Waking is not the same as having something to do: the wait is capped for the watchdog,
     * so it expires long before a deadline that is further out than the cap. */
    if(triggered == 0 && !_bluecherry_sync_due()) {
      continue;
    }

    _bluecherry_ota_service_requests();

    esp_err_t ret = _bluecherry_sync_once();
    _bluecherry_settle_state();

    /* Recorded at the end of a cycle, so the interval is "time since the last exchange". */
    _last_sync_us = esp_timer_get_time();
    _bluecherry_arm_auto_sync();

    /* Self-notify rather than loop, so every cycle takes the same path past the watchdog. */
    if(ret == BLUECHERRY_SYNC_CONTINUE) {
      xTaskNotifyGive(_sync_task);
    }

    /* Also fed on the way out, so a long sync is bracketed rather than merely
     * preceded by a reset. Feeding only before the call leaves the effective
     * budget at "the watchdog timeout minus one whole sync". */
    _bluecherry_tickle_watchdog();
  }
}

#pragma region OTA

/**
 * @brief Get the current OTA progress.
 *
 * This function returns the current OTA progress. If no OTA is in progress, 0 is returned.
 *
 * @return The current OTA progress.
 */
static float _bluecherry_ota_progress_percent(void)
{
  if(_bluecherry_opdata.ota_size == 0) {
    return 0.0f;
  }

  return ((float) _bluecherry_opdata.ota_progress / (float) _bluecherry_opdata.ota_size) * 100.0f;
}

/**
 * @brief Write a flash sector to flash, erasing the block first if on an as of yet
 * uninitialized block
 *
 * @return True if succeeded, false if not.
 */
static bool _bluecherry_ota_buffer_to_flash(void)
{
  /* first bytes of new firmware must be postponed so
   * partially written firmware is not bootable just yet
   */
  uint8_t skip = 0;

  if(!_bluecherry_opdata.ota_progress) {
    /* meanwhile check for the magic byte */
    if(_bluecherry_opdata.ota_buffer[0] != ESP_IMAGE_HEADER_MAGIC) {
      ESP_LOGD(TAG, "OTA chunk: magic header not found");
      return false;
    }

    skip = ENCRYPTED_BLOCK_SIZE;
    memcpy(_bluecherry_opdata.ota_skip_buffer, _bluecherry_opdata.ota_buffer, skip);
  }

  size_t flash_offset = _bluecherry_opdata.ota_partition->address + _bluecherry_opdata.ota_progress;

  // if it's the block boundary, than erase the whole block from here
  bool block_erase =
      (_bluecherry_opdata.ota_size - _bluecherry_opdata.ota_progress >= SPI_FLASH_BLOCK_SIZE) &&
      (flash_offset % SPI_FLASH_BLOCK_SIZE == 0);

  // sector belong to unaligned partition heading block
  bool partition_head_sectors =
      _bluecherry_opdata.ota_partition->address % SPI_FLASH_BLOCK_SIZE &&
      flash_offset < (_bluecherry_opdata.ota_partition->address / SPI_FLASH_BLOCK_SIZE + 1) *
                         SPI_FLASH_BLOCK_SIZE;

  // sector belong to unaligned partition tailing block
  bool partition_tail_sectors =
      flash_offset >= (_bluecherry_opdata.ota_partition->address + _bluecherry_opdata.ota_size) /
                          SPI_FLASH_BLOCK_SIZE * SPI_FLASH_BLOCK_SIZE;

  if(block_erase || partition_head_sectors || partition_tail_sectors) {
    if(esp_partition_erase_range(_bluecherry_opdata.ota_partition, _bluecherry_opdata.ota_progress,
                                 block_erase ? SPI_FLASH_BLOCK_SIZE : SPI_FLASH_SEC_SIZE) !=
       ESP_OK) {
      ESP_LOGE(TAG, "OTA chunk: could not erase partition");
      return false;
    }
  }

  if(esp_partition_write(_bluecherry_opdata.ota_partition, _bluecherry_opdata.ota_progress + skip,
                         (uint32_t*) _bluecherry_opdata.ota_buffer + skip / sizeof(uint32_t),
                         _bluecherry_opdata.ota_buffer_pos - skip) != ESP_OK) {
    ESP_LOGE(TAG, "OTA chunk: could not write data to partition");
    return false;
  }

  _bluecherry_opdata.ota_progress += _bluecherry_opdata.ota_buffer_pos;
  _bluecherry_opdata.ota_buffer_pos = 0;

  return true;
}

/**
 * @brief Queue one internal-channel (topic 0x00) frame in the priority slot.
 *
 * The slot is checked before out_ring in the send step, so a protocol reply
 * goes out on the very next sync instead of queueing behind the application's
 * publishes. That matters most for the probe reply: any topic 0x00 frame sets
 * want_resync, so the sync task loops again in milliseconds and the answer is
 * back before the server has packed a single chunk.
 *
 * Only one internal event is ever outstanding - each is a reply the server then
 * responds to - so a single slot is enough. A second call overwrites the first.
 *
 * @param payload The event payload, starting with the event type byte.
 * @param len Payload length.
 *
 * @return ESP_OK on success, ESP_ERR_INVALID_SIZE when the framed event does not fit the slot.
 */
static esp_err_t _bluecherry_publish_event(const uint8_t* payload, uint8_t len)
{
  const size_t total = BLUECHERRY_COAP_HEADER_SIZE + BLUECHERRY_MQTT_HEADER_SIZE + len;

  if(total > sizeof(_bluecherry_opdata.pending_event)) {
    ESP_LOGE(TAG, "Internal event of %uB does not fit the priority slot", len);
    return ESP_ERR_INVALID_SIZE;
  }

  uint8_t* p = _bluecherry_opdata.pending_event + BLUECHERRY_COAP_HEADER_SIZE;
  p[0] = 0x00; /* internal channel */
  p[1] = len;
  memcpy(p + BLUECHERRY_MQTT_HEADER_SIZE, payload, len);

  _bluecherry_opdata.pending_event_len = total;
  return ESP_OK;
}

/**
 * @brief Report an OTA event to the application, if it registered a handler.
 *
 * Two gates: the NULL check answers "is anyone watching" and the return value
 * answers "who decides this event". Only the second can differ per event, so a
 * handler registered purely to log cannot accidentally stop a device updating.
 *
 * @return True when the application took this event's decision, false when the
 * library should apply its own default.
 */
static bool _bluecherry_ota_notify(bluecherry_ota_event_t event, uint8_t error_code)
{
  if(_bluecherry_opdata.ota_handler == NULL) {
    return false;
  }

  bluecherry_ota_info_t info = {
    .version = _bluecherry_opdata.ota_target_version,
    .size = _bluecherry_opdata.ota_size,
    .bytes_received = _bluecherry_opdata.ota_progress,
    .error_code = error_code,
  };
  memcpy(info.sha256, _bluecherry_opdata.ota_expected_hash, BLUECHERRY_PARTITION_HASH_LEN);

  return _bluecherry_opdata.ota_handler(event, &info, _bluecherry_opdata.ota_handler_args);
}

/**
 * @brief Flush the staging buffer to flash and report the progress it made.
 *
 * The only place a progress event is emitted: ota_progress advances nowhere but
 * in _bluecherry_ota_buffer_to_flash, so tying the event to arriving chunks instead would
 * repeat the same byte count for a whole sector's worth of them.
 *
 * @return True if the flush succeeded, false if the write failed.
 */
static bool _bluecherry_ota_flush(void)
{
  if(!_bluecherry_ota_buffer_to_flash()) {
    return false;
  }

  ESP_LOGD(TAG, "OTA: %lu / %lu bytes written (%.2f%%)", _bluecherry_opdata.ota_progress,
           _bluecherry_opdata.ota_size, _bluecherry_ota_progress_percent());
  _bluecherry_ota_notify(BLUECHERRY_OTA_EVENT_PROGRESS, 0);
  return true;
}

/**
 * @brief Clear all OTA transfer state.
 *
 * Every field describing an update goes, not just the transfer counters: a stale
 * ota_target_version or ota_unverified carried into the next offer would describe the previous
 * one, and ota_partition would be left pointing at a partition nothing is writing to.
 */
static void _bluecherry_ota_reset(void)
{
  _bluecherry_opdata.ota_state = BLUECHERRY_OTA_STATE_IDLE;
  _bluecherry_opdata.ota_size = 0;
  _bluecherry_opdata.ota_progress = 0;
  _bluecherry_opdata.ota_buffer_pos = 0;
  _bluecherry_opdata.ota_target_version = 0;
  _bluecherry_opdata.ota_unverified = false;
  _bluecherry_opdata.ota_partition = NULL;
  memset(_bluecherry_opdata.ota_expected_hash, 0, BLUECHERRY_PARTITION_HASH_LEN);
}

/**
 * @brief Abandon the transfer, tell the cloud why, and inform the application.
 */
static void _bluecherry_ota_fail(uint8_t error_code)
{
  ESP_LOGE(TAG, "OTA: failing with code %u", error_code);

  uint8_t payload[3] = { BLUECHERRY_EVENT_TYPE_OTA_ERROR,
                         (uint8_t) _bluecherry_opdata.ota_target_version, error_code };
  _bluecherry_publish_event(payload, sizeof(payload));

  _bluecherry_ota_notify(BLUECHERRY_OTA_EVENT_FAILED, error_code);
  _bluecherry_ota_reset();
}

/**
 * @brief Accept the offered update and ask the server to start sending it.
 *
 * The body of bluecherry_ota_start, moved here so it runs on the synchronisation task: it
 * writes the priority slot that the task transmits out of, and a second writer there can splice
 * a frame that is mid-flight across its retransmits.
 */
static void _bluecherry_ota_begin(void)
{
  /* The authoritative check: the offer can be withdrawn between the request and this running. */
  if(_bluecherry_opdata.ota_state != BLUECHERRY_OTA_STATE_OFFERED) {
    ESP_LOGW(TAG, "OTA: the offer was withdrawn before the update could start");
    return;
  }

  uint8_t payload[2] = { BLUECHERRY_EVENT_TYPE_OTA_START,
                         (uint8_t) _bluecherry_opdata.ota_target_version };
  if(_bluecherry_publish_event(payload, sizeof(payload)) != ESP_OK) {
    return;
  }

  _bluecherry_opdata.ota_state = BLUECHERRY_OTA_STATE_DOWNLOADING;
  _bluecherry_opdata.ota_progress = 0;
  _bluecherry_opdata.ota_buffer_pos = 0;

  ESP_LOGI(TAG, "OTA: requesting firmware v%d (%lu bytes)", _bluecherry_opdata.ota_target_version,
           _bluecherry_opdata.ota_size);
  _bluecherry_ota_notify(BLUECHERRY_OTA_EVENT_STARTED, 0);
}

/**
 * @brief Carry out whatever bluecherry_ota_start or bluecherry_ota_abort asked for.
 *
 * Run before the send step, so the resulting event goes out in the same cycle.
 */
static void _bluecherry_ota_service_requests(void)
{
  if(_ota_start_req) {
    _ota_start_req = false;
    _bluecherry_ota_begin();
  }

  if(_ota_abort_req) {
    _ota_abort_req = false;
    if(_bluecherry_opdata.ota_state != BLUECHERRY_OTA_STATE_IDLE) {
      _bluecherry_ota_fail(_ota_abort_code);
    }
  }
}

/**
 * @brief Finish the image and report it verified.
 *
 * Ordering is load-bearing, not incidental:
 *
 *   1. write the withheld 16-byte header  -> image complete, still NOT bootable
 *   2. hash the partition and compare     -> mismatch: report and give up
 *   3. send VERIFIED                      -> committed only once acked
 *
 * The boot partition is NOT set here but in _bluecherry_ota_commit, once the
 * server has acknowledged the VERIFIED, so an unexpected reset in between boots
 * the OLD image and the server simply retries. Committing first is what lets a
 * device reboot into firmware the cloud never learned about.
 *
 * The hash is read back from flash rather than accumulated over the arriving
 * bytes, so it attests to what is actually stored, and it is exactly the
 * SHA-256 ESP-IDF appends to the image - the same value the cloud records as the
 * fingerprint of that build.
 */
static void _bluecherry_ota_verify(void)
{
  /* 1. Enable the partition: write the stashed first bytes. */
  if(esp_partition_write(_bluecherry_opdata.ota_partition, 0,
                         (uint32_t*) _bluecherry_opdata.ota_skip_buffer,
                         ENCRYPTED_BLOCK_SIZE) != ESP_OK) {
    ESP_LOGE(TAG, "OTA: could not write the image header");
    _bluecherry_ota_fail(BLUECHERRY_OTA_ERR_WRITE_FAILED);
    return;
  }

  uint8_t header[ENCRYPTED_BLOCK_SIZE];
  if(esp_partition_read(_bluecherry_opdata.ota_partition, 0, (uint32_t*) header,
                        ENCRYPTED_BLOCK_SIZE) != ESP_OK) {
    ESP_LOGE(TAG, "OTA: could not read back the image header");
    _bluecherry_ota_fail(BLUECHERRY_OTA_ERR_WRITE_FAILED);
    return;
  }
  if(header[0] != ESP_IMAGE_HEADER_MAGIC) {
    ESP_LOGE(TAG, "OTA: magic header missing on the partition");
    _bluecherry_ota_fail(BLUECHERRY_OTA_ERR_BAD_MAGIC);
    return;
  }

  /* 2. Hash what is actually in flash. */
  uint8_t actual[BLUECHERRY_PARTITION_HASH_LEN];
  if(esp_partition_get_sha256(_bluecherry_opdata.ota_partition, actual) != ESP_OK) {
    ESP_LOGE(TAG, "OTA: could not hash the written partition");
    _bluecherry_ota_fail(BLUECHERRY_OTA_ERR_HASH_MISMATCH);
    return;
  }

  if(!_bluecherry_opdata.ota_unverified &&
     memcmp(actual, _bluecherry_opdata.ota_expected_hash, BLUECHERRY_PARTITION_HASH_LEN) != 0) {
    ESP_LOGE(TAG, "OTA: hash mismatch, the image in flash is not the one announced");
    _bluecherry_ota_fail(BLUECHERRY_OTA_ERR_HASH_MISMATCH);
    return;
  }

  /* 3. Report it. In unverified mode there was nothing to compare against, but
   * the hash is still sent: it is the value an operator needs to record as the
   * build's fingerprint and turn this into a verified update. */
  uint8_t payload[2 + BLUECHERRY_PARTITION_HASH_LEN];
  payload[0] = BLUECHERRY_EVENT_TYPE_OTA_VERIFIED;
  payload[1] = (uint8_t) _bluecherry_opdata.ota_target_version;
  memcpy(payload + 2, actual, BLUECHERRY_PARTITION_HASH_LEN);

  if(_bluecherry_publish_event(payload, sizeof(payload)) != ESP_OK) {
    _bluecherry_ota_fail(BLUECHERRY_OTA_ERR_WRITE_FAILED);
    return;
  }

  _bluecherry_opdata.ota_state = BLUECHERRY_OTA_STATE_AWAITING_VERIFIED;
  ESP_LOGI(TAG, "OTA: image verified, reporting to the cloud before committing");
}

/**
 * @brief Commit the new image once the cloud has acknowledged the VERIFIED.
 *
 * Called from the send step, which knows the message was acknowledged because
 * _bluecherry_coap_rxtx only returns ESP_OK on an ACK. This is the single
 * irreversible step in the whole flow.
 */
static void _bluecherry_ota_commit(void)
{
  if(esp_ota_set_boot_partition(_bluecherry_opdata.ota_partition) != ESP_OK) {
    ESP_LOGE(TAG, "OTA: could not set the boot partition");
    _bluecherry_ota_fail(BLUECHERRY_OTA_ERR_SET_BOOT_FAILED);
    return;
  }

  _bluecherry_opdata.ota_state = BLUECHERRY_OTA_STATE_COMPLETE;
  ESP_LOGI(TAG, "OTA: firmware v%d installed and acknowledged; boot partition set",
           _bluecherry_opdata.ota_target_version);

  /* Nobody watching, or watching without taking the decision: reboot now. An
   * application that says it owns the moment keeps running the old firmware
   * until it reboots, which is the point of saying so. */
  if(!_bluecherry_ota_notify(BLUECHERRY_OTA_EVENT_COMPLETE, 0)) {
    ESP_LOGI(TAG, "OTA: rebooting into the new firmware");
    esp_restart();
  }
}

/**
 * @brief Map a partition to a platform-neutral OTA slot index.
 *
 * ESP subtypes OTA_0..OTA_15 become 0..15; a factory or test partition, or no
 * partition at all, becomes BLUECHERRY_OTA_SLOT_NONE. The wire carries the
 * index rather than the subtype, so reporting it does not require the reader to
 * understand an ESP-specific encoding.
 */
static uint8_t _bluecherry_ota_slot_index(const esp_partition_t* part)
{
  if(part == NULL || part->subtype < ESP_PARTITION_SUBTYPE_APP_OTA_MIN ||
     part->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MAX) {
    return BLUECHERRY_OTA_SLOT_NONE;
  }
  return (uint8_t) (part->subtype - ESP_PARTITION_SUBTYPE_APP_OTA_MIN);
}

/**
 * @brief Why the device last booted, as a string.
 *
 * A string rather than the raw esp_reset_reason_t, so the report is
 * self-describing and the cloud needs no lookup table for it - the numeric
 * values behind these names are not portable.
 *
 * Only the reasons that exist across the IDF versions this library claims to
 * support are named; ESP_RST_USB, _JTAG and friends arrived in 5.0 and would
 * break a 4.x build, so they fall through to "unknown" rather than being
 * listed. Widen the switch if the declared IDF floor is ever raised.
 */
static const char* _bluecherry_reset_reason_str(void)
{
  switch(esp_reset_reason()) {
  case ESP_RST_POWERON:
    return "poweron";
  case ESP_RST_EXT:
    return "ext";
  case ESP_RST_SW:
    return "sw";
  case ESP_RST_PANIC:
    return "panic";
  case ESP_RST_INT_WDT:
    return "int_wdt";
  case ESP_RST_TASK_WDT:
    return "task_wdt";
  case ESP_RST_WDT:
    return "wdt";
  case ESP_RST_DEEPSLEEP:
    return "deepsleep";
  case ESP_RST_BROWNOUT:
    return "brownout";
  case ESP_RST_SDIO:
    return "sdio";
  default:
    return "unknown";
  }
}

/**
 * @brief Append a [1B length][UTF-8] INIT_INFO field, or drop it if it will not
 * fit.
 *
 * Returns true when the field was written, so the caller can set its presence
 * bit only then. Dropping is the safe failure: a cleared bit is something the
 * server renders correctly, whereas a half-written string would misalign every
 * field after it - the parser locates fields positionally and cannot resync.
 */
static bool _bluecherry_info_add_str(uint8_t* buf, size_t cap, size_t* n, const char* s)
{
  size_t len = strnlen(s, BLUECHERRY_INFO_STR_MAX);
  if(*n + 1 + len > cap) {
    ESP_LOGW(TAG, "INIT_INFO field \"%s\" dropped: only %uB left", s, (unsigned) (cap - *n));
    return false;
  }
  buf[(*n)++] = (uint8_t) len;
  memcpy(buf + *n, s, len);
  *n += len;
  return true;
}

/**
 * @brief Queue INIT_INFO: the running partition hash plus optional details.
 *
 * Queued from bluecherry_sync, on every connect, as the first thing the new session carries.
 * The contents cannot change while the device runs, but the server tracks this per session:
 * it is how a reconnecting device re-identifies the image it is running, and how a reboot
 * into new firmware is confirmed. Re-sending is therefore not redundant - the priority slot
 * is cleared on reconnect precisely because a reply owed to the dead session is meaningless,
 * and this is queued straight after.
 *
 * The hash is the part the cloud acts on. Everything behind the presence bitmap is
 * informational and the server never makes a decision on it.
 *
 * Fields MUST be written in ascending presence-bit order: the server decodes
 * positionally and cannot recover from a field out of place.
 */
static void _bluecherry_send_init_info(void)
{
  const esp_partition_t* running = esp_ota_get_running_partition();
  if(running == NULL) {
    ESP_LOGW(TAG, "No running partition; skipping INIT_INFO");
    return;
  }

  /* Sized from the priority slot's payload budget rather than by adding the
   * fields up. Typical case is ~84 bytes.
   *
   * Only the STRING fields are bounds-checked, by _bluecherry_info_add_str.
   * Every fixed-width field is written straight in, and ota_slot's two bytes
   * land after two strings that may each be BLUECHERRY_INFO_STR_MAX long - so
   * what has to hold unconditionally is that the whole unchecked path fits even
   * at those maxima.
   *
   * Spelled out as a sum rather than a single number so it cannot go stale: it
   * was hand-derived as 121 and the true figure is 120. Adding a third string
   * BEFORE ota_slot breaks the assumption, not just the total. */
  uint8_t payload[BLUECHERRY_EVENT_PAYLOAD_MAX];
  _Static_assert(1 + 1 + BLUECHERRY_PARTITION_HASH_LEN + 2 /* event, schema, hash, bitmap */
                         + 1 + 3 + 4 + 4 + 4 /* platform, version, slot size, uptime, heap */
                         + 2                 /* ota_slot, written after the strings */
                         + 2 * (1 + BLUECHERRY_INFO_STR_MAX) /* lib_name, mcu */
                     <= BLUECHERRY_EVENT_PAYLOAD_MAX,
                 "INIT_INFO's unchecked writes must fit the event payload budget even when "
                 "every preceding string field is at its maximum length");
  size_t n = 0;

  payload[n++] = BLUECHERRY_EVENT_TYPE_INIT_INFO;
  payload[n++] = BLUECHERRY_INIT_INFO_SCHEMA;

  if(esp_partition_get_sha256(running, payload + n) != ESP_OK) {
    ESP_LOGW(TAG, "Could not hash the running partition; skipping INIT_INFO");
    return;
  }
  n += BLUECHERRY_PARTITION_HASH_LEN;

  /* The bitmap has to be written before the fields it describes, so the strings
   * are measured first and their bits only set once they are known to fit. */
  const size_t bitmap_at = n;
  n += 2;

  uint16_t present = BLUECHERRY_INFO_BIT_PLATFORM | BLUECHERRY_INFO_BIT_LIB_VERSION |
                     BLUECHERRY_INFO_BIT_OTA_SLOT_SIZE | BLUECHERRY_INFO_BIT_UPTIME |
                     BLUECHERRY_INFO_BIT_TOTAL_HEAP | BLUECHERRY_INFO_BIT_OTA_SLOT;

  /* Optional fields, in ascending bit order. */
#ifdef ARDUINO
  payload[n++] = BLUECHERRY_PLATFORM_ARDUINO;
#else
  payload[n++] = BLUECHERRY_PLATFORM_ESP_IDF;
#endif

  payload[n++] = BLUECHERRY_LIB_VERSION_MAJOR;
  payload[n++] = BLUECHERRY_LIB_VERSION_MINOR;
  payload[n++] = BLUECHERRY_LIB_VERSION_PATCH;

  const esp_partition_t* slot = esp_ota_get_next_update_partition(NULL);
  const uint32_t slot_size = slot ? slot->size : 0;
  payload[n++] = slot_size & 0xFF;
  payload[n++] = (slot_size >> 8) & 0xFF;
  payload[n++] = (slot_size >> 16) & 0xFF;
  payload[n++] = (slot_size >> 24) & 0xFF;

  const uint32_t uptime = (uint32_t) (esp_timer_get_time() / 1000000);
  payload[n++] = uptime & 0xFF;
  payload[n++] = (uptime >> 8) & 0xFF;
  payload[n++] = (uptime >> 16) & 0xFF;
  payload[n++] = (uptime >> 24) & 0xFF;

  /* Total, not free: free heap moves with whatever the application has
   * allocated, so it cannot be compared between devices or over time. Total is
   * the chip's internal-RAM capacity, which is what tells you how much room
   * there ever was. */
  const uint32_t heap = (uint32_t) heap_caps_get_total_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  payload[n++] = heap & 0xFF;
  payload[n++] = (heap >> 8) & 0xFF;
  payload[n++] = (heap >> 16) & 0xFF;
  payload[n++] = (heap >> 24) & 0xFF;

  if(_bluecherry_info_add_str(payload, sizeof(payload), &n, BLUECHERRY_LIB_NAME)) {
    present |= BLUECHERRY_INFO_BIT_LIB_NAME;
  }

#ifdef BLUECHERRY_MCU
  if(_bluecherry_info_add_str(payload, sizeof(payload), &n, BLUECHERRY_MCU)) {
    present |= BLUECHERRY_INFO_BIT_MCU;
  }
#endif

  payload[n++] = _bluecherry_ota_slot_index(running);
  payload[n++] = _bluecherry_ota_slot_index(slot);

  if(_bluecherry_info_add_str(payload, sizeof(payload), &n, _bluecherry_reset_reason_str())) {
    present |= BLUECHERRY_INFO_BIT_RESET_REASON;
  }

  payload[bitmap_at] = present & 0xFF;
  payload[bitmap_at + 1] = (present >> 8) & 0xFF;

  if(_bluecherry_publish_event(payload, (uint8_t) n) == ESP_OK) {
    ESP_LOGD(TAG, "INIT_INFO queued (%uB)", (unsigned) n);
  }
}

/**
 * @brief Process an OTA initialize event: an update is on offer.
 *
 * Payload: [version(1)][size(4, LE)][sha256(32)][chunk size(1)] = 38 bytes
 * after the event type byte.
 */
static void _bluecherry_ota_process_initialize(uint8_t* data, uint16_t len)
{
  if(len != 38) {
    ESP_LOGE(TAG, "OTA: initialize expected 38B, got %uB", len);
    return;
  }

  if(_bluecherry_opdata.ota_state != BLUECHERRY_OTA_STATE_IDLE &&
     _bluecherry_opdata.ota_state != BLUECHERRY_OTA_STATE_OFFERED) {
    ESP_LOGW(TAG, "OTA: already busy, ignoring re-offer");
    return;
  }

  _bluecherry_opdata.ota_partition = esp_ota_get_next_update_partition(NULL);
  if(!_bluecherry_opdata.ota_partition) {
    _bluecherry_opdata.ota_target_version = (int8_t) data[0];
    _bluecherry_ota_fail(BLUECHERRY_OTA_ERR_NO_PARTITION);
    return;
  }

  _bluecherry_opdata.ota_target_version = (int8_t) data[0];
  _bluecherry_opdata.ota_size = ((uint32_t) data[1]) | ((uint32_t) data[2] << 8) |
                                ((uint32_t) data[3] << 16) | ((uint32_t) data[4] << 24);
  memcpy(_bluecherry_opdata.ota_expected_hash, data + 5, BLUECHERRY_PARTITION_HASH_LEN);

  /* An all-zero expected hash means the cloud has no fingerprint on record, so
   * there is nothing to check the image against. The hash is still computed and
   * reported, since that is the value an operator needs to record one. */
  _bluecherry_opdata.ota_unverified = true;
  for(size_t i = 0; i < BLUECHERRY_PARTITION_HASH_LEN; ++i) {
    if(_bluecherry_opdata.ota_expected_hash[i] != 0) {
      _bluecherry_opdata.ota_unverified = false;
      break;
    }
  }

  if(_bluecherry_opdata.ota_size == 0 ||
     _bluecherry_opdata.ota_size > _bluecherry_opdata.ota_partition->size) {
    ESP_LOGE(TAG, "OTA: %lu bytes will not fit a %lu byte slot", _bluecherry_opdata.ota_size,
             _bluecherry_opdata.ota_partition->size);
    _bluecherry_ota_fail(BLUECHERRY_OTA_ERR_TOO_LARGE);
    return;
  }

  _bluecherry_opdata.ota_progress = 0;
  _bluecherry_opdata.ota_buffer_pos = 0;
  _bluecherry_opdata.ota_state = BLUECHERRY_OTA_STATE_OFFERED;

  ESP_LOGI(TAG, "OTA: firmware v%d offered, %lu bytes, %s", _bluecherry_opdata.ota_target_version,
           _bluecherry_opdata.ota_size,
           _bluecherry_opdata.ota_unverified ? "UNVERIFIED (no fingerprint)" : "verified");

  /* Nobody watching, or watching without taking the decision: start now. An
   * application only gets to choose the moment by saying so, so forgetting to
   * decide cannot leave a device sitting on an update forever. */
  if(!_bluecherry_ota_notify(BLUECHERRY_OTA_EVENT_AVAILABLE, 0)) {
    bluecherry_ota_start();
  }
}

/**
 * @brief Process an OTA chunk: stage it, and flush a sector at a time.
 *
 * The DOWNLOADING guard is what protects a finished image: once the last chunk
 * has been staged and hashed the state moves to AWAITING_VERIFIED, so a chunk
 * arriving after it - a duplicated frame on a lossy link - is dropped here
 * instead of tripping the overrun check below. That path called
 * _bluecherry_ota_fail, which overwrites the queued VERIFIED in the single
 * priority slot with an OTA_ERROR and discards a correctly written image.
 */
static void _bluecherry_ota_process_chunk(uint8_t* data, uint16_t len)
{
  if(_bluecherry_opdata.ota_state != BLUECHERRY_OTA_STATE_DOWNLOADING) {
    ESP_LOGW(TAG, "OTA: chunk outside a download, ignoring");
    return;
  }

  if(len == 0 || _bluecherry_opdata.ota_progress + len > _bluecherry_opdata.ota_size) {
    ESP_LOGE(TAG, "OTA: chunk empty or beyond the announced size");
    _bluecherry_ota_fail(BLUECHERRY_OTA_ERR_CHUNK_OVERRUN);
    return;
  }

  size_t left = len;

  while((_bluecherry_opdata.ota_buffer_pos + left) > SPI_FLASH_SEC_SIZE) {
    size_t to_buff = SPI_FLASH_SEC_SIZE - _bluecherry_opdata.ota_buffer_pos;

    memcpy(_bluecherry_opdata.ota_buffer + _bluecherry_opdata.ota_buffer_pos, data + (len - left),
           to_buff);
    _bluecherry_opdata.ota_buffer_pos += to_buff;

    if(!_bluecherry_ota_flush()) {
      _bluecherry_ota_fail(BLUECHERRY_OTA_ERR_WRITE_FAILED);
      return;
    }

    left -= to_buff;
  }

  memcpy(_bluecherry_opdata.ota_buffer + _bluecherry_opdata.ota_buffer_pos, data + (len - left),
         left);
  _bluecherry_opdata.ota_buffer_pos += left;

  /* The last sector is short of the flush threshold above, so the final flush
   * is triggered by the byte count instead - and it is the one that reports
   * 100%. No progress event is emitted for a chunk that only staged bytes:
   * nothing observable changed. */
  if(_bluecherry_opdata.ota_progress + _bluecherry_opdata.ota_buffer_pos ==
     _bluecherry_opdata.ota_size) {
    if(!_bluecherry_ota_flush()) {
      _bluecherry_ota_fail(BLUECHERRY_OTA_ERR_WRITE_FAILED);
      return;
    }
    ESP_LOGI(TAG, "OTA: %lu bytes received, verifying", _bluecherry_opdata.ota_progress);
    _bluecherry_ota_verify();
  }
}

/**
 * @brief Process an incoming BlueCherry event.
 *
 * Called for every record that arrives on topic byte 0x00, BlueCherry's internal channel,
 * eg for OTA updates.
 *
 * Events 1, 2 and 3 are OTA messages this client does not implement - see
 * BLUECHERRY_OTA_ERROR_UNSUPPORTED_PROTOCOL for why the cloud sends them at
 * all. Event 1 is answered with the [4][0xB2] probe reply and nothing else; 2
 * and 3 are discarded outright. Discarding them is not laziness - a handful can
 * still be in flight in the window before the cloud's switch takes effect, and
 * writing them would corrupt the partition.
 *
 * @param data The event data.
 * @param len The length of the data block.
 */
static void _bluecherry_process_event(uint8_t* data, uint8_t len)
{
  if(len == 0) {
    ESP_LOGW(TAG, "Empty BlueCherry event, ignoring");
    return;
  }

  switch(data[0]) {
  case BLUECHERRY_EVENT_TYPE_OTA_PROBE: {
    /* Answer it and touch no OTA state: the cloud has not yet been told what we
     * speak, and treating this as an offer would clobber a transfer that may
     * already be running. */
    ESP_LOGD(TAG, "OTA probe from the cloud, answered");
    uint8_t reply[2] = { BLUECHERRY_EVENT_TYPE_ERROR, BLUECHERRY_OTA_ERROR_UNSUPPORTED_PROTOCOL };
    _bluecherry_publish_event(reply, sizeof(reply));
    break;
  }

  case BLUECHERRY_EVENT_TYPE_OTA_UNSUPPORTED_CHUNK:
  case BLUECHERRY_EVENT_TYPE_OTA_UNSUPPORTED_FINISH:
    /* Leftovers from the probe window. Discard them. */
    ESP_LOGD(TAG, "Ignoring unsupported OTA event 0x%x", data[0]);
    break;

  case BLUECHERRY_EVENT_TYPE_OTA_INITIALIZE:
    _bluecherry_ota_process_initialize(data + 1, len - 1);
    break;

  case BLUECHERRY_EVENT_TYPE_OTA_CHUNK:
    _bluecherry_ota_process_chunk(data + 1, len - 1);
    break;

  default:
    /* Benign on purpose. An unknown event must never abort a running update:
     * this arm once reported failure to the caller, which zeroed ota_size and
     * killed a transfer because the cloud mentioned something newer than us. */
    ESP_LOGW(TAG, "Ignoring unknown BlueCherry event type 0x%x from cloud server", data[0]);
    break;
  }
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
 * @return The number of bytes read from the socket, or a negative Mbed TLS error code. Callers
 * distinguish MBEDTLS_ERR_SSL_TIMEOUT (nothing arrived in time) from a real failure, so the
 * code must be passed through rather than collapsed to a flag.
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
      _bluecherry_tickle_watchdog();
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
      _bluecherry_tickle_watchdog();
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
 * Releases only what the CSR itself owns. The entropy and CTR_DRBG contexts are deliberately
 * NOT freed here: they are seeded once in _bluecherry_setup_mbedtls and ssl_conf keeps a
 * pointer to the DRBG for the lifetime of the library (mbedtls_ssl_conf_rng), so freeing them
 * would leave every later handshake running on a zeroed generator with no entropy source.
 * _bluecherry_cleanup_mbedtls is what frees them, at teardown. devkey is safe to free because
 * the key has already been written out as PEM and _bluecherry_configure_own_cert re-inits the
 * context before parsing it back.
 *
 * @param result The result of the CSR generation process.
 *
 * @return The result it was given, unchanged, so callers can `return _ztp_finish_csr_gen(false)`.
 */
static bool _ztp_finish_csr_gen(bool result)
{
  mbedtls_pk_free(&_bluecherry_opdata.devkey);
  mbedtls_x509write_csr_free(&_bluecherry_opdata.ztp_mb_csr);

  if(!result) {
    ztp_pkey_buf[0] = '\0';
    ztp_cert_buf[0] = '\0';
  }

  return result;
}

/**
 * @brief Cleanup the Mbed TLS resources.
 *
 * This function cleans up the Mbed TLS resources used by the BlueCherry connection.
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
 */
static void _bluecherry_cleanup_network()
{
  if(_bluecherry_opdata.sock >= 0) {
    shutdown(_bluecherry_opdata.sock, 0);
    close(_bluecherry_opdata.sock);
    _bluecherry_opdata.sock = -1;
  }
}

/**
 * @brief Cleanup the current DTLS session (socket + SSL context only).
 *
 * This function closes the current socket and frees the SSL session state,
 * without touching RNG, entropy, certificates, or SSL config.
 */
static void _bluecherry_cleanup_session()
{
  _bluecherry_cleanup_network();
  mbedtls_ssl_free(&_bluecherry_opdata.ssl);
  mbedtls_ssl_init(&_bluecherry_opdata.ssl);
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
 * @brief Configure the CA chain used to authenticate the BlueCherry server.
 *
 * Called exactly once per init. It is kept separate from the device credentials because
 * provisioning needs the CA before it has a device certificate to present, and
 * mbedtls_x509_crt_parse appends to the chain it is given - so parsing the CA a second time
 * would leave two copies of it in the context.
 *
 * @param ca_cert Pointer to the CA certificate in PEM format.
 *
 * @return true if the configuration was successful, false otherwise.
 */
static bool _bluecherry_configure_ca(const char* ca_cert)
{
  int ret = mbedtls_x509_crt_parse(&_bluecherry_opdata.cacert, (const uint8_t*) ca_cert,
                                   strlen(ca_cert) + 1);
  if(ret != 0) {
    ESP_LOGE(TAG, "Could not parse CA certificate: -%04X", -ret);
    return false;
  }

  mbedtls_ssl_conf_ca_chain(&_bluecherry_opdata.ssl_conf, &_bluecherry_opdata.cacert, NULL);
  return true;
}

/**
 * @brief Configure the device certificate and key this device presents to the server.
 *
 * Called either at init for an already provisioned device, or from bluecherry_sync once
 * provisioning has issued a certificate.
 *
 * @param dev_cert Pointer to the device certificate in PEM format.
 * @param dev_key Pointer to the device private key in PEM format.
 *
 * @return true if the configuration was successful, false otherwise.
 */
static bool _bluecherry_configure_own_cert(const char* dev_cert, const char* dev_key)
{
  int ret;

  if(dev_cert == NULL || dev_key == NULL) {
    return false;
  }

  /* Start from empty contexts. mbedtls_x509_crt_parse appends, so a retry after a partial
   * failure here would otherwise leave two copies of the certificate in the chain. Freeing a
   * context that was only initialised is well defined, so this is safe on the first call. */
  mbedtls_x509_crt_free(&_bluecherry_opdata.devcert);
  mbedtls_pk_free(&_bluecherry_opdata.devkey);
  mbedtls_x509_crt_init(&_bluecherry_opdata.devcert);
  mbedtls_pk_init(&_bluecherry_opdata.devkey);

  ret = mbedtls_x509_crt_parse(&_bluecherry_opdata.devcert, (const uint8_t*) dev_cert,
                               strlen(dev_cert) + 1);
  if(ret != 0) {
    ESP_LOGE(TAG, "Could not parse device certificate: -%04X", -ret);
    return false;
  }

  ret = mbedtls_pk_parse_key(&_bluecherry_opdata.devkey, (const uint8_t*) dev_key,
                             strlen(dev_key) + 1, NULL, 0, mbedtls_entropy_func,
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
  bool success = false;
  struct addrinfo hints = { 0 };
  struct addrinfo* res = NULL;
  int ret;

  _bluecherry_cleanup_session();

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;

  /* getaddrinfo blocks for as long as the resolver takes and cannot be given a
   * timeout, so the watchdog is fed on both sides of it. With no route out,
   * lwIP walks every configured server before returning. */
  _bluecherry_tickle_watchdog();
  ret = getaddrinfo(host, port, &hints, &res);
  _bluecherry_tickle_watchdog();
  if(ret != 0 || res == NULL) {
    ESP_LOGE(TAG, "DNS lookup failed: %d", ret);
    goto cleanup;
  }

  _bluecherry_opdata.sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if(_bluecherry_opdata.sock < 0) {
    ESP_LOGE(TAG, "socket() failed: %s", strerror(errno));
    goto cleanup;
  }

  struct timeval timeout = { .tv_sec = 3, .tv_usec = 0 };
  setsockopt(_bluecherry_opdata.sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  ret = connect(_bluecherry_opdata.sock, res->ai_addr, res->ai_addrlen);
  if(ret != 0) {
    ESP_LOGE(TAG, "connect() failed: %s", strerror(errno));
    goto cleanup;
  }

  ret = mbedtls_ssl_setup(&_bluecherry_opdata.ssl, &_bluecherry_opdata.ssl_conf);
  if(ret != 0) {
    ESP_LOGE(TAG, "Could not setup SSL context: -%04X", -ret);
    goto cleanup;
  }

  mbedtls_ssl_set_timer_cb(&_bluecherry_opdata.ssl, &_bluecherry_opdata.timer,
                           mbedtls_timing_set_delay, mbedtls_timing_get_delay);

  ret = mbedtls_ssl_set_hostname(&_bluecherry_opdata.ssl, host);
  if(ret != 0) {
    ESP_LOGE(TAG, "Could not set hostname: -%04X", -ret);
    goto cleanup;
  }

  mbedtls_ssl_set_bio(&_bluecherry_opdata.ssl, &_bluecherry_opdata.sock, _bluecherry_dtls_send,
                      _bluecherry_dtls_recv, NULL);

  /* An unanswered ClientHello parks this loop for the full handshake budget, so
   * it must feed the watchdog like every other polling loop here. It is also
   * the only one reachable before the sync task exists: the provisioning path
   * calls this from the application's own task.
   *
   * The deadline is monotonic on purpose. time(NULL) moves when SNTP steps the
   * clock, which typically happens seconds after the network comes up - exactly
   * when the first handshake runs - and a stepped clock makes a wall-clock
   * deadline either expire at once or never expire at all. */
  {
    int64_t start_us = esp_timer_get_time();
    while((ret = mbedtls_ssl_handshake(&_bluecherry_opdata.ssl)) != 0) {
      if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
         ret == MBEDTLS_ERR_SSL_TIMEOUT) {
        if((esp_timer_get_time() - start_us) >= (int64_t) SSL_HANDSHAKE_TIMEOUT_SEC * 1000000) {
          ESP_LOGE(TAG, "DTLS handshake timeout");
          goto cleanup;
        }
        _bluecherry_tickle_watchdog();
        vTaskDelay(pdMS_TO_TICKS(10));
        continue;
      }
      ESP_LOGE(TAG, "DTLS handshake failed: -%04X", -ret);
      goto cleanup;
    }
  }

  success = true;

cleanup:
  if(res)
    freeaddrinfo(res);

  if(!success)
    _bluecherry_cleanup_session();

  return success;
}

#pragma endregion
#pragma region CoAP RXTX
/**
 * @brief Parse the ACK message ID from a received CoAP packet.
 *
 * @param buf Pointer to the input packet buffer.
 * @param len Number of bytes in the packet buffer.
 * @param type Output pointer for the packet type.
 * @param msg_id Output pointer for the parsed message ID.
 *
 * @return ESP_OK if parsing succeeded.
 */
static esp_err_t _bluecherry_parse_ack_meta(const uint8_t* buf, size_t len, uint8_t* type,
                                            uint16_t* msg_id)
{
  if(len < 4) {
    return ESP_ERR_INVALID_SIZE;
  }

  size_t offset = 0;
  uint8_t header = buf[offset++];
  uint8_t version = (header >> 6) & 0x03;
  if(version != 1) {
    return ESP_ERR_INVALID_VERSION;
  }

  *type = (header >> 4) & 0x03;
  uint8_t token_len = header & 0x0F;

  if(len < (size_t) (4 + token_len)) {
    return ESP_ERR_INVALID_SIZE;
  }

  offset += token_len;
  offset++; // code

  *msg_id = buf[offset++];
  *msg_id <<= 8;
  *msg_id |= buf[offset++];

  return ESP_OK;
}

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
    ESP_LOGE(TAG, "Cannot send CoAP message smaller than %uB", BLUECHERRY_COAP_HEADER_SIZE);
    return ESP_ERR_NO_MEM;
  }

  uint16_t tx_message_id = _bluecherry_opdata.cur_message_id + 1;
  if(tx_message_id == 0) {
    tx_message_id = 1;
  }

  uint8_t missed_msg_count =
      (uint8_t) (tx_message_id - _bluecherry_opdata.last_acked_message_id - 1);

  /* Two deliberate departures from CoAP, both of which the server depends on:
   *
   *   - byte 1 is the CoAP Code, repurposed as this device's lost-message
   *     counter. The server reads it as nr_lost to decide whether to replay the
   *     previous frame or pop new messages, and closes the session at 250.
   *   - byte 4 is the 0xFF payload marker, written even when there is no
   *     payload. Real CoAP omits it; this framing always expects it. */
  data[0] = 0x40; /* CON, TKL=0 */
  data[1] = missed_msg_count;
  data[2] = tx_message_id >> 8;
  data[3] = tx_message_id & 0xFF;
  data[4] = 0xFF;

  double timeout = BLUECHERRY_ACK_TIMEOUT *
                   (1 + (rand() / (RAND_MAX + 1.0)) * (BLUECHERRY_ACK_RANDOM_FACTOR - 1));

  for(uint8_t attempt = 1; attempt <= BLUECHERRY_MAX_RETRANSMITS; ++attempt) {
    _bluecherry_opdata.last_tx_time = time(NULL);
    _bluecherry_tickle_watchdog();

    if(_bluecherry_mbed_dtls_write(data, data_len) < 0) {
      return ESP_FAIL;
    }

    _bluecherry_set_state(BLUECHERRY_STATE_AWAITING_RESPONSE);

    while(true) {
      int ret = _bluecherry_mbed_dtls_read(_bluecherry_opdata.in_buf, BLUECHERRY_MAX_MESSAGE_LEN);
      if(ret > 0) {
        _bluecherry_opdata.in_buf_len = ret;

        uint8_t rsp_type = 0;
        uint16_t rsp_message_id = 0;
        esp_err_t perr = _bluecherry_parse_ack_meta(
            _bluecherry_opdata.in_buf, _bluecherry_opdata.in_buf_len, &rsp_type, &rsp_message_id);
        if(perr == ESP_ERR_INVALID_VERSION) {
          ESP_LOGW(TAG, "Ignoring CoAP packet with invalid version while awaiting ACK");
          continue;
        }
        if(perr != ESP_OK) {
          ESP_LOGW(TAG, "Ignoring malformed CoAP packet while awaiting ACK");
          continue;
        }

        if(rsp_type != BLUECHERRY_COAP_TYPE_ACK) {
          ESP_LOGW(TAG, "Ignoring non-ACK CoAP packet while awaiting ACK");
          continue;
        }

        if(rsp_message_id != tx_message_id) {
          ESP_LOGW(TAG,
                   "Received ACK with mismatching message ID %" PRIu16 " while awaiting %" PRIu16,
                   rsp_message_id, tx_message_id);
          continue;
        }

        _bluecherry_opdata.cur_message_id = tx_message_id;
        /* Left at AWAITING_RESPONSE: the response has not been walked, so IDLE would tell an
         * application waiting to sleep that nothing is outstanding before CONTINUE was read. */
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

  /* Left at AWAITING_RESPONSE for the same reason; the caller moves it to AWAIT_CONNECTION. */
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
 * The response is not parsed: a fixed header length is skipped and the remainder is handed
 * back verbatim. rx_cap is therefore the only thing standing between a malformed or hostile
 * response and the caller's buffer, so an oversized response is rejected rather than
 * truncated - a short CBOR frame would fail to decode anyway, so the error is the honest
 * outcome.
 *
 * @param tx_buf Pointer to the buffer containing the payload to transmit.
 * @param tx_len Length of the payload to transmit.
 * @param rx_buf Pointer to the buffer where the received data will be stored.
 * @param rx_cap Capacity of rx_buf in bytes.
 * @param rx_len Pointer to a variable where the length of the received data will be stored.
 * @param header Pointer to the CoAP header to be used for the message.
 * @param header_len Length of the CoAP header.
 *
 * @return true if the transmission and reception were successful, false otherwise.
 */
static bool _bluecherry_ztp_coap_rxtx_common(uint8_t* tx_buf, uint16_t tx_len, uint8_t* rx_buf,
                                             size_t rx_cap, uint16_t* rx_len, const uint8_t* header,
                                             size_t header_len)
{
  static time_t last_tx_time = 0;

  _bluecherry_opdata.cur_message_id += 1;
  if(_bluecherry_opdata.cur_message_id == 0) {
    _bluecherry_opdata.cur_message_id = 1;
  }

  size_t data_len = header_len;
  uint8_t data[BLUECHERRY_ZTP_TX_BUF_SIZE];

  if(header_len + 1 + (size_t) tx_len > sizeof(data)) {
    ESP_LOGE(TAG, "ZTP request of %u bytes does not fit the transmit buffer",
             (unsigned) (header_len + 1 + (size_t) tx_len));
    return false;
  }

  memcpy(data, header, header_len);

  if(tx_len > 0) {
    data[header_len] = 0xFF;
    memcpy(data + header_len + 1, tx_buf, tx_len);
    data_len = header_len + 1 + tx_len;
  }

  double timeout = 2.0 * (1 + (rand() / (RAND_MAX + 1.0)) * (1.5 - 1));

  /* Receive into the session buffer instead of a second kilobyte of stack. Provisioning only
   * runs from BLUECHERRY_STATE_NOT_PROVISIONED, before any CoAP session exists, so in_buf is
   * idle and no other path can be reading it. in_buf_len is left alone: the receive path sets
   * it from the read that fills the buffer, so it never describes what is written here. */
  uint8_t* rx_scratch = _bluecherry_opdata.in_buf;
  const size_t rx_scratch_cap = sizeof(_bluecherry_opdata.in_buf);

  for(uint8_t attempt = 1; attempt <= 4; ++attempt) {
    last_tx_time = time(NULL);
    _bluecherry_tickle_watchdog();

    if(_bluecherry_mbed_dtls_write(data, data_len) < 0)
      return false;

    while(true) {
      int ret = _bluecherry_mbed_dtls_read(rx_scratch, rx_scratch_cap);

      if(ret > 0) {
        if(ret > BLUECHERRY_ZTP_RSP_HEADER_LEN) {
          size_t payload_len = (size_t) ret - BLUECHERRY_ZTP_RSP_HEADER_LEN;
          if(payload_len > rx_cap) {
            ESP_LOGE(TAG, "ZTP response payload of %u bytes exceeds the %u byte buffer",
                     (unsigned) payload_len, (unsigned) rx_cap);
            return false;
          }
          memcpy(rx_buf, rx_scratch + BLUECHERRY_ZTP_RSP_HEADER_LEN, payload_len);
          *rx_len = (uint16_t) payload_len;
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
 * @param rx_cap Capacity of rx_buf in bytes.
 * @param rx_len Pointer to a variable where the length of the received data will be stored.
 *
 * @return true if the transmission and reception were successful, false otherwise.
 */
static bool _bluecherry_ztp_coap_rxtx_devid(uint8_t* tx_buf, uint16_t tx_len, uint8_t* rx_buf,
                                            size_t rx_cap, uint16_t* rx_len)
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

  return _bluecherry_ztp_coap_rxtx_common(tx_buf, tx_len, rx_buf, rx_cap, rx_len, header,
                                          sizeof(header));
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
 * @param rx_cap Capacity of rx_buf in bytes.
 * @param rx_len Pointer to a variable where the length of the received data will be stored.
 *
 * @return true if the transmission and reception were successful, false otherwise.
 */
static bool _bluecherry_ztp_coap_rxtx_sign(uint8_t* tx_buf, uint16_t tx_len, uint8_t* rx_buf,
                                           size_t rx_cap, uint16_t* rx_len)
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

  return _bluecherry_ztp_coap_rxtx_common(tx_buf, tx_len, rx_buf, rx_cap, rx_len, header,
                                          sizeof(header));
}

#pragma endregion
#pragma region ZTP

/**
 * @brief Initializes the CBOR context.
 *
 * @param cbor CBOR context to initialize.
 * @param buffer Output buffer to use.
 * @param capacity Maximum size of the buffer.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_init(_ztp_cbor_t* cbor, uint8_t* buffer, size_t capacity)
{
  if(buffer == NULL || capacity == 0) {
    return -1;
  }

  cbor->buffer = buffer;
  cbor->capacity = capacity;
  cbor->position = 0;

  return 0;
}

/**
 * @brief Returns the size of encoded data.
 *
 * @param cbor CBOR context.
 *
 * @return Size of encoded data.
 */
static size_t _ztp_cbor_size(const _ztp_cbor_t* cbor)
{
  return cbor->position;
}

/**
 * @brief Writes a single byte to the CBOR buffer.
 *
 * @param cbor CBOR context.
 * @param byte Byte to write.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_write_byte(_ztp_cbor_t* cbor, uint8_t byte)
{
  if(cbor->position < cbor->capacity) {
    cbor->buffer[cbor->position++] = byte;
    return 0; // Success
  }
  return -1; // Buffer overflow
}

/**
 * @brief Writes a byte array to the CBOR buffer.
 *
 * @param cbor CBOR context.
 * @param data Data to write.
 * @param length Length of data to write.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_write_bytes(_ztp_cbor_t* cbor, const uint8_t* data, size_t length)
{
  if(cbor->position + length <= cbor->capacity) {
    memcpy(&cbor->buffer[cbor->position], data, length);
    cbor->position += length;
    return 0; // Success
  }
  return -1; // Buffer overflow
}

/**
 * @brief Encodes the type and value into CBOR format.
 *
 * @param cbor CBOR context.
 * @param major_type Major type of the CBOR data.
 * @param value Value to encode.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_encode_type_and_value(_ztp_cbor_t* cbor, uint8_t major_type, size_t value)
{
  if(value < 24) {
    return _ztp_cbor_write_byte(cbor, (major_type << 5) | value);
  } else if(value < 256) {
    if(_ztp_cbor_write_byte(cbor, (major_type << 5) | 0x18) < 0)
      return -1;
    return _ztp_cbor_write_byte(cbor, (uint8_t) value);
  } else if(value < 65536) {
    if(_ztp_cbor_write_byte(cbor, (major_type << 5) | 0x19) < 0)
      return -1;
    uint8_t bytes[] = { (uint8_t) (value >> 8), (uint8_t) value };
    return _ztp_cbor_write_bytes(cbor, bytes, 2);
  }
  return -1; // Larger values not supported
}

/**
 * @brief Encodes a byte string into CBOR format.
 *
 * @param cbor CBOR context.
 * @param data Data to encode.
 * @param length Length of data to encode.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_encode_bytes(_ztp_cbor_t* cbor, const uint8_t* data, size_t length)
{
  if(_ztp_cbor_encode_type_and_value(cbor, 2, length) < 0)
    return -1;                                      // Major type 2 (byte string)
  return _ztp_cbor_write_bytes(cbor, data, length); // Write byte array to buffer
}

/**
 * @brief Encodes a string into CBOR format.
 *
 * @param cbor CBOR context.
 * @param str String to encode.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_encode_string(_ztp_cbor_t* cbor, const char* str)
{
  size_t len = strlen(str);
  if(_ztp_cbor_encode_type_and_value(cbor, 3, len) < 0)
    return -1; // Major type 3 (text string)
  return _ztp_cbor_write_bytes(cbor, (const uint8_t*) str, len);
}

/**
 * @brief Encodes a 64-bit unsigned integer into CBOR format.
 *
 * @param cbor CBOR context.
 * @param value Value to encode.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_encode_uint64(_ztp_cbor_t* cbor, uint64_t value)
{
  if(_ztp_cbor_encode_type_and_value(cbor, 2, 8) < 0)
    return -1;

  uint8_t bytes[] = { (uint8_t) (value >> 56), (uint8_t) (value >> 48), (uint8_t) (value >> 40),
                      (uint8_t) (value >> 32), (uint8_t) (value >> 24), (uint8_t) (value >> 16),
                      (uint8_t) (value >> 8),  (uint8_t) value };

  return _ztp_cbor_write_bytes(cbor, bytes, 8);
}

/**
 * @brief Encodes a signed integer into CBOR format.
 *
 * @param cbor The CBOR context.
 * @param value Value to encode.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_encode_int(_ztp_cbor_t* cbor, int value)
{
  if(value >= 0) {
    return _ztp_cbor_encode_type_and_value(cbor, 0,
                                           (size_t) value); // Major type 0
  } else {
    return _ztp_cbor_encode_type_and_value(cbor, 1,
                                           (size_t) (-value - 1)); // Major type 1
  }
}

/**
 * @brief Starts encoding an array into CBOR format.
 *
 * @param cbor The CBOR context.
 * @param size Expected size of the array.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_start_array(_ztp_cbor_t* cbor, size_t size)
{
  return _ztp_cbor_encode_type_and_value(cbor, 4, size); // Major type 4 (array)
}

/**
 * @brief Starts encoding a map into CBOR format.
 *
 * @param cbor The CBOR context.
 * @param size Expected size of the map.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_start_map(_ztp_cbor_t* cbor, size_t size)
{
  return _ztp_cbor_encode_type_and_value(cbor, 5, size); // Major type 5 (map)
}

/**
 * @brief Decodes a device ID from CBOR data.
 *
 * @param cbor_data CBOR data to decode.
 * @param cbor_size Size of CBOR data.
 * @param decoded_str Buffer to store decoded device ID.
 * @param decoded_size Size of decoded device ID buffer.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_decode_device_id(const uint8_t* cbor_data, size_t cbor_size, char* decoded_str,
                                      size_t decoded_size)
{
  if(cbor_size < 1 || !cbor_data) {
    return -1; // CBOR data is invalid
  }

  // Ensure initial byte is a text string (major type 3)
  uint8_t initial_byte = cbor_data[0];
  if((initial_byte >> 5) != 3) {
    return -2; // CBOR data is not a text string
  }

  // Extract the length of the string
  size_t length = 0;
  uint8_t additional_info = initial_byte & 0x1F;

  if(additional_info > 23) {
    return -3; // String length unsupported
  }

  length = additional_info;
  cbor_data++;
  cbor_size--;

  // Validate the length against the remaining CBOR data
  if(length > cbor_size) {
    return -4; // Incomplete CBOR data for string length
  }

  // Validate the length against the output buffer size
  if(length >= decoded_size) {
    return -5; // Decoded string buffer too small
  }

  // Copy the string into the output buffer and null-terminate it
  memcpy(decoded_str, cbor_data, length);
  decoded_str[length] = '\0';

  return 0;
}

/**
 * @brief Decodes a signed certificate from CBOR data.
 *
 * @param cbor_data CBOR data to decode.
 * @param cbor_size Size of CBOR data.
 * @param decoded_data Buffer to store decoded certificate.
 * @param decoded_len Pointer to store size of decoded certificate.
 *
 * @return 0 on success, non-zero on failure.
 */
static int _ztp_cbor_decode_certificate(const uint8_t* cbor_data, size_t cbor_size,
                                        unsigned char* decoded_data, size_t* decoded_len)
{
  if(cbor_size < 1 || !cbor_data) {
    return -1; // CBOR data is invalid
  }

  // Ensure initial byte is a byte string (major type 2)
  uint8_t initial_byte = cbor_data[0];
  if((initial_byte >> 5) != 2) {
    return -2; // CBOR data is not a byte string
  }

  // Extract the length of the string
  size_t length = 0;
  size_t offset = 1;
  uint8_t additional_info = initial_byte & 0x1F;

  if(additional_info < 24) {
    length = additional_info;
  } else if(additional_info == 24) {
    length = cbor_data[offset++];
  } else if(additional_info == 25) {
    length = (cbor_data[offset] << 8) | cbor_data[offset + 1];
    offset += 2;
  } else if(additional_info == 26) {
    length = (cbor_data[offset] << 24) | (cbor_data[offset + 1] << 16) |
             (cbor_data[offset + 2] << 8) | cbor_data[offset + 3];
    offset += 4;
  } else {
    return -3; // Length not supported
  }

  if(offset + length > cbor_size) {
    return -4; // Length exceeds buffer size
  }

  memcpy(decoded_data, cbor_data + offset, length);
  *decoded_len = length;

  return 0;
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
     _bluecherry_opdata.ztp_dev_id_params.count >= BLUECHERRY_ZTP_MAX_DEVICE_ID_PARAMS) {
    return false;
  }

  switch(type) {
  case BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC:
    _bluecherry_opdata.ztp_dev_id_params.param[_bluecherry_opdata.ztp_dev_id_params.count].type =
        BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC;
    memcpy(_bluecherry_opdata.ztp_dev_id_params.param[_bluecherry_opdata.ztp_dev_id_params.count]
               .value.mac,
           blob, BLUECHERRY_ZTP_MAC_LEN);
    _bluecherry_opdata.ztp_dev_id_params.count += 1;
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
  uint8_t cbor_buf[256];
  _ztp_cbor_t cbor;

  if(_ztp_cbor_init(&cbor, cbor_buf, sizeof(cbor_buf)) < 0) {
    ESP_LOGE(TAG, "Failed to init CBOR buffer");
    return false;
  };

  // Start the CBOR array
  if(_ztp_cbor_start_array(&cbor, 2) < 0) {
    ESP_LOGE(TAG, "Failed to start CBOR array");
    return false;
  }

  // Encode type ID value
  if(_ztp_cbor_encode_string(&cbor, bc_type_id) < 0) {
    ESP_LOGE(TAG, "Failed to encode typeId value");
    return false;
  }

  // Start the CBOR map (key-value pairs)
  if(_ztp_cbor_start_map(&cbor, _bluecherry_opdata.ztp_dev_id_params.count) < 0) {
    ESP_LOGE(TAG, "Failed to start CBOR map");
    return false;
  }

  for(size_t i = 0; i < _bluecherry_opdata.ztp_dev_id_params.count; i++) {

    int type = (int) _bluecherry_opdata.ztp_dev_id_params.param[i].type;
    if(_ztp_cbor_encode_int(&cbor, type) < 0) {
      ESP_LOGE(TAG, "Failed to encode param type (%u)", type);
      return false;
    }

    switch(_bluecherry_opdata.ztp_dev_id_params.param[i].type) {
    case BLUECHERRY_ZTP_DEVICE_ID_TYPE_IMEI: {
      // Encode IMEI number (15 characters)
      uint64_t imei = strtoull(_bluecherry_opdata.ztp_dev_id_params.param[i].value.imei, NULL, 10);
      if(_ztp_cbor_encode_uint64(&cbor, imei) < 0) {
        ESP_LOGE(TAG, "Failed to encode IMEI number");
        return false;
      }
    } break;

    case BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC: {
      // Encode MAC address (6 bytes)
      if(_ztp_cbor_encode_bytes(
             &cbor, (uint8_t*) _bluecherry_opdata.ztp_dev_id_params.param[i].value.mac, 6) < 0) {
        ESP_LOGE(TAG, "Failed to encode MAC address");
        return false;
      }
    } break;

    case BLUECHERRY_ZTP_DEVICE_ID_TYPE_OOB_CHALLENGE: {
      // Encode OOB challenge (64 bit unsigned int)
      uint64_t oob_challenge = _bluecherry_opdata.ztp_dev_id_params.param[0].value.oob_challenge;
      if(_ztp_cbor_encode_uint64(&cbor, oob_challenge) < 0) {
        ESP_LOGE(TAG, "Failed to encode OOB challenge");
        return false;
      }
    } break;

    default:
      break;
    }
  }

  uint8_t in_buf[16];
  uint16_t in_len = 0;
  if(!_bluecherry_ztp_coap_rxtx_devid(cbor_buf, _ztp_cbor_size(&cbor), in_buf, sizeof(in_buf),
                                      &in_len)) {
    ESP_LOGE(TAG, "Failed to sync with ZTP COAP server");
    return false;
  }

  ret = _ztp_cbor_decode_device_id(in_buf, in_len, ztp_bc_dev_id, sizeof(ztp_bc_dev_id));
  if(ret < 0) {
    ESP_LOGD(TAG, "Failed to decode device id: %d", ret);
    return false;
  }

  return true;
}

/**
 * @brief Generate a key pair and CSR for ZTP.
 *
 * This function generates an EC key pair and creates a Certificate Signing Request (CSR)
 * using the provided device type ID and device ID. The generated private key is stored
 * in PEM format in the global ztp_pkey_buf, and the CSR is stored in the _bluecherry_opdata
 * structure.
 *
 * @return true if the key pair and CSR were generated successfully, false otherwise.
 */
static bool _ztp_generate_key_and_csr()
{
  int ret;
  uint8_t csr_buf[BLUECHERRY_ZTP_CERT_BUF_SIZE];

  if(bc_type_id == NULL || strlen(bc_type_id) != BLUECHERRY_ZTP_ID_LEN ||
     strlen(ztp_bc_dev_id) != BLUECHERRY_ZTP_ID_LEN) {
    return false;
  }

  mbedtls_pk_init(&_bluecherry_opdata.devkey);
  mbedtls_x509write_csr_init(&_bluecherry_opdata.ztp_mb_csr);

  if(mbedtls_pk_setup(&_bluecherry_opdata.devkey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) !=
     0) {
    return _ztp_finish_csr_gen(false);
  }

  if(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(_bluecherry_opdata.devkey),
                         mbedtls_ctr_drbg_random, &_bluecherry_opdata.ctr_drbg) != 0) {
    return _ztp_finish_csr_gen(false);
  }

  if(mbedtls_pk_write_key_pem(&_bluecherry_opdata.devkey, (unsigned char*) ztp_pkey_buf,
                              BLUECHERRY_ZTP_PKEY_BUF_SIZE) != 0) {
    return _ztp_finish_csr_gen(false);
  }

  mbedtls_x509write_csr_set_md_alg(&_bluecherry_opdata.ztp_mb_csr, MBEDTLS_MD_SHA256);
  mbedtls_x509write_csr_set_key(&_bluecherry_opdata.ztp_mb_csr, &_bluecherry_opdata.devkey);

  snprintf(ztp_subj_buf, BLUECHERRY_ZTP_SUBJ_BUF_SIZE, "C=BE,CN=%s.%s", bc_type_id, ztp_bc_dev_id);
  if(mbedtls_x509write_csr_set_subject_name(&_bluecherry_opdata.ztp_mb_csr, ztp_subj_buf) != 0) {
    return _ztp_finish_csr_gen(false);
  }

  ret = mbedtls_x509write_csr_der(&_bluecherry_opdata.ztp_mb_csr, csr_buf,
                                  BLUECHERRY_ZTP_CERT_BUF_SIZE, mbedtls_ctr_drbg_random,
                                  &_bluecherry_opdata.ctr_drbg);
  if(ret < 0) {
    ESP_LOGE(TAG, "Failed to write CSR DER: -0x%04X", -ret);
    return _ztp_finish_csr_gen(false);
  }

  size_t offset = BLUECHERRY_ZTP_CERT_BUF_SIZE - ret;
  _bluecherry_opdata.ztp_csr.length = ret;
  memcpy(_bluecherry_opdata.ztp_csr.buffer, csr_buf + offset, _bluecherry_opdata.ztp_csr.length);

  return _ztp_finish_csr_gen(true);
}

/**
 * @brief Request a signed certificate from the BlueCherry ZTP server.
 *
 * This function sends the previously generated CSR to the BlueCherry ZTP server
 * via CoAP, receives the signed certificate in DER format, converts it to PEM format,
 * and stores it in the global ztp_cert_buf.
 *
 * @return true if the signed certificate was successfully requested and stored, false otherwise.
 */
static bool _ztp_request_signed_certificate()
{
  int ret;
  uint8_t cbor_buf[BLUECHERRY_ZTP_CERT_BUF_SIZE];
  uint8_t coap_data[BLUECHERRY_ZTP_CERT_BUF_SIZE];
  _ztp_cbor_t cbor;

  _ztp_cbor_init(&cbor, cbor_buf, BLUECHERRY_ZTP_CERT_BUF_SIZE);
  mbedtls_x509_crt_init(&_bluecherry_opdata.devcert);

  if(_ztp_cbor_encode_bytes(&cbor, _bluecherry_opdata.ztp_csr.buffer,
                            _bluecherry_opdata.ztp_csr.length) < 0) {
    ESP_LOGE(TAG, "Failed to encode CSR");
    return false;
  }

  uint16_t in_len = 0;
  if(!_bluecherry_ztp_coap_rxtx_sign(cbor_buf, _ztp_cbor_size(&cbor), coap_data, sizeof(coap_data),
                                     &in_len)) {
    ESP_LOGE(TAG, "Failed to receive response from ZTP COAP server");
    return false;
  }

  size_t decoded_size;
  ret = _ztp_cbor_decode_certificate(coap_data, in_len, cbor_buf, &decoded_size);
  if(ret < 0) {
    ESP_LOGE(TAG, "Failed to decode certificate: %d", ret);
    return false;
  }

  // Parse the DER-encoded certificate
  ret = mbedtls_x509_crt_parse_der(&_bluecherry_opdata.devcert, cbor_buf, decoded_size);
  if(ret < 0) {
    ESP_LOGE(TAG, "Failed to parse DER certificate, error code: -0x%x", -ret);
    mbedtls_x509_crt_free(&_bluecherry_opdata.devcert);
    return false;
  }

  // Convert the certificate to PEM format
  size_t pem_len;
  ret =
      mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
                               _bluecherry_opdata.devcert.raw.p, _bluecherry_opdata.devcert.raw.len,
                               cbor_buf, BLUECHERRY_ZTP_CERT_BUF_SIZE, &pem_len);
  if(ret < 0) {
    ESP_LOGE(TAG, "Failed to write PEM: -0x%04X", -ret);
    mbedtls_x509_crt_free(&_bluecherry_opdata.devcert);
    return false;
  }

  /* pem_len counts the terminating NUL, so the copy is already terminated. Writing one more
   * would land on ztp_cert_buf[BLUECHERRY_ZTP_CERT_BUF_SIZE] for a maximal certificate. */
  memcpy(ztp_cert_buf, cbor_buf, pem_len);

  mbedtls_x509_crt_free(&_bluecherry_opdata.devcert);
  return true;
}

#pragma endregion
#pragma region PUBLIC

/**
 * @brief Load or obtain the device credentials, then install them.
 *
 * Reads the stored certificate and key through the application's storage handler and, when
 * they are absent, runs a full provisioning cycle against the provisioning service before
 * writing the issued pair back through the same handler.
 *
 * Runs from bluecherry_sync rather than from init, so that reserving memory and reaching the
 * network stay separate concerns and a device with no cloud in sight still initialises.
 *
 * @return true once credentials are installed and the connection can be attempted.
 */
static bool _bluecherry_provision(void)
{
  const char* device_cert =
      _bluecherry_opdata.ztp_bio_handler(true, false, _bluecherry_opdata.ztp_bio_handler_args);
  const char* device_key =
      _bluecherry_opdata.ztp_bio_handler(true, true, _bluecherry_opdata.ztp_bio_handler_args);

  if(device_cert == NULL || device_key == NULL) {
    uint8_t mac[8] = { 0 };

    ESP_LOGI(TAG, "Device is not provisioned for BlueCherry communication, starting ZTP...");

    if(esp_read_mac(mac, ESP_MAC_WIFI_STA) != ESP_OK) {
      ESP_LOGE(TAG, "(ZTP) Could not read the MAC address to identify this device");
      goto fail;
    }

    /* The provisioning service is authenticated against the same CA, but this device has no
     * certificate of its own to present yet, so the session is one-sided. */
    if(!_bluecherry_dtls_connect(BLUECHERRY_HOST, BLUECHERRY_ZTP_PORT)) {
      ESP_LOGE(TAG, "(ZTP) Could not connect to the provisioning server");
      goto fail;
    }

    ESP_LOGI(TAG, "(ZTP) Connected");

    if(!_ztp_add_device_id_parameter_blob(BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC, mac)) {
      ESP_LOGE(TAG, "(ZTP) Could not add MAC address as ZTP device ID parameter");
      goto fail;
    }

    if(!_ztp_request_device_id()) {
      ESP_LOGD(TAG, "(ZTP) Could not request device ID");
      ESP_LOGE(TAG, "(ZTP) This device might not exist- or is not set to WAIT-PROVISION on the "
                    "BlueCherry platform.");
      goto fail;
    }

    if(!_ztp_generate_key_and_csr()) {
      ESP_LOGE(TAG, "(ZTP) Could not generate private key");
      goto fail;
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    if(!_ztp_request_signed_certificate()) {
      ESP_LOGE(TAG, "(ZTP) Could not request signed certificate");
      goto fail;
    }

    /* Persist before installing: a reset between the two re-reads them on the next boot,
     * whereas the other order would discard a certificate that has already been issued. */
    _bluecherry_opdata.ztp_bio_handler(false, false, (void*) ztp_cert_buf);
    _bluecherry_opdata.ztp_bio_handler(false, true, (void*) ztp_pkey_buf);

    device_cert = ztp_cert_buf;
    device_key = ztp_pkey_buf;

    /* The provisioning session authenticated only the server. Drop it so the traffic session
     * is built from scratch with the credentials just installed. */
    _bluecherry_cleanup_session();
  }

  if(!_bluecherry_configure_own_cert(device_cert, device_key)) {
    ESP_LOGE(TAG, "Could not configure device credentials");
    goto fail;
  }

  _bluecherry_opdata.ztp_dev_id_params.count = 0;
  return true;

fail:
  /* The specific reason is logged where it was detected; the caller reports the failure
   * itself, so that the message can name the retry delay it is about to apply. */
  _bluecherry_cleanup_session();
  _bluecherry_opdata.ztp_dev_id_params.count = 0;
  return false;
}

/**
 * @brief Reserve everything both entry points need, without touching the network.
 *
 * Reserves the publish buffer, sets up the Mbed TLS contexts and the CA chain, configures the
 * watchdog and starts the synchronisation task. The caller supplies the state to settle in,
 * which is the only thing that differs between a pre-provisioned device and one that still has
 * to be provisioned.
 *
 * @param msg_handler The message handler or NULL to ignore incoming messages.
 * @param msg_handler_args Optional user arguments to pass to the message handler.
 * @param auto_sync True to spawn the automatic synchronisation task.
 * @param watchdog_timeout_seconds The task watchdog timeout in seconds, or 0 to leave it alone.
 * @param publish_buffer The application's publish buffer, or NULL to allocate one.
 * @param initial_state The state to leave the library in on success.
 *
 * @return ESP_OK on success, ESP_FAIL otherwise.
 */
static esp_err_t _bluecherry_init_common(bluecherry_msg_handler_t msg_handler,
                                         void* msg_handler_args, bool auto_sync,
                                         uint16_t watchdog_timeout_seconds,
                                         const bluecherry_publish_buffer_t* publish_buffer,
                                         bluecherry_state initial_state)
{
  _bluecherry_opdata.msg_handler = msg_handler;
  _bluecherry_opdata.msg_handler_args = msg_handler_args;

  uint8_t mac[6];
  esp_err_t eret = esp_read_mac(mac, ESP_MAC_WIFI_STA);
  if(eret != ESP_OK) {
    ESP_LOGE(TAG, "Could not read MAC: %s", esp_err_to_name(eret));
    return ESP_FAIL;
  }

  esp_err_t bret = _bluecherry_ring_init(publish_buffer);
  if(bret != ESP_OK) {
    return bret;
  }

  if(!_bluecherry_setup_mbedtls(mac)) {
    ESP_LOGE(TAG, "Could not setup Mbed TLS context");
    goto fail;
  }
  if(!_bluecherry_configure_ca(BLUECHERRY_CA)) {
    ESP_LOGE(TAG, "Could not configure the CA chain");
    goto fail;
  }

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
    _watchdog = true;
  }

  /* INIT_INFO is deliberately NOT queued here. bluecherry_sync clears the priority slot on
   * every connect and refills it with a fresh INIT_INFO, so anything queued before the first
   * session would be discarded unsent. */

  /* Started unconditionally: bluecherry_sync is a trigger, so the task has to exist even when
   * the application drives synchronisation itself. Guarded on the handle so a retried init
   * cannot leave two running. The stack has to carry the deepest operation, which is
   * provisioning: a DTLS handshake, ~2.8 kB of CBOR buffers and an EC key generation. */
  if(_sync_task == NULL) {
    BaseType_t ret =
        xTaskCreate(_bluecherry_sync_task, "bc_sync", CONFIG_BLUECHERRY_SYNC_TASK_STACK_SIZE, NULL,
                    BLUECHERRY_SP, &_sync_task);
    if(ret != pdPASS) {
      _sync_task = NULL;
      ESP_LOGE(TAG, "Could not start the synchronisation task");
      goto fail;
    }
  }

  if(auto_sync) {
    ESP_LOGW(TAG, "the auto_sync argument is deprecated, "
                  "call bluecherry_set_auto_sync(seconds) instead");
    bluecherry_set_auto_sync(CONFIG_BLUECHERRY_AUTO_SYNC_SEC);
  }

  _bluecherry_set_state(initial_state);

  /* There is always something to do here, so start the first cycle rather than wait it out. */
  xTaskNotifyGive(_sync_task);
  return ESP_OK;

fail:
  /* The publish buffer is released here too. It used to survive these paths, so a caller that
   * retried init leaked one buffer per attempt. */
  _bluecherry_ring_deinit();
  _bluecherry_cleanup_network();
  _bluecherry_cleanup_mbedtls();
  return ESP_FAIL;
}

esp_err_t bluecherry_init(const char* device_cert, const char* device_key,
                          bluecherry_msg_handler_t msg_handler, void* msg_handler_args,
                          bool auto_sync, uint16_t watchdog_timeout_seconds,
                          const bluecherry_publish_buffer_t* publish_buffer)
{
  if(_bluecherry_opdata.state != BLUECHERRY_STATE_UNINITIALIZED)
    return ESP_OK;

  if(device_cert == NULL || device_key == NULL) {
    ESP_LOGE(TAG, "A device certificate and key are required");
    return ESP_ERR_INVALID_ARG;
  }

  esp_err_t ret =
      _bluecherry_init_common(msg_handler, msg_handler_args, auto_sync, watchdog_timeout_seconds,
                              publish_buffer, BLUECHERRY_STATE_AWAIT_CONNECTION);
  if(ret != ESP_OK) {
    return ret;
  }

  if(!_bluecherry_configure_own_cert(device_cert, device_key)) {
    ESP_LOGE(TAG, "Could not configure device credentials");
    _bluecherry_set_state(BLUECHERRY_STATE_UNINITIALIZED);
    return ESP_FAIL;
  }

  return ESP_OK;
}

esp_err_t bluecherry_init_ztp(bluecherry_ztp_bio_handler_t ztp_bio_handler,
                              void* ztp_bio_handler_args, const char* bc_device_type,
                              bluecherry_msg_handler_t msg_handler, void* msg_handler_args,
                              bool auto_sync, uint16_t watchdog_timeout_seconds,
                              const bluecherry_publish_buffer_t* publish_buffer)
{
  if(_bluecherry_opdata.state != BLUECHERRY_STATE_UNINITIALIZED) {
    return ESP_OK;
  }

  if(ztp_bio_handler == NULL || bc_device_type == NULL) {
    ESP_LOGE(TAG, "A credential storage handler and a device type are required");
    return ESP_ERR_INVALID_ARG;
  }

  bc_type_id = bc_device_type;
  _bluecherry_opdata.ztp_bio_handler = ztp_bio_handler;
  _bluecherry_opdata.ztp_bio_handler_args = ztp_bio_handler_args;

  /* Nothing here talks to the network. Reading the stored credentials and, if there are none,
   * provisioning this device both happen on the first bluecherry_sync - so this call cannot
   * fail because the cloud is unreachable, and the caller does not have to retry it. */
  return _bluecherry_init_common(msg_handler, msg_handler_args, auto_sync, watchdog_timeout_seconds,
                                 publish_buffer, BLUECHERRY_STATE_NOT_PROVISIONED);
}

/**
 * @brief Run one synchronisation cycle: provision, connect, send one message, dispatch the reply.
 *
 * Runs only on the synchronisation task, one at a time, which is what lets it touch the shared
 * connection state without locking. Timing is the caller's concern, not its own.
 *
 * @return BLUECHERRY_SYNC_CONTINUE when work is still outstanding and another cycle should
 * follow immediately, ESP_OK when everything settled, or an error for the round that failed.
 */
static esp_err_t _bluecherry_sync_once(void)
{
  static int64_t last_retry_time_us = 0;
  static uint32_t retry_interval_ms = 100;
  static uint32_t provision_interval_ms = BLUECHERRY_PROVISION_RETRY_MS;

  /* Obtain credentials before anything else. This is backoff-gated on its own timer rather
   * than sharing the connect one, so a provisioning service that is down does not also
   * throttle the reconnects of a device that is already provisioned.
   *
   * A deadline rather than an elapsed-time comparison, so that _next_provision_us == 0 means
   * "due now" and the first attempt after boot is not itself delayed by the backoff.
   *
   * At most one attempt per call, and the gate returns immediately when the next one is not
   * yet due: the application may be driving bluecherry_sync itself, so this must never block
   * waiting for a retry to come round. */
  if(_bluecherry_opdata.state == BLUECHERRY_STATE_NOT_PROVISIONED) {
    if(esp_timer_get_time() < _next_provision_us) {
      return ESP_ERR_NOT_FINISHED;
    }

    if(!_bluecherry_provision()) {
      ESP_LOGE(TAG, "(ZTP) Provisioning failed, retrying in %lu s", provision_interval_ms / 1000);
      _next_provision_us = esp_timer_get_time() + (int64_t) provision_interval_ms * 1000;

      provision_interval_ms *= 2;
      if(provision_interval_ms > BLUECHERRY_PROVISION_RETRY_MAX_MS) {
        provision_interval_ms = BLUECHERRY_PROVISION_RETRY_MAX_MS;
      }
      return ESP_ERR_NOT_FINISHED;
    }

    _next_provision_us = 0;
    provision_interval_ms = BLUECHERRY_PROVISION_RETRY_MS;
    _bluecherry_set_state(BLUECHERRY_STATE_AWAIT_CONNECTION);
  }

  // (re)connect if needed with exponential backoff (non-blocking)
  if(_bluecherry_opdata.state == BLUECHERRY_STATE_AWAIT_CONNECTION) {
    int64_t now_us = esp_timer_get_time();
    int64_t elapsed_ms = (now_us - last_retry_time_us) / 1000;
    if(elapsed_ms >= retry_interval_ms) {
      last_retry_time_us = now_us;
      if(!_bluecherry_dtls_connect(BLUECHERRY_HOST, BLUECHERRY_PORT)) {
        ESP_LOGE(TAG, "Could not connect to BlueCherry server");
        retry_interval_ms = (retry_interval_ms < 30000) ? retry_interval_ms * 2 : 30000;
        return ESP_ERR_NOT_FINISHED;
      }

      _bluecherry_opdata.cur_message_id = 0;
      _bluecherry_opdata.last_acked_message_id = 0;

      /* Abandon any transfer in progress. The server restarts an OTA from
       * chunk 0 on a new session, so keeping ota_progress would resume writing
       * at a stale offset and quietly corrupt the image - and unfixable any
       * other way, because sequential chunks carry no offset to re-sync
       * against. A protocol reply from the dead session is
       * equally meaningless, so the priority slot goes with it. */
      _bluecherry_ota_reset();
      _bluecherry_opdata.pending_event_len = 0;

      /* Not IDLE: the INIT_INFO queued just below still has to go out. */
      _bluecherry_set_state(BLUECHERRY_STATE_PENDING_MESSAGES);
      retry_interval_ms = 100;

      /* Report the running image on every connect, not only at boot. */
      _bluecherry_send_init_info();
    } else {
      return ESP_ERR_NOT_FINISHED;
    }
  }

  if(_bluecherry_opdata.state == BLUECHERRY_STATE_UNINITIALIZED) {
    ESP_LOGE(TAG, "Cannot sync in the current state");
    return ESP_ERR_INVALID_STATE;
  }

  /* AWAITING_RESPONSE is no longer rejected here: only the task calls this, serially, so it
   * cannot be observed on entry except as a leftover from a cycle that got no response. */

  _bluecherry_msg_t out_msg;

  // Internal-channel protocol replies jump the application queue. Only one
  // message goes out per sync, so a probe reply left to queue behind a full
  // publish buffer would be that many syncs away - long enough for the server
  // to push a whole image in a form this client cannot accept.
  if(_bluecherry_opdata.pending_event_len > 0) {
    _bluecherry_msg_t ev = { .len = _bluecherry_opdata.pending_event_len,
                             .data = _bluecherry_opdata.pending_event };
    if(_bluecherry_coap_rxtx(&ev) != ESP_OK) {
      ESP_LOGE(TAG, "Could not sync internal event with cloud");
      _bluecherry_set_state(BLUECHERRY_STATE_AWAIT_CONNECTION);
      return ESP_ERR_NOT_FINISHED;
    }
    _bluecherry_opdata.pending_event_len = 0;

    // rxtx only returns ESP_OK once the ACK is in, so this is where a VERIFIED
    // is known to have landed - and therefore the only safe point to make the
    // new image the boot target.
    if(_bluecherry_opdata.ota_state == BLUECHERRY_OTA_STATE_AWAITING_VERIFIED) {
      _bluecherry_ota_commit();
    }
  }
  // Peeked, not popped: the message stays in the buffer until its ACK is in, so
  // a failed sync retries it rather than dropping it.
  else if(_bluecherry_ring_peek(&out_msg)) {
    if(_bluecherry_coap_rxtx(&out_msg) == ESP_OK) {
      _bluecherry_ring_pop();
    } else {
      ESP_LOGE(TAG, "Could not sync payload with cloud");
      _bluecherry_set_state(BLUECHERRY_STATE_AWAIT_CONNECTION);
      return ESP_ERR_NOT_FINISHED;
    }
  } else {
    // Nothing to send, but an empty sync is still the only thing that lets the server deliver
    // downlink to a device that never publishes. Whether one is due is the task's decision.
    if(_bluecherry_coap_rxtx(NULL) != ESP_OK) {
      ESP_LOGE(TAG, "Could not sync with cloud");
      _bluecherry_set_state(BLUECHERRY_STATE_AWAIT_CONNECTION);
      return ESP_ERR_NOT_FINISHED;
    }
  }

  bool want_resync = false;

  if(_bluecherry_opdata.in_buf_len < BLUECHERRY_COAP_HEADER_SIZE) {
    ESP_LOGE(TAG, "Received CoAP packet too small: %u", (unsigned) _bluecherry_opdata.in_buf_len);
    return ESP_ERR_INVALID_SIZE;
  }

  uint16_t offset = 0;

  uint8_t header = _bluecherry_opdata.in_buf[offset++];
  uint8_t version = (header >> 6) & 0x03;
  if(version != 1) {
    ESP_LOGE(TAG, "Received CoAP packet with version %d, expeced 1", version);
    return ESP_ERR_INVALID_VERSION;
  }

  uint8_t type = (header >> 4) & 0x03;
  uint8_t token_len = header & 0x0F;

  size_t min_header_len = (size_t) (1 + token_len + 1 + 2 + 1);
  if(_bluecherry_opdata.in_buf_len < min_header_len) {
    ESP_LOGE(TAG, "Received CoAP packet with invalid length %u for token length %u",
             (unsigned) _bluecherry_opdata.in_buf_len, token_len);
    return ESP_ERR_INVALID_SIZE;
  }

  offset += token_len;
  uint8_t code = _bluecherry_opdata.in_buf[offset++];
  uint16_t msg_id = _bluecherry_opdata.in_buf[offset++];
  msg_id <<= 8;
  msg_id |= _bluecherry_opdata.in_buf[offset++];
  if(_bluecherry_opdata.in_buf[offset++] != 0xFF) {
    ESP_LOGE(TAG, "Received CoAP packet without payload marker");
    return ESP_ERR_INVALID_RESPONSE;
  }

  if(type == BLUECHERRY_COAP_TYPE_ACK) {
    if(msg_id != _bluecherry_opdata.cur_message_id) {
      ESP_LOGE(TAG, "Received ACK for %" PRIu16 " instead of %" PRIu16 "", msg_id,
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
    /* Both header bytes have to be there before either is read: a single trailing byte would
     * otherwise take the length from past the payload, and from past in_buf itself on a frame
     * that filled it. */
    if(offset + 2 > _bluecherry_opdata.in_buf_len) {
      ESP_LOGE(TAG, "Received truncated payload header");
      return ESP_ERR_INVALID_SIZE;
    }

    uint8_t topic = _bluecherry_opdata.in_buf[offset++];
    uint8_t data_len = _bluecherry_opdata.in_buf[offset++];

    if(offset + data_len > _bluecherry_opdata.in_buf_len) {
      ESP_LOGE(TAG, "Received malformed payload length");
      return ESP_ERR_INVALID_SIZE;
    }

    if(topic == 0x00) {
      want_resync = true;

      _bluecherry_process_event(_bluecherry_opdata.in_buf + offset, data_len);
    } else if(_bluecherry_opdata.msg_handler != NULL) {
      _bluecherry_opdata.msg_handler(topic, data_len, _bluecherry_opdata.in_buf + offset,
                                     _bluecherry_opdata.msg_handler_args);
    }

    offset += data_len;
  }

  ESP_LOGD(TAG, "Synchronized messages with cloud");

  /* An application is entitled to sleep on IDLE, so the server having more queued is only one
   * way this can be unsettled - the outgoing queue and a just-queued reply count too. */
  if(_bluecherry_work_pending(want_resync)) {
    _bluecherry_set_state(BLUECHERRY_STATE_PENDING_MESSAGES);
    return BLUECHERRY_SYNC_CONTINUE;
  }

  _bluecherry_set_state(BLUECHERRY_STATE_IDLE);
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

  esp_err_t ret = _bluecherry_ring_push(topic, len, data);
  if(ret != ESP_OK) {
    return ret;
  }

  /* Something to send is reason enough to run: the interval exists to force an empty sync when
   * there is nothing queued, not to hold queued messages back. With auto-sync off there is no
   * timer at all, so the message waits for the application to call bluecherry_sync. */
  if(_auto_sync_interval_sec > 0 && _sync_task != NULL) {
    xTaskNotifyGive(_sync_task);
  }

  return ESP_OK;
}

esp_err_t bluecherry_set_ota_handler(bluecherry_ota_handler_t handler, void* args)
{
  _bluecherry_opdata.ota_handler = handler;
  _bluecherry_opdata.ota_handler_args = args;
  return ESP_OK;
}

esp_err_t bluecherry_ota_start(void)
{
  /* Advisory: the application may be on any task, and the offer could be withdrawn between this
   * check and the request being serviced. The task re-checks before acting. Answering here
   * anyway keeps the return value meaning what it always did. */
  if(_bluecherry_opdata.ota_state != BLUECHERRY_OTA_STATE_OFFERED) {
    ESP_LOGW(TAG, "bluecherry_ota_start: no update is on offer");
    return ESP_ERR_INVALID_STATE;
  }

  _ota_start_req = true;
  return bluecherry_sync();
}

esp_err_t bluecherry_ota_abort(uint8_t error_code)
{
  if(_bluecherry_opdata.ota_state == BLUECHERRY_OTA_STATE_IDLE) {
    return ESP_ERR_INVALID_STATE;
  }

  _ota_abort_code = error_code;
  _ota_abort_req = true;
  return bluecherry_sync();
}

esp_err_t bluecherry_sync(void)
{
  if(_sync_task == NULL || _bluecherry_opdata.state == BLUECHERRY_STATE_UNINITIALIZED) {
    return ESP_ERR_INVALID_STATE;
  }

  xTaskNotifyGive(_sync_task);
  return ESP_OK;
}

esp_err_t bluecherry_set_auto_sync(uint32_t interval_sec)
{
  if(_sync_task == NULL) {
    return ESP_ERR_INVALID_STATE;
  }

  _auto_sync_interval_sec = interval_sec;
  _bluecherry_arm_auto_sync();

  if(interval_sec > 0) {
    /* Only when the new interval leaves one already overdue. Setting a schedule is not the
     * same as asking for a synchronisation, and anything still in the future is picked up by
     * the task's next wake anyway. */
    if(esp_timer_get_time() >= _next_auto_sync_us) {
      xTaskNotifyGive(_sync_task);
    }
    ESP_LOGI(TAG, "Automatic synchronisation every %lu s", interval_sec);
  } else {
    ESP_LOGI(TAG, "Automatic synchronisation disabled");
  }

  return ESP_OK;
}

bluecherry_state bluecherry_get_state(void)
{
  return _bluecherry_opdata.state;
}

esp_err_t bluecherry_set_state_handler(bluecherry_state_handler_t handler, void* args)
{
  _bluecherry_opdata.state_handler_args = args;
  _bluecherry_opdata.state_handler = handler;
  return ESP_OK;
}

#pragma endregion