/**
 * @file main.c
 * @author Daan Pape <daan@dptechnics.com>
 * @author Arnoud Devoogdt <arnoud@dptechnics.com>
 * @brief This code connects to the BlueCherry platform.
 * @version 1.4.0
 * @date 2026-09-15
 * @copyright Copyright (c) 2025-2026 DPTechnics BV <info@dptechnics.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.
 */

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_system.h>
#include <sdkconfig.h>
#include <nvs_flash.h>
#include <inttypes.h>
#include <esp_log.h>
#include <string.h>
#include <stdio.h>

#include "bluecherry.h"
#include "wifi.h"

/**
 * @brief The BlueCherry device type for this application. Required for ZTP.
 *
 * Replace this with the device type issued to your organization on the BlueCherry platform. It is
 * eight characters and forms the first half of this device's identity, so provisioning fails if it
 * does not name a type that exists.
 */
#define BLUECHERRY_DEVICE_TYPE "walter01"

/**
 * @brief How much room to give messages that are waiting to be published.
 */
#define PUBLISH_BUFFER_SIZE 8192

/**
 * @brief The logging tag for this application.
 */
static const char* TAG = "EXAMPLE";

/**
 * @brief The device certificate from the symbol section of the firmware.
 *
 * Only used by the pre-provisioned path, which is the uncommon one. See app_main.
 */
extern const char devcert[] asm("_binary_devcert_pem_start");

/**
 * @brief The device key from the symbol section of the firmware.
 */
extern const char devkey[] asm("_binary_devkey_pem_start");

/**
 * @brief Initialize NVS.
 *
 * Needed by the WiFi stack, and by the credential storage below.
 *
 * @return ESP_OK on success.
 */
static esp_err_t nvs_init()
{
  esp_err_t ret = nvs_flash_init();
  if(ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    if((ret = nvs_flash_erase()) != ESP_OK) {
      ESP_LOGE(TAG, "Could not erase NVS: %s", esp_err_to_name(ret));
      return ret;
    }
    ret = nvs_flash_init();
  }

  if(ret != ESP_OK) {
    ESP_LOGE(TAG, "Could not init NVS: %s", esp_err_to_name(ret));
    return ret;
  }

  ESP_LOGI(TAG, "Initialized non-volatile storage");
  return ESP_OK;
}

/**
 * @brief Handle an incoming MQTT message.
 *
 * This function handles an incoming MQTT message.
 *
 * @param topic The topic as the topic index.
 * @param len The length of the incoming data.
 * @param data The incoming data buffer.
 * @param args A NULL pointer.
 */
static void bluecherry_msg_handler(uint8_t topic, uint16_t len, const uint8_t* data, void* args)
{
  ESP_LOGI(TAG, "Received MQTT message of length %d on topic %02X: %.*s", len, topic, len, data);
}

/**
 * @brief Watch this device's topic map.
 *
 * A topic byte is only a number until the cloud maps it to an MQTT topic. This
 * handler prints the mapping behind each one, and is also where the answer to
 * bluecherry_topic_map_set() and _delete() arrives.
 *
 * Nothing is cached by the library: an entry is valid only for this call, so
 * copy anything worth keeping. ACCEPTED means the cloud took a set or delete;
 * the ENTRY reporting the change is what says it is live. A change made in the
 * cloud arrives as the same ENTRY, with no request behind it.
 */
static void bluecherry_topic_map_handler(bluecherry_topic_map_ev_t event,
                                         const bluecherry_topic_map_info_t* info, void* args)
{
  switch(event) {
  case BLUECHERRY_TOPIC_MAP_EV_ACCEPTED:
    ESP_LOGI(TAG, "Topic map write for 0x%02X accepted", info->topic);
    break;

  case BLUECHERRY_TOPIC_MAP_EV_REJECTED:
    ESP_LOGW(TAG, "Topic map request refused for topic 0x%02X, reason %d", info->topic, info->err);
    break;

  case BLUECHERRY_TOPIC_MAP_EV_ENTRY:
    ESP_LOGI(TAG, "Topic 0x%02X %s %s%s (cause %d)", info->entry->topic,
             info->entry->dir == BLUECHERRY_TOPIC_DIR_UPLINK ? "UP" : "DOWN", info->entry->suffix,
             info->entry->readonly ? " [device type, read-only]" : "", info->cause);
    break;

  case BLUECHERRY_TOPIC_MAP_EV_LIST_DONE:
    ESP_LOGI(TAG, "Topic map listing complete, %u mapping(s)", info->count);
    break;

  case BLUECHERRY_TOPIC_MAP_EV_COMMIT_FAILED:
    ESP_LOGE(TAG, "Topic map write for 0x%02X did not commit, reason %d", info->topic, info->err);
    break;
  }
}

/**
 * @brief Take the OTA decisions in the application instead of leaving them to the library.
 *
 * Exactly three events carry a decision, and this handler takes all of them explicitly so that
 * the calls involved are visible and easy to move:
 *
 *  - DOWNLOAD_AVAILABLE: bluecherry_ota_start_download() accepts the update. Returning true
 *    means "I have this", so nothing is downloaded until that call is made - which is where you
 *    would instead stash the offer and start it at 3am, on battery power, or once your machine
 *    is idle.
 *  - DOWNLOAD_COMPLETE: the new image is downloaded and verified, but nothing boots it until
 *    bluecherry_ota_install() is called. Returning true means the library will neither install
 *    it nor restart for you.
 *  - FIRSTBOOT: the new firmware is running for the first time, and the bootloader rolls it back
 *    on the next restart unless bluecherry_ota_mark_valid() is called.
 *
 * Returning false from any of them hands that decision back: the library downloads on offer,
 * installs and restarts once the download is complete, and marks new firmware valid on its first
 * boot, which is what happens when no handler is registered at all. That is the point of the
 * return value - a handler that only logs is free to return false everywhere and change nothing.
 * The other three events are notifications and the return is ignored.
 *
 * @param event The OTA event.
 * @param info Details for the event, valid only for this call.
 * @param args A NULL pointer.
 *
 * @return True when this handler took the decision the event carries.
 */
static bool bluecherry_ota_handler(bluecherry_ota_event_t event, const bluecherry_ota_info_t* info,
                                   void* args)
{
  switch(event) {
  case BLUECHERRY_OTA_EVENT_DOWNLOAD_AVAILABLE:
    ESP_LOGI(TAG, "Firmware v%d available, %lu bytes - accepting", info->version, info->size);
    /* Accept now, or call this later to update when it suits you - there is no deadline, and
     * this event repeats on every reconnect while the update is on offer. */
    bluecherry_ota_start_download();
    return true;

  case BLUECHERRY_OTA_EVENT_DOWNLOAD_STARTED:
    ESP_LOGI(TAG, "Firmware v%d downloading", info->version);
    break;

  case BLUECHERRY_OTA_EVENT_DOWNLOAD_PROGRESS:
    ESP_LOGI(TAG, "OTA progress %lu / %lu bytes (%lu%%)", info->bytes_received, info->size,
             info->size ? (unsigned long) ((uint64_t) info->bytes_received * 100 / info->size)
                        : 0UL);
    break;

  case BLUECHERRY_OTA_EVENT_DOWNLOAD_COMPLETE:
    ESP_LOGI(TAG, "Firmware v%d downloaded - installing and restarting", info->version);
    /* Both calls can wait if a restart now would interrupt your application. The device keeps
     * running this firmware until then. */
    bluecherry_ota_install();
    esp_restart();
    return true;

  case BLUECHERRY_OTA_EVENT_FIRSTBOOT:
    ESP_LOGI(TAG, "First boot of new firmware - keeping it");
    /* Or confirm it later, once your application has checked it works, or call
     * bluecherry_ota_rollback_restart() to return to the previous firmware. */
    bluecherry_ota_mark_valid();
    return true;

  case BLUECHERRY_OTA_EVENT_FAILED:
    ESP_LOGE(TAG, "Firmware v%d failed, error code %u", info->version, info->error_code);
    break;
  }

  return false;
}

/**
 * @brief Report what the BlueCherry connection is doing.
 *
 * Must not block. Wait for BLUECHERRY_STATE_IDLE to know it is safe to sleep.
 *
 * @param state The state just entered.
 * @param args A NULL pointer.
 */
static void bluecherry_state_handler(bluecherry_state state, void* args)
{
  /* Set while there is no connection, so the first state after one comes up is
   * known to start a new connection. */
  static bool connecting = false;

  switch(state) {
  case BLUECHERRY_STATE_AWAIT_CONNECTION:
    ESP_LOGI(TAG, "BlueCherry connecting...");
    connecting = true;
    break;

  case BLUECHERRY_STATE_IDLE:
    ESP_LOGI(TAG, "BlueCherry synchronized");
    break;

  default:
    break;
  }

  /* The cloud only reports changes to the topic map within a connection in which
   * this device has made a topic map request, so list the map at the start of
   * every connection. The answer arrives in bluecherry_topic_map_handler. Every
   * state from IDLE on means the connection is up. */
  if(connecting && state >= BLUECHERRY_STATE_IDLE) {
    connecting = false;
    if(bluecherry_topic_map_get(BLUECHERRY_TOPIC_SEL_ALL, 0) != ESP_OK) {
      ESP_LOGW(TAG, "Could not request the topic map");
    }
  }
}

/**
 * @brief Read a string from NVS.
 *
 * This function reads a string value from NVS under the specified key.
 *
 * @param key The key under which the string is stored.
 * @param buf The buffer to store the read string.
 * @param len The length of the buffer.
 *
 * @return ESP_OK on success.
 */
static esp_err_t nvs_read_str(const char* key, char* buf, size_t len)
{
  nvs_handle_t handle;
  esp_err_t err = nvs_open("bcztp_store", NVS_READONLY, &handle);
  if(err != ESP_OK)
    return err;

  err = nvs_get_str(handle, key, buf, &len);
  nvs_close(handle);
  return err;
}

/**
 * @brief Store and retrieve the credentials that zero-touch provisioning issues.
 *
 * ZTP hands the device a certificate and a private key the first time it runs, and expects to
 * get them back on every boot after that. Where they live is up to the application - NVS here.
 * Returning NULL when reading is how the library is told there are none yet, which is what
 * makes it provision.
 *
 * @param read True when reading, false when writing.
 * @param secure True when handling the private key, false when handling the certificate.
 * @param args Optional user arguments, key or certificate passed as arguments when writing.
 *
 * @return The certificate or key when reading, NULL when writing.
 */
static const char* bluecherry_ztp_bio_handler(bool read, bool secure, void* args)
{
  static char devcert[4096];
  static char devkey[4096];

  const char* keyname = secure ? "bcztp_key" : "bcztp_cert";

  if(read) {
    esp_err_t err =
        nvs_read_str(keyname, secure ? devkey : devcert, secure ? sizeof(devkey) : sizeof(devcert));
    if(err != ESP_OK) {
      ESP_LOGD(TAG, "No %s found in NVS (err=0x%x)", keyname, err);
      return NULL;
    }
    return secure ? devkey : devcert;
  } else {
    const char* data = (const char*) args;

    nvs_handle_t handle;
    ESP_ERROR_CHECK(nvs_open("bcztp_store", NVS_READWRITE, &handle));

    if(data == NULL) {
      ESP_LOGW(TAG, "Erasing %s from NVS", keyname);
      nvs_erase_key(handle, keyname);
      nvs_commit(handle);
      nvs_close(handle);
      return NULL;
    }

    ESP_ERROR_CHECK(nvs_set_str(handle, keyname, data));
    ESP_ERROR_CHECK(nvs_commit(handle));
    nvs_close(handle);

    ESP_LOGI(TAG, "Stored %s in NVS", keyname);
    return data;
  }
}

/**
 * @brief The main application entrypoint.
 */
void app_main(void)
{
  ESP_LOGI(TAG, "BlueCherry example V1.4.0");

  ESP_ERROR_CHECK(nvs_init());
  ESP_ERROR_CHECK(wifi_init());

  /* Optional. This handler takes the OTA decisions itself so the calls are visible; drop it, or
   * return false from those events, and the library downloads an offered update, installs it and
   * reboots into it on its own. Registered before init, which can raise OTA events itself. */
  bluecherry_set_ota_handler(bluecherry_ota_handler, NULL);

  /* Optional. Poll bluecherry_get_state() instead if you prefer. */
  bluecherry_set_state_handler(bluecherry_state_handler, NULL);

  /* Optional. Without it incoming messages are acknowledged and discarded. */
  bluecherry_set_msg_handler(bluecherry_msg_handler, NULL);

  /* Required to use the topic map calls at all: unlike OTA there is no library
   * default, so without a handler their answers are parsed and dropped. */
  bluecherry_set_topic_map_handler(bluecherry_topic_map_handler, NULL);

  /* Messages waiting to be published are kept here. Put it wherever you like and make it as
   * large as you need - a static array below, or pass NULL to let the library allocate it. */
  static uint8_t publish_buffer[PUBLISH_BUFFER_SIZE];
  bluecherry_publish_buffer_t pub = { .buffer = publish_buffer, .size = PUBLISH_BUFFER_SIZE };

  /* Zero-touch provisioning: the device asks BlueCherry for its own certificate and key on first
   * boot, using its MAC address to find the Walter it was registered as. Nothing to flash and
   * nothing to keep track of - the handler above stores what it is issued.
   *
   * Publishing schedules a synchronisation on its own; the 10 seconds is how long we go without
   * one when there is nothing to send. Call bluecherry_set_auto_sync() at any time to change it.
   * Passing 0 turns it off entirely: nothing is then sent or received until bluecherry_sync()
   * is called. */
  ESP_ERROR_CHECK(bluecherry_init_ztp(bluecherry_ztp_bio_handler, NULL, BLUECHERRY_DEVICE_TYPE, 10,
                                      30, &pub));

  /* The alternative, for the rare device whose credentials were issued by hand and built into
   * the firmware. ZTP above is the normal way. */
  // ESP_ERROR_CHECK(bluecherry_init(devcert, devkey, 10, 30, &pub));

  /* The topic map is listed by bluecherry_state_handler above, at the start of
   * every connection, and printed by bluecherry_topic_map_handler.
   *
   * Mappings marked read-only come from the device type and are shared by every
   * device of it. The rest belong to this device, and can be changed from here:
   *
   *   bluecherry_topic_map_set(BLUECHERRY_TOPIC_DIR_UPLINK, 0x85, "/sensors/humidity");
   *   bluecherry_topic_map_delete(BLUECHERRY_TOPIC_DIR_UPLINK, 0x85);
   *
   * Uplink and downlink are separate maps, so using one byte both ways is two
   * calls, one per direction. */

  uint32_t counter = 0;

  while(true) {
    char payload[40];
    snprintf(payload, sizeof(payload), "Hello from ESP-IDF! %lu", ++counter);

    ESP_LOGI(TAG, "Publishing %s", payload);

    /* Queue the payload for publishing to the BlueCherry cloud. */
    esp_err_t err = bluecherry_publish(0x84, strlen(payload), (const uint8_t*) payload);
    if(err != ESP_OK) {
      ESP_LOGW(TAG, "Publish rejected, queue full: %s", esp_err_to_name(err));
    }

    /* Schedules a synchronisation: upload what is queued, download whatever the cloud has.
     * Redundant here because auto-sync is on, but with it off this is the only thing that
     * sends the message above. */
    // bluecherry_sync();

    vTaskDelay(pdMS_TO_TICKS(15000));
    if(esp_task_wdt_status(NULL) == ESP_OK) {
      esp_task_wdt_reset();
    }
  }
}
