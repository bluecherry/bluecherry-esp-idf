/**
 * @file main.c
 * @author Daan Pape <daan@dptechnics.com>
 * @author Arnoud Devoogdt <arnoud@dptechnics.com>
 * @brief This code connects to the BlueCherry platform.
 * @version 1.3.4
 * @date 2025-10-27
 * @copyright Copyright (c) 2025 DPTechnics BV
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
#include <esp_heap_caps.h>
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
 * @brief Take the OTA decisions in the application instead of leaving them to the library.
 *
 * Exactly two events carry a decision, and this handler takes both of them explicitly so that
 * the two calls involved are visible and easy to move:
 *
 *  - AVAILABLE: bluecherry_ota_start() accepts the update. Returning true means "I have this",
 *    so nothing is downloaded until that call is made - which is where you would instead stash
 *    the offer and start it at 3am, on battery power, or once your machine is idle.
 *  - COMPLETE: the new image is installed and the boot target is already set, so the only thing
 *    left is when to restart. Returning true means the library will not do it for you.
 *
 * Returning false from either event hands that decision back: the library downloads on offer
 * and restarts on install, which is what happens when no handler is registered at all. That is
 * the point of the return value - a handler that only logs is free to return false everywhere
 * and change nothing. The other three events are notifications and the return is ignored.
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
  case BLUECHERRY_OTA_EVENT_AVAILABLE:
    ESP_LOGI(TAG, "Firmware v%d available, %lu bytes - accepting", info->version, info->size);
    /* Accept now, or call this later to update when it suits you - there is no deadline, and
     * this event repeats on every reconnect while the update is on offer. */
    bluecherry_ota_start();
    return true;

  case BLUECHERRY_OTA_EVENT_STARTED:
    ESP_LOGI(TAG, "Firmware v%d downloading", info->version);
    break;

  case BLUECHERRY_OTA_EVENT_PROGRESS:
    ESP_LOGI(TAG, "OTA progress %lu / %lu bytes (%lu%%)", info->bytes_received, info->size,
             info->size ? (unsigned long) ((uint64_t) info->bytes_received * 100 / info->size)
                        : 0UL);
    break;

  case BLUECHERRY_OTA_EVENT_COMPLETE:
    ESP_LOGI(TAG, "Firmware v%d installed - restarting", info->version);
    /* The boot target is already set, so this is only about timing. Finish what your
     * application is doing first if a restart here would interrupt it. */
    esp_restart();
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
  switch(state) {
  case BLUECHERRY_STATE_AWAIT_CONNECTION:
    ESP_LOGI(TAG, "BlueCherry connecting...");
    break;

  case BLUECHERRY_STATE_IDLE:
    ESP_LOGI(TAG, "BlueCherry synchronized");
    break;

  default:
    break;
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
  ESP_LOGI(TAG, "BlueCherry example V1.3.4");

  ESP_ERROR_CHECK(nvs_init());
  ESP_ERROR_CHECK(wifi_init());

  /* Optional. This handler takes both OTA decisions itself so the calls are visible; drop it,
   * or return false from those events, and the library downloads an offered update and reboots
   * into it on its own. */
  bluecherry_set_ota_handler(bluecherry_ota_handler, NULL);

  /* Optional. Poll bluecherry_get_state() instead if you prefer. */
  bluecherry_set_state_handler(bluecherry_state_handler, NULL);

  /* Messages waiting to be published are kept here. Put it wherever you like and make it as
   * large as you need - PSRAM below, or pass NULL instead to let the library allocate it. */
  bluecherry_publish_buffer_t pub = { .buffer =
                                          heap_caps_malloc(PUBLISH_BUFFER_SIZE, MALLOC_CAP_SPIRAM),
                                      .size = PUBLISH_BUFFER_SIZE };

  /* Zero-touch provisioning: the device asks BlueCherry for its own certificate and key on first
   * boot, using its MAC address to find the Walter it was registered as. Nothing to flash and
   * nothing to keep track of - the handler above stores what it is issued. */
  ESP_ERROR_CHECK(bluecherry_init_ztp(bluecherry_ztp_bio_handler, NULL, BLUECHERRY_DEVICE_TYPE,
                                      bluecherry_msg_handler, NULL, false, 30,
                                      pub.buffer != NULL ? &pub : NULL));

  /* The alternative, for the rare device whose credentials were issued by hand and built into
   * the firmware. ZTP above is the normal way. */
  // ESP_ERROR_CHECK(bluecherry_init(devcert, devkey, bluecherry_msg_handler, NULL, false, 30,
  //                                 pub.buffer != NULL ? &pub : NULL));

  /* Publishing schedules a synchronisation on its own; the 10 seconds is how long we go without
   * one when there is nothing to send. Call this again at any time to change the interval.
   * Passing 0 turns it off entirely: nothing is then sent or received until bluecherry_sync()
   * is called. */
  bluecherry_set_auto_sync(10);

  uint32_t counter = 0;

  while(true) {
    char payload[40];
    snprintf(payload, sizeof(payload), "Hello from ESP-IDF! %lu", ++counter);

    ESP_LOGI(TAG, "Publishing %s", payload);

    /* Queue the payload for publishing to the BlueCherry cloud*/
    esp_err_t err = bluecherry_publish(0x84, strlen(payload) + 1, (const uint8_t*) payload);
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
