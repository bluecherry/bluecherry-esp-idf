/**
 * @file main.c
 * @author Daan Pape (daan@dptechnics.com)
 * @brief This code connects to the BlueCherry platform.
 * @version 0.1
 * @date 2025-07-14
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

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <esp_log.h>
#include <sdkconfig.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_chip_info.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <esp_wifi.h>
#include <esp_event.h>

#include "bluecherry.h"
#include "credentials/wifi.h"

/**
 * @brief The logging tag for this BlueCherry module.
 */
static const char* TAG = "BlueCherry";

/**
 * @brief The network interface used to connect to the WiFi.
 */
static esp_netif_t* netif = NULL;

/**
 * @brief The event handler for IP events.
 */
static esp_event_handler_instance_t ip_evh;

/**
 * @brief The event handler for WiFi events.
 */
static esp_event_handler_instance_t wifi_evh;

/**
 * @brief The WiFi event group handle.
 */
static EventGroupHandle_t wifi_ev_group = NULL;

/**
 * @brief The device certificate from the symbol section of the firmware.
 */
extern const char devcert[] asm("_binary_devcert_pem_start");

/**
 * @brief The device key from the symbol section of the firmware.
 */
extern const char devkey[] asm("_binary_devkey_pem_start");

/**
 * @brief Handle IP events.
 *
 * This function is called when an IP stack event occurs.
 *
 * @param arg A NULL pointer.
 * @param event_base Base event of type IP_EVENT.
 * @param event_id The specific event id.
 * @param event_data Event specific data.
 *
 * @return None.
 */
static void ip_ev_cb(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
  ESP_LOGI(TAG, "Handling IP event, event code 0x%" PRIx32, event_id);
  switch(event_id) {
  case IP_EVENT_STA_GOT_IP:
    ip_event_got_ip_t* event_ip = (ip_event_got_ip_t*) event_data;
    ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event_ip->ip_info.ip));
    xEventGroupSetBits(wifi_ev_group, BIT0);
    break;

  case IP_EVENT_STA_LOST_IP:
    ESP_LOGI(TAG, "Lost IP");
    break;

  case IP_EVENT_GOT_IP6:
    ip_event_got_ip6_t* event_ip6 = (ip_event_got_ip6_t*) event_data;
    ESP_LOGI(TAG, "Got IPv6: " IPV6STR, IPV62STR(event_ip6->ip6_info.ip));
    xEventGroupSetBits(wifi_ev_group, BIT1);
    break;

  default:
    ESP_LOGI(TAG, "IP event not handled");
    break;
  }
}

/**
 * @brief Handle WiFi events.
 *
 * This function is called when a WiFi event occurs.
 *
 * @param arg A NULL pointer.
 * @param event_base Base event of type WIFI_EVENT.
 * @param event_id The specific event id.
 * @param event_data Event specific data.
 *
 * @return None.
 */
static void wifi_ev_cb(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
  ESP_LOGI(TAG, "Handling Wi-Fi event, event code 0x%" PRIx32, event_id);

  switch(event_id) {
  case WIFI_EVENT_WIFI_READY:
    ESP_LOGI(TAG, "Wi-Fi ready");
    break;

  case WIFI_EVENT_SCAN_DONE:
    ESP_LOGI(TAG, "Wi-Fi scan done");
    break;

  case WIFI_EVENT_STA_START:
    ESP_LOGI(TAG, "Wi-Fi started, connecting to AP...");
    esp_wifi_connect();
    break;

  case WIFI_EVENT_STA_STOP:
    ESP_LOGI(TAG, "Wi-Fi stopped");
    break;

  case WIFI_EVENT_STA_CONNECTED:
    ESP_LOGI(TAG, "Wi-Fi connected");
    break;

  case WIFI_EVENT_STA_DISCONNECTED:
    ESP_LOGI(TAG, "Wi-Fi disconnected");
    ESP_LOGI(TAG, "Retrying to connect to Wi-Fi network...");
    esp_wifi_connect();
    break;

  case WIFI_EVENT_STA_AUTHMODE_CHANGE:
    ESP_LOGI(TAG, "Wi-Fi authmode changed");
    break;

  default:
    ESP_LOGI(TAG, "Wi-Fi event not handled");
    break;
  }
}

/**
 * @brief Initialize NVS.
 *
 * This function will initialize non-volatile storage memory.
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
 * @brief Initialize the WiFi as a station.
 *
 * This function will initialize the WiFi adapter and connect to the WiFi infrastructure.
 *
 * @param ssid The SSID to connect to.
 * @param password The password to use.
 * @param auth_mode The authentication method to use.
 *
 * @return ESP_OK on success.
 */
static esp_err_t wifi_init(const char* ssid, const char* password, wifi_auth_mode_t auth_mode)
{
  esp_err_t ret = esp_netif_init();
  if(ret != ESP_OK) {
    ESP_LOGE(TAG, "Could not init the TCP/IP stack: %s", esp_err_to_name(ret));
    return ret;
  }

  wifi_ev_group = xEventGroupCreate();
  if(wifi_ev_group == NULL) {
    ESP_LOGE(TAG, "Failed to create WiFi event group");
    return ESP_FAIL;
  }

  if((ret = esp_event_loop_create_default()) != ESP_OK) {
    ESP_LOGE(TAG, "Could not init the default event loop: %s", esp_err_to_name(ret));
    return ret;
  }

  if((ret = esp_wifi_set_default_wifi_sta_handlers()) != ESP_OK) {
    ESP_LOGE(TAG, "Could not set default WiFi STA event handlers: %s", esp_err_to_name(ret));
    return ret;
  }

  /* Create the WiFi station network interface */
  netif = esp_netif_create_default_wifi_sta();
  if(netif == NULL) {
    ESP_LOGE(TAG, "Failed to create WiFi STA interface");
    return ESP_FAIL;
  }

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  if((ret = esp_wifi_init(&cfg)) != ESP_OK) {
    ESP_LOGE(TAG, "Could not initialize the WiFi adapter: %s", esp_err_to_name(ret));
    return ret;
  }

  ret = esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_ev_cb, NULL,
                                            &wifi_evh);
  if(ret != ESP_OK) {
    ESP_LOGE(TAG, "Could not set WiFi event handler: %s", esp_err_to_name(ret));
    return ret;
  }

  ret = esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, &ip_ev_cb, NULL, &ip_evh);
  if(ret != ESP_OK) {
    ESP_LOGE(TAG, "Could not set IP event handler: %s", esp_err_to_name(ret));
    return ret;
  }

  wifi_config_t wifi_config = { 0 };
  wifi_config.sta.threshold.authmode = auth_mode;
  strncpy((char*) wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
  strncpy((char*) wifi_config.sta.password, password, sizeof(wifi_config.sta.password));

  if((ret = esp_wifi_set_ps(WIFI_PS_NONE)) != ESP_OK) {
    ESP_LOGE(TAG, "Could not set WiFi power save mode to NONE: %s", esp_err_to_name(ret));
    return ret;
  }

  if((ret = esp_wifi_set_storage(WIFI_STORAGE_RAM)) != ESP_OK) {
    ESP_LOGE(TAG, "Could not set WiFi storage to RAM mode: %s", esp_err_to_name(ret));
    return ret;
  }

  if((ret = esp_wifi_set_mode(WIFI_MODE_STA)) != ESP_OK) {
    ESP_LOGE(TAG, "Could net configure adapter in station mode: %s", esp_err_to_name(ret));
    return ret;
  }

  if((ret = esp_wifi_set_config(WIFI_IF_STA, &wifi_config)) != ESP_OK) {
    ESP_LOGE(TAG, "Could not apply the station configuration: %s", esp_err_to_name(ret));
    return ret;
  }

  ESP_LOGI(TAG, "Connecting to Wi-Fi network: %s", wifi_config.sta.ssid);
  if((ret = esp_wifi_start()) != ESP_OK) {
    ESP_LOGE(TAG, "Could not start the WiFi adapter: %s", esp_err_to_name(ret));
    return ret;
  }

  EventBits_t bits =
      xEventGroupWaitBits(wifi_ev_group, BIT0 | BIT1, pdFALSE, pdFALSE, portMAX_DELAY);

  if(bits & BIT0) {
    ESP_LOGI(TAG, "Connected to Wi-Fi network: %s", wifi_config.sta.ssid);
    return ESP_OK;
  } else if(bits & BIT1) {
    ESP_LOGE(TAG, "Failed to connect to Wi-Fi network: %s", wifi_config.sta.ssid);
    return ESP_FAIL;
  }

  ESP_LOGE(TAG, "Unknown error while connecting to WiFi");
  return ESP_FAIL;
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

static const char* bluecherry_ztp_bio_handler(bool read, bool secure, void* args) {
    if (!read) return NULL;
    return secure ? devkey : devcert;
}

/**
 * @brief The main application entrypoint.
 */
void app_main(void)
{
  ESP_LOGI(TAG, "BlueCherry example V1.2.0");

  ESP_ERROR_CHECK(nvs_init());
  ESP_ERROR_CHECK(wifi_init(WIFI_SSID, WIFI_PASSWORD, WIFI_AUTH_MODE));
  ESP_ERROR_CHECK(bluecherry_init_ztp(bluecherry_ztp_bio_handler, NULL, "walter01", bluecherry_msg_handler, NULL, true, 30));

  while(true) {
    ESP_LOGI(TAG, "Publishing message");
    bluecherry_publish(0x84, strlen("Test message") + 1, (const uint8_t*) "Test message");
    vTaskDelay(pdMS_TO_TICKS(5000));
    if(esp_task_wdt_status(NULL) == ESP_OK) {
      esp_task_wdt_reset();
    }
  }
}
