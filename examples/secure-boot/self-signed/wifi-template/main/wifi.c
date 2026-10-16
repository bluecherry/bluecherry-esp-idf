/**
 * @file wifi.c
 * @author Daan Pape <daan@dptechnics.com>
 * @author Arnoud Devoogdt <arnoud@dptechnics.com>
 * @brief WiFi station bring-up for the BlueCherry example.
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
#include <freertos/event_groups.h>
#include <esp_event.h>
#include <esp_netif.h>
#include <esp_wifi.h>
#include <inttypes.h>
#include <esp_log.h>
#include <string.h>

#include "wifi.h"

/**
 * @brief The logging tag for the network bring-up.
 */
static const char* TAG = "WIFI";

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

esp_err_t wifi_init(void)
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
  wifi_config.sta.threshold.authmode = WIFI_AUTH_MODE;
  strncpy((char*) wifi_config.sta.ssid, WIFI_SSID, sizeof(wifi_config.sta.ssid));
  strncpy((char*) wifi_config.sta.password, WIFI_PASSWORD, sizeof(wifi_config.sta.password));

  /* Scan every channel and take the strongest match. The default is to take the first access
   * point answering to the SSID, which on a network with more than one of them can land you on
   * a distant one and make everything after this look slow. */
  wifi_config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
  wifi_config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;

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
