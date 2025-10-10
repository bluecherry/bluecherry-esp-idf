/**
 * @file wifi.h
 * @author Daan Pape (daan@dptechnics.com)
 * @brief This code connects to the BlueCherry platform.
 * @version 1.2.0
 * @date 2025-07-25
 * @copyright Copyright (c) 2025 DPTechnics BV
 *
 * This example is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This example is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this example. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef WIFI_H
#define WIFI_H

#include <esp_wifi.h>

/**
 * @brief Fill in the SSID of the WiFi network you want to connect to.
 */
#define WIFI_SSID ""

/**
 * @brief Fill in the password of the WiFi network you want to connect to.
 */
#define WIFI_PASSWORD ""

/**
 * @brief Choose the WiFi authentication method that your network uses.
 */
#define WIFI_AUTH_MODE WIFI_AUTH_WPA2_PSK

#endif