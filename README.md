# BlueCherry library for ESP-IDF

[![Component Registry](https://components.espressif.com/components/bluecherry/bluecherry/badge.svg)](https://components.espressif.com/components/bluecherry/bluecherry)

## Overview

The [BlueCherry](https://www.bluecherry.io) platform is used to securely and efficiently connect IoT
devices to the internet. The main functions of the platform are:
 - The routing and translation of data from the device to the data consumer (end user or API)
 - The management of device firmware through secure over-the-air firmware updates
 - Notifications via email, SMS, virtual phone-call or push-notifications
 - Fleet managment through an intuitive web interface which is multi-tenant
 - Management of all stake-holders in IoT: device manufacturer, dealers, installers and end-users
 - Data storage and backup, both in the cloud as on-premise
 - Remote access of web interfaces and shells without port-forwarding, dynamic DNS or open ports
 - BYOS (Bring Your Own Stack) business logic and UI hosting for MCU or low bandwith devices
 - Customisation of the interface with your colors, logo and domain name
 - Possibility of running the platform via browser enabled native smartphone applications
 - Full separation of the UI and the API
 - Full compliance with the requirements of GDPR and CRA legislation

The above functionality list is non-exhaustive and the platform is in continuous development. 
Because the platform is built from the ground up by our engineering team in Belgium, Europe, we can 
easily handle feature requests and/or special customization if required. 

This ESP-IDF component contains the library which is used to communicate with the BlueCherry 
platform. The underlying protocol is CoAP + DTLS but on the application level it looks as if you are
talking MQTT. This makes programming your application very straigtforward while making it compatible
with LPWAN cellular.

## Getting started

### Add the dependency

Add the BlueCherry component to your project using the `idf.py` command:

```bash
idf.py add-dependency "bluecherry/bluecherry"
```

If you don't have the `idf.py` command in your path, you can also add the dependency manually to
the `idf_components.yml` file inside the `main` folder of your project:

```yml
dependencies:
  bluecherry/bluecherry:
    version: ">=1.3.4"
```

### Connect to the platform

After registering on the BlueCherry platform you will receive a device certificate. With this unique
certificate you can connect your device to the platform after you have a network connection. On the
ESP32 this is typically through WiFi, but it can also be ethernet or cellular. Connecting to the
platform is now done in only a few lines of code:

```C
void msg_handler(uint8_t topic, uint16_t len, const uint8_t *data, void *args)
{
  ESP_LOGI(TAG, "Received MQTT message of length %d on topic %02X: %.*s", len, topic, len, data);
}

/* 60 is the task watchdog timeout in seconds, 0 to leave it alone. The last argument is where
 * messages waiting to be published are kept - NULL for a buffer allocated here.
 * This call reserves buffers and starts the background sync task; it does not touch the
 * network, so it does not need to be retried when the cloud is unreachable. */
bluecherry_init(device_cert, device_key, msg_handler, NULL, true, 60, NULL);

while(true) {
  bluecherry_publish(0x84, strlen("Hello World") + 1, (const uint8_t*) "Hello World");
  vTaskDelay(pdMS_TO_TICKS(5000));
} 
```

Messages are queued, not sent: `bluecherry_publish` copies the payload into the publish buffer and
returns. `bluecherry_sync` is what talks to the cloud - the background task above calls it for
you, or you can set `auto_sync` to false and call it yourself.

Nothing is dropped to make room: a message stays in the buffer until the cloud acknowledges it, so
`bluecherry_publish` returns `ESP_ERR_NO_MEM` once the buffer is full and the connection is not
keeping up. Pass a `bluecherry_publish_buffer_t` to `bluecherry_init` to decide how much room that
is and where it comes from - PSRAM, say, or memory your application reserved itself:

```c
bluecherry_publish_buffer_t pub = { .buffer = heap_caps_malloc(8192, MALLOC_CAP_SPIRAM),
                                    .size = 8192 };
bluecherry_init(device_cert, device_key, msg_handler, NULL, true, 60, &pub);
```

With `NULL` the library allocates `CONFIG_BLUECHERRY_PUBLISH_BUFFER_SIZE` bytes itself.

If you would rather not handle certificates at all, `bluecherry_init_ztp` provisions the device
on first use and stores the issued certificate through a callback you supply.

As you see the only thing that differs from regular MQTT is that topics are represented as a single
byte instead of a string. The BlueCherry platform maps this byte to a topic string which also
contains your device id. This way you save huge amounts of data. For example:

 - Topic `0x84` -> `typeid01/lsiv983s/sensordata/temperature`

The device id is `typeid01/lsiv983s` and byte `0x84` maps to topic `/sensordata/temperature`. This
means that sending a 4B float to this topic would only consume 5 bytes (the topic byte + the 4B 
floating point) instead of 44B (the 40B of the topic string + the 4B floating point). Especially on
paid cellular plains this is a huge win.

## Licence 

The library is published under the 'GNU LESSER GENERAL PUBLIC LICENSE'. The full license text can 
be read [here](license.md).

## Over-the-air updates

Firmware updates are handled for you: when the platform offers one, the library downloads it,
verifies the written image against the hash the cloud published, and reboots into it.

An application that needs a say registers a handler with `bluecherry_set_ota_handler`. It is
told when an update becomes available, how far along the download is, and when the new image is
installed. Returning `true` from the handler means "I will decide this one" - which is how you
defer a download to a quiet hour with `bluecherry_ota_start`, or postpone the reboot until it is
safe. Returning `false`, or registering no handler at all, leaves the library to get on with it.
`bluecherry_ota_abort` gives up on an update in progress.

## Roadmap

On the roadmap for this library is the following:
 - Implement the session resumption functionality after deep sleep
 - Implement topic synchronisation.