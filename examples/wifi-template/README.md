# BlueCherry WiFi template

## Introduction

A minimal application showing how the library is used on a WiFi enabled device for bi-directional
communication. It demonstrates:

 - Zero-touch provisioning
 - MQTT publish
 - MQTT subscribe
 - OTA updates

## Layout

```
main/
  main.c            BlueCherry: provisioning, publishing, OTA and state handling
  wifi.c            network bring-up, nothing BlueCherry specific
  includes/wifi.h   WiFi credentials - edit this before building
  credentials/      device certificate and key, only for the pre-provisioned path
```

## Zero-touch provisioning

Every device has to prove who it is before the BlueCherry cloud will talk to it, which means it
needs a certificate and a private key. **Zero-touch provisioning (ZTP) obtains those
automatically**, so there is nothing to generate, flash or keep track of per device.

On first boot the library asks the BlueCherry provisioning service for credentials, identifying
itself by the device's **MAC address** - which is what links it to the device you registered on the
BlueCherry platform. The credentials it is issued are handed to your storage callback
(`bluecherry_ztp_bio_handler` in `main.c`, which puts them in NVS) and read back on every boot
after that. Provisioning therefore happens exactly once.

Two things have to be in place before it works:

 - The device is registered on the BlueCherry platform and set to **WAIT-PROVISION**.
 - `BLUECHERRY_DEVICE_TYPE` in `main.c` names your organization's device type.

Until both are true the library reports the failure and retries with a growing back-off.

### The pre-provisioned alternative

`bluecherry_init` takes a certificate and key you supply yourself, built into the firmware from
`main/credentials/`. It still works and is kept for the few devices that were set up that way, but
it means issuing and flashing credentials per device by hand. Prefer ZTP.

## Getting started

1. Fill in `WIFI_SSID` and `WIFI_PASSWORD` in `main/includes/wifi.h`.
2. Set `BLUECHERRY_DEVICE_TYPE` in `main/main.c` to your device type.
3. Register the device on the BlueCherry platform and set it to WAIT-PROVISION.
4. `idf.py build flash monitor`

## Licence

The library is published under the 'GNU LESSER GENERAL PUBLIC LICENSE'. The full license text can
be read [here](LICENSE.md).
