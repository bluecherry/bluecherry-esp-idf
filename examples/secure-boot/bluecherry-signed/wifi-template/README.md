# BlueCherry WiFi template with BlueCherry-signed OTA updates

> **Concept, work in progress.** The BlueCherry platform does not support this flow yet. For signed
> updates that work today, see [self-signed](../../self-signed/wifi-template).

## Introduction

In the [self-signed](../../self-signed/wifi-template) example you sign firmware with your own key,
and your devices trust that key. The idea here is that BlueCherry signs instead: you only prove to
BlueCherry that an upload comes from you, and the key your devices trust never leaves BlueCherry.

The application is the [wifi-template](../../../wifi-template) one: zero-touch provisioning, MQTT
publish and subscribe, and OTA updates.

## Intended flow

1. Build the firmware.
2. `idf.py sign-ota` wraps the image in an `OTAPKG` package, signed with your ED25519 key: an SSH
   key, optionally kept on a YubiKey.
3. Upload `build/wifi-template-bluecherry-signed.ota` to BlueCherry.
4. BlueCherry checks your signature, signs the image with the device key and offers it to your
   devices.
5. A device installs it only when it is signed with that key, exactly as in self-signed.

## What works today

**The device side.** It is configured as in self-signed: ESP-IDF's *Require signed app images*,
Secure Boot V2 signatures (RSA-3072), nothing burned into eFuse. The build signs with a local
`secure_boot_signing_key.pem`, standing in for the key BlueCherry will hold.

**The upload side**, in `components/bluecherry_ota_signing/`:

- `idf.py fetch-key` copies the resident key `OTA_update` from a YubiKey (`ssh-keygen -K`) to the
  path set under *BlueCherry OTA signing* in menuconfig, `~/.ssh/id_ed25519_OTA_update` by
  default.
- `idf.py sign-ota` builds, then writes `build/wifi-template-bluecherry-signed.ota`: a 21-byte
  header (`OTAPKG`, framework, header and firmware version, lengths, secure boot version), the
  `.bin`, and an
  `ssh-keygen -Y sign` signature in the `ota-update` namespace.

## Not done yet

- BlueCherry neither accepts `.ota` packages nor signs images. Until it does, test the device side
  by uploading the signed `.bin`, as in self-signed.
- The package carries the `.bin` the build already signed with the stand-in key. In the intended
  flow it would carry the unsigned image, for BlueCherry to sign.
- The header's secure boot version is read from `CONFIG_SECURE_BOOT_V1_ENABLED` and
  `CONFIG_SECURE_BOOT_V2_ENABLED`, so it says 0 in this configuration, although the images carry
  Secure Boot V2 signatures.

## Getting started

1. Fill in `WIFI_SSID` and `WIFI_PASSWORD` in `main/includes/wifi.h`, and `BLUECHERRY_DEVICE_TYPE`
   in `main/main.c`. Register the device on the BlueCherry platform and set it to WAIT-PROVISION.
2. Create the stand-in device key and flash the firmware:
   ```bash
   idf.py set-target esp32s3
   idf.py secure-generate-signing-key --version 2 --scheme rsa3072 secure_boot_signing_key.pem
   idf.py reconfigure
   idf.py build flash monitor
   ```
3. Create your ED25519 upload key, either as a file:
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_OTA_update
   ```
   or on a YubiKey, then copy its handle into place:
   ```bash
   ssh-keygen -t ed25519-sk -O resident -O application=ssh:OTA_update
   idf.py fetch-key
   ```
4. Package an update: `idf.py sign-ota`.

`idf.py fingerprint` prints the fingerprint BlueCherry records for the image, see
[The fingerprint](../../self-signed/wifi-template/README.md#the-fingerprint).

## Licence

The library is published under the 'GNU LESSER GENERAL PUBLIC LICENSE'. The full license text can
be read [here](LICENSE.md).
