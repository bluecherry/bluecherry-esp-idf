# BlueCherry WiFi template with self-signed OTA updates

## Introduction

The [wifi-template](../../../wifi-template) application, built so that devices only install
firmware updates signed with your own key. It demonstrates:

 - Zero-touch provisioning
 - MQTT publish
 - MQTT subscribe
 - OTA updates with signed firmware

## What it protects

Every OTA image is checked before it is installed. An image that is unsigned, or signed with a
different key, is refused: the device keeps running its current firmware and reports the failed
update to BlueCherry.

This uses ESP-IDF's *Require signed app images* option with the Secure Boot V2 signature scheme
(RSA-3072), but not hardware secure boot. **Nothing is burned into eFuse**, so a board can be erased
and reused at any time.

What it does not protect against is someone with physical access: the bootloader does not check
the app at boot, and anyone with a cable can still flash anything. That takes hardware secure boot,
which this example can be switched to on purpose, see [Hardware secure boot](#hardware-secure-boot).

A device trusts the key that signed the firmware it is running. The firmware you first flash
therefore decides which key every later update has to carry.

## Hardware

Any ESP32-S3 with at least 4 MB of flash. The target is pinned to `esp32s3` in
`sdkconfig.defaults`.

## Layout

```
main/
  main.c              the template's application, plus a report of the image hash at boot
  wifi.c              network bring-up, nothing BlueCherry specific
  includes/wifi.h     WiFi credentials - edit this before building
  credentials/        device certificate and key, only for the pre-provisioned path
sdkconfig.defaults    the signing configuration, at the bottom

sdkconfig.hardware-secure-boot        opt-in only, burns eFuses: see Hardware secure boot
partitions-hardware-secure-boot.csv   the partition table that goes with it
```

## Getting started

1. Fill in `WIFI_SSID` and `WIFI_PASSWORD` in `main/includes/wifi.h`.
2. Set `BLUECHERRY_DEVICE_TYPE` in `main/main.c` to your device type.
3. Register the device on the BlueCherry platform and set it to WAIT-PROVISION.
4. In this directory, generate the signing key and build:
   ```bash
   idf.py set-target esp32s3
   idf.py secure-generate-signing-key --version 2 --scheme rsa3072 secure_boot_signing_key.pem
   idf.py reconfigure
   idf.py build flash monitor
   ```

`reconfigure` is needed once, after the key is generated: generating it configures the project
while the key does not exist yet, and that configuration fails every build until it is redone.

At boot the application reports its state:

```
I (...) EXAMPLE: Secure boot: DISABLED
I (...) EXAMPLE: Flash encryption: DISABLED
I (...) EXAMPLE: Running image in app0, SHA-256 <64 hex digits>
```

Both read DISABLED on purpose: signatures are checked without hardware secure boot. The SHA-256 is
the image's fingerprint, see [The fingerprint](#the-fingerprint).

## The signing key

`secure_boot_signing_key.pem` is an RSA-3072 private key. Git ignores it. Keep a backup somewhere
safe: without it, devices in the field can no longer be updated over the air.

The key belongs to the firmware, not to a device: every device running firmware signed with it
accepts only updates signed with it.

## Releasing an update

The build signs the firmware: upload **`build/wifi-template-self-signed.bin`** to BlueCherry. Next
to it, `wifi-template-self-signed-unsigned.bin` is the same image without a signature, and devices
refuse it.

To keep the key off the build machine, sign the unsigned image wherever the key is:

```bash
python -m espsecure sign_data --version 2 --keyfile secure_boot_signing_key.pem \
    --output signed.bin build/wifi-template-self-signed-unsigned.bin
```

The result is equivalent to the image the build signs. Only the signature bytes differ, since
RSA-PSS signatures are randomised. Mind that the firmware you flash by cable has to be signed too,
because its key is the one devices trust.

## The fingerprint

BlueCherry identifies firmware by the SHA-256 that ESP-IDF appends to the image. The platform
records it when an update is uploaded, and the device reports it for the firmware it runs.

```
| image | SHA-256 | signature block | 0xFF padding |
        ^ fingerprint             end of the 4 KB sector ^
```

In a signed image it is not the file's last 32 bytes: signing appends a 4 KB signature sector after
it, mostly `0xFF`. To print it:

```bash
idf.py fingerprint
```

This builds the project and runs `scripts/firmware_fingerprint.py` from the library on the image.
The script also works on its own, on any ESP-IDF app image, signed or not:

```bash
python managed_components/bluecherry__bluecherry/scripts/firmware_fingerprint.py build/wifi-template-self-signed.bin
```

## Hardware secure boot

Hardware secure boot adds what the default build leaves out: the chip verifies the bootloader and
the bootloader verifies the app on every boot, flash encryption keeps the flash unreadable, and NVS
encryption protects the credentials ZTP stores. It uses the same key, so firmware is signed and
released exactly as above.

> **This is permanent.** The first boot burns eFuses that can never be cleared. From then on the
> chip only boots firmware signed with your `secure_boot_signing_key.pem`, and JTAG is disabled.
> Lose the key and the chip can never take new firmware again. Try it on a board you can spare.

None of this happens by accident: `sdkconfig.hardware-secure-boot` and
`partitions-hardware-secure-boot.csv` are only used when you name them. With the signing key
generated (see [Getting started](#getting-started)), in this directory:

```bash
rm -f sdkconfig
idf.py fullclean
idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.hardware-secure-boot" build
grep "CONFIG_SECURE_BOOT=y" sdkconfig
idf.py flash monitor
```

The `sdkconfig` has to go first, because an existing one overrides both files. The `grep` must
print the line before you flash, or the opt-in did not take effect.

On the first boot the bootloader enables secure boot, encrypts the flash in place and restarts. It
takes a moment longer than usual: **do not power the device off while it runs.** The application
then reports `Secure boot: enabled` and `Flash encryption: development`.

From then on:

- **Reflash by cable with `idf.py encrypted-app-flash`.** A plain `idf.py flash` writes plaintext
  the chip can no longer boot. This is possible because flash encryption is in Development mode.
- **Keep building this product's updates with the same configuration.** The `sdkconfig` you just
  made keeps it. An update built without it looks for the partition table in the wrong place, and
  the device rolls it back.
- **For production**, replace `CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y` in
  `sdkconfig.hardware-secure-boot` with `CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y`, and remove
  `CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC=y`. Reflashing by cable is then impossible for
  good, and OTA is the only way to update.

The bootloader enables all of this and cannot be updated over the air, so a device gets hardware
secure boot when it is first flashed, never through an update. Espressif's
[Secure Boot V2](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/security/secure-boot-v2.html)
and
[flash encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/security/flash-encryption.html)
guides cover the details.

## Troubleshooting

- **"Secure Boot Signing Key secure_boot_signing_key.pem does not exist"** right after generating
  it: run `idf.py reconfigure`.
- **`idf.py secure-sign-data` or `idf.py secure-verify-signature` cannot find a file**: both run
  espsecure inside `build/`, so relative paths miss. Use `python -m espsecure` as shown above.
- **The device refuses an update**: it logs `OTA: could not set the boot partition`, and BlueCherry
  receives OTA error 7. The image is unsigned, or signed with a different key than the firmware the
  device is running.

## Licence

The library is published under the 'GNU LESSER GENERAL PUBLIC LICENSE'. The full license text can
be read [here](LICENSE.md).
