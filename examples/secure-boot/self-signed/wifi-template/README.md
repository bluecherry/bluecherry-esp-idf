# BlueCherry WiFi template with self-signed OTA updates

## Introduction

The [wifi-template](../../../wifi-template) application, built so that devices only install
firmware updates signed with your own key. It demonstrates:

 - Zero-touch provisioning
 - MQTT publish
 - MQTT subscribe
 - OTA updates with signed firmware

It is meant to be used in two stages. The default build is for **development**: devices refuse
unsigned updates, but nothing is burned into eFuse, so a board can always be erased and reused.
**Before your first release** you turn on hardware secure boot, which also protects devices
against someone with physical access, permanently.

## What you can and cannot do

| | Default build (development) | Hardware secure boot (release) |
|---|---|---|
| OTA update signed with your key | Installed | Installed |
| OTA update unsigned, or signed with another key | Refused | Refused |
| Firmware flashed by cable | Anything, signed or not | Only signed firmware boots |
| Checked by the chip at every boot | Nothing | The bootloader and the app |
| Flash contents, including the credentials ZTP stores | Readable by anyone with a cable | Encrypted |
| JTAG debugging | Available | Disabled |
| Return the chip to stock | Any time, by erasing the flash | Never: the eFuses stay burned |

A refused update leaves the device running its current firmware, and BlueCherry receives OTA
error 7.

In the default build, a device trusts the key that signed the firmware it is running. The firmware
you flash first therefore decides which key every later update has to carry. Flash unsigned
firmware by cable and no key is trusted any more: every update is refused until signed firmware is
flashed again.

## Hardware

Any ESP32-S3 with at least 4 MB of flash. The target is pinned to `esp32s3` in
`sdkconfig.defaults`.

## Layout

```
main/
  main.c              the template's application, plus a report of the security state at boot
  wifi.c              network bring-up, nothing BlueCherry specific
  includes/wifi.h     WiFi credentials - edit this before building
  credentials/        device certificate and key, only for the pre-provisioned path
sdkconfig.defaults    the signing configuration, and hardware secure boot commented out below it
partitions.csv        two OTA slots, laid out so hardware secure boot fits without changes
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
I (...) EXAMPLE: Hardware secure boot: disabled
I (...) EXAMPLE: Flash encryption: disabled
I (...) EXAMPLE: OTA updates: only installed when signed with a trusted key
I (...) EXAMPLE: Running image in app0, SHA-256 <64 hex digits>
```

The first two lines read the chip's eFuses, which the default build leaves alone. The third is what
the firmware enforces, eFuses or not. The SHA-256 is the image's fingerprint, see
[The fingerprint](#the-fingerprint).

## The signing key

`secure_boot_signing_key.pem` is an RSA-3072 private key. Git ignores it. Keep a backup somewhere
safe: without it, devices in the field can no longer be updated over the air.

The key belongs to the firmware, not to a device: every device running firmware signed with it
accepts only updates signed with it. Hardware secure boot uses the same key.

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
RSA-PSS signatures are randomised.

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

## Before your first release: hardware secure boot

The default build stops unsigned updates, not someone with a cable. Before devices leave your
hands, turn on hardware secure boot: the chip then verifies the bootloader, and the bootloader the
app, on every boot. Flash encryption keeps the flash, and the credentials in it, unreadable, and
JTAG is disabled. Signing and releasing updates stay exactly as above, with the same key.

> **This is permanent.** The first boot burns eFuses that can never be cleared. From then on the
> chip only boots firmware signed with your `secure_boot_signing_key.pem`. Lose the key and the
> chip can never take new firmware again.

A device gets hardware secure boot when it is first flashed, never through an update: the
bootloader enables it, and the bootloader cannot be updated over the air. Devices that ship
without it stay without it.

### Turning it on

Try it on a board you can spare first. None of this happens by accident: the settings sit at the
bottom of `sdkconfig.defaults`, commented out, and `partitions.csv` already has room for them.
With the signing key generated (see [Getting started](#getting-started)), in this directory:

1. Uncomment the eight `CONFIG_` lines of the hardware secure boot block in `sdkconfig.defaults`.
2. Build from a fresh configuration, check that it took, and flash:
   ```bash
   rm -f sdkconfig
   idf.py fullclean
   idf.py build
   grep "CONFIG_SECURE_BOOT=y" sdkconfig
   idf.py flash monitor
   ```

The `sdkconfig` has to go first, because an existing one overrides `sdkconfig.defaults`. The `grep`
must print the line before you flash, or the change did not take effect.

On the first boot the bootloader enables secure boot, encrypts the flash in place and restarts. It
takes a moment longer than usual: **do not power the device off while it runs.** The application
then reports `Hardware secure boot: enabled` and `Flash encryption: development`.

Keep building that product's updates with this configuration. The `sdkconfig` you just made keeps
it. An update built without it does not know NVS is encrypted, and cannot read what is stored
there.

### Development mode, then Release mode

The block turns flash encryption on in **Development mode**. The board can still be reflashed by
cable, with `idf.py encrypted-app-flash`: a plain `idf.py flash` writes plaintext the chip can no
longer boot. Use it to try your release on a board you can spare.

For the devices you ship, switch to **Release mode**: in that block, replace
`CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y` with
`CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y`, and remove
`CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC=y`. Reflashing by cable is then impossible for good,
and OTA is the only way to update.

Espressif's
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
  receives OTA error 7. The image is unsigned, or signed with a different key than the one the
  device trusts.

## Licence

The library is published under the 'GNU LESSER GENERAL PUBLIC LICENSE'. The full license text can
be read [here](LICENSE.md).
