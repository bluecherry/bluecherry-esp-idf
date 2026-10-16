# BlueCherry WiFi template with security features

## Introduction

This example is a simple template that demonstrates how the library can be used on a WiFi enabled
device for bi-directional communication. After registering an account on the BlueCherry platform and
applying for your own device-type you can create your device credentials and connect right away. The
example allows for:
 - MQTT publish
 - MQTT subscribe
 - OTA updates
 - Zero-Touch provisioning

### Security features

This example enables the following security features on the ESP32-S3. **All three are configured during the initial flash and activate permanently on first boot. They cannot be undone.**

| Feature | What it does | Reversible? |
|---|---|---|
| **Secure Boot V2** | Cryptographically verifies the bootloader and application on every boot. Any unsigned or incorrectly signed firmware is permanently rejected. | ❌ No — eFuse burned on first boot |
| **Flash Encryption** | Encrypts the entire flash contents (firmware, partition table, NVS) using a device-unique AES key generated on-chip. The key never leaves the device. | ❌ No — eFuse burned on first boot |
| **NVS Encryption** | Encrypts credentials and certificates stored in NVS at rest, using a key protected by flash encryption. | ❌ No — depends on flash encryption |

---

> **⚠️ Warning — read before flashing:**
> - Once flashed, the device will **only boot signed firmware** signed with your `secure_boot_signing_key.pem`. Losing this key makes it **permanently impossible** to update the firmware on any device provisioned with it.
> - In `Release` mode, UART reflashing is **permanently disabled**. The only way to update firmware after provisioning is OTA.
> - **Do not power off the device during first boot.** The ROM encrypts the entire flash in place. Interrupting this process will **permanently brick the device**.

If you are unsure about any of the above, test with `Development` mode first (see Section 3) — it preserves UART access while still validating the security setup.

---

## 1. Generate the Secure Boot V2 Signing Key

```bash
idf.py secure-generate-signing-key --version 2 --scheme rsa3072 secure_boot_signing_key.pem
```

Never commit this file to version control.

---

## 2. Partition Table

The partition table must include an `nvs_keys` partition before the first flash.

```
# Name,     Type, SubType,  Offset,   Size, Flags
nvs,        data, nvs,      0xe000,   16K,
otadata,    data, ota,      0x12000,  8K,
phy_init,   data, phy,      0x14000,  4K,
factory,    app,  factory,  0x20000,  1M,
ota_0,      app,  ota_0,    0x120000, 1M,
ota_1,      app,  ota_1,    0x220000, 1M,
nvs_key,    data, nvs_keys, 0x320000, 4K,   encrypted
```

---

## 3. menuconfig

Run `idf.py menuconfig` and apply the following settings.

### Security features

```
    App Signing Scheme (RSA)
[*] Enable hardware Secure Boot in bootloader (READ DOCS FIRST)
        Select secure boot version (Enable Secure Boot version 2)
[*] Sign binaries during build
(secure_boot_signing_key.pem) Secure boot private signing key
[*] Flash bootloader along with other artifacts when using the default flash command
[*] Enable flash encryption on boot (READ DOCS FIRST)
        Size of generated XTS-AES key (AES-128 (256-bit key))
        Enable usage mode (Development (NOT SECURE))
[*] Encrypt contents up to app image length in app partition
[*] Check Flash Encryption enabled on app startup
```

> **Warning:** `Release` mode permanently disables UART reflashing once eFuses are burned on first boot. Use `Development` for testing.

> The bootloader flash option is only needed for the initial flash. It can be disabled afterwards.

### Component config → NVS

```
[*] Enable NVS encryption
```

### Component config → NVS Security Provider

```
NVS Encryption: Key Protection Scheme (Using Flash Encryption)
```

---

## 4. Build and Flash

```bash
idf.py build
idf.py flash
```

This flashes the signed bootloader, partition table, and signed application — all in plaintext at this stage. Flash encryption activates on first boot.

---

## 5. First Boot

No intervention required. The ROM bootloader will automatically:

1. Generate a random AES-256 key and burn it into an eFuse key block — **it never leaves the chip**
2. Encrypt the entire flash in place (bootloader, partition table, application)
3. Burn the eFuses marking flash encryption as active and reboot
4. On the second boot, verify the signed images and burn `SECURE_BOOT_EN`
5. Start the application

> **Warning:** Do not power off the device during the first boot. Interrupting the flash encryption pass will permanently brick the device. The first boot takes a few extra seconds — this is expected.

---

## 6. NVS Encryption Initialisation

NVS encryption is initialised at runtime. Call `nvs_encrypted_init()` in `app_main()` before any NVS access.

---

## 7. OTA Updates

Once provisioned, all firmware updates must be **signed with the same `secure_boot_signing_key.pem`**. Unsigned or incorrectly signed images are rejected by the bootloader. Flash encryption transparently handles re-encryption of images written to the inactive OTA slot. The bootloader and partition table cannot be updated via OTA.

---

## Licence

The library is published under the 'GNU GENERAL PUBLIC LICENSE'. The full license text can be read
[here](license.md).