# BlueCherry library for ESP-IDF changelog

## [V1.0.0](https://github.com/bluecherry/bluecherry-esp-idf/releases/tag/v1.0.0)

### Features
 - Initial release

### Bug Fixes
- None

## [V1.1.0](https://github.com/bluecherry/bluecherry-esp-idf/releases/tag/v1.1.0)

## [V1.2.0](https://github.com/bluecherry/bluecherry-esp-idf/releases/tag/v1.2.0)

### Features

- cpp support ([#1](https://github.com/bluecherry/bluecherry-esp-idf/pull/1))
- socket and ssl reconnection upon failure (uc) ([#2](https://github.com/bluecherry/bluecherry-esp-idf/pull/2))
- feat(OTA): added OTA support and improved socket error handling ([#3](https://github.com/bluecherry/bluecherry-esp-idf/pull/3))
- feat(auto-sync): blocks until queue is ready or timeout ([#4](https://github.com/bluecherry/bluecherry-esp-idf/pull/4))

## [V1.3.0](https://github.com/bluecherry/bluecherry-esp-idf/releases/tag/v1.3.0)

### Features

- feat(ZTP): Zero Touch Provisioning integration ([#7](https://github.com/bluecherry/bluecherry-esp-idf/pull/7))

## [V1.3.1](https://github.com/bluecherry/bluecherry-esp-idf/releases/tag/v1.3.1)

### Features

- feat(Kconfig): added kconfig and removed watchdog from main thread ([#8](https://github.com/bluecherry/bluecherry-esp-idf/pull/8))

### Fixes

- fix(reconnection): improved reconnection handling for bluecherry sync ([#9](https://github.com/bluecherry/bluecherry-esp-idf/pull/9))

## [V1.3.2](https://github.com/bluecherry/bluecherry-esp-idf/releases/tag/v1.3.2)

### Fixes

- fix(CoAP): message id type uint16_t ([#11](https://github.com/bluecherry/bluecherry-esp-idf/pull/11))

## [V1.3.3](https://github.com/bluecherry/bluecherry-esp-idf/releases/tag/v1.3.3)

## [V1.3.4](https://github.com/bluecherry/bluecherry-esp-idf/releases/tag/v1.3.4)

- fix (sync): [ack offset receiving bug, more stable parsing](https://github.com/bluecherry/bluecherry-esp-idf/commit/776bd51614aef32038464e6968a842470e1e11a7)

## [V1.4.0](https://github.com/bluecherry/bluecherry-esp-idf/releases/tag/V1.4.0)

### Breaking changes

- `bluecherry_sync` takes no argument and returns once the sync task is signalled, not once the exchange completed ([#18](https://github.com/bluecherry/bluecherry-esp-idf/pull/18))
- `bluecherry_init` and `bluecherry_init_ztp` take a publish buffer argument; `auto_sync` is deprecated in favour of `bluecherry_set_auto_sync` ([#18](https://github.com/bluecherry/bluecherry-esp-idf/pull/18))
- `CONFIG_BLUECHERRY_MAX_PENDING_OUTGOING_MESSAGES` replaced by `CONFIG_BLUECHERRY_PUBLISH_BUFFER_SIZE`, bounded in bytes instead of messages ([#18](https://github.com/bluecherry/bluecherry-esp-idf/pull/18))
- `bluecherry_sync` returns `ESP_ERR_NOT_FINISHED` while provisioning or backing off ([#17](https://github.com/bluecherry/bluecherry-esp-idf/pull/17))
- minimum supported ESP-IDF is now 5.0 ([#20](https://github.com/bluecherry/bluecherry-esp-idf/pull/20))

### Features

- feat(OTA): reworked OTA protocol, the application decides when to download and when to reboot ([#16](https://github.com/bluecherry/bluecherry-esp-idf/pull/16))
- feat(sync): asynchronous sync, runtime auto-sync and a caller-owned publish buffer ([#18](https://github.com/bluecherry/bluecherry-esp-idf/pull/18))
- feat(state): `bluecherry_get_state` and `bluecherry_set_state_handler`, and `IDLE` now means safe to sleep ([#18](https://github.com/bluecherry/bluecherry-esp-idf/pull/18))
- feat(idf): ESP-IDF 6 support, and Kconfig selects the mbedtls options the library requires ([#20](https://github.com/bluecherry/bluecherry-esp-idf/pull/20))
- feat(ZTP): provisioning moved into `bluecherry_sync`, so init no longer touches the network ([#17](https://github.com/bluecherry/bluecherry-esp-idf/pull/17))
- example: wifi template restructured, network bring-up split out into `wifi.c` ([#19](https://github.com/bluecherry/bluecherry-esp-idf/pull/19))

### Fixes

- fix(ZTP): freed the shared RNG that `ssl_conf` points at, so every handshake on a freshly provisioned device ran on a zeroed generator ([#17](https://github.com/bluecherry/bluecherry-esp-idf/pull/17))
- fix(ZTP): buffer overrun on the receive path, one-past-end write in `ztp_certBuf`, and a 100ms back-off that hammered the provisioning service ([#17](https://github.com/bluecherry/bluecherry-esp-idf/pull/17))
- fix(watchdog): panic when the cloud was unreachable during the DTLS handshake ([#17](https://github.com/bluecherry/bluecherry-esp-idf/pull/17))
- fix(sync): state latched at `AWAITING_RESPONSE` after a failed exchange, rejecting every later sync ([#17](https://github.com/bluecherry/bluecherry-esp-idf/pull/17))
- fix(OTA): `pending_event` was an unguarded cross-thread slot that could be erased mid-flight ([#18](https://github.com/bluecherry/bluecherry-esp-idf/pull/18))
- fix(sync): `IDLE` was reported before a cycle had finished, so an application sleeping on it could strand unsent data ([#18](https://github.com/bluecherry/bluecherry-esp-idf/pull/18))
- fix(mbedtls): `CONFIG_MBEDTLS_SSL_PROTO_DTLS` is off by default in every ESP-IDF, producing a library that could not connect ([#20](https://github.com/bluecherry/bluecherry-esp-idf/pull/20))
- fix(example): the NUL terminator was published, showing as a stray byte on the topic ([#20](https://github.com/bluecherry/bluecherry-esp-idf/pull/20))
