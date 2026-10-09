# Handoff: device-managed MQTT topic mappings (ESP-IDF client)

Status: **written, NOT built**. Builds are run by hand, so none of this has been
through a compiler. The changed code matches `.clang-format`. The server
counterpart is complete and tested, see `bc-lite-server/HANDOFF-topicmap.md`; its
README's "Topic maps" section is the protocol overview, diagram included.

**First thing to do: build it.** `idf.py build` in `examples/wifi-template`,
which exercises the API.

## What this adds

An application can read this device's BlueCherry topic-byte to MQTT-topic map,
manage the half the device owns, and hear about every change to it. This closes
the `README.md` roadmap item "Implement topic synchronisation".

```c
esp_err_t bluecherry_set_topic_map_handler(bluecherry_topic_map_handler_t h, void* args);
esp_err_t bluecherry_topic_map_get(bluecherry_topic_sel_t sel, uint8_t topic);
esp_err_t bluecherry_topic_map_set(bluecherry_topic_dir_t dir, uint8_t topic, const char* suffix);
esp_err_t bluecherry_topic_map_delete(bluecherry_topic_dir_t dir, uint8_t topic);
```

The handler is **required**: there is no library default, so without it the
answers are parsed and dropped.

## How each call is answered

- **get**: one `ENTRY` per mapping with cause `RETRIEVED`, then `LIST_DONE`. No
  `ACCEPTED`: the entries are the answer.
- **set / delete**: `ACCEPTED` or `REJECTED` at once. The mapping is live when an
  `ENTRY` with cause `CREATED`, `UPDATED` or `DELETED` reports it, even when the
  set changed nothing. A write the database refused ends in `COMMIT_FAILED`.
- **a change made in the cloud**: the same `ENTRY` with cause `CREATED`,
  `UPDATED` or `DELETED`, with no request behind it. The device cannot tell it
  from its own write, and does not need to.

The reserved cause `CHANGED_EXTERNALLY` (5) is gone: the server reports a cloud
change with the same causes as a device write.

## Known limitation: changes are reported only after a request

The server sends a change unasked only within a connection in which this device
has made a topic map request. Released firmware answers an unknown internal
event with an OTA `ERROR`, so the server cannot push to devices that never asked.
After a reconnect nothing is reported until the application asks again.

Documented in `bluecherry_topic_map_handler_t` and the README. The example lists
the map from its state handler on the first state after
`BLUECHERRY_STATE_AWAIT_CONNECTION`, which is the application opting in again.
The lite-v2 protocol is to lift this; the library does nothing automatically
until then.

## Decisions that shape the API

1. **The library caches nothing.** Each mapping is reported as it is parsed and
   forgotten. `bluecherry_topic_map_t.suffix` is valid **only for the duration of
   the handler call**.
2. **Uplink and downlink are separate maps with independent byte spaces.** A
   mapping is identified by `(direction, byte)`. **There is no `BOTH`.**
3. **Suffix only.** The cloud adds `<type_id>/<dev_id>`.
4. **A DELETED entry carries direction and byte with an EMPTY suffix.**
5. **Requests go out through `out_ring`, not the `pending_event` slot.** That
   slot holds one internal message and a second write destroys the first. An
   application can call these at any moment, including mid-OTA, so sharing the
   slot would lose either an OTA reply or the request. The cost is that a
   request queues behind already-queued publishes.

## Behaviour change

**`bluecherry_publish()` rejects topic `0x00` with `ESP_ERR_INVALID_ARG`.**
Publishing there never delivered a message; it let application code forge
internal protocol messages.

**`CHANGELOG.md` was deliberately NOT touched** (release time only). For the next
release's notes:

- `feat(topics)`: read and manage this device's MQTT topic map from the device,
  and hear about changes made in the cloud. `bluecherry_topic_map_get`, `_set`
  and `_delete`, answered through `bluecherry_set_topic_map_handler`. Uplink and
  downlink are separate maps, a mapping is identified by direction and topic
  byte, and a device sets only the suffix below its own id. Mappings inherited
  from the device type are read-only and win any collision. Changes are reported
  only within a connection in which the device made a topic map request.
- `fix(publish)`: `bluecherry_publish` now rejects topic `0x00` with
  `ESP_ERR_INVALID_ARG`.

## Where things live

| Location | What |
|---|---|
| `src/bluecherry.h`, `#pragma region Topic map` | Public types, enums, handler typedef. |
| `src/bluecherry.h`, `#pragma region Topic map API` | The four function declarations. |
| `src/bluecherry.h`, `_bluecherry_t` | `topic_map_handler`, `..._args`, `topic_map_count`. |
| `src/bluecherry.c`, `#pragma region TOPIC MAP` | Wire constants, parsers, request builder, suffix validator. |
| `src/bluecherry.c`, `#pragma region TOPIC MAP API` | The four public functions. |
| `src/bluecherry.c`, `_bluecherry_process_event` | Cases 18 and 19. |

`topic_map_count` is the only topic map state the library keeps: the number of
**listed** entries seen so far, reported and reset with `LIST_DONE`. A change
that arrives between two pages of a listing is not counted.

## The wire format

On topic `0x00`, authoritative description in the server repository:

```
request  [17][schema=1][op][sel][byte][suffixLen][suffix...]
status   [18][schema=1][op][stage][code][sel][byte]           set/delete only
entries  [19][schema=1][cause][more][count] then count x [dir][byte][attrs][suffixLen][suffix...]
```

`stage` 1 is accepted or refused; stage 2 is sent only for a failed write. No
sequence numbers or cursor: the cloud answers `CONTINUE` while records remain.

## What to check when you build it

1. **It has never been compiled.** Expect ordinary mistakes.
2. **Two stack buffers** sized from `BLUECHERRY_TOPIC_MAX_SUFFIX` (239):
   `_bluecherry_topic_map_report_entry` (240 bytes, on the `bc_sync` task) and
   `_bluecherry_topic_map_request` (245 bytes, **on the calling task**). The
   example now calls `bluecherry_topic_map_get` from its state handler, which
   runs on whichever task changed the state, usually `bc_sync`.
3. **`end` in `_bluecherry_topic_map_report_entry` is `unsigned` on purpose**:
   `offset + 4 + suffix_len` can exceed 255. Do not narrow it.

## Not done

- **No tests.** This component has none; verification is the example against a
  real server.
- **`walter-wifi-template` was not touched**, nor the Walter client
  (`WalterBlueCherry`), which follows later.
- **Pre-existing bug, noted not fixed:** `bluecherry_publish` accepts `len` up to
  1017 but the record header carries a **one-byte** length, so a 300-byte publish
  is mis-framed. 255 is the real per-record limit.

## Suggested smoke test against a real server

With a device whose type defines at least one topic byte:

1. Boot: the example lists the map on connecting. Expect one ENTRY per mapping,
   type ones `readonly`, then LIST_DONE with the count, and **no** ACCEPTED.
2. `bluecherry_topic_map_set(BLUECHERRY_TOPIC_DIR_UPLINK, 0x85, "/sensors/humidity")`:
   ACCEPTED, then on a later sync an ENTRY with cause CREATED. Publish on `0x85`
   and confirm it lands on `<type>/<dev>/sensors/humidity`.
3. The same set again: ENTRY with cause UPDATED.
4. A set on a byte the **device type** owns: REJECTED with
   `BLUECHERRY_TOPIC_ERR_READONLY` and nothing after it.
5. `bluecherry_topic_map_delete(BLUECHERRY_TOPIC_DIR_UPLINK, 0x85)`: ENTRY with
   cause DELETED and an empty suffix.
6. Edit a device row in the cloud: within a minute, an ENTRY with no request
   behind it.
7. Reconnect (drop WiFi), then edit in the cloud again: the example re-lists on
   connecting, so the change is reported. Without that request it would not be.
