# Handoff: device-managed MQTT topic mappings (ESP-IDF client)

Status: **written, NOT built**. This environment has no ESP-IDF toolchain and no
C compiler, so none of this has been through a compiler. The server counterpart
is complete and tested, see `bc-lite-server/HANDOFF-topicmap.md`.

**First thing to do: build it.** `idf.py build` in `examples/wifi-template`,
which now exercises the new API.

## What this adds

An application can read this device's BlueCherry topic-byte to MQTT-topic map and
manage the half the device owns. This closes the `README.md` roadmap item
"Implement topic synchronisation", which has been removed from that list.

Four new public calls:

```c
esp_err_t bluecherry_set_topic_map_handler(bluecherry_topic_map_handler_t h, void* args);
esp_err_t bluecherry_topic_map_get(bluecherry_topic_sel_t sel, uint8_t topic);
esp_err_t bluecherry_topic_map_set(bluecherry_topic_dir_t dir, uint8_t topic, const char* suffix);
esp_err_t bluecherry_topic_map_delete(bluecherry_topic_dir_t dir, uint8_t topic);
```

The handler is **required**, unlike the OTA one: there is no library default to
fall back on, so without it the answers are parsed and dropped.

## The decisions that shape the API

1. **The library caches nothing.** Each mapping is reported as it is parsed and
   forgotten, so a map of any size costs the same and there is no cache to go
   stale. `bluecherry_topic_map_t.suffix` is valid **only for the duration of the
   handler call**, exactly like `msg_handler`'s data pointer.

2. **Uplink and downlink are separate maps with independent byte spaces.** A
   mapping is identified by `(direction, byte)`. **There is no `BOTH`**, not even
   as a convenience: byte `0x25` may legitimately be uplink `/test2test` and
   downlink `/test2test-downlink`, and a combined value could not carry both
   strings. Using a byte in both directions is two calls.

3. **Two-stage answers.** `BLUECHERRY_TOPIC_MAP_EV_ACCEPTED` means only that the
   cloud took the request. The `BLUECHERRY_TOPIC_MAP_EV_ENTRY` that follows a
   write is what says the mapping is live. An application that publishes on a
   byte the moment it sees ACCEPTED is acting early by its own choice.

4. **Suffix only.** `bluecherry_topic_map_set(UPLINK, 0x85, "/sensors/humidity")`
   becomes `typeid01/lsiv983s/sensors/humidity`. The cloud adds the prefix, which
   is what makes naming another device's topic impossible rather than forbidden.

5. **A DELETE entry carries direction and byte with an EMPTY suffix.** The pair
   identifies the mapping, so the removed string adds nothing to act on.

## The one structural decision worth understanding

**Requests go out through `out_ring`, the ordinary publish buffer, not through
the `pending_event` priority slot.**

That slot holds exactly one internal message and a second write silently destroys
the first - the code says so outright, and `_bluecherry_ota_fail` clobbering a
queued `VERIFIED` was already a real bug once. It is safe today only because
every internal event is a *reply* to something the cloud just sent, so two never
race.

Topic map requests break that assumption completely: an application can call
`bluecherry_topic_map_set` at any moment, including mid-OTA. Sharing the slot
would mean either the request destroys a pending `OTA_VERIFIED`, losing an OTA
completion the cloud is waiting for, or an OTA event destroys the request
silently with no error.

Using `out_ring` reuses the proven peek / send / pop-after-ACK path, so
retransmission and multiple queued requests work with no new buffer and no flags,
and **the OTA path is untouched**. The cost is that a request queues behind
already-queued application publishes rather than jumping ahead of them.

## Behaviour change

**`bluecherry_publish()` now rejects topic `0x00` with `ESP_ERR_INVALID_ARG`.**

It accepted it before, which let application code forge internal protocol
messages. Now that `0x00` carries a write API that is a hole rather than a
curiosity. Publishing on `0x00` never delivered a message anyway - the server
routes it to `HandleBlueCherryEvent` - so nothing real should break.

**`CHANGELOG.md` was deliberately NOT touched**, since it is only updated at
release time. Both of the following belong in the next release's notes:

- `feat(topics)`: read and manage this device's MQTT topic map from the device.
  `bluecherry_topic_map_get`, `_set` and `_delete`, answered through
  `bluecherry_set_topic_map_handler`. Uplink and downlink are separate maps with
  independent byte spaces, a mapping is identified by direction and topic byte,
  and a device sets only the suffix below its own id. Mappings inherited from the
  device type are read-only and win any collision.
- `fix(publish)`: `bluecherry_publish` now rejects topic `0x00` with
  `ESP_ERR_INVALID_ARG`.

## Where things live, all in the two existing files

| Location | What |
|---|---|
| `src/bluecherry.h`, `#pragma region Topic map` | Public types, enums, handler typedef. |
| `src/bluecherry.h`, `#pragma region Topic map API` | The four function declarations. |
| `src/bluecherry.h`, `_bluecherry_t` | `topic_map_handler`, `..._args`, `topic_map_count`. |
| `src/bluecherry.c`, `#pragma region TOPIC MAP` | Wire constants, parsers, request builder, suffix validator. |
| `src/bluecherry.c`, `#pragma region TOPIC MAP API` | The four public functions. |
| `src/bluecherry.c`, `_bluecherry_process_event` | Two new cases, 18 and 19. |

`topic_map_count` is the **only** topic map state the library keeps: a running
count of the listing being received, reset when it is reported with
`BLUECHERRY_TOPIC_MAP_EV_LIST_DONE`.

## The wire format

See `bc-lite-server/HANDOFF-topicmap.md` for the authoritative description. In
short, on topic `0x00`:

```
request  [17][schema=1][op][sel][byte][suffixLen][suffix...]
status   [18][schema=1][op][stage][code][sel][byte]
entries  [19][schema=1][cause][more][count] then count x [dir][byte][attrs][suffixLen][suffix...]
```

Paging has **no sequence numbers and no cursor on either side**. The cloud queues
every page, answers `CONTINUE` while any remain, and the sync task fetches the
rest on its own; `more` clearing is the end of the listing. Only a listing
(`cause == RETRIEVED`) ends in `LIST_DONE`; a write result is a single entry with
no list to finish.

## What to check first when you build it

1. **It has never been compiled.** Expect ordinary mistakes: a missing cast, an
   `-Wunused` on `BLUECHERRY_TOPIC_STAGE_COMMIT` if it ends up unreferenced, or
   `_Static_assert` placement. The assert at the top of the region checks that a
   maximum-length request fits a BlueCherry record.

2. **Two stack buffers**, both sized from `BLUECHERRY_TOPIC_MAX_SUFFIX` (239):
   - `_bluecherry_topic_map_report_entry` holds 240 bytes, on the `bc_sync` task
     (default 8192, `CONFIG_BLUECHERRY_SYNC_TASK_STACK_SIZE`).
   - `_bluecherry_topic_map_request` holds 245 bytes, **on the calling
     application task**, whose stack the library does not control. Worth checking
     against whatever task the examples call it from.

3. **One deliberate widening.** In `_bluecherry_topic_map_report_entry`, `end` is
   `unsigned`, not `uint8_t`: `offset + 4 + suffix_len` can exceed 255 and wrap,
   and a wrapped value would read as comfortably inside the record instead of
   past it. Do not narrow it back.

4. **Run `clang-format`** with the repo's `.clang-format` before committing; the
   new code was written to the 2-space, 100-column style by hand.

## Not done

- **No tests.** This component has none - no `test/`, no `test_apps/`, no Unity -
  and CI does not compile it either, it only publishes to the Espressif registry
  on a `V*` tag. Verification is the example app against a real server.
- **`walter-wifi-template` was not touched.** Only `examples/wifi-template` grew
  a topic map handler and a `bluecherry_topic_map_get` call.
- **Nothing persists across deep sleep.** The map is not cached, so there is
  nothing to keep; an application that wants one re-lists after a wake.
- **Pre-existing bug, noted not fixed:** `bluecherry_publish` accepts `len` up to
  1017 but `_bluecherry_ring_push` writes a **one-byte** length field
  (`src/bluecherry.c:442`), so a 300-byte publish is framed with a length of 44
  and silently mis-parsed by the server. 255 is the real per-record limit in both
  directions. Unrelated to this feature and deserves its own fix.

## Suggested smoke test against a real server

With a device whose type defines at least one topic byte:

1. `bluecherry_topic_map_get(BLUECHERRY_TOPIC_SEL_ALL, 0)` - expect ACCEPTED,
   one ENTRY per mapping with the device-type ones marked `readonly`, then
   LIST_DONE with the count.
2. `bluecherry_topic_map_set(BLUECHERRY_TOPIC_DIR_UPLINK, 0x85, "/sensors/humidity")`
   - expect ACCEPTED, then an ENTRY with cause `CREATED`. Then publish on `0x85`
   and confirm it lands on `<type>/<dev>/sensors/humidity`.
3. The same `set` again with a different suffix - expect cause `UPDATED`.
4. `bluecherry_topic_map_set` on a byte the **device type** owns - expect
   REJECTED with `BLUECHERRY_TOPIC_ERR_READONLY` and no entry.
5. `bluecherry_topic_map_delete(BLUECHERRY_TOPIC_DIR_UPLINK, 0x85)` - expect
   cause `DELETED` with an empty suffix.
6. A device with more than ~20 mappings, to watch a listing page across several
   syncs. The server side of this is covered by
   `tests/e2e/topicmap_test.go`.
