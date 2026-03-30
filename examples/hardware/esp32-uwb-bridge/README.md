# ESP32 UWB Bridge Firmware

**Status:** Not yet implemented.

This directory is a placeholder for the ESP32 bridge firmware referenced by `src/proximity/adapters/esp32-uart.ts`. The firmware should expose a JSON-over-UART protocol so the host adapter can communicate with the UWB radio.

## Expected Protocol

Host sends JSON commands, ESP32 replies with JSON responses:

```
Host → ESP32: {"cmd":"range","peer":"<id>","challenge":"<hex>","sts":true}
ESP32 → Host: {"dist":3.21,"quality":92,"sts_ok":true,"rounds":3}
```

### Commands

| Command | Description |
|---|---|
| `range` | Perform TWR ranging with a peer. Fields: `peer`, `challenge`, `sts` (STS mode). Returns: `dist` (meters), `quality` (0-100), `sts_ok`, `rounds`. |
| `status` | Return chip/firmware info. Returns: `chip`, `firmware`, `ready`. |
| `data_send` | Send raw data to peer via UWB. Fields: `peer`, `data` (hex). |
| `data_recv` | Poll for received data. Returns: `peer`, `data` (hex), or `null`. |

## Target Hardware

- Makerfabs ESP32 UWB (DW3000, ~$30)
- Ai-Thinker BW16-Kit (DW1000, ~$20)

## Implementation Notes

- Use Arduino or ESP-IDF
- Serial baud: 115200 (configurable via `ATLAS_ESP32_BAUD` env var in host adapter)
- One JSON object per line (newline-delimited)
- The host adapter auto-detects the ESP32 by scanning `/dev/ttyUSB*` and `/dev/ttyACM*`
