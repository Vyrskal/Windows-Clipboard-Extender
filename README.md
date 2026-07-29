# Windows Clipboard History Patcher

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6)](#requirements)
[![Release](https://img.shields.io/github/v/release/Vyrskal/Windows-Clipboard-Extender)](https://github.com/Vyrskal/Windows-Clipboard-Extender/releases/latest)

Removes the hardcoded **25-item** and **4 MB** limits from Windows' native clipboard history (`Win+V`).
Pure PowerShell, zero external dependencies — either run it as a script, or grab the one-click GUI `.exe`.

> ⚠️ **Memory-only patch.** It lives until reboot with enabled auto-start by default in GUI to re-apply it at every logon.
<img width="805" height="938" alt="image" src="https://github.com/user-attachments/assets/7c2bc22a-793d-454f-82b1-5810b7ff6bae" />


## Download

Grab the latest build from **[Releases](https://github.com/Vyrskal/Windows-Clipboard-Extender/releases/latest)** — `ClipboardUnlocker.exe`, no install needed.

1. Download `ClipboardUnlocker.exe`.
2. Double-click it → accept the UAC prompt.
3. Pick a limit and click **APPLY**. Done — `Win+V` now remembers 255 (or more) items.
4. Tick **"Re-apply automatically after every restart"** to keep it after a reboot.

Every release is built directly from this repo's source by [GitHub Actions](.github/workflows/release.yml) — nothing is uploaded by hand.

## How it works

The patcher is **self-adapting** — it never hardcodes addresses, so it survives Windows updates that shuffle the code around:

1. **Parses `cbdhsvc.dll` from disk** — reads PE headers, locates the `.text` section.
2. **Finds the settings constructor** — scans for `mov eax, 25` followed by `mov [reg+disp], eax` stores, cross-checked against the adjacent 4 MB / 5 MB size constants the same constructor writes.
3. **Refuses to guess** — it patches only when the scan finds **exactly one** match. Zero → "unsupported build" (prints a build fingerprint to report); more than one → "ambiguous, aborting" rather than risk corrupting the service.
4. **Computes this build's exact RVAs and field offsets** — both the instruction immediates (item count + 4 MB / 5 MB size caps) and the in-memory struct field offsets, which differ between Windows versions.
5. **Patches in-memory & restarts** — overwrites the constructor immediates at `BaseAddress + RVA`, then restarts the service so they re-execute.
6. **Patches live structs** — overwrites already-allocated `ClipboardSettingsImpl` instances (at the detected field offsets) for immediate effect, no logoff needed.

## Tested builds

The disk parser was validated against real `cbdhsvc.dll` binaries spanning every Windows build that has clipboard history — from Windows 10 1809 (where `Win+V` first shipped) through Windows 11 24H2 — pulled from Microsoft's symbol server. On each it finds a single unambiguous match and resolves the correct — and sometimes *differing* — offsets automatically:

| Windows build | Count fields | Size fields | Result |
|---|---|---|---|
| Windows 10 1809 (17763) | `+0x68 / +0x6C` | `+0x58 / +0x60` | ✅ unique match |
| Windows 10 1903 / 1909 (18362) | `+0x68 / +0x6C` | `+0x58 / +0x60` | ✅ unique match |
| Windows 10 2004 → 22H2 (19041) | `+0x68 / +0x6C` | `+0x58 / +0x60` | ✅ unique match |
| Windows 11 21H2 (22000) | `+0x68 / +0x6C` | `+0x58 / +0x60` | ✅ unique match |
| Windows 11 22H2 / 23H2 (22621) | `+0x68 / +0x6C` | `+0x58 / +0x60` | ✅ unique match |
| Windows 11 24H2 (26100) | `+0x70 / +0x74` | `+0x60 / +0x68` | ✅ unique match |

The layout held steady across all of Windows 10 and early Windows 11; only 24H2 moved things — every field shifted by `+0x08`, which the parser adapts to automatically instead of writing to the wrong offset. (Detection is verified on all the above; the live memory write is confirmed on Windows 10.)

## Two ways to use it

### GUI (recommended) — `ClipboardUnlocker.exe` / `ClipboardUnlocker.ps1`

One window, item-count and item-size (MB) fields — each with presets — an **APPLY** button, an auto-start checkbox, and a live log.

```powershell
# run the script directly instead of the exe
powershell -ExecutionPolicy Bypass -File .\ClipboardUnlocker.ps1

# headless (used internally by the logon scheduled task)
powershell -ExecutionPolicy Bypass -File .\ClipboardUnlocker.ps1 -Silent -Limit 255 -SizeLimitMB 64
```

Improvements over the raw scripts below:

- **Auto-start = scheduled task at logon** (`RunLevel Highest`) — runs silently and elevated with no UAC popup. The GUI and `Install-Persistence.ps1` register the same `ClipboardUnlocker` task, so either entry point (and removing it) behaves identically.
- **Auto-elevation** — the exe's manifest requests UAC itself; no need to "run as administrator" manually.
- **Configurable item-size limit** (`-SizeLimitMB`, default 64) instead of a hardcoded value.
- **Cleaner service restart** — tries `Start-Service` first, only falls back to the `Win+V` nudge if needed.
- **`-Silent` mode** for unattended runs (what the scheduled task actually invokes).

### Scripts (advanced / no exe)

```powershell
# One-time patch (until reboot)
.\Patch-ClipboardHistory.ps1

# Persistent: register a logon scheduled task (silent, elevated, no UAC prompt)
.\Install-Persistence.ps1

# Remove persistence
.\Uninstall-Persistence.ps1
```

| Parameter | Default | Description |
|-----------|---------|--------------|
| `-NewItemLimit` | `255` | New max item count (1–65535) |
| `-NewSizeLimitMB` | `64` | New per-item size cap in MB (1–1900), lifting the built-in 4 MB limit |

## Building the exe yourself

On **Windows**, in a normal PowerShell (admin not required):

```powershell
powershell -ExecutionPolicy Bypass -File .\Build-Exe.ps1
```

This installs the [`ps2exe`](https://github.com/MScholtes/PS2EXE) module if missing and compiles `ClipboardUnlocker.exe` with the icon, version info, and a `requireAdmin` manifest (double-click prompts UAC immediately). The same script runs in CI to produce release builds.

## Requirements

- Windows 10 (build 19041+) or Windows 11
- PowerShell 5.1 or later
- Administrator privileges

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Patch applies but still capped at 25 | The service restarted with a new PID — the script handles this automatically, just re-check after it finishes. |
| `cbdhsvc not found` | Press `Win+V` once to start the service, then re-run. |
| `unsupported build` / `ambiguous match` | A Windows update rearranged `cbdhsvc.dll`. The tool prints a fingerprint (file version + `.text` SHA256) — please open an issue with it so a recipe can be added. |
| Antivirus blocks `WriteProcessMemory` | Expected — see [Security notes](#security-notes) below. Add an exclusion or test in a VM. |

## Security notes

- This tool injects into a running system service (`cbdhsvc_*`) via `WriteProcessMemory` to lift a hardcoded limit. **Antivirus/EDR flagging this is expected behavior**, not a sign of malware — read the source before running it, like you should for any script that asks for admin rights.
- The patch only ever **writes a numeric limit** (item count / size cap); it does not read, exfiltrate, or transmit clipboard contents anywhere.
- No network calls, no telemetry.
- For clean distribution to other machines, consider signing the exe with your own code-signing certificate.
- Not affiliated with or endorsed by Microsoft.

## License

[MIT](LICENSE)
