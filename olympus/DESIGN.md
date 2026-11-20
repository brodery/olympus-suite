# Olympus — design notes (for whoever works on this next)

Olympus is a suite of ten small Windows apps built with the C# 5 compiler that ships with
Windows (.NET Framework 4.8, `csc.exe`), like Aegis. `build.ps1` compiles everything.

| App | Role | Runs as | Data |
|---|---|---|---|
| Olympus | hub: the one tray icon, dashboard, alert inbox, hotkey, runs the watchers | you (Run key) | %LOCALAPPDATA%\Olympus\olympus |
| Aegis | DNS filter from the [Aegis project](../aegis) | background engine and tray icon | queried over DNS: `status.aegis.invalid`, `NAME.check.aegis.invalid` |
| Argus | hijack/persistence watcher: snapshot + diff of startup spots | SYSTEM task every 5 min (`--scan`) | ProgramData\Olympus\argus |
| Sibyl | link and scam checker (Ctrl+Alt+L via the hub) | you, on demand | LocalAppData |
| Janus | download inspector (watches Downloads) | you, `--watch` started by the hub | LocalAppData |
| Arachne | infostealer tripwire: SACL audit on login files + decoys, reads Security 4663 | SYSTEM engine (`--engine`) | ProgramData |
| Athena | security report card; SYSTEM part collects admin-only facts | you (`--report`, hub runs it daily) + SYSTEM (`--collect`) | both |
| Cerberus | outbound firewall: connections per app, DNS-Client log attribution, block rules | SYSTEM engine (`--engine`) | ProgramData |
| Ark | versioned hard-link snapshots to A:\Ark | SYSTEM task hourly (`--backup`) | ProgramData + A:\Ark |
| Ares | game-mode autopilot + memory-leak watch | you, `--watch` started by the hub | LocalAppData |
| Atlas | disk space map (tree + treemap), cleanup, drive-space warnings | you, `--watch` started by the hub; elevated only on a click (`--map-admin`, `--clean-admin`) | LocalAppData (`maps\`, `settings.ini`, `junk.json`, `state.json`) |

## Conventions
- Source: `src\Common\*.cs` is compiled into every exe. `src\<App>\*.cs` per app;
  `src\<App>\AssemblyInfo.cs` holds the assembly attributes (excluded from the test build).
- Namespaces: `Olympus` (common), `Olympus.<App>` per app. C# 5 only: no `$""`, `?.`, `=>` members, `nameof`.
- Identity: `AppInfo` (Core.cs) holds each app's name, role and colours; icons are drawn by
  `IconArt` and written to `assets\<app>.ico` at build time, embedded with `/win32icon`.
- Every app writes `status.json` (state ok|warn|alert|off|busy|error + summary) and appends
  alerts to `alerts.jsonl` in its data folder. The hub reads both folders (ProgramData and
  LocalAppData) for every app and shows toasts. `Suite.DataDir`: SYSTEM-engine apps use
  ProgramData when elevated, otherwise LocalAppData (so dev runs work without admin).
- Alert actions run `<App>.exe --action <id> --alert <alertId>`, elevated when `Elevate` is set.
- SYSTEM engines learn who the user is from `ProgramData\Olympus\install.json` (written by install.ps1).
- Windows: `AppWindow` (Ui.cs) gives every window the same header/toolbar/body/status layout.
  `--snapshot <png> [--tab N] [--wait ms]` renders a window, or one tab of it, to a PNG for checking
  layouts without showing it. `obj\snap-all.ps1` renders every tab of every app; run it outside the
  Claude package so it reads the real data.
- Lists: `Ui.List("Name|200", "Size|90>", "Path|300*")`. Widths are unscaled px, and `>` right-aligns
  a number column.
  - The column marked `*`, or else a last column of text, takes the leftover width, never narrower
    than given. A table that ends in numbers just ends.
  - `Ui.Empty(list, text)` shows a centred line while the list is empty (Windows' own
    LVN_GETEMPTYMARKUP).
  - `Ui.Show(textBox, text)` sets read-only text without it all turning selected when its tab
    gets focus.
- Ares writes `game.json` (heartbeat each minute while a game runs). The hub holds non-urgent
  toasts while gaming; Ark postpones hourly backups while gaming.
- Nothing in the suite changes security settings by itself: firewall rules, ASR rules, audit
  policy and SACLs are only changed by an explicit user click (UAC) or by install.ps1.
- Installed copy: `C:\Program Files\Olympus` (admin-only), so SYSTEM tasks never run user-writable files.
- install.ps1 / uninstall.ps1 (+ olympus-setup.ps1): one UAC prompt; the user info is captured
  before elevating and passed in (-UserB64). Records prior DNS-Client log state in
  ProgramData\Olympus\install-state.json; Arachne records the prior audit policy in its setup.json.
- Arachne's watch list is data (`src\Arachne\arachne.ini`, copied next to the exe), not code:
  Defender's ML flagged a build carrying the list as PWS:MSIL/Stealer. Keep stealer-like file
  names (browser login DBs, token stores, wallets) out of compiled code and tests.
- Guardian tray icons are NotifyIcons owned by the hub (SYSTEM engines run in session 0 and
  can't show icons). They're created at hub start in a fixed order (stable icon IDs, so Windows
  remembers placement) and shown while `AppState.Running`. `pin_icons` sets IsPromoted once per
  NotifyIconSettings key whose ExecutablePath ends in \Olympus\Olympus.exe (keys remembered in inbox.json).
- Atlas's scanner reads each folder with one `GetFileInformationByHandleEx(FileIdBothDirectoryInfo)`
  loop on up to 8 threads (C: with ~750k files maps in about 6 s cold, 1 s warm). Sizes are
  allocation sizes; Windows-compressed (WOF) files list 0 there, so files with no allocation
  but more than 4 KB of data get `GetCompressedFileSize`. Hard links count once: the link whose
  path sorts first keeps the space (deterministic across threads; Ark's oldest snapshot and
  System32 over WinSxS). Junctions/symlinks/mount points (name-surrogate reparse tags) aren't
  followed; cloud placeholders are. Files under 1 MB (drives) or 16 KB (folders) are summed per
  folder instead of kept as nodes. Maps are saved gzipped per drive (`maps\C.map`).
- Atlas's cleaning: user-level places come from `atlas.ini` (next to the exe); admin places are
  built into the code (`Catalog.AdminItems`), and the elevated `--clean-admin` helper only ever
  cleans those, so an editable file can't steer an admin delete. Every place passes
  `Safety.Refuse` (drives, Windows, Program Files roots, profile and main folders, Olympus, Ark).
  Cleaning never descends into a reparse point; caches are deleted, folders go to the Recycle Bin.
- Atlas's treemap: `MapLayout` (Treemap.cs) works out the blocks without drawing, so it's unit-tested.
  - Things under about 11x11 px fold into one hatched "N smaller items" block per folder, so every
    block can be hovered. C: draws about 1,000-5,000 blocks in 25-90 ms.
  - Folders under about 22 px are drawn whole, in the colour of their biggest content.
  - A folder whose biggest subfolder holds 90% or more shares that subfolder's name strip
    (`Program Files (x86)\Steam\steamapps\common`).
  - Slivers thinner than 6 px get extra hover reach.
  - Map labels use GDI+ `TextRenderingHint.AntiAlias`. ClearType's colour fringes looked ragged on
    coloured blocks, and GDI grayscale and GDI+ grid-fit both space letters oddly.
  - The hover card uses GDI ClearType on its plain dark background. Measure TextRenderer text without
    an ellipsis flag: with one, MeasureText returns the already shortened width.
  - The folder list's share of the Map tab is remembered in `view.json`.
- Tests: `src\Tests` (OlympusTests.exe, 347 tests); never call AlertStore.Raise from tests (it
  writes into the real inbox), and never point a clean at a real user folder. Tests log to
  `%TEMP%\olympus-tests\logs\tests.log`, never the hub's log. `build.ps1 -TestsOnly` rebuilds and
  runs them without touching bin\ (csc output isn't reproducible, so a full build always differs
  from the installed release even when no source changed).
