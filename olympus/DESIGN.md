# Olympus — design notes (for whoever works on this next)

Olympus is a suite of ten small Windows apps built with the C# 5 compiler that ships with
Windows (.NET Framework 4.8, `csc.exe`), like Aegis. `build.ps1` compiles everything. The hub is a
general app hub: it also watches and switches the other programs built for this PC (apps.ini).

| App | Role | Runs as | Data |
|---|---|---|---|
| Olympus | app hub: the one tray icon, dashboard, alert inbox, hotkey, runs the watchers, switches every app (its own and the ones in apps.ini) on/off and starts/stops it | you (Run key) | %LOCALAPPDATA%\Olympus\olympus |
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
- Routine updates (`Common\Versioned.cs`): `IsUpdate` says a path is a newer copy of the same program
  when exactly one folder differs and went forward: a version folder of a known self-updating layout (a
  bare version like `158.0.4370.33`, or Squirrel's `app-1.0.9175`; other prefixes such as `tenant-1.0` or
  `jdk-17.0.1` are usually side-by-side installs and don't count),
  an MSIX package folder directly under WindowsApps (same name, architecture and publisher ID), or a
  driver-store folder of the same INF (ordered by its DriverVer, see below). Paths must be
  `PlainLocalPath` (drive letter, no environment variables, 8.3 aliases, streams, `..`, DOS device names
  including COM¹-³/LPT¹-³/CONIN$/CONOUT$, trailing dots or spaces).
  - Argus (`Engine.RoutineUpdate`) keeps a changed run, service, driver or Active Setup entry silently only
    when `SplitLaunch` reads the old and new command as one literal program plus byte-identical
    arguments (`\SystemRoot\` only with a relative rest), the verified file is that program (not a
    service DLL), it isn't a script runner, its settings are exactly the baseline's (`SettingsOf`:
    switched on/off, start mode, type, account, registry value kind; every field always written, so a
    removed account is a change; an entry with no settings on record gets one review), a driver-store
    driver's DriverVer is later than the one on record, and `VerifyProtected` passes:
    `Versioned.Protect(image, Siblings.Tree)` holds the program and every folder above it open from the
    drive root down (no delete sharing, no reparse following), checks each owner and DACL on its handle,
    requires the path to be its own long form (a failed `GetLongPathName` fails) and the whole folder tree
    beside it to be locked down, and the signature is verified from the held handle
    (`Signature.CheckHeld`). Tasks and startup shortcuts always go to review.
  - Entries Argus keeps on its own because of a signature (a routine update, `KeptBy = "update"`; a new
    entry for a verified Microsoft program or a retired COM notice, `KeptBy = "signature"`, recorded from
    one more held verification by `SignatureKeep`, and left in review if that fails) are marked `AutoKept`
    and verified again every scan (`LostTrust`): the program must exist and pass `VerifyProtected` with the
    same neighbour check (tree or files) and the signer identity on record, and an exec task must still
    start in an admin-only folder. Otherwise a `trust` finding opens, showing the held verification's
    result (a notice only when Windows says the file or its folder doesn't exist, a warning otherwise); it
    closes by itself when the program verifies again. A loss of trust is checked whatever else is pending
    and comes first, as its own occurrence (a settings change goes into its reason). Silent decisions need
    a verified identity: `Item.Microsoft` requires `SignerInfo.Id`.
  - Settings alone (same command and actions, `SettingsRisk`): a routine change is noted in the history as
    what changed (`SettingsChangeLabel`: switched on, with its start mode; switched off; start mode changed
    to X, was Y). Windows flips some of its own services between start modes several times an hour (BITS),
    so a start-mode change of one entry is noted at most once a day (`BaselineEntry.StartNoted`); switching
    on or off always is. Switched off is routine;
    switched back on or a new start mode is routine only for a program that verifies as Microsoft's in
    admin-only folders (Windows toggles its own tasks and services), otherwise rated like a new entry
    (at least a notice); a new account, service type or value kind is always a warning, and so is
    switching on an entry you turned off with Argus (`BaselineEntry.TurnedOff`). These are `settings`
    findings; they close by themselves when the settings go back to the record. Turning a task, service
    or driver off records the switched-off settings and `TurnedOff`; an accepted entry keeps its record
    (and trust), a new or changed one is recorded only as off, never as accepted; Undo restores the
    earlier record. An entry accepted before settings were recorded gets them from the previous scan's
    item when that shows the accepted command (what it recorded, today's values for the rest), so a change
    in between is still seen. Pending findings refresh only while their settings match (`SameOccurrence`);
    findings from before all settings were recorded compare what they have.
  - Signer identity (`SignerInfo.Id`): SHA-256 over the signing certificate's subject name and its
    issuing CA's public key, both read from WinTrust's own verification state, so it is the certificate
    that produced the verdict and survives a renewal by the same CA key. Baseline entries record it when
    accepted; an entry accepted before identities existed doesn't get one silently later (only a publisher
    name survives from then). Such an entry is matched only inside an installed MSIX package
    (`GetStagedPackagePathByFullName`) or the driver store; anywhere else its update gets one review, and
    keeping it records the identity. "Microsoft" (`Signature.IsMicrosoftCode`, from the verified chain:
    `SignerInfo.Issuer` and `Root`) means Microsoft's own code: a Microsoft publisher name, not "Microsoft
    Windows Hardware Compatibility Publisher" (WHQL and attestation-signed third-party drivers and their
    package catalogs) nor a third-party component signer, not issued by a "Third Party" CA, and ending at one
    of Microsoft's product roots (Root CA 2010, 2011, the 2001 root, the older Root Authority, ECC Product
    Root 2018; checked against this PC's store, and every Microsoft-named signature surveyed here ends at one
    of the first three). Not the Identity Verification root (Trusted Signing, other companies' code) and not
    a root an organisation adds, which could issue any name. The issuing CA's own name isn't matched:
    Microsoft's vary ("Windows Production PCA 2023", "Microsoft Windows Production PCA 2026 ..."). So a new
    third-party driver or service signed through Microsoft gets a look.
  - Raw DACLs are evaluated (`Locked`): only SYSTEM, Administrators and TrustedInstaller may hold write,
    append, attributes, EA, delete, delete-child, permission or owner rights (inherit-only ACEs skipped,
    conditional ACEs count as grants, unknown ACE types and missing DACLs fail). A drive root above the
    program's own folder must not let others empty it or take it over; a program directly at a root gets
    the full check (its parent is "C:\", never the drive-relative "C:"); a bare "C:" working folder fails.
    Neighbour verdicts are reused for at most 30 seconds.
  - Cerberus (`NetEngine.Classify`) runs on a program's first public TCP (also for records created by
    blocked DNS lookups, `Connections == 0`). Any Cerberus rule for another version of the same program
    (`Versioned.SameFamily`: older or newer, compared case-insensitively, record or not) makes it a warning
    with a block button; with the rules unreadable, any other version seen counts, whoever signed it. Every
    first sighting of a versioned path reads the rules again and checks the folder tree afresh (no reused
    verdict), since that decision is final. Those checks run on a worker thread (`SightingWorker`, queue of
    32; when full, the sampler checks inline), so the 2-second sampler keeps sampling; connections seen while
    a sighting waits are counted aside in memory and added once it's decided, so an engine stopped meanwhile
    meets it again as a first sighting; queued checks are finished and decided when the engine stops, and a
    check that fails comes back unverified without taking the thread down. A verified newer version with the same identity gets no
    notice, unless a later version was already seen (a rollback); in the driver store it also needs a
    later DriverVer than every copy seen. Expensive checks run only for paths with a version folder
    (`HasVersionFolder`, case-insensitive). `Block` re-enables a disabled rule and verifies it took effect; `Unblock`
    renames each matching rule before removing it, so same-named rules for other paths stay, and reports
    success only once the rules read back clear; rule names carry a 64-bit path hash.
  - DriverVer (`Versioned.DriverVerOf`) is read from the INF's [Version] section only; a second DriverVer
    or one in any other section (an install section's overrides [Version]) makes it unknown (review). It
    must have the INF format's shape: a date with / or -, and four version parts of 0-65534, not 0.0.0.0.
- New entries (`Engine.NewEntryRisk`): a Microsoft signature makes a new entry routine only when its whole
  launch is pinned down: a literal program path with no arguments that is the verified file; a one-action
  task whose working folder is admin-only too, or a verified inbox COM handler; and the program, verified
  then from a held handle, is Microsoft's in admin-only folders with the files beside it. Startup-folder
  shortcuts always get a look. Interpreters are recognised by long file name and by the version resource's
  original name.
- Argus collection: a task's entry hash covers every action in order (program, arguments and working
  folder; or COM class, the server it's registered to (classic DLL as written, or packaged server) and a
  digest of its data or "unreadable"), the account, run level, logon type and group, each field
  length-prefixed (`Collector.Field`); hashes from before migrate silently (nothing recorded then can show
  whether those parts changed, and that version didn't watch them), except an entry whose verified COM
  data no longer matches the record, which keeps its old hash so the change is reported once. Services record type and account; startup entries record
  their registry value kind. Legacy `Windows\Load`/`Run` values are read unexpanded. Entries that fail to
  read or to be checked aren't taken as gone (`Collector.Partial` / `Unreadable`), nor are their findings,
  and they stay listed as last seen. A service now registered as a driver (or the other way round) keeps its
  registry key but changes kind: it's a change to the accepted entry (`Engine.OtherKind`, a warning, checked
  before the first-full-read shortcut), not a new entry, and the old record stays until you've kept the
  switched one. Saved data that exists but can't be read (`ArgusData.Unreadable`: any read error other than
  "file or folder not found", contents that don't parse or parse to nothing, or rows that can't be used,
  meta.json included) stops the scan or action with nothing changed (an unreadable baseline would look like
  a first scan and accept everything, an unreadable meta.json like nothing ever read in full); the scan
  writes an error status, and the window and CLI say the list can't be read rather than showing it empty.
  Every scan logs and reports (status facts) its whole duration, saving and alerts included, and its held
  verifications (count, programs, time); re-checks of kept entries verify each program and neighbour check
  once per scan (`OncePerScan`, exact path spelling: case-sensitive folders exist). An entry kept as
  Microsoft's (`KeptBy = "signature"`) must still verify as Microsoft's own code.
- Argus and SoftLanding: Windows' tips handler (`SoftLandingTask.exe`, packaged COM) runs from per-user
  tasks Windows keeps recreating. `PackagedCom.IsRoutineSoftLanding` accepts only the observed shapes,
  field for field (`ParseTaskData`): render/noOp (SoftLanding or ActionCenter task names) and the unlock
  tip bubble (systemStateChange/ShowBubble on WNF_SHEL_DEVICE_UNLOCKED). `Engine.CanRetireComNotice`
  closes an older notice once the unchanged task verifies with the same raw data it was raised for
  (`Finding.ComRawHash`).
- Review state: dismissing an alert (hub, Argus, Arachne) records its ID in the hub's
  `dismissed-alerts.json`; the hub, Argus's window and CLI, and Athena's grade all apply it through
  `ArgusAlertReview.ApplyStatus(status, dir)` / `ArachneAlertReview.ApplyStatus`. Argus's status lists
  the exact findings it counted (`open`: "alertId:severity,..."), so no newer pending list is mixed in;
  older statuses fall back to the pending list in the status's own folder when the count matches. Every
  reader takes Argus's status and rows from one folder, `ArgusAlertReview.DisplayDirectory`
  (`ReadDisplayStatus`): once installed, always the engine's protected ProgramData folder, the one its
  elevated actions change. The window's summary comes from the same pending list as its rows
  (`ApplyFindings`). A SYSTEM app's raw status.json still counts dismissed findings.
- Argus occurrences and alert IDs: a finding whose settings, COM action data or verification changed is a
  new finding with its own alert (`SameOccurrence`). A new finding gets its alert ID before anything is
  published and is saved with it (`Finding.Unpublished`); the alert goes out after the save and the flag
  clears only once the alert is written (`AlertStore.Raise` returns whether it was), so a failed write is
  tried again next scan, and a scan stopped after writing but before saving finds that ID in the log and
  doesn't write it twice. The first scan's notes go out before the first baseline is saved. Findings saved
  before IDs existed get a lasting ID on the next scan (their alert's, looked up only in the protected log
  once installed, or a new one).
  Actions from the To review tab capture the finding's alert ID before any question and are checked
  against the protected pending list; "Keep all" sends the exact listed alert IDs (`accept-listed`); only
  16-hex-digit IDs reach an elevated Argus. If a scan kept or replaced a finding meanwhile, nothing
  changes (exit code 3; the hub says so too). The window also pins the entry down before any question
  (`ReviewDigest`: key, entry hash, settings, passed as `--digest`): keep and turn off act only if the saved
  entry still matches it, so a replacement a scan records while a question or the admin prompt is open is
  left alone. Turn off then reads the entry again (`Collector.Only`) and acts only if it's still registered
  as reviewed, with the same entry hash and settings (`StillAsReviewed`). Otherwise nothing changes (exit
  code 4, explained in the window and the hub) and the next scan reports it as it is. Scans record closed alert IDs before saving; manual actions
  save first. Turn off saves the Undo record before it changes Windows (Save writes turned-off.json
  first) and records a task's earlier on/off state, so Undo switches it back on only if it was on. Undo
  marks itself done only after the baseline it restored is saved (`Save(undoLast)`); every step can run
  again (a startup file already moved back is left alone). A finding older than the baseline's acceptance
  of the current state is dropped on the next scan.
- install.ps1 / uninstall.ps1 (+ olympus-setup.ps1): one UAC prompt; the user info is captured
  before elevating and passed in (-UserB64). Records prior DNS-Client log state in
  ProgramData\Olympus\install-state.json; Arachne records the prior audit policy in its setup.json.
- Arachne's watch list is data (`src\Arachne\arachne.ini`, copied next to the exe), not code:
  Defender's ML flagged a build carrying the list as PWS:MSIL/Stealer. Keep stealer-like file
  names (browser login DBs, token stores, wallets) out of compiled code and tests.
- The hub manages apps (`src\Olympus\Apps.cs`). `AppRegistry.All()` = the suite's own (`AppInfo.Guardians`,
  each given an `AppKind` by `AppEntry.KindOf`) + registered programs: `AppRegistry.BuiltInList` (compiled
  in; entries whose program is missing are dropped) overlaid by the user's `%LOCALAPPDATA%\Olympus\olympus\apps.ini`
  (same name replaces, `remove = true` hides; suite names can't be taken). Adding a program is one INI
  section: `exe`/`stop`/`log`/`status`/`icon`/`color`, or `type = launcher` + `command`. Registered
  programs never run elevated and the elevated helper never reads apps.ini.
  - On/off per kind (`AppControl.Switch`): Watcher/OnDemand = `off_apps` in olympus.ini (Supervise skips
    them; Sibyl's hotkey is released); Periodic/Engine = the `\Olympus\<App>` task via the elevated helper
    `Olympus.exe --task enable|disable|start|stop <App>` (`TaskControl.Elevated`: only those five task
    names, only from the installed copy; disable also ends the running instance; it records every task's
    Enabled in ProgramData\Olympus\olympus\tasks.json because the user can't read Cerberus's and Arachne's
    tasks — Argus/Ark/Athena are read straight from Task Scheduler, which install.ps1 lets the user read);
    Aegis = `Aegis.exe pause forever` / `resume` (a pause that runs out in 9999, `Overview.PausedForGood`;
    the engine keeps answering, so DNS never breaks, and Windows' DNS settings are never touched);
    Startup = Windows' StartupApproved\Run switch for the Run value (`StartupEntry`; Enable writes the Run
    value from `run_command` only when there's none), which Argus reads and treats switched off as routine.
  - Start/Stop: watchers via `--watch` / the `<app>.stop` signal, and Stop adds the name to held.txt so the
    hub doesn't restart it until Start or the next hub start (which clears it); engines via the helper;
    periodic apps "Run now" (the existing --scan-now / --backup-now / --report); Aegis opens/closes its tray;
    registered programs start in their own folder and stop with `stop =` args (or `kill`). Every action
    pokes `Local\Olympus.hub.apps` so the hub re-reads settings and refreshes at once; the CLI
    (`Olympus.exe apps|enable|disable|start|stop|run NAME`) uses the same `AppControl`.
  - Switched-off and held apps and launchers don't count towards the overall verdict (`Overview.Overall`).
    update.ps1 doesn't start an engine whose task is disabled; install.ps1 re-creates the tasks switched on.
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
- Tests: `src\Tests` (OlympusTests.exe, 695 tests); never call AlertStore.Raise from tests (it
  writes into the real inbox), and never point a clean at a real user folder. Tests log to
  `%TEMP%\olympus-tests\logs\tests.log`, never the hub's log. `build.ps1 -TestsOnly` rebuilds and
  runs them without touching bin\ (csc output isn't reproducible, so a full build always differs
  from the installed release even when no source changed).
