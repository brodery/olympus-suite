# Olympus

Your own app hub: small apps that each look after something (security, backups, disk space,
game mode), plus the other tools built for this PC, all watched and switched on and off from one
place. Built on this PC with the C# compiler that ships with Windows, like Aegis.

| App | What it does | How it runs |
|---|---|---|
| **Olympus** | The hub. One tray icon (its badge turns amber or red when something needs a look), a dashboard with a tile per app, one inbox for every alert with that alert's buttons, and an **Apps** tab to enable, disable, start and stop every app. **Ctrl+Alt+L** checks whatever you copied. | Starts when you sign in |
| **Aegis** | DNS filter from the [Aegis project](../aegis). The hub shows its live numbers. | Background engine and tray icon |
| **Argus** | Watches startup entries, scheduled tasks, services, drivers, browser extensions and policies, proxy, hosts file, DNS, trusted root certificates, WMI, program hijacks and sign-in hooks. Review changed startup commands and choose **keep** or **turn off** (with Undo). | Every 5 minutes, as SYSTEM |
| **Sibyl** | Paste a link or a whole message. It follows links without opening them in a browser, flags look-alike and brand-new domains, asks Aegis about every site on the way, and spots scam wording (fake eBay payments, delivery texts, "I accidentally reported your account"...). Optional second opinion from your local LM Studio model. | On demand (Ctrl+Alt+L) |
| **Janus** | Checks every new download: what it really is (not what its name says), double extensions, who signed it, which site it came from, programs hidden in zips, adware-bundling download portals. Optional VirusTotal / MalwareBazaar lookups with free keys. | In the background |
| **Arachne** | Infostealer tripwire for browser, Discord, Steam and Telegram login files and hidden decoys. Dismiss individual alerts in its Alerts tab while monitoring continues. The watch list is in `arachne.ini`. | Engine as SYSTEM |
| **Athena** | Security report card (A-F) covering Defender, firewall, Aegis, UAC, Secure Boot, Windows and app updates, open ports, router port forwards, devices on your network, backups, and the other Olympus apps. Can try Defender's attack-surface rules in watch-only mode. | Daily (admin facts at 4:00 as SYSTEM) |
| **Cerberus** | Samples public TCP connections and estimates destinations from DNS lookups. Shows Aegis blocks and can keep a program offline through Windows Firewall. | Engine as SYSTEM |
| **Ark** | Versioned backups to `A:\Ark` by default. Backs up Documents, Desktop, Saved Games and Pictures daily. Defaults for Claude projects, Claude memory and an MCP server are enabled when their folders exist during setup. Unchanged files are hard links. Keeps everything from 48 hours, then daily for 30 days and weekly for 12 weeks. A partial backup preserves the last complete snapshot. Waits while you're gaming. | Hourly, as SYSTEM |
| **Ares** | Game mode on autopilot: when a game starts it can unload LM Studio's model, switch the power plan, and ask chosen apps to close. After the game, it restores the plan and reopens apps that exited. Warns when a program leaks memory or Windows is running out. The hub holds non-urgent pop-ups while you play. | In the background |
| **Atlas** | Disk space map, like WizTree: every drive as a folder tree plus a treemap (blocks sized by space, coloured by kind of file), the biggest files and the space per file type. A drive maps in seconds; hard links count once. **Clean up** lists throwaway data (temp files, shader caches, crash dumps, AMD's installer files, Steam's leftovers, browser caches, the Recycle Bin) and only cleans what you tick; Windows' own folders ask for admin rights once. **Worth a look** suggests big things you might not need (games you haven't played in 60 days, LM Studio models, Flight Simulator's scenery, big downloads, the hibernation file) but never removes them itself. Warns when a drive gets full. | In the background (drive space), window on demand |

## Your other apps
Olympus also lists programs built for this PC outside the suite. Out of the box:

| App | What it does | Enable / Disable | Stop |
|---|---|---|---|
| **Orpheus** | The keyboard's volume roller turns Spotify up and down. | Starts at sign-in, or not | `Orpheus.exe --exit` |
| **Iris** | Stretches Xbox remote play across the ultrawide. | Starts at sign-in, or not | `Iris.exe --exit` |
| **Proteus** | Turns mouse and keyboard into an Xbox controller for remote play. | Starts at sign-in, or not | `Proteus.exe --exit` |

and **launchers**, which run once when you click **Run**: iFunny download, Desktop layout,
Sonar backup, Rock Band ultrawide fix and Rock Band money. An entry whose program isn't on the PC
is left out.

Add your own in `%LOCALAPPDATA%\Olympus\olympus\apps.ini` (**Edit my apps list** on the Apps tab):
one `[Name]` section with `exe =` (plus optional `role`, `about`, `args`, `stop`, `log`, `status`,
`icon`, `color`, `service`), or `type = launcher` with `command =`. The file explains every key. A section with
the name of a built-in entry replaces it; `remove = true` hides one. Olympus re-reads it every 15
seconds. An app that writes an Olympus-style `status.json` (`state`, `summary`, `detail`,
`updated`) can point `status =` at it to show its own health.

## Enable, disable, start, stop
The **Apps** tab (and right-click on any tile) switches each app on or off; that stays after a
restart. Start and Stop act now.

| App | Disable means | Start / Stop |
|---|---|---|
| Janus, Ares, Atlas | The hub stops it and leaves it off (`off_apps` in `olympus.ini`). | Stop keeps it stopped until you start it again or Olympus restarts. |
| Sibyl | The hub lets go of Ctrl+Alt+L. | Start opens it. |
| Argus, Ark, Athena | Its SYSTEM scheduled task is switched off (admin prompt). | Run now: a scan, a backup, a fresh grade. |
| Cerberus, Arachne | Its SYSTEM scheduled task is switched off and its engine stops (admin prompt). | Start/Stop the engine (admin prompt). |
| Aegis | Filtering is paused until you enable it again. Windows still sends its lookups to Aegis, so DNS never stops working; nothing in Windows' DNS settings changes. | Opens or closes its tray icon; filtering carries on either way. |
| Your apps | Windows' own Startup-apps switch for its Run value (the same switch as Task Manager's Startup apps page). Enable writes the Run value if there's none. | Starts the program / asks it to close. |

Argus notes a startup entry or task you switch off as routine; switching one back on (and a brand-new
Run value, such as Iris's first Enable) gets the usual Argus review. `install.cmd` re-creates the
scheduled tasks switched on. From the command line: `Olympus.exe apps`, `Olympus.exe enable NAME`,
`disable`, `start`, `stop`, `run`.

## Tray icons
Besides Olympus's own icon, each Olympus app gets a tray icon while it's running (the hub shows
them, since most run as SYSTEM where they can't show icons themselves; Aegis and your other apps
keep their own). The hub's menu lists your other apps (tick = open; click to start or stop) and a
**Run** menu with the launchers.
The dot shows its state: green fine, blue working (Ark backing up, Ares in game mode), amber or red
needs a look. Hover for its status, click to open it, right-click for its quick actions
(Scan now, Back up now, Game mode, Check what I copied, Check again, Clean up junk, Map drive C:)
or **Hide this icon**.
Olympus asks Windows once to show its icons on the taskbar rather than in the ^ overflow; after
that, Settings > Personalization > Taskbar > Other system tray icons is where you choose.
`guardian_icons = false` in Olympus's settings turns them all off.

## Install, update, remove

Build as your normal user with `build.ps1`. Before installing or updating, review the build
and **copy** the release files into `C:\Program Files\Olympus Release` from an administrator
session. Use a regular folder with administrator ownership and inherited Program Files
permissions. Copy these files from the same reviewed build:

- `olympus-release.ps1`, `olympus-setup.ps1`, `release-signing.ps1`, `install.ps1`, `update.ps1`
  and `uninstall.ps1`.
- `bin\<App>.exe` and `assets\<app>.ico` for Olympus, Ark, Argus, Sibyl, Janus, Ares, Athena,
  Cerberus, Arachne and Atlas, plus `bin\arachne.ini` and `bin\atlas.ini`.

The release launcher checks ownership and write permissions before elevating and again
before copying files. Verify the copied files against the build you reviewed. The launchers
use this protected directory when invoked from the development workspace.

- **Install** with `install.cmd`. It copies the reviewed programs to `C:\Program Files\Olympus`,
  creates the scheduled tasks, enables DNS and Arachne auditing, and protects `A:\Ark`.
  `install.cmd -DryRun` previews an already staged release. For a working build, run
  `.\install.ps1 -DryRun` in ordinary PowerShell.
- **Update** with `update.cmd`. It replaces changed program files and restarts affected
  apps (an engine you switched off stays off). Use `install.cmd` for changes to `arachne.ini` or install steps.
- **Remove** with `uninstall.cmd`. Keep the protected release scripts available for
  removal. `-KeepFirewallRules` preserves blocks and `-Purge` removes logs and history.
  Removal keeps backups in `A:\Ark`.

### Local code signing

On a PC with an administrator-configured `CertificateSha256` under
`HKLM:\SOFTWARE\Olympus\ReleaseSigning`, the build signs the app executables, including
Atlas, before copying them to `bin`. Build from the Windows account that holds the local
private key and trusts the corresponding code-signing certificate. The same registry value in
the current user hive enables signing for development builds. The release launcher uses
the machine pin and
verifies the Authenticode signature and the configured fingerprint before installing or
updating. The private key stays in that account's Windows certificate store.

A source checkout on a PC without a signing pin in either hive builds unsigned executables. Anyone
building their own copy can use their own signing identity.

## Where things are
- Apps: `C:\Program Files\Olympus` (once installed) or `bin\` (fresh builds).
- SYSTEM engines' data and logs: `C:\ProgramData\Olympus\<app>` (readable by you).
- Your apps' data and settings: `%LOCALAPPDATA%\Olympus\<app>` (`olympus.ini`, `ares.ini`...).
  Your own app list: `%LOCALAPPDATA%\Olympus\olympus\apps.ini`.
- Backup settings: `C:\ProgramData\Olympus\ark\ark.ini`. Tripwire list: `arachne.ini` next to the exes.
- If your backup drive uses a different letter, set `target` in `ark.ini` to a folder on that NTFS
  drive. Ark pauses backups until the configured drive is available. The initial settings include
  commented-out sets for source folders that are missing during setup.
- Atlas: cleanup list `atlas.ini` next to the exes; settings (warning level, drives to ignore) in
  `%LOCALAPPDATA%\Olympus\atlas\settings.ini`; saved maps in its `maps` folder.
- Dismiss an alert in the hub, Argus, or Arachne to clear it from both review lists. Dismissal acknowledges that occurrence, and Athena's report card stops counting it too. Use **It's fine, keep it** in Argus to accept the change into its baseline, or **It's fine, allow it** in Arachne to change its allow list. Select an alert in the hub for the actions the app offers and a shortcut to its details.
- App updates don't need review: when a service, startup entry, driver or Active Setup entry moves to a newer version folder of the same program (Edge, Chrome, Store apps, driver updates), signed by the same publisher, inside folders only administrators can change, Argus keeps it on its own and notes old and new in its history. Cerberus likewise doesn't report a verified app's new version as a new program going online, but warns if you had kept the old version offline. A new publisher or certificate, changed arguments, an older version, a script runner, a scheduled task, other settings (switched back on, a new account) or a folder you can write to still goes to review; the first update of an entry recorded before this check existed may need one review. Entries Argus keeps on its own are checked again on every scan, and come back for review if their program disappears or no longer verifies. A new driver or service from another company always gets a look, even when Microsoft signed it for them through its hardware program (WHQL). Turn it off acts only if the entry is still exactly as Argus showed it to you.
- Every app has a command line too: `Argus.exe help`, `Ark.exe status`, `Olympus.exe status`...
  (from PowerShell add `| Out-String`).

## Good to know
- Nothing changes a security setting on its own: firewall rules, Defender rules and the
  install-time audit settings only happen when you click (with an admin prompt) or run install.cmd.
- Arachne's list of watched files is in `arachne.ini`, not in the program, partly because
  Windows Defender's heuristics flag programs that carry a password-stealer-like list of file
  names (it flagged an early test build). If Defender ever quarantines an Olympus app, that's
  why; check Windows Security's Protection history before restoring anything.
- In Atlas, right-click a file or folder in the tree, treemap, or Biggest files for **Move to
  the Recycle Bin…** or **Delete permanently…**. Permanent deletion skips the Recycle Bin and
  asks you to confirm the full path. Atlas protects whole drives, important Windows and user
  folders, installed Steam games, and Ark's backups. Its admin cleanup list is built into the
  program.
- Discord reads its token store often, so Arachne's audit adds to the Windows Security log; remove
  the `[kind:discord]` lines from `arachne.ini` and re-run install.cmd if that bothers you.
- `DESIGN.md` explains how the pieces fit together (for future changes).
