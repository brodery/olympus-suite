# Olympus

Your own security suite: small apps that each guard something, and one hub that ties them
together. Built on this PC with the C# compiler that ships with Windows, like Aegis.

| App | What it does | How it runs |
|---|---|---|
| **Olympus** | One tray icon (its badge turns amber or red when something needs a look), a dashboard with a tile per app, one inbox for every alert with that alert's buttons. **Ctrl+Alt+L** checks whatever you copied. | Starts when you sign in |
| **Aegis** | DNS filter from the [Aegis project](../aegis). The hub shows its live numbers. | Background engine and tray icon |
| **Argus** | Watches startup entries, scheduled tasks, services, drivers, browser extensions and policies, proxy, hosts file, DNS, trusted root certificates, WMI, program hijacks and sign-in hooks. Review changed startup commands and choose **keep** or **turn off** (with Undo). | Every 5 minutes, as SYSTEM |
| **Sibyl** | Paste a link or a whole message. It follows links without opening them in a browser, flags look-alike and brand-new domains, asks Aegis about every site on the way, and spots scam wording (fake eBay payments, delivery texts, "I accidentally reported your account"...). Optional second opinion from your local LM Studio model. | On demand (Ctrl+Alt+L) |
| **Janus** | Checks every new download: what it really is (not what its name says), double extensions, who signed it, which site it came from, programs hidden in zips, adware-bundling download portals. Optional VirusTotal / MalwareBazaar lookups with free keys. | In the background |
| **Arachne** | Infostealer tripwire for browser, Discord, Steam and Telegram login files and hidden decoys. Dismiss individual alerts in its Alerts tab while monitoring continues. The watch list is in `arachne.ini`. | Engine as SYSTEM |
| **Athena** | Security report card (A-F) covering Defender, firewall, Aegis, UAC, Secure Boot, Windows and app updates, open ports, router port forwards, devices on your network, backups, and the other guardians. Can try Defender's attack-surface rules in watch-only mode. | Daily (admin facts at 4:00 as SYSTEM) |
| **Cerberus** | Samples public TCP connections and estimates destinations from DNS lookups. Shows Aegis blocks and can keep a program offline through Windows Firewall. | Engine as SYSTEM |
| **Ark** | Versioned backups to `A:\Ark` by default. Backs up Documents, Desktop, Saved Games and Pictures daily. Defaults for Claude projects, Claude memory and an MCP server are enabled when their folders exist during setup. Unchanged files are hard links. Keeps everything from 48 hours, then daily for 30 days and weekly for 12 weeks. A partial backup preserves the last complete snapshot. Waits while you're gaming. | Hourly, as SYSTEM |
| **Ares** | Game mode on autopilot: when a game starts it can unload LM Studio's model, switch the power plan, and ask chosen apps to close. After the game, it restores the plan and reopens apps that exited. Warns when a program leaks memory or Windows is running out. The hub holds non-urgent pop-ups while you play. | In the background |
| **Atlas** | Disk space map, like WizTree: every drive as a folder tree plus a treemap (blocks sized by space, coloured by kind of file), the biggest files and the space per file type. A drive maps in seconds; hard links count once. **Clean up** lists throwaway data (temp files, shader caches, crash dumps, AMD's installer files, Steam's leftovers, browser caches, the Recycle Bin) and only cleans what you tick; Windows' own folders ask for admin rights once. **Worth a look** suggests big things you might not need (games you haven't played in 60 days, LM Studio models, Flight Simulator's scenery, big downloads, the hibernation file) but never removes them itself. Warns when a drive gets full. | In the background (drive space), window on demand |

## Tray icons
Besides Olympus's own icon, each guardian gets a tray icon while it's running (the hub shows them,
since most guardians run as SYSTEM where they can't show icons themselves; Aegis keeps its own).
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
  guardians. Use `install.cmd` for changes to `arachne.ini` or install steps.
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
