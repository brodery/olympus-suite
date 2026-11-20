# Aegis: DNS ad and malware filter for this PC

Aegis answers this PC's DNS lookups itself. Ad, tracker and malware domains get `0.0.0.0`,
so they never load. Everything else goes to Quad9 (9.9.9.9), which also refuses known
malware domains.

## On, off, pause

- **On:** double-click `install.cmd` (one UAC prompt).
- **Off:** double-click `uninstall.cmd` (one UAC prompt). Puts your previous DNS settings back.
- **Pause:** tray menu, *Pause for 10 minutes* or *1 hour*. It resumes by itself.

## Using it

- The tray shield: green = filtering, amber = paused, grey = Windows isn't using Aegis,
  red = the engine isn't answering.
- Click the shield (or the desktop **Aegis** shortcut) for the window:
  - *Recent blocks*: the last 7 days, newest first, with how many times each was blocked. A site
    won't load? Find it, then *Allow this site*.
  - *Your lists*: what you always allow or block.
  - *Check a site*: is it blocked, and by which list?
  - *About*: lists, counts and settings.
- Command line (from PowerShell add `| Out-String`):
  `Aegis.exe status | recent [N] | check NAME | allow NAME | block NAME | unallow NAME | unblock NAME | pause [MIN] | resume | update`

## How it works

- `AegisEngine.exe` runs as the scheduled task **Aegis DNS filter**: as you, from boot, before
  logon. It listens on 127.0.0.1:53 and [::1]:53 and is restarted within a minute if it stops.
- Blocklists: HaGeZi Multi PRO and HaGeZi Threat Intelligence Feeds (full), about 2.5 million
  domains, refreshed every 24 hours (the engine uses about 45-55 MB, briefly ~215 MB while
  downloading). A listed domain covers its subdomains. A name that is an alias (CNAME) of a
  blocked domain is blocked too.
- Your overrides: `allow.txt` and `block.txt`. The most specific rule wins, and a tie goes to
  allow. Always allowed: Windows' connectivity check, Windows Update, Claude, and the blocklist
  download sites.
- Local names (`mynetworksettings.com`, single-label names, reverse lookups of private
  addresses) go to your router, as before. If Quad9 can't be reached at all, the router answers
  everything for the moment (the lists still apply), so a Quad9 outage doesn't take you offline.
- Windows may keep an allowed answer for at most 60 seconds (`max_client_ttl`), so a new block
  takes effect within about a minute. Blocked answers last 5 seconds, so allowing a site is quick.
- Blocked names, our own status name and cached answers are answered without waiting for the
  network, so the engine stays responsive even while the internet is down.
- Safety switch: the task **Aegis DNS filter safety** runs as SYSTEM. It starts as soon as
  Windows logs a failed lookup (DNS Client event 1014), and every 15 minutes besides. If Windows
  points at Aegis and Aegis has been silent for 90 seconds in a row (4 minutes after boot, while
  it may still be starting), it sets the adapters Aegis manages back to automatic DNS, so a broken
  filter can't take the internet down for long. It reads nothing from this folder: the adapters
  it may touch are written into it at install time. (If the event trigger can't be set up, it
  falls back to checking every 3 minutes.)
- If the install fails at any step, DNS goes back to how it was and the tasks are removed.
- Settings: `aegis.ini`. Logs: `logs\` (`engine.log`, `blocked-DATE.log`; kept 7 days).
- Install details: `state\install.json` (your previous DNS settings; `.bak` is the last good
  copy) and `state\install-log.txt`. `aegis-setup.ps1` holds what install and uninstall share.

## Rebuilding

`build.ps1` compiles everything with the C# compiler that ships with Windows into `build\`, runs
the unit tests, and only then puts the new files in place, with Aegis still running and no admin
prompt: a running exe is renamed aside (`*.old.exe`, cleared when the next engine starts), the
engine is asked to exit (`restart.aegis.invalid`) and its task started again (about a second
without DNS), and the tray icon is restarted. `-NoDeploy` builds and tests only.
Live checks against a running engine: `build\AegisTests.exe live`.

On a PC configured with an Olympus local signing certificate, the build signs `Aegis.exe`
and `AegisEngine.exe` with that certificate, including builds made with `-NoDeploy`.
The installer verifies both signatures against the machine's pinned signing identity before
changing settings. A pin in the current user hive also enables signing for development
builds. The signing key stays in the Windows certificate store of the account
that builds the apps. A checkout on a PC without the pin can build and install unsigned
executables.
