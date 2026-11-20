# Olympus Security Suite

Olympus is a personal security and maintenance hub for 64-bit Windows. It brings together Argus, Sibyl, Janus, Arachne, Athena, Cerberus, Ark, Ares, and Atlas. Aegis provides DNS filtering and comes in the same installer.

## Restore on a new PC

Use a 64-bit Windows 10 or 11 PC with .NET Framework 4.8 and Windows PowerShell 5.1. Sign in to Windows with an administrator account so the same account can approve setup.

1. Sign in to GitHub with an account that has access to this private repository.
2. Download **Olympus-Windows-x64.zip** from the [latest release](https://github.com/brodery/olympus-suite/releases/latest).
3. Extract the ZIP, then open **Setup.exe**. Windows will ask for administrator approval to register scheduled tasks.
4. Choose **Set up Aegis DNS filtering** if you want it to configure local DNS filtering. Open **Olympus** from the Start menu after setup finishes.

The ZIP includes all the app binaries and default settings needed for setup. GitHub builds are unsigned because the local signing key stays in the Windows certificate store. Windows may show an unknown publisher warning. The release also provides a SHA-256 checksum for verifying the downloaded ZIP.

The GitHub backup contains the application source and defaults. Keep a separate copy of your settings, custom DNS lists, and Ark backup data if you want those after a wipe. Ark uses `A:\Ark` by default on NTFS. If the backup drive has a different letter after reinstalling Windows, change `target` in `%ProgramData%\Olympus\ark\ark.ini`.

## Build and update

Use this checkout for future app changes. To build an installer locally, open Windows PowerShell in the repository folder and run

```powershell
.\build-release.ps1
```

The build puts the installer ZIP and checksum in `dist`. It uses Windows PowerShell 5.1 and the Windows .NET Framework C# compiler. On a PC with Olympus signing configured, build while signed in to the Windows account that holds the matching certificate and key. The installer honors the PC's existing signing requirement.

Run a newer Setup to update an installed suite. Setup also offers to update Aegis if you installed it through the bundle. Standalone Aegis installations continue to use their own updater.

GitHub Actions builds and verifies the installer when the source changes. Push a new version tag such as `v1.0.1` to publish a fresh installer and checksum under **Releases**. The build bundles the current app code automatically, so ordinary app changes need no installer edits.

- [Olympus and the guardians](olympus/README.md)
- [Aegis DNS filter](aegis/README.md)
