using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("Olympus Suite Setup")]
[assembly: AssemblyProduct("Olympus Suite")]

internal static class Setup
{
    const string Title = "Olympus Suite Setup";
    const string OlympusRelease = "Olympus Release";
    const string AegisRelease = "Olympus Aegis";
    const string IncompleteMarker = "installation-incomplete";
    const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string PinKey = @"SOFTWARE\Olympus\ReleaseSigning";
    static readonly string ProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    static readonly SecurityIdentifier Administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
    static readonly SecurityIdentifier SystemUser = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
    static readonly SecurityIdentifier Users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
    static readonly SecurityIdentifier TrustedInstaller = new SecurityIdentifier(
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    static readonly string[] Apps = {
        "Olympus", "Argus", "Sibyl", "Janus", "Arachne", "Athena", "Cerberus", "Ark", "Ares", "Atlas"
    };
    enum AegisState { Absent, Bundled, Standalone }

    [STAThread]
    static int Main(string[] args)
    {
        bool verifyOnly = args.Length == 1 && args[0] == "--verify-only";
        if (verifyOnly)
        {
            try { using (OpenVerifiedBundle()) { } return 0; }
            catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }
        }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        try
        {
            if (args.Length == 3 && args[0] == "--install-elevated" &&
                (args[1] == "Olympus" || args[1] == "All"))
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    if (!new WindowsPrincipal(identity).IsInRole(Administrators) || args[2] != identity.User.Value)
                        throw new InvalidOperationException("Open Setup from an administrator account and approve its Windows prompt using that same account.");
                    Install(args[1] == "All");
                }
            }
            else if (args.Length == 0)
            {
                using (OpenVerifiedBundle()) { }
                ShowWelcome();
            }
            else throw new ArgumentException("Unsupported setup option.");
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    static void ShowWelcome()
    {
        using (var window = new Form())
        using (var explanation = new Label())
        using (var aegis = new CheckBox())
        using (var note = new Label())
        using (var install = new Button())
        using (var cancel = new Button())
        {
            window.Text = Title;
            window.Font = SystemFonts.MessageBoxFont;
            window.AutoScaleMode = AutoScaleMode.Font;
            window.StartPosition = FormStartPosition.CenterScreen;
            window.FormBorderStyle = FormBorderStyle.FixedDialog;
            window.MaximizeBox = false;
            window.MinimizeBox = false;
            window.ClientSize = new Size(510, 211);

            bool update = File.Exists(Path.Combine(ProgramFiles, "Olympus", "Olympus.exe"));
            explanation.Location = new Point(20, 20);
            explanation.Size = new Size(470, 46);
            explanation.Text = update
                ? "Update Olympus and its nine apps, including Atlas, using the existing Olympus updater."
                : "Install the Olympus app hub and its nine apps, including Atlas.";

            aegis.Location = new Point(20, 75);
            aegis.Size = new Size(470, 24);
            string aegisStartup = AegisStartupEntry();
            bool bundledAegis = UsesBundledAegis(aegisStartup);
            aegis.Text = bundledAegis ? "Update Aegis DNS filtering" : "Set up Aegis DNS filtering";
            aegis.Enabled = bundledAegis || String.IsNullOrWhiteSpace(aegisStartup);
            aegis.Checked = bundledAegis;
            note.Location = new Point(40, 105);
            note.Size = new Size(450, 48);
            note.Text = bundledAegis ? "Keep your existing DNS settings and Aegis preferences." :
                aegis.Enabled ? "Aegis changes this PC's DNS settings to filter domains. An existing Aegis setup is kept." :
                "Aegis is already set to start with Windows.";

            install.Location = new Point(318, 164);
            install.Size = new Size(87, 30);
            install.Text = update ? "Update" : "Install";
            cancel.Location = new Point(411, 164);
            cancel.Size = new Size(79, 30);
            cancel.Text = "Close";
            cancel.DialogResult = DialogResult.Cancel;
            window.AcceptButton = install;
            window.CancelButton = cancel;
            window.Controls.AddRange(new Control[] { explanation, aegis, note, install, cancel });
            bool installing = false;
            window.FormClosing += (sender, eventArgs) => { eventArgs.Cancel = installing; };
            install.Click += async (sender, eventArgs) =>
            {
                installing = true;
                window.UseWaitCursor = true;
                window.Enabled = false;
                string previous = explanation.Text;
                explanation.Text = "Setting up Olympus. This can take a minute after you approve the Windows prompt.";
                try
                {
                    using (var identity = WindowsIdentity.GetCurrent())
                    using (var child = Process.Start(new ProcessStartInfo(
                        Assembly.GetExecutingAssembly().Location,
                        "--install-elevated " + (aegis.Checked ? "All" : "Olympus") + " " + identity.User.Value)
                    {
                        UseShellExecute = true,
                        Verb = "runas",
                        WorkingDirectory = Environment.SystemDirectory
                    }))
                    {
                        await Task.Run(() => child.WaitForExit());
                        if (child.ExitCode == 0)
                        {
                            installing = false;
                            window.Close();
                            return;
                        }
                    }
                }
                catch (Win32Exception ex)
                {
                    if (ex.NativeErrorCode != 1223)
                        MessageBox.Show(window, ex.Message, Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                finally
                {
                    installing = false;
                    if (!window.IsDisposed)
                    {
                        explanation.Text = previous;
                        window.Enabled = true;
                        window.UseWaitCursor = false;
                    }
                }
            };
            window.ShowDialog();
        }
    }

    static string AegisStartupEntry()
    {
        using (RegistryKey run = Registry.CurrentUser.OpenSubKey(RunKey))
            return run != null ? run.GetValue("Aegis") as string : null;
    }

    static bool UsesBundledAegis(string startup)
    {
        string target = "\"" + Path.Combine(ProgramFiles, AegisRelease, "Aegis.exe") + "\"";
        return !String.IsNullOrWhiteSpace(startup) &&
            (startup.Equals(target, StringComparison.OrdinalIgnoreCase) ||
            startup.StartsWith(target + " ", StringComparison.OrdinalIgnoreCase));
    }

    static ZipArchive OpenVerifiedBundle()
    {
        Assembly assembly = Assembly.GetExecutingAssembly();
        string expectedHash = assembly.GetCustomAttributes(typeof(AssemblyMetadataAttribute), false)
            .Cast<AssemblyMetadataAttribute>().Single(a => a.Key == "BundleSha256").Value;
        Stream stream = assembly.GetManifestResourceStream("Olympus.Payload.zip");
        if (stream == null) throw new InvalidDataException("The installer is missing its application bundle.");

        try
        {
            string actualHash;
            using (SHA256 sha = SHA256.Create())
                actualHash = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
            if (!String.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The installer bundle did not pass its integrity check. Download the ZIP again.");

            stream.Position = 0;
            var zip = new ZipArchive(stream, ZipArchiveMode.Read);
            var expected = new HashSet<string>(BundleFiles(), StringComparer.Ordinal);
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                // Older .NET ZIP creation uses Windows separators.
                if (!expected.Remove(EntryPath(entry)) || entry.Length == 0)
                    throw new InvalidDataException("Unexpected bundle file: " + entry.FullName);
            }
            if (expected.Count != 0)
                throw new InvalidDataException("Missing bundle file: " + expected.OrderBy(p => p).First());
            return zip;
        }
        catch { stream.Dispose(); throw; }
    }

    static string EntryPath(ZipArchiveEntry entry)
    {
        return entry.FullName.Replace('\\', '/');
    }

    static IEnumerable<string> BundleFiles()
    {
        foreach (string name in Apps)
        {
            yield return "Olympus/bin/" + name + ".exe";
            yield return "Olympus/assets/" + name.ToLowerInvariant() + ".ico";
        }
        foreach (string name in new[] {
            "bin/arachne.ini", "bin/atlas.ini", "install.ps1", "install.cmd", "update.ps1",
            "update.cmd", "uninstall.ps1", "uninstall.cmd", "olympus-setup.ps1",
            "olympus-release.ps1", "release-signing.ps1"
        }) yield return "Olympus/" + name;
        foreach (string name in new[] {
            "Aegis.exe", "AegisEngine.exe", "aegis.ico", "aegis.ini", "install.ps1", "install.cmd",
            "uninstall.ps1", "uninstall.cmd", "aegis-setup.ps1", "release-signing.ps1"
        }) yield return "Aegis/" + name;
    }

    static void Install(bool includeAegis)
    {
        CheckProtected(new DirectoryInfo(ProgramFiles));
        using (var lockFile = new FileStream(Path.Combine(ProgramFiles, "Olympus Suite Setup.lock"),
            FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.DeleteOnClose))
        using (ZipArchive zip = OpenVerifiedBundle())
        {
            string work = Path.Combine(ProgramFiles, "Olympus Suite Setup-" + Guid.NewGuid().ToString("N"));
            DirectoryInfo workDir = CreateProtectedDirectory(work);
            bool olympusInstalled = false;
            bool keepWork = false;
            string summary = "Olympus is ready.";
            try
            {
                string olympus = Extract(zip, work, "Olympus");
                string aegis = null;
                AegisState aegisState = AegisState.Absent;
                if (includeAegis)
                {
                    aegisState = ReadAegisState();
                    if (aegisState == AegisState.Standalone)
                        summary += "\n\nYour existing Aegis installation was kept.";
                    else
                        aegis = Extract(zip, work, "Aegis");
                }
                VerifyPinnedBuild(olympus, aegis);

                bool update = OlympusIsInstalled();
                if (!update) File.WriteAllText(Path.Combine(olympus, IncompleteMarker), "Run Setup again to complete installation.");
                string stage = MoveIntoPlace(olympus, OlympusRelease);
                RunScript(Path.Combine(stage, "olympus-release.ps1"),
                    " -Operation " + (update ? "Update" : "Install") + " -NoPause");
                if (!update) File.Delete(Path.Combine(stage, IncompleteMarker));
                olympusInstalled = true;

                if (aegis != null)
                {
                    if (aegisState == AegisState.Bundled)
                    {
                        UpdateAegis(aegis, ref keepWork);
                        summary += "\n\nAegis is up to date.";
                    }
                    else
                    {
                        string aegisPath = MoveIntoPlace(aegis, AegisRelease);
                        RunScript(Path.Combine(aegisPath, "install.ps1"), "");
                        summary += "\n\nAegis DNS filtering is on.";
                    }
                }
            }
            catch (Exception ex)
            {
                if (olympusInstalled)
                    throw new InvalidOperationException("Olympus is ready. Aegis setup stopped.\n\n" + ex.Message, ex);
                throw;
            }
            finally
            {
                if (!keepWork)
                {
                    try
                    {
                        CheckProtected(workDir);
                        workDir.Delete(true);
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            MessageBox.Show(summary, Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    static AegisState ReadAegisState()
    {
        string expected = Path.Combine(ProgramFiles, AegisRelease, "AegisEngine.exe");
        string result = RunPowerShell("$tasks = @(Get-ScheduledTask | Where-Object { " +
            "$_.TaskPath -eq '\\' -and $_.TaskName -in 'Aegis DNS filter', 'Aegis DNS filter safety' }); " +
            "$engine = $tasks | Where-Object TaskName -eq 'Aegis DNS filter'; " +
            "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); " +
            "$owned = $engine.Principal.UserId -in $identity.Name, $identity.User.Value; " +
            "if ($engine -and $engine.State -ne 'Disabled' -and @($engine.Actions).Count -eq 1 -and " +
            "$owned -and $engine.Actions[0].Execute -eq " + PsLiteral(expected) +
            ") { 'Bundled' } elseif ($tasks.Count) { 'Standalone' } else { 'Absent' }");
        string startup = AegisStartupEntry();
        if (!String.IsNullOrWhiteSpace(startup) && !UsesBundledAegis(startup)) return AegisState.Standalone;
        AegisState state = (AegisState)Enum.Parse(typeof(AegisState), result.Trim());
        return state == AegisState.Absent && UsesBundledAegis(startup) ? AegisState.Standalone : state;
    }

    static void UpdateAegis(string source, ref bool keepWork)
    {
        string target = Path.Combine(ProgramFiles, AegisRelease);
        CheckProtected(new DirectoryInfo(target));
        string[] changed = Directory.GetFiles(source).Where(file =>
        {
            string installed = Path.Combine(target, Path.GetFileName(file));
            if (!File.Exists(installed)) return true;
            CheckProtected(new FileInfo(installed));
            return !String.Equals(FileHash(file), FileHash(installed), StringComparison.Ordinal);
        }).ToArray();
        if (changed.Length == 0) return;

        string task = " -TaskPath '\\' -TaskName 'Aegis DNS filter'";
        string tray = Path.Combine(target, "Aegis.exe");
        string shutdown = "Disable-ScheduledTask" + task + " | Out-Null; " +
            "Stop-ScheduledTask" + task + " -ErrorAction SilentlyContinue; " +
            "Get-Process -Name AegisEngine, Aegis -ErrorAction SilentlyContinue | Where-Object { " +
            "$_.Path -in " + PsLiteral(Path.Combine(target, "AegisEngine.exe")) + ", " + PsLiteral(tray) +
            " } | ForEach-Object { Stop-Process -InputObject $_ -Force; $_.WaitForExit(5000) | Out-Null }";
        string startup = "Enable-ScheduledTask" + task + " | Out-Null; Start-ScheduledTask" + task;
        var replaced = new List<string>();
        try
        {
            RunPowerShell(shutdown);
            foreach (string file in changed)
            {
                string installed = Path.Combine(target, Path.GetFileName(file));
                if (File.Exists(installed)) File.Replace(file, installed, file + ".previous");
                else File.Move(file, installed);
                replaced.Add(file);
            }
            RunPowerShell(startup + "; . " + PsLiteral(Path.Combine(target, "aegis-setup.ps1")) +
                "; $ready = $false; for ($i = 0; $i -lt 15 -and -not $ready; $i++) { " +
                "Start-Sleep -Seconds 1; $ready = Test-EngineEverywhere }; " +
                "if (-not $ready) { throw 'Aegis did not restart. Check its engine log for details.' }");
        }
        catch
        {
            try
            {
                RunPowerShell(shutdown);
                foreach (string file in Enumerable.Reverse(replaced))
                {
                    string installed = Path.Combine(target, Path.GetFileName(file));
                    string backup = file + ".previous";
                    if (File.Exists(backup)) File.Replace(backup, installed, null);
                    else File.Delete(installed);
                }
                RunPowerShell(startup);
            }
            catch (Exception ex)
            {
                keepWork = true;
                throw new InvalidOperationException("Aegis could not restore the previous version. Saved files: " +
                    source + "\n\n" + ex.Message, ex);
            }
            throw;
        }
        finally
        {
            try
            {
                using (Process.Start(new ProcessStartInfo(
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"),
                    "\"" + tray + "\"") { UseShellExecute = false })) { }
            }
            catch (Win32Exception) { }
        }
    }

    static string FileHash(string path)
    {
        using (SHA256 sha = SHA256.Create())
        using (Stream stream = File.OpenRead(path))
            return BitConverter.ToString(sha.ComputeHash(stream));
    }

    static bool OlympusIsInstalled()
    {
        if (!File.Exists(Path.Combine(ProgramFiles, "Olympus", "Olympus.exe")) ||
            File.Exists(Path.Combine(ProgramFiles, OlympusRelease, IncompleteMarker)))
            return false;
        string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Olympus");
        if (!File.Exists(Path.Combine(data, "install.json")) || !File.Exists(Path.Combine(data, "install-state.json")))
            return false;
        CheckProtected(new DirectoryInfo(data));
        CheckProtected(new FileInfo(Path.Combine(data, "install.json")));
        string result = RunPowerShell(
            "$names = @(Get-ScheduledTask -TaskPath '\\Olympus\\' -ErrorAction SilentlyContinue | ForEach-Object TaskName); " +
            "$info = Get-Content -Raw -LiteralPath " + PsLiteral(Path.Combine(data, "install.json")) + " | ConvertFrom-Json; " +
            "$owner = [Security.Principal.SecurityIdentifier]$info.User.Sid; " +
            "$key = 'Registry::HKEY_USERS\\' + $owner.Value + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'; " +
            "$startup = (Get-ItemProperty -LiteralPath $key -Name Olympus -ErrorAction SilentlyContinue).Olympus; " +
            "$known = @(('Argus', 'Ark', 'Athena', 'Cerberus', 'Arachne') | Where-Object { $_ -in $names }); " +
            "($known.Count -eq 5 -and ($startup -or $owner.Value -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value))");
        return result.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
    }

    static DirectoryInfo CreateProtectedDirectory(string path)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(Administrators);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, inherit,
            PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(SystemUser, FileSystemRights.FullControl, inherit,
            PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, inherit,
            PropagationFlags.None, AccessControlType.Allow));
        DirectoryInfo directory = Directory.CreateDirectory(path, security);
        CheckProtected(directory);
        return directory;
    }

    static bool Trusted(IdentityReference sid)
    {
        return sid.Equals(Administrators) || sid.Equals(SystemUser) || sid.Equals(TrustedInstaller);
    }

    static void CheckProtected(FileSystemInfo item)
    {
        if ((item.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Windows redirected a protected setup item: " + item.FullName);
        var directory = item as DirectoryInfo;
        const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Access;
        FileSystemSecurity security = directory != null ? (FileSystemSecurity)directory.GetAccessControl(sections) :
            ((FileInfo)item).GetAccessControl(sections);
        AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
        const int writes = (int)(FileSystemRights.Write | FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership) |
            0x50000000;
        if (!Trusted(security.GetOwner(typeof(SecurityIdentifier))) || rules.Count == 0)
            throw new IOException("The setup item needs an administrator owner: " + item.FullName);
        foreach (FileSystemAccessRule rule in rules)
            if (rule.AccessControlType == AccessControlType.Allow &&
                (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0 &&
                ((int)rule.FileSystemRights & writes) != 0 && !Trusted(rule.IdentityReference))
                throw new IOException("Windows permits standard-user changes to a protected setup item: " + item.FullName);
    }

    static string Extract(ZipArchive zip, string work, string component)
    {
        string root = Path.Combine(work, component);
        CreateProtectedDirectory(root);
        foreach (ZipArchiveEntry entry in zip.Entries)
        {
            string path = EntryPath(entry);
            if (!path.StartsWith(component + "/", StringComparison.Ordinal)) continue;
            string destination = Path.Combine(work, path.Replace('/', '\\'));
            string directory = Path.GetDirectoryName(destination);
            if (!Directory.Exists(directory)) CreateProtectedDirectory(directory);
            using (Stream source = entry.Open())
            using (Stream file = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                source.CopyTo(file);
            var security = File.GetAccessControl(destination, AccessControlSections.Owner);
            security.SetOwner(Administrators);
            File.SetAccessControl(destination, security);
        }
        return root;
    }

    static string MoveIntoPlace(string source, string directoryName)
    {
        string target = Path.Combine(ProgramFiles, directoryName);
        string previous = null;
        if (Directory.Exists(target))
        {
            CheckProtected(new DirectoryInfo(target));
            previous = target + ".previous-" + Guid.NewGuid().ToString("N");
            Directory.Move(target, previous);
        }
        try { Directory.Move(source, target); }
        catch
        {
            if (previous != null && !Directory.Exists(target)) Directory.Move(previous, target);
            throw;
        }
        return target;
    }

    static void VerifyPinnedBuild(string olympus, string aegis)
    {
        bool hasPin;
        using (RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        using (RegistryKey key = machine.OpenSubKey(PinKey))
            hasPin = key != null;
        if (!hasPin) return;

        var files = Directory.GetFiles(Path.Combine(olympus, "bin"), "*.exe").AsEnumerable();
        if (aegis != null) files = files.Concat(Directory.GetFiles(aegis, "*.exe"));
        try
        {
            RunPowerShell(". " + PsLiteral(Path.Combine(olympus, "release-signing.ps1")) +
                "; $pin = Get-OlympusSigningPin; if ($pin) { foreach ($file in @(" +
                String.Join(",", files.Select(PsLiteral)) + ")) { Assert-OlympusArtifactSignature $file $pin } }");
        }
        catch (InvalidOperationException ex)
        {
            throw new InvalidOperationException("This PC has an Olympus signing certificate configured. Use a locally signed ZIP that matches it.\n\n" + ex.Message, ex);
        }
    }

    static string PsLiteral(string value)
    {
        return "'" + value.Replace("'", "''") + "'";
    }

    static void RunScript(string path, string arguments)
    {
        RunPowerShell("$LASTEXITCODE = 0; & " + PsLiteral(path) + arguments + "; exit $LASTEXITCODE");
    }

    static string RunPowerShell(string command)
    {
        string exe = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(
            "$ErrorActionPreference = 'Stop'; " + command));
        var invocation = new ProcessStartInfo(exe, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Environment.SystemDirectory
        };
        invocation.EnvironmentVariables["PSModulePath"] = Path.Combine(Path.GetDirectoryName(exe), "Modules");
        invocation.EnvironmentVariables["PATH"] = Environment.SystemDirectory + ";" +
            Environment.GetFolderPath(Environment.SpecialFolder.Windows) + ";" + Path.Combine(Environment.SystemDirectory, "Wbem");
        var errors = new StringBuilder();
        using (Process child = Process.Start(invocation))
        {
            child.ErrorDataReceived += (sender, e) => { if (e.Data != null) errors.AppendLine(e.Data); };
            child.BeginErrorReadLine();
            string output = child.StandardOutput.ReadToEnd();
            child.WaitForExit();
            if (child.ExitCode != 0)
            {
                string detail = (output + "\n" + errors).Trim();
                if (detail.Length > 1600) detail = detail.Substring(detail.Length - 1600);
                throw new InvalidOperationException(detail.Length == 0 ? "The setup script failed." : detail);
            }
            return output;
        }
    }
}
