using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace FlutterFirewallManager
{
    /// <summary>
    /// Event system to allow the FirewallHelper to trigger real-time updates back to the FirewallWorker (TCP Broadcaster)
    /// </summary>
    public static class FirewallEvents
    {
        public static event Func<string, Task>? OnBroadcast;

        public static async Task BroadcastAsync(string eventMessage)
        {
            if (OnBroadcast != null)
            {
                await OnBroadcast.Invoke(eventMessage);
            }
        }
    }

    public static class FirewallHelper
    {
        private const string RulePrefixAllow = "AppManager_Allow_";
        private const string RulePrefixBlock = "AppManager_Block_";

        // Configuration file directory and path for persisting blocked apps list
        private static readonly string BlockedListDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 
            "FlutterFirewallManager"
        );
        private static readonly string BlockedListPath = Path.Combine(BlockedListDir, "blocked_apps.txt");

        // Thread-safe dictionary storing normalized path -> original app path
        private static readonly ConcurrentDictionary<string, string> BlockedApps = new ConcurrentDictionary<string, string>();

        public static bool IsAllowMode { get; set; } = true;

        /// <summary>
        /// Initializes the blocked application list by loading persisted paths from disk.
        /// </summary>
        public static void InitializeBlockedAppsList(ILogger logger)
        {
            try
            {
                if (!Directory.Exists(BlockedListDir))
                {
                    Directory.CreateDirectory(BlockedListDir);
                }

                if (File.Exists(BlockedListPath))
                {
                    var lines = File.ReadAllLines(BlockedListPath);
                    foreach (var line in lines)
                    {
                        string path = line.Trim();
                        if (!string.IsNullOrWhiteSpace(path))
                        {
                            string normalized = NormalizePath(path);
                            BlockedApps[normalized] = path;
                        }
                    }
                    logger.LogInformation("Loaded {Count} blocked applications from disk.", BlockedApps.Count);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to initialize blocked apps list from disk.");
            }
        }

        /// <summary>
        /// Saves the current list of blocked applications to disk.
        /// </summary>
        private static void SaveBlockedApps()
        {
            try
            {
                if (!Directory.Exists(BlockedListDir))
                {
                    Directory.CreateDirectory(BlockedListDir);
                }

                // Write all original paths to the file (one per line)
                File.WriteAllLines(BlockedListPath, BlockedApps.Values);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to write blocked applications database to disk: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Checks if the Windows Firewall is currently enabled.
        /// </summary>
        public static async Task<bool> IsFirewallEnabledAsync(CancellationToken cancellationToken)
        {
            var (exitCode, stdout, stderr) = await RunNetshAsync(new[] { "advfirewall", "show", "allprofiles", "state" }, cancellationToken);
            if (exitCode != 0)
            {
                throw new InvalidOperationException($"Failed to query firewall status. Exit code: {exitCode}. Error: {stderr}");
            }

            var lines = stdout.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            bool anyOn = false;
            bool foundState = false;

            foreach (var line in lines)
            {
                if (line.Contains("State", StringComparison.OrdinalIgnoreCase))
                {
                    foundState = true;
                    if (line.Contains("ON", StringComparison.OrdinalIgnoreCase))
                    {
                        anyOn = true;
                    }
                }
            }

            if (!foundState)
            {
                throw new InvalidOperationException("Could not parse firewall state from netsh output.");
            }

            return anyOn;
        }

        /// <summary>
        /// Adds a permanent inbound and outbound rule to ALLOW all traffic for the specified executable.
        /// Also removes it from the process-kill list.
        /// </summary>
        public static async Task AllowApplicationAsync(string appPath, CancellationToken cancellationToken)
        {
            ValidateAppPath(appPath);
            string appName = Path.GetFileNameWithoutExtension(appPath);
            string allowRuleName = $"{RulePrefixAllow}{appName}";
            string blockRuleName = $"{RulePrefixBlock}{appName}";

            // Remove from local blocking lists and persist to disk
            string normalized = NormalizePath(appPath);
            BlockedApps.TryRemove(normalized, out _);
            SaveBlockedApps();

            // Delete existing rules for this app first to ensure clean state
            await DeleteRuleAsync(allowRuleName, cancellationToken);
            await DeleteRuleAsync(blockRuleName, cancellationToken);

            if (IsAllowMode)
            {
                // In Allow Mode, we don't need to add allow rules because the firewall is disabled
                return;
            }

            // Add inbound and outbound allow rules
            await AddRuleAsync(allowRuleName, "in", "allow", appPath, cancellationToken);
            await AddRuleAsync(allowRuleName, "out", "allow", appPath, cancellationToken);
        }

        /// <summary>
        /// Adds a permanent inbound and outbound rule to BLOCK all traffic for the specified executable.
        /// Also registers it in the process-kill list and immediately terminates any running instance.
        /// </summary>
        public static async Task BlockApplicationAsync(string appPath, CancellationToken cancellationToken)
        {
            ValidateAppPath(appPath);
            string appName = Path.GetFileNameWithoutExtension(appPath);
            string allowRuleName = $"{RulePrefixAllow}{appName}";
            string blockRuleName = $"{RulePrefixBlock}{appName}";

            // Register in the local blocking lists and persist to disk
            string normalized = NormalizePath(appPath);
            BlockedApps[normalized] = appPath;
            SaveBlockedApps();

            if (IsAllowMode)
            {
                // In Allow Mode, we do NOT apply rules or kill processes.
                // We just make sure any existing block rule is deleted to keep it clean.
                await DeleteRuleAsync(allowRuleName, cancellationToken);
                await DeleteRuleAsync(blockRuleName, cancellationToken);
                return;
            }

            // Force close any running instance of the blocked app immediately
            KillProcessesForPath(normalized);

            // Delete existing rules for this app first to ensure clean state
            await DeleteRuleAsync(allowRuleName, cancellationToken);
            await DeleteRuleAsync(blockRuleName, cancellationToken);

            // Add inbound and outbound block rules
            await AddRuleAsync(blockRuleName, "in", "block", appPath, cancellationToken);
            await AddRuleAsync(blockRuleName, "out", "block", appPath, cancellationToken);
        }

        /// <summary>
        /// Scans the firewall status and rule counts. If they have been tampered with or disabled,
        /// it automatically restores the firewall state and re-adds any missing rules.
        /// </summary>
        public static async Task EnforceFirewallIntegrityAsync(ILogger logger, CancellationToken cancellationToken)
        {
            if (IsAllowMode) return;
            // 1. Check and restore Firewall State (Domain, Private, Public profiles must be enabled)
            try
            {
                bool enabled = await IsFirewallEnabledAsync(cancellationToken);
                if (!enabled)
                {
                    logger.LogWarning("Firewall status tampered! Re-enabling all profiles to maintain system integrity...");
                    await LockFirewallAsync(cancellationToken);
                    
                    // Broadcast event to all connected sockets
                    await FirewallEvents.BroadcastAsync("STATUS_RESTORED");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to verify or restore firewall enabled status.");
            }

            // 2. Check and restore individual blocked app rules
            if (BlockedApps.IsEmpty) return;

            try
            {
                var ruleCounts = GetActiveRuleNameCounts(logger);
                
                foreach (var kvp in BlockedApps)
                {
                    string appPath = kvp.Value;
                    string appName = Path.GetFileNameWithoutExtension(appPath);
                    string blockRuleName = $"{RulePrefixBlock}{appName}";

                    // We expect exactly 2 rules: one inbound and one outbound
                    ruleCounts.TryGetValue(blockRuleName, out int count);
                    if (count < 2)
                    {
                        logger.LogWarning("Firewall rule integrity violation detected for '{AppName}' (Expected 2 rules, found {Count}). Re-applying block rules...", appName, count);
                        
                        // Re-apply rules
                        await BlockApplicationAsync(appPath, cancellationToken);
                        
                        // Broadcast event to all connected sockets
                        await FirewallEvents.BroadcastAsync($"RULE_RESTORED:{appName}");
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to enforce firewall rule integrity.");
            }
        }

        /// <summary>
        /// Reads all active rules from the Windows Firewall using fast native COM Interop (FwPolicy2).
        /// Returns a map of ruleName -> occurrenceCount. Spawns 0 external processes.
        /// </summary>
        private static Dictionary<string, int> GetActiveRuleNameCounts(ILogger logger)
        {
            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            try
            {
#pragma warning disable CA1416 // Validate platform compatibility
#pragma warning disable IL2072 // Dynamically accessed members annotations
#pragma warning disable IL2075 // Dynamically accessed members annotations
                Type? fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (fwPolicyType == null)
                {
                    logger.LogWarning("HNetCfg.FwPolicy2 COM object is not available on this machine.");
                    return counts;
                }

                object fwPolicy2 = Activator.CreateInstance(fwPolicyType)!;

                object? rules = fwPolicyType.InvokeMember(
                    "Rules",
                    System.Reflection.BindingFlags.GetProperty,
                    null,
                    fwPolicy2,
                    null
                );

                if (rules is System.Collections.IEnumerable rulesEnum)
                {
                    foreach (object rule in rulesEnum)
                    {
                        if (rule != null)
                        {
                            try
                            {
                                object? nameObj = rule.GetType().InvokeMember(
                                    "Name",
                                    System.Reflection.BindingFlags.GetProperty,
                                    null,
                                    rule,
                                    null
                                );

                                string? name = nameObj as string;
                                if (!string.IsNullOrEmpty(name))
                                {
                                    counts.TryGetValue(name, out int count);
                                    counts[name] = count + 1;
                                }
                            }
                            catch (Exception ex)
                            {
                                logger.LogDebug(ex, "Failed to read name of a firewall rule via reflection.");
                            }
                            finally
                            {
                                System.Runtime.InteropServices.Marshal.ReleaseComObject(rule);
                            }
                        }
                    }
                }

                if (rules != null)
                {
                    System.Runtime.InteropServices.Marshal.ReleaseComObject(rules);
                }
                System.Runtime.InteropServices.Marshal.ReleaseComObject(fwPolicy2);
#pragma warning restore IL2075
#pragma warning restore IL2072
#pragma warning restore CA1416
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error reading active firewall rules collection via COM Interop.");
            }
            return counts;
        }

        /// <summary>
        /// Scans running Windows processes and forcefully terminates any that are in the blocked list.
        /// </summary>
        public static void ForceCloseRunningBlockedApps(ILogger logger)
        {
            if (IsAllowMode) return;
            if (BlockedApps.IsEmpty) return;

            int currentPid = Environment.ProcessId;

            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    if (process.Id == currentPid) continue;

                    string path = process.MainModule?.FileName ?? "";
                    if (string.IsNullOrEmpty(path)) continue;

                    string normalized = NormalizePath(path);
                    if (BlockedApps.ContainsKey(normalized))
                    {
                        logger.LogWarning("Force closing running blocked application: {Path} (PID: {Pid})", path, process.Id);
                        process.Kill(true);
                    }
                }
                catch (Exception)
                {
                    // Ignore processes we do not have permission to inspect (system processes)
                    // or processes that exit while we query them.
                }
            }
        }

        /// <summary>
        /// Forcefully kills all running processes that match a specific executable path.
        /// </summary>
        public static void KillProcessesForPath(string appPath)
        {
            string normalizedPath = NormalizePath(appPath);
            int currentPid = Environment.ProcessId;

            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    if (process.Id == currentPid) continue;

                    string path = process.MainModule?.FileName ?? "";
                    if (string.IsNullOrEmpty(path)) continue;

                    if (NormalizePath(path) == normalizedPath)
                    {
                        process.Kill(true);
                    }
                }
                catch (Exception)
                {
                    // Ignore access errors on system processes
                }
            }
        }

        /// <summary>
        /// Normalizes a path string for case-insensitive comparison on Windows.
        /// </summary>
        public static string NormalizePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return "";
            try
            {
                return Path.GetFullPath(path).Trim().ToLowerInvariant();
            }
            catch
            {
                return path.Trim().ToLowerInvariant();
            }
        }

        /// <summary>
        /// Enables the firewall for all profiles (Domain, Private, Public).
        /// </summary>
        public static async Task LockFirewallAsync(CancellationToken cancellationToken)
        {
            var (exitCode, stdout, stderr) = await RunNetshAsync(new[] { "advfirewall", "set", "allprofiles", "state", "on" }, cancellationToken);
            if (exitCode != 0)
            {
                throw new InvalidOperationException($"Failed to lock firewall (enable state). Exit code: {exitCode}. Error: {stderr.Trim()} {stdout.Trim()}");
            }
        }

        /// <summary>
        /// Disables the firewall for all profiles (Domain, Private, Public).
        /// </summary>
        public static async Task UnlockFirewallAsync(CancellationToken cancellationToken)
        {
            var (exitCode, stdout, stderr) = await RunNetshAsync(new[] { "advfirewall", "set", "allprofiles", "state", "off" }, cancellationToken);
            if (exitCode != 0)
            {
                throw new InvalidOperationException($"Failed to unlock firewall (disable state). Exit code: {exitCode}. Error: {stderr.Trim()} {stdout.Trim()}");
            }
        }

        /// <summary>
        /// Resets the Windows Firewall configuration to default settings.
        /// </summary>
        public static async Task ResetFirewallAsync(CancellationToken cancellationToken)
        {
            var (exitCode, stdout, stderr) = await RunNetshAsync(new[] { "advfirewall", "reset" }, cancellationToken);
            if (exitCode != 0)
            {
                throw new InvalidOperationException($"Failed to reset firewall. Exit code: {exitCode}. Error: {stderr.Trim()} {stdout.Trim()}");
            }
        }

        private static void ValidateAppPath(string appPath)
        {
            if (string.IsNullOrWhiteSpace(appPath))
            {
                throw new ArgumentException("Application path cannot be empty.");
            }

            try
            {
                string fullPath = Path.GetFullPath(appPath);
                string ext = Path.GetExtension(fullPath);
                if (!ext.Equals(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    throw new ArgumentException("The path must point to an executable (.exe) file.");
                }
            }
            catch (Exception ex) when (ex is not ArgumentException)
            {
                throw new ArgumentException($"Invalid application path format: {ex.Message}", ex);
            }
        }

        private static async Task DeleteRuleAsync(string ruleName, CancellationToken cancellationToken)
        {
            var (exitCode, stdout, stderr) = await RunNetshAsync(new[]
            {
                "advfirewall", "firewall", "delete", "rule", $"name={ruleName}"
            }, cancellationToken);

            if (exitCode != 0 &&
                !stdout.Contains("No rules match", StringComparison.OrdinalIgnoreCase) &&
                !stderr.Contains("No rules match", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"Failed to delete firewall rule '{ruleName}'. Exit code: {exitCode}. Error: {stderr.Trim()} {stdout.Trim()}");
            }
        }

        private static async Task AddRuleAsync(string ruleName, string direction, string action, string appPath, CancellationToken cancellationToken)
        {
            var (exitCode, stdout, stderr) = await RunNetshAsync(new[]
            {
                "advfirewall", "firewall", "add", "rule",
                $"name={ruleName}",
                $"dir={direction}",
                $"action={action}",
                $"program={appPath}",
                "enable=yes"
            }, cancellationToken);

            if (exitCode != 0)
            {
                throw new InvalidOperationException($"Failed to add firewall rule '{ruleName}' ({direction}). Exit code: {exitCode}. Error: {stderr.Trim()} {stdout.Trim()}");
            }
        }

        /// <summary>
        /// Securely executes netsh.exe with the given arguments using ProcessStartInfo.ArgumentList.
        /// This ensures argument separation and prevents command execution injection vulnerabilities.
        /// </summary>
        private static async Task<(int ExitCode, string StdOut, string StdErr)> RunNetshAsync(string[] arguments, CancellationToken cancellationToken)
        {
            using var process = new Process();
            process.StartInfo.FileName = "netsh.exe";
            
            foreach (var arg in arguments)
            {
                process.StartInfo.ArgumentList.Add(arg);
            }

            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;

            process.StartInfo.StandardOutputEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
            process.StartInfo.StandardErrorEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);

            try
            {
                process.Start();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to start netsh.exe process. Ensure the service has appropriate system privileges.", ex);
            }

            var stdOutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stdErrTask = process.StandardError.ReadToEndAsync(cancellationToken);

            await process.WaitForExitAsync(cancellationToken);

            return (process.ExitCode, await stdOutTask, await stdErrTask);
        }

        /// <summary>
        /// Transitions the service mode between LOCKDOWN (default) and ALLOW.
        /// In ALLOW mode:
        /// 1. We remove all block rules for currently registered blocked applications.
        /// 2. We unlock/disable the Windows Firewall.
        /// 3. Process monitor loops and integrity loops are suspended.
        /// In LOCKDOWN mode:
        /// 1. We lock/enable the Windows Firewall.
        /// 2. We re-apply block rules for all registered blocked applications.
        /// 3. Background enforcement and process monitoring resume.
        /// </summary>
        public static async Task SetAllowModeAsync(bool enableAllowMode, ILogger logger, CancellationToken cancellationToken)
        {
            IsAllowMode = enableAllowMode;
            if (enableAllowMode)
            {
                logger.LogInformation("Transitioning to ALLOW mode. Suspending lockdown enforcement and removing firewall block rules...");
                // 1. Remove all block rules for currently registered blocked applications
                foreach (var kvp in BlockedApps)
                {
                    try
                    {
                        string appName = Path.GetFileNameWithoutExtension(kvp.Value);
                        string blockRuleName = $"{RulePrefixBlock}{appName}";
                        string allowRuleName = $"{RulePrefixAllow}{appName}";
                        await DeleteRuleAsync(blockRuleName, cancellationToken);
                        await DeleteRuleAsync(allowRuleName, cancellationToken);
                        logger.LogInformation("Removed firewall rules for '{AppName}' due to ALLOW mode transition.", appName);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Failed to remove rules for '{AppName}' during ALLOW mode transition.", kvp.Value);
                    }
                }
                
                // 2. Unlock/disable the firewall profiles
                try
                {
                    await UnlockFirewallAsync(cancellationToken);
                    logger.LogInformation("Firewall profiles disabled due to ALLOW mode transition.");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to disable firewall profiles during ALLOW mode transition.");
                }
            }
            else
            {
                logger.LogInformation("Transitioning to LOCKDOWN mode. Re-enabling firewall and applying block rules...");
                // 1. Lock/enable the firewall profiles
                try
                {
                    await LockFirewallAsync(cancellationToken);
                    logger.LogInformation("Firewall profiles enabled due to LOCKDOWN mode transition.");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to enable firewall profiles during LOCKDOWN mode transition.");
                }

                // 2. Re-apply block rules for all registered applications
                foreach (var kvp in BlockedApps)
                {
                    try
                    {
                        await BlockApplicationAsync(kvp.Value, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Failed to re-apply block rule for '{AppName}' during LOCKDOWN mode transition.", kvp.Value);
                    }
                }
            }
        }
    }
}
