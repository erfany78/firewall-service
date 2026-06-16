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
        private static readonly string SafeListPath = Path.Combine(BlockedListDir, "safe_apps.txt");
        private static readonly string StrategyPath = Path.Combine(BlockedListDir, "strategy.txt");

        // Thread-safe dictionary storing normalized path -> original app path
        private static readonly ConcurrentDictionary<string, string> BlockedApps = new ConcurrentDictionary<string, string>();

        // Thread-safe dictionary storing normalized path -> original safe app path
        private static readonly ConcurrentDictionary<string, string> SafeApps = new ConcurrentDictionary<string, string>();

        // Thread-safe dictionary storing active client PIDs -> client app path
        public static readonly ConcurrentDictionary<int, string> ActiveClientPids = new ConcurrentDictionary<int, string>();

        public static bool IsAllowMode { get; set; } = true;

        public enum FilteringStrategy
        {
            Blacklist,
            Whitelist
        }

        public static FilteringStrategy CurrentStrategy { get; private set; } = FilteringStrategy.Blacklist;

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
        /// Initializes the filtering strategy by loading persisted state from disk.
        /// </summary>
        public static void InitializeStrategy(ILogger logger)
        {
            try
            {
                if (File.Exists(StrategyPath))
                {
                    string content = File.ReadAllText(StrategyPath).Trim();
                    if (Enum.TryParse<FilteringStrategy>(content, true, out var strategy))
                    {
                        CurrentStrategy = strategy;
                        logger.LogInformation("Loaded filtering strategy from disk: {Strategy}", CurrentStrategy);
                        return;
                    }
                }
                CurrentStrategy = FilteringStrategy.Blacklist;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to initialize filtering strategy from disk.");
            }
        }

        /// <summary>
        /// Saves the current filtering strategy to disk.
        /// </summary>
        public static void SaveStrategy()
        {
            try
            {
                File.WriteAllText(StrategyPath, CurrentStrategy.ToString());
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to save strategy: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Sets and applies the filtering strategy.
        /// </summary>
        public static async Task SetStrategyAsync(FilteringStrategy strategy, ILogger logger, CancellationToken cancellationToken)
        {
            CurrentStrategy = strategy;
            SaveStrategy();
            
            if (!IsAllowMode)
            {
                await ApplyCurrentStrategyAsync(logger, cancellationToken);
            }
        }

        /// <summary>
        /// Initializes the safe application list by loading persisted paths from disk.
        /// </summary>
        public static void InitializeSafeAppsList(ILogger logger)
        {
            try
            {
                if (!Directory.Exists(BlockedListDir))
                {
                    Directory.CreateDirectory(BlockedListDir);
                }

                if (File.Exists(SafeListPath))
                {
                    var lines = File.ReadAllLines(SafeListPath);
                    foreach (var line in lines)
                    {
                        string path = line.Trim();
                        if (!string.IsNullOrWhiteSpace(path))
                        {
                            string normalized = NormalizePath(path);
                            SafeApps[normalized] = path;
                        }
                    }
                    logger.LogInformation("Loaded {Count} safe applications from disk.", SafeApps.Count);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to initialize safe apps list from disk.");
            }
        }

        /// <summary>
        /// Saves the current list of safe applications to disk.
        /// </summary>
        private static void SaveSafeApps()
        {
            try
            {
                if (!Directory.Exists(BlockedListDir))
                {
                    Directory.CreateDirectory(BlockedListDir);
                }

                File.WriteAllLines(SafeListPath, SafeApps.Values);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to write safe applications database to disk: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Adds a permanent entry to the SAFE list (whitelisted application).
        /// </summary>
        public static async Task AddSafeAppAsync(string appPath, CancellationToken cancellationToken)
        {
            ValidateAppPath(appPath);

            // Log safe app addition to Sentry
            Sentry.SentrySdk.CaptureMessage($"Safe application added: {appPath}", Sentry.SentryLevel.Info);

            string normalized = NormalizePath(appPath);

            // Remove from blocked apps first if present
            if (BlockedApps.ContainsKey(normalized))
            {
                await AllowApplicationAsync(appPath, cancellationToken);
            }

            SafeApps[normalized] = appPath;
            SaveSafeApps();
        }

        /// <summary>
        /// Removes an entry from the SAFE list.
        /// </summary>
        public static void RemoveSafeApp(string appPath)
        {
            if (string.IsNullOrWhiteSpace(appPath)) return;
            string normalized = NormalizePath(appPath);
            SafeApps.TryRemove(normalized, out _);
            SaveSafeApps();
        }

        /// <summary>
        /// Returns a pipe-separated string of currently blocked application paths.
        /// </summary>
        public static string GetBlockedAppsList()
        {
            return string.Join("|", BlockedApps.Values);
        }

        /// <summary>
        /// Returns a pipe-separated string of currently safe/whitelisted application paths.
        /// </summary>
        public static string GetSafeAppsList()
        {
            return string.Join("|", SafeApps.Values);
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

            // Log application allow action to Sentry
            Sentry.SentrySdk.CaptureMessage($"Application allowed: {appPath}", Sentry.SentryLevel.Info);

            string appName = Path.GetFileNameWithoutExtension(appPath);
            string allowRuleName = $"{RulePrefixAllow}{appName}";
            string blockRuleName = $"{RulePrefixBlock}{appName}";
            string normalized = NormalizePath(appPath);

            if (CurrentStrategy == FilteringStrategy.Blacklist)
            {
                // Blacklist strategy: ALLOW means remove from BlockedApps (blacklist)
                BlockedApps.TryRemove(normalized, out _);
                SaveBlockedApps();

                await DeleteRuleAsync(allowRuleName, cancellationToken);
                await DeleteRuleAsync(blockRuleName, cancellationToken);

                if (IsAllowMode)
                {
                    return;
                }

                await AddRuleAsync(allowRuleName, "in", "allow", appPath, cancellationToken);
                await AddRuleAsync(allowRuleName, "out", "allow", appPath, cancellationToken);
            }
            else
            {
                // Whitelist strategy: ALLOW means add to SafeApps (whitelist)
                SafeApps[normalized] = appPath;
                SaveSafeApps();

                // Make sure it's not in BlockedApps
                BlockedApps.TryRemove(normalized, out _);
                SaveBlockedApps();

                await DeleteRuleAsync(allowRuleName, cancellationToken);
                await DeleteRuleAsync(blockRuleName, cancellationToken);

                if (IsAllowMode)
                {
                    return;
                }

                await AddRuleAsync(allowRuleName, "in", "allow", appPath, cancellationToken);
                await AddRuleAsync(allowRuleName, "out", "allow", appPath, cancellationToken);
            }
        }

        /// <summary>
        /// Adds a permanent inbound and outbound rule to BLOCK all traffic for the specified executable.
        /// Also registers it in the process-kill list and immediately terminates any running instance.
        /// </summary>
        public static async Task BlockApplicationAsync(string appPath, CancellationToken cancellationToken)
        {
            ValidateAppPath(appPath);
            VerifyNotCriticalApp(appPath);
            string appName = Path.GetFileNameWithoutExtension(appPath);
            string allowRuleName = $"{RulePrefixAllow}{appName}";
            string blockRuleName = $"{RulePrefixBlock}{appName}";
            string normalized = NormalizePath(appPath);

            // Add to BlockedApps (blacklist)
            BlockedApps[normalized] = appPath;
            SaveBlockedApps();

            // Remove from SafeApps (whitelist)
            SafeApps.TryRemove(normalized, out _);
            SaveSafeApps();

            await DeleteRuleAsync(allowRuleName, cancellationToken);
            await DeleteRuleAsync(blockRuleName, cancellationToken);

            if (IsAllowMode)
            {
                return;
            }

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
                    await ApplyCurrentStrategyAsync(logger, cancellationToken); // Apply policy & rules
                    await FirewallEvents.BroadcastAsync("STATUS_RESTORED");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to verify or restore firewall enabled status.");
            }

            // 2. Check and restore rules based on Strategy
            try
            {
                var ruleCounts = GetActiveRuleNameCounts(logger);

                if (CurrentStrategy == FilteringStrategy.Blacklist)
                {
                    foreach (var kvp in BlockedApps)
                    {
                        string appPath = kvp.Value;
                        string appName = Path.GetFileNameWithoutExtension(appPath);
                        string blockRuleName = $"{RulePrefixBlock}{appName}";

                        ruleCounts.TryGetValue(blockRuleName, out int count);
                        if (count < 2)
                        {
                            logger.LogWarning("Firewall rule integrity violation detected for '{AppName}' (Expected 2 rules, found {Count}). Re-applying block rules...", appName, count);
                            await BlockApplicationAsync(appPath, cancellationToken);
                            await FirewallEvents.BroadcastAsync($"RULE_RESTORED:{appName}");
                        }
                    }
                }
                else
                {
                    // Whitelist strategy self-healing
                    foreach (var kvp in SafeApps)
                    {
                        string appPath = kvp.Value;
                        string appName = Path.GetFileNameWithoutExtension(appPath);
                        string allowRuleName = $"{RulePrefixAllow}{appName}";

                        ruleCounts.TryGetValue(allowRuleName, out int count);
                        if (count < 2)
                        {
                            logger.LogWarning("Firewall rule integrity violation detected for safe app '{AppName}' (Expected 2 rules, found {Count}). Re-applying allow rules...", appName, count);
                            await AddSafeAppAsync(appPath, cancellationToken);
                            await FirewallEvents.BroadcastAsync($"RULE_RESTORED:{appName}");
                        }
                    }

                    // Enforce block rules for BlockedApps in Whitelist mode
                    foreach (var kvp in BlockedApps)
                    {
                        string appPath = kvp.Value;
                        string appName = Path.GetFileNameWithoutExtension(appPath);
                        string blockRuleName = $"{RulePrefixBlock}{appName}";

                        ruleCounts.TryGetValue(blockRuleName, out int count);
                        if (count < 2)
                        {
                            logger.LogWarning("Firewall rule integrity violation detected for blocked app '{AppName}' in whitelist mode (Expected 2 rules, found {Count}). Re-applying block rules...", appName, count);
                            await BlockApplicationAsync(appPath, cancellationToken);
                            await FirewallEvents.BroadcastAsync($"RULE_RESTORED:{appName}");
                        }
                    }

                    // Check system rules (DNS, DHCP, NTP, AD, Loopback, mDNS, NCSI, VPN)
                    if (!ruleCounts.ContainsKey("AppManager_System_DNS_UDP") ||
                        !ruleCounts.ContainsKey("AppManager_System_DNS_TCP") ||
                        !ruleCounts.ContainsKey("AppManager_System_DHCP_Out") ||
                        !ruleCounts.ContainsKey("AppManager_System_NTP_Out") ||
                        !ruleCounts.ContainsKey("AppManager_System_Kerberos_UDP") ||
                        !ruleCounts.ContainsKey("AppManager_System_Kerberos_TCP") ||
                        !ruleCounts.ContainsKey("AppManager_System_LDAP_UDP") ||
                        !ruleCounts.ContainsKey("AppManager_System_LDAP_TCP") ||
                        !ruleCounts.ContainsKey("AppManager_System_Loopback_Out") ||
                        !ruleCounts.ContainsKey("AppManager_System_Loopback_In") ||
                        !ruleCounts.ContainsKey("AppManager_System_mDNS_Out") ||
                        !ruleCounts.ContainsKey("AppManager_System_NCSI_Out") ||
                        !ruleCounts.ContainsKey("AppManager_System_VPN_IKE_UDP") ||
                        !ruleCounts.ContainsKey("AppManager_System_VPN_L2TP_UDP") ||
                        !ruleCounts.ContainsKey("AppManager_System_VPN_PPTP_TCP") ||
                        !ruleCounts.ContainsKey("AppManager_System_VPN_GRE") ||
                        !ruleCounts.ContainsKey("AppManager_System_VPN_ESP") ||
                        !ruleCounts.ContainsKey("AppManager_System_VPN_RasMan") ||
                        !ruleCounts.ContainsKey("AppManager_System_VPN_Ikeext") ||
                        !ruleCounts.ContainsKey("AppManager_System_VPN_SstpSvc"))
                    {
                        logger.LogWarning("System firewall rules tampered! Re-applying DNS/DHCP/NCSI/VPN rules...");
                        await AddSystemRulesAsync(logger, cancellationToken);
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
                    if (ActiveClientPids.ContainsKey(process.Id)) continue; // Safeguard: Never kill dynamic authenticated clients

                    string path = process.MainModule?.FileName ?? "";
                    if (string.IsNullOrEmpty(path)) continue;

                    string normalized = NormalizePath(path);
                    if (SafeApps.ContainsKey(normalized)) continue; // Safeguard: Never kill registered safe applications

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
            VerifyNotCriticalApp(appPath);
            string normalizedPath = NormalizePath(appPath);
            int currentPid = Environment.ProcessId;

            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    if (process.Id == currentPid) continue;
                    if (ActiveClientPids.ContainsKey(process.Id)) continue; // Safeguard: Never kill dynamic authenticated clients

                    string path = process.MainModule?.FileName ?? "";
                    if (string.IsNullOrEmpty(path)) continue;

                    string normalized = NormalizePath(path);
                    if (SafeApps.ContainsKey(normalized)) continue; // Safeguard: Never kill registered safe applications

                    if (normalized == normalizedPath)
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

        /// <summary>
        /// Prevents critical applications and the firewall service itself from being blocked or terminated.
        /// </summary>
        private static void VerifyNotCriticalApp(string appPath)
        {
            if (string.IsNullOrWhiteSpace(appPath)) return;
            string normalized = NormalizePath(appPath);
            string fileName = Path.GetFileName(normalized);

            // 1. Prevent blocking the firewall manager service itself
            string ownPath = NormalizePath(Environment.ProcessPath ?? "");
            if (normalized == ownPath || fileName.Equals("firewall.exe", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Cannot block or terminate the firewall manager service itself.");
            }

            // 2. Prevent blocking any registered safe application
            if (SafeApps.ContainsKey(normalized))
            {
                throw new InvalidOperationException($"Cannot block or terminate safe application: '{appPath}'.");
            }

            // 3. Prevent blocking active client applications dynamically
            foreach (var clientPath in ActiveClientPids.Values)
            {
                if (!string.IsNullOrEmpty(clientPath) && NormalizePath(clientPath) == normalized)
                {
                    throw new InvalidOperationException("Cannot block or terminate the active client application.");
                }
            }

            // 4. Prevent blocking critical Windows system processes
            var criticalApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "explorer.exe",
                "svchost.exe",
                "lsass.exe",
                "wininit.exe",
                "winlogon.exe",
                "services.exe",
                "csrss.exe",
                "smss.exe",
                "taskmgr.exe"
            };

            if (criticalApps.Contains(fileName))
            {
                throw new InvalidOperationException($"Cannot block or terminate critical system process: '{fileName}'.");
            }
        }

        public static async Task DeleteRuleAsync(string ruleName, CancellationToken cancellationToken)
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

        public static async Task AddRuleAsync(string ruleName, string direction, string action, string appPath, CancellationToken cancellationToken)
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
        /// Sets the Windows Firewall policy to block or allow outbound traffic by default.
        /// </summary>
        public static async Task SetFirewallPolicyAsync(bool blockOutboundByDefault, CancellationToken cancellationToken)
        {
            string policy = blockOutboundByDefault ? "blockinbound,blockoutbound" : "blockinbound,allowoutbound";
            var (exitCode, stdout, stderr) = await RunNetshAsync(new[] { "advfirewall", "set", "allprofiles", "firewallpolicy", policy }, cancellationToken);
            if (exitCode != 0)
            {
                throw new InvalidOperationException($"Failed to set firewall policy to {policy}. Exit code: {exitCode}. Error: {stderr.Trim()} {stdout.Trim()}");
            }
        }

        /// <summary>
        /// Removes all AppManager allow rules and system-wide critical rules.
        /// </summary>
        private static async Task DeleteAllAllowRulesAsync(ILogger logger, CancellationToken cancellationToken)
        {
            try
            {
                var ruleCounts = GetActiveRuleNameCounts(logger);
                foreach (var ruleName in ruleCounts.Keys)
                {
                    if (ruleName.StartsWith(RulePrefixAllow, StringComparison.OrdinalIgnoreCase) ||
                        ruleName.StartsWith("AppManager_System_", StringComparison.OrdinalIgnoreCase))
                    {
                        await DeleteRuleAsync(ruleName, cancellationToken);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to delete allow and system rules.");
            }
        }

        /// <summary>
        /// Removes all AppManager block rules.
        /// </summary>
        private static async Task DeleteAllBlockRulesAsync(ILogger logger, CancellationToken cancellationToken)
        {
            try
            {
                var ruleCounts = GetActiveRuleNameCounts(logger);
                foreach (var ruleName in ruleCounts.Keys)
                {
                    if (ruleName.StartsWith(RulePrefixBlock, StringComparison.OrdinalIgnoreCase))
                    {
                        await DeleteRuleAsync(ruleName, cancellationToken);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to delete block rules.");
            }
        }

        /// <summary>
        /// Adds a protocol and port-based system rule.
        /// </summary>
        private static async Task AddSystemRuleAsync(string ruleName, string direction, string action, string protocol, string port, CancellationToken cancellationToken)
        {
            var (exitCode, stdout, stderr) = await RunNetshAsync(new[]
            {
                "advfirewall", "firewall", "add", "rule",
                $"name={ruleName}",
                $"dir={direction}",
                $"action={action}",
                $"protocol={protocol}",
                $"remoteport={port}",
                "enable=yes"
            }, cancellationToken);

            if (exitCode != 0)
            {
                throw new InvalidOperationException($"Failed to add system rule '{ruleName}'. Exit code: {exitCode}. Error: {stderr.Trim()} {stdout.Trim()}");
            }
        }

        /// <summary>
        /// Adds system rules required for basic connectivity (DNS, DHCP) in Whitelist mode.
        /// </summary>
        private static async Task AddSystemRulesAsync(ILogger logger, CancellationToken cancellationToken)
        {
            try
            {
                // 1. DNS UDP Port 53 Outbound
                await DeleteRuleAsync("AppManager_System_DNS_UDP", cancellationToken);
                await AddSystemRuleAsync("AppManager_System_DNS_UDP", "out", "allow", "udp", "53", cancellationToken);

                // 2. DNS TCP Port 53 Outbound
                await DeleteRuleAsync("AppManager_System_DNS_TCP", cancellationToken);
                await AddSystemRuleAsync("AppManager_System_DNS_TCP", "out", "allow", "tcp", "53", cancellationToken);

                // 3. DHCP UDP Port 67,68 Outbound
                await DeleteRuleAsync("AppManager_System_DHCP_Out", cancellationToken);
                await AddSystemRuleAsync("AppManager_System_DHCP_Out", "out", "allow", "udp", "67,68", cancellationToken);

                // 4. NTP UDP Port 123 Outbound (Windows Time)
                await DeleteRuleAsync("AppManager_System_NTP_Out", cancellationToken);
                await AddSystemRuleAsync("AppManager_System_NTP_Out", "out", "allow", "udp", "123", cancellationToken);

                // 5. Active Directory / Kerberos Port 88 UDP/TCP Outbound
                await DeleteRuleAsync("AppManager_System_Kerberos_UDP", cancellationToken);
                await AddSystemRuleAsync("AppManager_System_Kerberos_UDP", "out", "allow", "udp", "88", cancellationToken);
                await DeleteRuleAsync("AppManager_System_Kerberos_TCP", cancellationToken);
                await AddSystemRuleAsync("AppManager_System_Kerberos_TCP", "out", "allow", "tcp", "88", cancellationToken);

                // 6. LDAP Port 389 UDP/TCP Outbound (Active Directory Domain query)
                await DeleteRuleAsync("AppManager_System_LDAP_UDP", cancellationToken);
                await AddSystemRuleAsync("AppManager_System_LDAP_UDP", "out", "allow", "udp", "389", cancellationToken);
                await DeleteRuleAsync("AppManager_System_LDAP_TCP", cancellationToken);
                await AddSystemRuleAsync("AppManager_System_LDAP_TCP", "out", "allow", "tcp", "389", cancellationToken);

                // 7. Loopback Communication (Allow all local loopback)
                await DeleteRuleAsync("AppManager_System_Loopback_Out", cancellationToken);
                await RunNetshAsync(new[]
                {
                    "advfirewall", "firewall", "add", "rule",
                    "name=AppManager_System_Loopback_Out",
                    "dir=out",
                    "action=allow",
                    "remoteip=127.0.0.1",
                    "enable=yes"
                }, cancellationToken);

                await DeleteRuleAsync("AppManager_System_Loopback_In", cancellationToken);
                await RunNetshAsync(new[]
                {
                    "advfirewall", "firewall", "add", "rule",
                    "name=AppManager_System_Loopback_In",
                    "dir=in",
                    "action=allow",
                    "localip=127.0.0.1",
                    "enable=yes"
                }, cancellationToken);

                // 8. Link-Local / mDNS / LLMNR for local name resolution
                await DeleteRuleAsync("AppManager_System_mDNS_Out", cancellationToken);
                await AddSystemRuleAsync("AppManager_System_mDNS_Out", "out", "allow", "udp", "5353,5355", cancellationToken);

                // 9. Windows Network Connectivity Status Indicator (NCSI) HTTP/HTTPS probe
                await DeleteRuleAsync("AppManager_System_NCSI_Out", cancellationToken);
                await RunNetshAsync(new[]
                {
                    "advfirewall", "firewall", "add", "rule",
                    "name=AppManager_System_NCSI_Out",
                    "dir=out",
                    "action=allow",
                    "service=NlaSvc",
                    "protocol=tcp",
                    "remoteport=80,443",
                    "enable=yes"
                }, cancellationToken);

                // 10. VPN IKE/NAT-T Outbound (UDP 500, 4500)
                await DeleteRuleAsync("AppManager_System_VPN_IKE_UDP", cancellationToken);
                await AddSystemRuleAsync("AppManager_System_VPN_IKE_UDP", "out", "allow", "udp", "500,4500", cancellationToken);

                // 11. VPN L2TP Outbound (UDP 1701)
                await DeleteRuleAsync("AppManager_System_VPN_L2TP_UDP", cancellationToken);
                await AddSystemRuleAsync("AppManager_System_VPN_L2TP_UDP", "out", "allow", "udp", "1701", cancellationToken);

                // 12. VPN PPTP Outbound (TCP 1723)
                await DeleteRuleAsync("AppManager_System_VPN_PPTP_TCP", cancellationToken);
                await AddSystemRuleAsync("AppManager_System_VPN_PPTP_TCP", "out", "allow", "tcp", "1723", cancellationToken);

                // 13. VPN GRE Protocol (Protocol 47) Outbound
                await DeleteRuleAsync("AppManager_System_VPN_GRE", cancellationToken);
                await RunNetshAsync(new[]
                {
                    "advfirewall", "firewall", "add", "rule",
                    "name=AppManager_System_VPN_GRE",
                    "dir=out",
                    "action=allow",
                    "protocol=47",
                    "enable=yes"
                }, cancellationToken);

                // 14. VPN ESP Protocol (Protocol 50) Outbound
                await DeleteRuleAsync("AppManager_System_VPN_ESP", cancellationToken);
                await RunNetshAsync(new[]
                {
                    "advfirewall", "firewall", "add", "rule",
                    "name=AppManager_System_VPN_ESP",
                    "dir=out",
                    "action=allow",
                    "protocol=50",
                    "enable=yes"
                }, cancellationToken);

                // 15. VPN RasMan Service Outbound (Remote Access Connection Manager)
                await DeleteRuleAsync("AppManager_System_VPN_RasMan", cancellationToken);
                await RunNetshAsync(new[]
                {
                    "advfirewall", "firewall", "add", "rule",
                    "name=AppManager_System_VPN_RasMan",
                    "dir=out",
                    "action=allow",
                    "service=RasMan",
                    "enable=yes"
                }, cancellationToken);

                // 16. VPN Ikeext Service Outbound (IKE and AuthIP IPsec Keying Modules)
                await DeleteRuleAsync("AppManager_System_VPN_Ikeext", cancellationToken);
                await RunNetshAsync(new[]
                {
                    "advfirewall", "firewall", "add", "rule",
                    "name=AppManager_System_VPN_Ikeext",
                    "dir=out",
                    "action=allow",
                    "service=Ikeext",
                    "enable=yes"
                }, cancellationToken);

                // 17. VPN SSTP Service Outbound (Secure Socket Tunneling Protocol Service)
                await DeleteRuleAsync("AppManager_System_VPN_SstpSvc", cancellationToken);
                await RunNetshAsync(new[]
                {
                    "advfirewall", "firewall", "add", "rule",
                    "name=AppManager_System_VPN_SstpSvc",
                    "dir=out",
                    "action=allow",
                    "service=SstpSvc",
                    "enable=yes"
                }, cancellationToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to apply system firewall rules for DNS/DHCP/NTP/AD/Loopback/NCSI.");
            }
        }

        /// <summary>
        /// Applies the current filtering strategy (Blacklist or Whitelist) and configures the firewall policy & rules.
        /// </summary>
        public static async Task ApplyCurrentStrategyAsync(ILogger logger, CancellationToken cancellationToken)
        {
            if (IsAllowMode) return;

            if (CurrentStrategy == FilteringStrategy.Blacklist)
            {
                logger.LogInformation("Applying BLACKLIST filtering strategy...");
                
                // 1. Set firewall policy to allow outbound by default
                await SetFirewallPolicyAsync(false, cancellationToken);

                // 2. Remove all whitelist (allow) rules and system rules to avoid leakage
                await DeleteAllAllowRulesAsync(logger, cancellationToken);

                // 3. Re-apply block rules for all blocked applications
                foreach (var kvp in BlockedApps)
                {
                    try
                    {
                        string appPath = kvp.Value;
                        string appName = Path.GetFileNameWithoutExtension(appPath);
                        string blockRuleName = $"{RulePrefixBlock}{appName}";

                        await DeleteRuleAsync(blockRuleName, cancellationToken);
                        await AddRuleAsync(blockRuleName, "in", "block", appPath, cancellationToken);
                        await AddRuleAsync(blockRuleName, "out", "block", appPath, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Failed to apply block rules for '{AppName}'", kvp.Value);
                    }
                }
            }
            else
            {
                logger.LogInformation("Applying WHITELIST filtering strategy...");

                // 1. Set firewall policy to block outbound by default
                await SetFirewallPolicyAsync(true, cancellationToken);

                // 2. Remove all blacklist (block) rules
                await DeleteAllBlockRulesAsync(logger, cancellationToken);

                // 3. Add system critical rules (DNS, DHCP)
                await AddSystemRulesAsync(logger, cancellationToken);

                // 4. Re-apply allow rules for all safe applications
                foreach (var kvp in SafeApps)
                {
                    try
                    {
                        string appPath = kvp.Value;
                        string appName = Path.GetFileNameWithoutExtension(appPath);
                        string allowRuleName = $"{RulePrefixAllow}{appName}";

                        await DeleteRuleAsync(allowRuleName, cancellationToken);
                        await AddRuleAsync(allowRuleName, "in", "allow", appPath, cancellationToken);
                        await AddRuleAsync(allowRuleName, "out", "allow", appPath, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Failed to apply allow rules for safe app '{AppName}'", kvp.Value);
                    }
                }

                // 4.5. Re-apply block rules for all blocked applications (overrides any general/system allow rules)
                foreach (var kvp in BlockedApps)
                {
                    try
                    {
                        string appPath = kvp.Value;
                        string appName = Path.GetFileNameWithoutExtension(appPath);
                        string blockRuleName = $"{RulePrefixBlock}{appName}";

                        await DeleteRuleAsync(blockRuleName, cancellationToken);
                        await AddRuleAsync(blockRuleName, "in", "block", appPath, cancellationToken);
                        await AddRuleAsync(blockRuleName, "out", "block", appPath, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Failed to apply block rules for '{AppName}' in whitelist mode", kvp.Value);
                    }
                }

                // 5. Allow the firewall service itself
                try
                {
                    string ownPath = Environment.ProcessPath ?? "";
                    if (!string.IsNullOrEmpty(ownPath))
                    {
                        string allowRuleName = $"{RulePrefixAllow}FirewallService";
                        await DeleteRuleAsync(allowRuleName, cancellationToken);
                        await AddRuleAsync(allowRuleName, "in", "allow", ownPath, cancellationToken);
                        await AddRuleAsync(allowRuleName, "out", "allow", ownPath, cancellationToken);
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to apply allow rule for the firewall service itself.");
                }

                // 6. Allow active client applications dynamically
                foreach (var clientPath in ActiveClientPids.Values)
                {
                    if (!string.IsNullOrEmpty(clientPath))
                    {
                        try
                        {
                            string appName = Path.GetFileNameWithoutExtension(clientPath);
                            string allowRuleName = $"{RulePrefixAllow}Client_{appName}";
                            await DeleteRuleAsync(allowRuleName, cancellationToken);
                            await AddRuleAsync(allowRuleName, "in", "allow", clientPath, cancellationToken);
                            await AddRuleAsync(allowRuleName, "out", "allow", clientPath, cancellationToken);
                        }
                        catch (Exception ex)
                        {
                            logger.LogError(ex, "Failed to apply dynamic allow rule for client '{ClientPath}'", clientPath);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Scans the active firewall rules and deletes any rule starting with AppManager_Block_ or AppManager_Allow_.
        /// This ensures that when the system is in ALLOW mode, no block/allow rules are active.
        /// </summary>
        public static async Task DeleteAllAppManagerRulesAsync(ILogger logger, CancellationToken cancellationToken)
        {
            try
            {
                var ruleCounts = GetActiveRuleNameCounts(logger);
                foreach (var ruleName in ruleCounts.Keys)
                {
                    if (ruleName.StartsWith(RulePrefixBlock, StringComparison.OrdinalIgnoreCase) ||
                        ruleName.StartsWith(RulePrefixAllow, StringComparison.OrdinalIgnoreCase) ||
                        ruleName.StartsWith("AppManager_System_", StringComparison.OrdinalIgnoreCase))
                    {
                        logger.LogInformation("Restoring firewall state: Deleting leftover custom rule '{RuleName}'", ruleName);
                        try
                        {
                            await DeleteRuleAsync(ruleName, cancellationToken);
                        }
                        catch (Exception ex)
                        {
                            logger.LogError(ex, "Failed to delete leftover custom rule '{RuleName}'", ruleName);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to scan and delete custom AppManager rules.");
            }
        }

        /// <summary>
        /// Transitions the service mode between LOCKDOWN (default) and ALLOW.
        /// </summary>
        public static async Task SetAllowModeAsync(bool enableAllowMode, ILogger logger, CancellationToken cancellationToken)
        {
            IsAllowMode = enableAllowMode;
            if (enableAllowMode)
            {
                logger.LogInformation("Transitioning to ALLOW mode. Suspending lockdown enforcement and removing firewall block rules...");
                Sentry.SentrySdk.CaptureMessage("Firewall transitioned to ALLOW mode (Unlocked).", Sentry.SentryLevel.Info);

                // Clear the safe apps (allow list) database when exiting lockdown
                SafeApps.Clear();
                try
                {
                    SaveSafeApps();
                    logger.LogInformation("Safe apps database cleared on ALLOW mode transition.");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to save empty safe apps database during ALLOW mode transition.");
                }
                
                // 1. Reset firewall policy to default (allow outbound)
                try
                {
                    await SetFirewallPolicyAsync(false, cancellationToken);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to reset firewall policy during ALLOW mode transition.");
                }

                // 2. Remove all AppManager block, allow, and system rules from the Windows Firewall
                await DeleteAllAppManagerRulesAsync(logger, cancellationToken);
                
                // 3. Unlock/disable the firewall profiles
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
                logger.LogInformation("Transitioning to LOCKDOWN mode. Re-enabling firewall and applying strategy rules...");
                Sentry.SentrySdk.CaptureMessage("Firewall transitioned to LOCKDOWN mode.", Sentry.SentryLevel.Info);
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

                // 2. Apply rules and policy for current strategy
                await ApplyCurrentStrategyAsync(logger, cancellationToken);
            }
        }
    }
}
