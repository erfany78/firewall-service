using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FlutterFirewallManager
{
    public class FirewallWorker : BackgroundService
    {
        private readonly ILogger<FirewallWorker> _logger;
        private const int Port = 45455;

        // Security key required for socket connection authentication
        private const string SecretApiKey = "553220ea750b04994de7bd70f";

        // Thread-safe dictionary tracking all authenticated client socket writers
        private static readonly ConcurrentDictionary<Guid, StreamWriter> ActiveWriters = new ConcurrentDictionary<Guid, StreamWriter>();

        // Heartbeat watchdog timestamp
        private static DateTime LastHeartbeatTime = DateTime.UtcNow;

        public FirewallWorker(ILogger<FirewallWorker> logger)
        {
            _logger = logger;
            // Register callback to capture events from FirewallHelper and broadcast them to TCP clients
            FirewallEvents.OnBroadcast += BroadcastEventInternalAsync;
        }

        /// <summary>
        /// Broadcasts an event message (e.g. EVENT:STATUS_RESTORED) to all active authenticated socket clients.
        /// </summary>
        private static async Task BroadcastEventInternalAsync(string eventMessage)
        {
            foreach (var writer in ActiveWriters.Values)
            {
                try
                {
                    await writer.WriteLineAsync($"EVENT:{eventMessage}");
                }
                catch
                {
                    // Ignore write failures; disconnected clients will be cleaned up in HandleClientAsync finally block
                }
            }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Initializing FlutterFirewallManagerService database...");
            
            // Check and log first run on device
            try
            {
                string markerPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FlutterFirewallManager",
                    "first_run.txt"
                );
                if (!File.Exists(markerPath))
                {
                    _logger.LogInformation("First run detected on this device. Logging to Sentry...");
                    Sentry.SentrySdk.CaptureMessage("First run of Flutter Firewall Manager Service on device.", Sentry.SentryLevel.Info);
                    
                    // Create directory if it doesn't exist
                    string dir = Path.GetDirectoryName(markerPath) ?? "";
                    if (!Directory.Exists(dir))
                    {
                        Directory.CreateDirectory(dir);
                    }
                    File.WriteAllText(markerPath, DateTime.UtcNow.ToString("O"));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check or write first run marker.");
            }

            // Load blocked application configuration from disk
            FirewallHelper.InitializeBlockedAppsList(_logger);

            // Load safe application configuration from disk
            FirewallHelper.InitializeSafeAppsList(_logger);

            // Load filtering strategy from disk
            FirewallHelper.InitializeStrategy(_logger);

            // Enforce default ALLOW mode on startup to prevent lockout if the service previously crashed in lockdown mode
            try
            {
                _logger.LogInformation("Enforcing default ALLOW mode on startup...");
                await FirewallHelper.SetAllowModeAsync(true, _logger, stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enforce default ALLOW mode on startup.");
            }

            // Spin up the background firewall and rule integrity enforcement loop (every 5s)
            _ = Task.Run(() => StartFirewallIntegrityLoopAsync(stoppingToken), stoppingToken);

            // Spin up the client heartbeat watchdog loop (every 1s)
            _ = Task.Run(() => StartWatchdogLoopAsync(stoppingToken), stoppingToken);

            // Start the TCP Listener loop
            await StartTcpListenerAsync(stoppingToken);
        }

        /// <summary>
        /// Background loop that checks firewall state and rules integrity every 5 seconds.
        /// </summary>
        private async Task StartFirewallIntegrityLoopAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Firewall integrity enforcement loop started.");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await FirewallHelper.EnforceFirewallIntegrityAsync(_logger, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Exception encountered in firewall integrity loop.");
                }

                try
                {
                    await Task.Delay(5000, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            _logger.LogInformation("Firewall integrity enforcement loop stopped.");
        }

        /// <summary>
        /// Starts and manages the TCP Socket listener.
        /// </summary>
        private async Task StartTcpListenerAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Starting TCP Listener on 127.0.0.1:{Port}...", Port);

            TcpListener listener;
            try
            {
                listener = new TcpListener(IPAddress.Loopback, Port);
                listener.Start();
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "Failed to start TCP Listener on 127.0.0.1:{Port}. Service exiting.", Port);
                throw;
            }

            using (stoppingToken.Register(() => listener.Stop()))
            {
                try
                {
                    while (!stoppingToken.IsCancellationRequested)
                    {
                        TcpClient client = await listener.AcceptTcpClientAsync(stoppingToken);
                        _logger.LogInformation("Accepted connection from {RemoteEndPoint}", client.Client.RemoteEndPoint);
                        
                        _ = HandleClientAsync(client, stoppingToken);
                    }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    _logger.LogInformation("TCP Listener shutdown requested.");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in TCP Listener accept loop.");
                }
                finally
                {
                    try
                    {
                        listener.Stop();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Error stopping TcpListener in cleanup.");
                    }
                    _logger.LogInformation("TCP Listener stopped.");
                }
            }
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
        {
            Guid clientId = Guid.NewGuid();
            bool isAuthenticated = false;
            int resolvedPid = -1;

            using (client)
            {
                try
                {
                    using var stream = client.GetStream();
                    using var reader = new StreamReader(stream, Encoding.UTF8);
                    using var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

                    client.ReceiveTimeout = 30000;
                    client.SendTimeout = 30000;

                    var remoteEndPoint = client.Client.RemoteEndPoint;

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        string? line = await reader.ReadLineAsync(cancellationToken);
                        if (line == null)
                        {
                            _logger.LogInformation("Client {RemoteEndPoint} disconnected.", remoteEndPoint);
                            break;
                        }

                        string command = line.Trim();

                        // Enforce authentication check on the very first command
                        if (!isAuthenticated)
                        {
                            if (command.StartsWith("AUTH:", StringComparison.OrdinalIgnoreCase))
                            {
                                string clientKey = command.Substring(5).Trim();
                                if (clientKey == SecretApiKey)
                                {
                                    isAuthenticated = true;
                                    ActiveWriters[clientId] = writer; // Add to active broadcast list
                                    LastHeartbeatTime = DateTime.UtcNow; // Reset heartbeat on authentication

                                    // Dynamically resolve client process ID and register it
                                    if (remoteEndPoint is IPEndPoint ipEndPoint)
                                    {
                                        resolvedPid = GetPidByClientPort((ushort)ipEndPoint.Port);
                                        if (resolvedPid > 0)
                                        {
                                            string clientPath = "";
                                            try
                                            {
                                                using var proc = System.Diagnostics.Process.GetProcessById(resolvedPid);
                                                clientPath = proc.MainModule?.FileName ?? "";
                                            }
                                            catch (Exception ex)
                                            {
                                                _logger.LogWarning(ex, "Failed to resolve client process path for PID {Pid}", resolvedPid);
                                            }

                                            FirewallHelper.ActiveClientPids[resolvedPid] = clientPath;
                                            _logger.LogInformation("Registered active client PID {Pid} ({Path})", resolvedPid, clientPath);

                                            // If strategy is Whitelist and service is locked, immediately add allow rule for the client
                                            if (!FirewallHelper.IsAllowMode && FirewallHelper.CurrentStrategy == FirewallHelper.FilteringStrategy.Whitelist && !string.IsNullOrEmpty(clientPath))
                                            {
                                                try
                                                {
                                                    string appName = Path.GetFileNameWithoutExtension(clientPath);
                                                    string allowRuleName = $"AppManager_Allow_Client_{appName}";
                                                    await FirewallHelper.AddRuleAsync(allowRuleName, "in", "allow", clientPath, cancellationToken);
                                                    await FirewallHelper.AddRuleAsync(allowRuleName, "out", "allow", clientPath, cancellationToken);
                                                }
                                                catch (Exception ex)
                                                {
                                                    _logger.LogError(ex, "Failed to apply dynamic allow rule for client '{ClientPath}' during connection.", clientPath);
                                                }
                                            }
                                        }
                                    }

                                    _logger.LogInformation("Client {RemoteEndPoint} successfully authenticated.", remoteEndPoint);
                                    await writer.WriteLineAsync("SUCCESS: Authenticated");
                                    continue;
                                }
                            }

                            _logger.LogWarning("Client {RemoteEndPoint} sent command before authentication. Disconnecting.", remoteEndPoint);
                            await writer.WriteLineAsync("ERROR: Unauthorized. Connection closed.");
                            break; // Disconnect immediately
                        }

                        _logger.LogInformation("Received command from {RemoteEndPoint}: '{Command}'", remoteEndPoint, command);
                        
                        // Reset watchdog heartbeat on any incoming authenticated command
                        if (isAuthenticated)
                        {
                            LastHeartbeatTime = DateTime.UtcNow;
                        }

                        string response = await ProcessCommandAsync(command, cancellationToken);
                        _logger.LogInformation("Sending response to {RemoteEndPoint}: '{Response}'", remoteEndPoint, response);

                        await writer.WriteLineAsync(response);
                    }
                }
                catch (IOException ex) when (ex.InnerException is SocketException)
                {
                    _logger.LogInformation("Client connection reset or closed by peer.");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Exception encountered while handling TCP client connection.");
                }
                finally
                {
                    // Clean up broadcast list registration
                    ActiveWriters.TryRemove(clientId, out _);

                    // Clean up client PID registration if we resolved it
                    if (resolvedPid > 0)
                    {
                        FirewallHelper.ActiveClientPids.TryRemove(resolvedPid, out var clientPath);
                        _logger.LogInformation("Unregistered active client PID {Pid}", resolvedPid);

                        // If strategy is Whitelist, remove its dynamic allow rule
                        if (!FirewallHelper.IsAllowMode && FirewallHelper.CurrentStrategy == FirewallHelper.FilteringStrategy.Whitelist && !string.IsNullOrEmpty(clientPath))
                        {
                            try
                            {
                                string appName = Path.GetFileNameWithoutExtension(clientPath);
                                string allowRuleName = $"AppManager_Allow_Client_{appName}";
                                // Delete rules asynchronously (use CancellationToken.None to ensure cleanup runs even if cancelled)
                                _ = FirewallHelper.DeleteRuleAsync(allowRuleName, CancellationToken.None);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "Failed to delete dynamic allow rule for client '{ClientPath}' during teardown.", clientPath);
                            }
                        }
                    }
                }
            }
        }

        private async Task<string> ProcessCommandAsync(string command, CancellationToken cancellationToken)
        {
            // 1. STATUS command
            if (command.Equals("STATUS", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    bool enabled = await FirewallHelper.IsFirewallEnabledAsync(cancellationToken);
                    return enabled ? "STATUS:ON" : "STATUS:OFF";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error executing STATUS command.");
                    return $"ERROR: {ex.Message}";
                }
            }

            // 2. ALLOW:<AppPath> command
            if (command.StartsWith("ALLOW:", StringComparison.OrdinalIgnoreCase))
            {
                string appPath = command.Substring(6).Trim();
                try
                {
                    await FirewallHelper.AllowApplicationAsync(appPath, cancellationToken);
                    return "SUCCESS";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error executing ALLOW command for path: {AppPath}", appPath);
                    return $"ERROR: {ex.Message}";
                }
            }

            // 3. BLOCK:<AppPath> command
            if (command.StartsWith("BLOCK:", StringComparison.OrdinalIgnoreCase))
            {
                string appPath = command.Substring(6).Trim();
                try
                {
                    await FirewallHelper.BlockApplicationAsync(appPath, cancellationToken);
                    return "SUCCESS";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error executing BLOCK command for path: {AppPath}", appPath);
                    return $"ERROR: {ex.Message}";
                }
            }

            // 4. LOCK command (transitions to LOCKDOWN mode)
            if (command.Equals("LOCK", StringComparison.OrdinalIgnoreCase) || command.Equals("MODE:LOCKDOWN", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    LastHeartbeatTime = DateTime.UtcNow; // Reset heartbeat on lock transition
                    await FirewallHelper.SetAllowModeAsync(false, _logger, cancellationToken);
                    return "SUCCESS";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error transitioning to LOCKDOWN mode.");
                    return $"ERROR: {ex.Message}";
                }
            }

            // 5. UNLOCK command (transitions to ALLOW mode)
            if (command.Equals("UNLOCK", StringComparison.OrdinalIgnoreCase) || command.Equals("MODE:ALLOW", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    await FirewallHelper.SetAllowModeAsync(true, _logger, cancellationToken);
                    return "SUCCESS";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error transitioning to ALLOW mode.");
                    return $"ERROR: {ex.Message}";
                }
            }

            // GET_MODE command
            if (command.Equals("GET_MODE", StringComparison.OrdinalIgnoreCase))
            {
                return FirewallHelper.IsAllowMode ? "MODE:ALLOW" : "MODE:LOCKDOWN";
            }

            // 6. RESET command
            if (command.Equals("RESET", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    await FirewallHelper.ResetFirewallAsync(cancellationToken);
                    return "SUCCESS";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error executing RESET command.");
                    return $"ERROR: {ex.Message}";
                }
            }

            // 7. Explicit KILL:<AppPath> command
            if (command.StartsWith("KILL:", StringComparison.OrdinalIgnoreCase))
            {
                string appPath = command.Substring(5).Trim();
                try
                {
                    FirewallHelper.KillProcessesForPath(appPath);
                    return "SUCCESS";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error executing KILL command for path: {AppPath}", appPath);
                    return $"ERROR: {ex.Message}";
                }
            }

            // 8. GET_BLOCK_LIST command
            if (command.Equals("GET_BLOCK_LIST", StringComparison.OrdinalIgnoreCase))
            {
                return $"BLOCK_LIST:{FirewallHelper.GetBlockedAppsList()}";
            }

            // 9. GET_SAFE_LIST command
            if (command.Equals("GET_SAFE_LIST", StringComparison.OrdinalIgnoreCase))
            {
                return $"SAFE_LIST:{FirewallHelper.GetSafeAppsList()}";
            }

            // 10. ADD_SAFE:<AppPath> command
            if (command.StartsWith("ADD_SAFE:", StringComparison.OrdinalIgnoreCase))
            {
                string appPath = command.Substring(9).Trim();
                try
                {
                    await FirewallHelper.AddSafeAppAsync(appPath, cancellationToken);
                    return "SUCCESS";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error executing ADD_SAFE command for path: {AppPath}", appPath);
                    return $"ERROR: {ex.Message}";
                }
            }

            // 11. REMOVE_SAFE:<AppPath> command
            if (command.StartsWith("REMOVE_SAFE:", StringComparison.OrdinalIgnoreCase))
            {
                string appPath = command.Substring(12).Trim();
                try
                {
                    FirewallHelper.RemoveSafeApp(appPath);
                    return "SUCCESS";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error executing REMOVE_SAFE command for path: {AppPath}", appPath);
                    return $"ERROR: {ex.Message}";
                }
            }

            // 12. GET_STRATEGY command
            if (command.Equals("GET_STRATEGY", StringComparison.OrdinalIgnoreCase))
            {
                return $"STRATEGY:{FirewallHelper.CurrentStrategy.ToString().ToUpperInvariant()}";
            }

            // 13. SET_STRATEGY:BLACKLIST command
            if (command.Equals("SET_STRATEGY:BLACKLIST", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    await FirewallHelper.SetStrategyAsync(FirewallHelper.FilteringStrategy.Blacklist, _logger, cancellationToken);
                    return "SUCCESS";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error executing SET_STRATEGY:BLACKLIST");
                    return $"ERROR: {ex.Message}";
                }
            }

            // 14. SET_STRATEGY:WHITELIST command
            if (command.Equals("SET_STRATEGY:WHITELIST", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    await FirewallHelper.SetStrategyAsync(FirewallHelper.FilteringStrategy.Whitelist, _logger, cancellationToken);
                    return "SUCCESS";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error executing SET_STRATEGY:WHITELIST");
                    return $"ERROR: {ex.Message}";
                }
            }

            // GET_VERSION command
            if (command.Equals("GET_VERSION", StringComparison.OrdinalIgnoreCase))
            {
                return "VERSION:1.0.4";
            }

            // PING command
            if (command.Equals("PING", StringComparison.OrdinalIgnoreCase))
            {
                LastHeartbeatTime = DateTime.UtcNow;
                return "PONG";
            }

            return "ERROR: Invalid or unknown command format.";
        }

        /// <summary>
        /// Periodic loop that acts as a heartbeat watchdog. If the service is in LOCKDOWN mode,
        /// and no client is connected or the last message/heartbeat was over 10 seconds ago,
        /// the firewall service automatically resets to ALLOW mode for user protection.
        /// </summary>
        private async Task StartWatchdogLoopAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Watchdog loop started.");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    if (!FirewallHelper.IsAllowMode)
                    {
                        var timeSinceLastHeartbeat = (DateTime.UtcNow - LastHeartbeatTime).TotalSeconds;

                        if (timeSinceLastHeartbeat > 15.0)
                        {
                            _logger.LogWarning("Watchdog: Heartbeat timeout or connection lost ({Seconds}s > 15s). Restoring ALLOW mode...", timeSinceLastHeartbeat);
                            await FirewallHelper.SetAllowModeAsync(true, _logger, stoppingToken);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Exception encountered in watchdog loop.");
                }

                try
                {
                    await Task.Delay(1000, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            _logger.LogInformation("Watchdog loop stopped.");
        }

        #region Native TCP helper for Dynamic Client PID resolution

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int dwOutBufLen,
            bool sort,
            int ipVersion,
            int tblClass,
            uint reserved = 0);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public int owningPid;
        }

        private static int GetPidByClientPort(ushort clientPort)
        {
            int bufferSize = 0;
            // 2 = AF_INET (IPv4), 5 = TCP_TABLE_OWNER_PID_ALL
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, 2, 5, 0);

            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
            try
            {
                if (GetExtendedTcpTable(tcpTablePtr, ref bufferSize, false, 2, 5, 0) == 0)
                {
                    int numEntries = Marshal.ReadInt32(tcpTablePtr);
                    IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);

                    int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                    for (int i = 0; i < numEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                        
                        ushort localPort = (ushort)(((row.localPort & 0xFF) << 8) | ((row.localPort >> 8) & 0xFF));
                        ushort remotePort = (ushort)(((row.remotePort & 0xFF) << 8) | ((row.remotePort >> 8) & 0xFF));

                        if (localPort == clientPort && remotePort == Port)
                        {
                            return row.owningPid;
                        }

                        rowPtr = (IntPtr)((long)rowPtr + rowSize);
                    }
                }
            }
            catch
            {
                // Fallback
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }
            return -1;
        }

        #endregion
    }
}
