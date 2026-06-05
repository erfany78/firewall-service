using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
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
            
            // Load blocked application configuration from disk
            FirewallHelper.InitializeBlockedAppsList(_logger);

            // Spin up the background process monitoring and force-closing loop (every 1s)
            _ = Task.Run(() => StartProcessMonitoringLoopAsync(stoppingToken), stoppingToken);

            // Spin up the background firewall and rule integrity enforcement loop (every 5s)
            _ = Task.Run(() => StartFirewallIntegrityLoopAsync(stoppingToken), stoppingToken);

            // Start the TCP Listener loop
            await StartTcpListenerAsync(stoppingToken);
        }

        /// <summary>
        /// Concurrent loop that scans running processes every 1 second and terminates blocked ones.
        /// </summary>
        private async Task StartProcessMonitoringLoopAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Process monitoring loop successfully started.");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    FirewallHelper.ForceCloseRunningBlockedApps(_logger);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Exception encountered in process monitoring loop.");
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

            _logger.LogInformation("Process monitoring loop stopped.");
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

            return "ERROR: Invalid or unknown command format.";
        }
    }
}
