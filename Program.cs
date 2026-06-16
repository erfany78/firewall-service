using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Configuration;
using Microsoft.Extensions.Logging.EventLog;

namespace FlutterFirewallManager
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Initialize Sentry SDK
            Sentry.SentrySdk.Init(options =>
            {
                options.Dsn = "https://2ae52fce696e437690b012129eb58423@feedback.zfara.co/3";
                options.TracesSampleRate = 0.01; // 1% of transactions
                options.Release = "1.0.4";
            });

            // Configure global Sentry tags
            Sentry.SentrySdk.ConfigureScope(scope =>
            {
                scope.SetTag("os_name", "Windows");
                scope.SetTag("windows_version", Environment.OSVersion.ToString());
                scope.SetTag("ip_address", GetLocalIpAddress());
                scope.SetTag("version", "1.0.4");
#if DEBUG
                scope.SetTag("release_mode", "Debug");
#else
                scope.SetTag("release_mode", "Release");
#endif
            });

            // Register CodePages encoding provider to support OEM/Console code pages like 437
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            var builder = Host.CreateApplicationBuilder(args);

            // Configure the host to run as a Windows Service.
            // This allows the service to integrate with the Windows Service Control Manager (SCM).
            // When running interactively (e.g. dotnet run), it gracefully defaults to standard console mode.
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = "FlutterFirewallManagerService";
            });

            // Register the FirewallWorker as the background host worker.
            builder.Services.AddHostedService<FirewallWorker>();

            // Configure Logging
            builder.Logging.ClearProviders();
            builder.Logging.AddConsole();
            
            // Register Windows EventLog provider so service logs are captured in Windows Event Viewer under Application logs
            if (OperatingSystem.IsWindows())
            {
                builder.Logging.AddEventLog(settings =>
                {
#pragma warning disable CA1416
                    settings.SourceName = "FlutterFirewallManagerService";
#pragma warning restore CA1416
                });
            }

            var host = builder.Build();
            host.Run();
        }

        private static string GetLocalIpAddress()
        {
            try
            {
                var host = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        if (!System.Net.IPAddress.IsLoopback(ip))
                        {
                            return ip.ToString();
                        }
                    }
                }
            }
            catch
            {
                // Fallback
            }
            return "Unknown";
        }
    }
}
