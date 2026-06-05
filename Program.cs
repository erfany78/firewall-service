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
    }
}
