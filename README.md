# Flutter Windows Firewall Manager Service

[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)](#)
[![Framework](https://img.shields.io/badge/.NET-8.0-purple.svg)](#)
[![Client](https://img.shields.io/badge/Client-Flutter%20%2F%20Dart-02569B.svg)](#)

A high-performance, secure Windows Service written in .NET 8.0 designed to manage Windows Firewall rules and enforce application lock-downs. It is specifically designed for high-security environments like **exam lockdown browsers** and **kiosk applications**. 

It runs with `LocalSystem` privileges, communicates over a local TCP socket (`127.0.0.1:45455`), and features real-time, low-overhead self-healing.

---

## 🚀 Key Features

* **Pre-Shared Key Security (IPC Protection)**: Only authorized local processes sending the secret token `AUTH:ExamLockdownSecureToken2026` can configure the firewall. Unauthenticated connections are dropped instantly.
* **Firewall Integrity & Self-Healing Loop**:
  * Scans Windows Firewall states every **5 seconds**.
  * Uses ultra-fast, in-process **COM Interop (`HNetCfg.FwPolicy2`)** to query rules at **0% CPU** overhead.
  * Restores disabled profiles (Domain, Private, Public) and recreates deleted/modified block rules automatically if tampered with.
* **Process Monitor & Force Close**:
  * Background thread runs every **1 second** scanning running processes.
  * Forcefully terminates any running instances of blocked applications.
* **Real-time Event Broadcasting**: Streams system-level events (e.g., `EVENT:STATUS_RESTORED` or `EVENT:RULE_RESTORED:<AppName>`) instantly to all connected and authenticated Flutter client sockets.
* **Highly Optimized Binary Size**: Published as a single-file, self-contained, trimmed executable (~14.3 MB) with all built-in COM interop features preserved.

---

## 🛠️ IPC Socket Protocol

The service runs a TCP server on `127.0.0.1:45455`. All commands and responses are text-based and terminated by a newline (`\n`).

### Client Commands
| Command | Description | Expected Response |
| :--- | :--- | :--- |
| `AUTH:ExamLockdownSecureToken2026` | Authenticates the socket connection. **Must be the first command sent.** | `SUCCESS: Authenticated` |
| `STATUS` | Queries whether the Windows Firewall is active. | `STATUS:ON` or `STATUS:OFF` |
| `ALLOW:<AppPath>` | Removes the app from block list, deletes its block rules, and adds allow rules. | `SUCCESS` or `ERROR: <reason>` |
| `BLOCK:<AppPath>` | Adds the app to the block list, blocks all traffic, and kills running instances. | `SUCCESS` or `ERROR: <reason>` |
| `LOCK` or `MODE:LOCKDOWN` | Transitions to **LOCKDOWN Mode** (fully enables firewall, applies block rules, starts killing blocked processes). | `SUCCESS` or `ERROR: <reason>` |
| `UNLOCK` or `MODE:ALLOW` | Transitions to **ALLOW Mode** (removes firewall block rules, disables profiles, suspends process killing and integrity check loops). | `SUCCESS` or `ERROR: <reason>` |
| `GET_MODE` | Queries the current operation mode. | `MODE:ALLOW` or `MODE:LOCKDOWN` |
| `RESET` | Resets the Windows Firewall to default configurations. | `SUCCESS` or `ERROR: <reason>` |
| `KILL:<AppPath>` | Force-closes any running process matching the executable path. | `SUCCESS` or `ERROR: <reason>` |

### Real-Time Broadcast Events
These events are sent spontaneously from the service to all authenticated sockets when self-healing actions occur:
* `EVENT:STATUS_RESTORED` — Fired when manual disabling of the firewall is detected and repaired.
* `EVENT:RULE_RESTORED:<AppName>` — Fired when a rule for a blocked application is deleted and automatically re-applied.

---

## 📦 Compilation & Publishing

To compile the service into a single, optimized, trimmed executable:

```powershell
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishReadyToRun=true -o C:\Publish\FirewallServiceSelfHealing
```

> [!NOTE]
> Trimming is fully supported. COM interop features are preserved via `<BuiltInComInteropSupport>true</BuiltInComInteropSupport>` inside the `firewall.csproj`.

---

## ⚙️ Service Installation (Production)

Open an **Administrator PowerShell** session and run the following commands:

### 1. Register the Windows Service
```powershell
New-Service -Name "FlutterFirewallManagerService" `
            -BinaryPathName "C:\Publish\FirewallServiceSelfHealing\firewall.exe" `
            -DisplayName "Flutter Firewall Manager Service" `
            -StartupType Automatic
```

### 2. Start the Service
```powershell
Start-Service -Name "FlutterFirewallManagerService"
```

### 3. Stop and Uninstall
```powershell
Stop-Service -Name "FlutterFirewallManagerService"
sc.exe delete "FlutterFirewallManagerService"
```

---

## 📱 Flutter (Dart) Client Integration

Save this helper class as `firewall_service.dart` in your Flutter project's `lib/` directory:

```dart
import 'dart:async';
import 'dart:convert';
import 'dart:io';

class FirewallService {
  static const String _host = '127.0.0.1';
  static const int _port = 45455;
  static const String _authKey = 'ExamLockdownSecureToken2026';

  Socket? _socket;
  final _eventController = StreamController<String>.broadcast();
  Completer<String>? _responseCompleter;

  /// Stream of real-time events broadcasted by the Windows Service
  Stream<String> get eventStream => _eventController.stream;

  /// Connects to the service and performs authentication.
  /// Must be called before sending other commands.
  Future<void> connectAndAuthenticate() async {
    try {
      _socket = await Socket.connect(_host, _port, timeout: const Duration(seconds: 3));
      
      _socket!.transform(utf8.decoder).transform(const LineSplitter()).listen(
        _handleIncomingLine,
        onError: (err) {
          _eventController.addError(err);
          disconnect();
        },
        onDone: () {
          disconnect();
        },
        cancelOnError: true,
      );

      // Authenticate as the very first step
      final authResponse = await _sendCommandInternal('AUTH:$_authKey');
      if (authResponse != 'SUCCESS: Authenticated') {
        throw Exception('Authentication failed: $authResponse');
      }
    } catch (e) {
      disconnect();
      rethrow;
    }
  }

  /// Disconnects and cleans up resources
  void disconnect() {
    _socket?.destroy();
    _socket = null;
  }

  /// Internal handler for incoming data
  void _handleIncomingLine(String line) {
    line = line.trim();
    if (line.startsWith('EVENT:')) {
      _eventController.add(line.substring(6).trim());
    } else {
      if (_responseCompleter != null && !_responseCompleter!.isCompleted) {
        _responseCompleter!.complete(line);
      }
    }
  }

  /// Sends a command and waits for the specific response
  Future<String> _sendCommandInternal(String command) async {
    if (_socket == null) {
      throw const SocketException('Not connected to firewall service.');
    }

    _responseCompleter = Completer<String>();
    _socket!.write('$command\n');
    await _socket!.flush();

    return _responseCompleter!.future.timeout(
      const Duration(seconds: 5),
      onTimeout: () => throw TimeoutException('Command timed out: $command'),
    );
  }

  /// Queries whether the Windows Firewall is currently enabled
  Future<bool> isFirewallEnabled() async {
    final response = await _sendCommandInternal('STATUS');
    if (response == 'STATUS:ON') return true;
    if (response == 'STATUS:OFF') return false;
    throw Exception('Failed to get firewall status: $response');
  }

  /// Requests the service to ALLOW all inbound/outbound traffic for the executable
  Future<void> allowApplication(String appPath) async {
    final response = await _sendCommandInternal('ALLOW:$appPath');
    if (response != 'SUCCESS') {
      throw Exception(response.startsWith('ERROR:') ? response.substring(6).trim() : response);
    }
  }

  /// Requests the service to BLOCK all inbound/outbound traffic for the executable
  Future<void> blockApplication(String appPath) async {
    final response = await _sendCommandInternal('BLOCK:$appPath');
    if (response != 'SUCCESS') {
      throw Exception(response.startsWith('ERROR:') ? response.substring(6).trim() : response);
    }
  }

  /// Requests the service to LOCK (fully enable) the firewall
  Future<void> lockFirewall() async {
    final response = await _sendCommandInternal('LOCK');
    if (response != 'SUCCESS') {
      throw Exception(response.startsWith('ERROR:') ? response.substring(6).trim() : response);
    }
  }

  /// Requests the service to UNLOCK (fully disable) the firewall
  Future<void> unlockFirewall() async {
    final response = await _sendCommandInternal('UNLOCK');
    if (response != 'SUCCESS') {
      throw Exception(response.startsWith('ERROR:') ? response.substring(6).trim() : response);
    }
  }

  /// Requests the service to RESET the Windows Firewall to defaults
  Future<void> resetFirewall() async {
    final response = await _sendCommandInternal('RESET');
    if (response != 'SUCCESS') {
      throw Exception(response.startsWith('ERROR:') ? response.substring(6).trim() : response);
    }
  }

  /// Explicitly terminates any running processes matching the specified path
  Future<void> killApplication(String appPath) async {
    final response = await _sendCommandInternal('KILL:$appPath');
    if (response != 'SUCCESS') {
      throw Exception(response.startsWith('ERROR:') ? response.substring(6).trim() : response);
    }
  }
}
```

### Listening to Broadcast Events in Flutter UI:

```dart
final firewallService = FirewallService();

void startMonitoring() async {
  try {
    await firewallService.connectAndAuthenticate();
    
    // Listen to real-time status/rule restoration events
    firewallService.eventStream.listen((event) {
      if (event == "STATUS_RESTORED") {
        print("ALERT: Windows Firewall status tampered! Re-enabled by service.");
      } else if (event.startsWith("RULE_RESTORED:")) {
        String appName = event.split(":")[1];
        print("ALERT: Firewall rule for '$appName' was deleted and restored!");
      }
    });
  } catch (e) {
    print("Connection/Auth failed: $e");
  }
}
```
