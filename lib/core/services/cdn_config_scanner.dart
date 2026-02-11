import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import 'xray_binary_service.dart';
import 'xray_process_manager.dart';

// Re-export exceptions for convenience
export 'xray_process_manager.dart' show XrayStartupException, PortInUseException;

/// Result of a CDN IP scan
class CdnScanResult {
  final String ip;
  final bool success;
  final double? latencyMs;
  final String? errorMessage;
  final DateTime timestamp;

  CdnScanResult({
    required this.ip,
    required this.success,
    this.latencyMs,
    this.errorMessage,
    DateTime? timestamp,
  }) : timestamp = timestamp ?? DateTime.now();

  @override
  String toString() {
    if (success) {
      return '$ip: ${latencyMs?.toStringAsFixed(0)}ms';
    } else {
      return '$ip: Failed ($errorMessage)';
    }
  }
}

/// Progress information for CDN scans
class CdnScanProgress {
  final CdnScanResult? result;
  final int completed;
  final int total;
  final int successful;
  final List<CdnScanResult> results;

  CdnScanProgress({
    this.result,
    required this.completed,
    required this.total,
    required this.successful,
    required this.results,
  });

  double get progress => total > 0 ? completed / total : 0;
  int get remaining => total - completed;
  bool get isComplete => completed >= total;
  int get failed => completed - successful;
}

/// Configuration for CDN scanning
class CdnScanConfig {
  final int concurrentInstances;
  final Duration timeout;
  final Duration startupDelay;
  final String testUrl;
  final int basePort;
  final bool enableXrayLogs;

  const CdnScanConfig({
    this.concurrentInstances = 5,
    this.timeout = const Duration(seconds: 10),
    this.startupDelay = const Duration(seconds: 2),
    this.testUrl = 'https://www.gstatic.com/generate_204',
    this.basePort = 10808,
    this.enableXrayLogs = kDebugMode,
  });

  CdnScanConfig copyWith({
    int? concurrentInstances,
    Duration? timeout,
    Duration? startupDelay,
    String? testUrl,
    int? basePort,
    bool? enableXrayLogs,
  }) {
    return CdnScanConfig(
      concurrentInstances: concurrentInstances ?? this.concurrentInstances,
      timeout: timeout ?? this.timeout,
      startupDelay: startupDelay ?? this.startupDelay,
      testUrl: testUrl ?? this.testUrl,
      basePort: basePort ?? this.basePort,
      enableXrayLogs: enableXrayLogs ?? this.enableXrayLogs,
    );
  }
}

/// Service for scanning CDN IPs through xray proxy
class CdnConfigScanner {
  final XrayBinaryService _binaryService;
  final CdnScanConfig config;

  XrayProcessManager? _processManager;
  bool _isScanning = false;
  bool _shouldStop = false;

  CdnConfigScanner({
    XrayBinaryService? binaryService,
    this.config = const CdnScanConfig(),
  }) : _binaryService = binaryService ?? XrayBinaryService();

  bool get isScanning => _isScanning;

  /// Parse IP input (supports single IPs and CIDR notation)
  static List<String> parseIpInput(String input) {
    final ips = <String>[];
    final lines = input.split('\n');

    for (var line in lines) {
      line = line.trim();
      if (line.isEmpty || line.startsWith('#')) continue;

      if (line.contains('/')) {
        // CIDR notation
        try {
          ips.addAll(_generateIpsFromSubnet(line));
        } catch (e) {
          // Skip invalid subnet
        }
      } else {
        // Single IP
        if (_isValidIp(line)) {
          ips.add(line);
        }
      }
    }

    return ips;
  }

  /// Generate list of IPs from a subnet in CIDR notation
  static List<String> _generateIpsFromSubnet(String subnet) {
    final parts = subnet.split('/');
    if (parts.length != 2) return [];

    final ipStr = parts[0];
    final prefixLength = int.tryParse(parts[1]);
    if (prefixLength == null || prefixLength < 0 || prefixLength > 32) return [];

    final ipParts = ipStr.split('.');
    if (ipParts.length != 4) return [];

    final octets = ipParts.map((p) => int.tryParse(p)).toList();
    if (octets.any((o) => o == null || o < 0 || o > 255)) return [];

    // Calculate network address
    int ipInt = 0;
    for (var i = 0; i < 4; i++) {
      ipInt = (ipInt << 8) | octets[i]!;
    }

    // Calculate number of hosts
    final hostBits = 32 - prefixLength;
    final numHosts = 1 << hostBits;

    // Network mask
    final netmask = ~((1 << hostBits) - 1) & 0xFFFFFFFF;
    final networkAddr = ipInt & netmask;

    // Generate IPs (excluding network and broadcast addresses for /31 and larger)
    final ips = <String>[];
    final start = prefixLength >= 31 ? 0 : 1;
    final end = prefixLength >= 31 ? numHosts : numHosts - 1;

    for (var i = start; i < end; i++) {
      final addr = networkAddr + i;
      final ip =
          '${(addr >> 24) & 0xFF}.${(addr >> 16) & 0xFF}.${(addr >> 8) & 0xFF}.${addr & 0xFF}';
      ips.add(ip);
    }

    return ips;
  }

  /// Validate an IP address
  static bool _isValidIp(String ip) {
    final parts = ip.split('.');
    if (parts.length != 4) return false;

    for (final part in parts) {
      final num = int.tryParse(part);
      if (num == null || num < 0 || num > 255) return false;
    }

    return true;
  }

  /// Test connection through SOCKS5 proxy.
  /// Uses curl on desktop (Linux/Windows) and native Dart sockets on Android.
  Future<CdnScanResult> _testWithSocks5Proxy(String ip, int proxyPort) async {
    if (Platform.isAndroid) {
      return _testWithSocks5ProxyDart(ip, proxyPort);
    }
    return _testWithSocks5ProxyCurl(ip, proxyPort);
  }

  /// Test connection through SOCKS5 proxy using curl command (Linux/Windows)
  Future<CdnScanResult> _testWithSocks5ProxyCurl(String ip, int proxyPort) async {
    try {
      // Use Process.run() instead of Process.start() to avoid file descriptor leaks
      // Process.run() automatically handles stdout/stderr cleanup
      final result = await Process.run(
        'curl',
        [
          '-s', // Silent mode
          '-o',
          Platform.isWindows ? 'NUL' : '/dev/null', // Discard output
          '-w',
          '%{http_code},%{time_total}', // Output status code and time
          '--proxy',
          'socks5h://127.0.0.1:$proxyPort',
          '--connect-timeout',
          config.timeout.inSeconds.toString(),
          '--max-time',
          (config.timeout.inSeconds + 2).toString(), // Total max time
          '-k', // Allow insecure SSL
          config.testUrl,
        ],
      ).timeout(config.timeout + const Duration(seconds: 5));

      if (result.exitCode == 0) {
        // Parse output: "204,0.123456"
        final output = result.stdout.toString().trim();
        final parts = output.split(',');

        if (parts.length >= 2) {
          final statusCode = int.tryParse(parts[0]) ?? 0;
          final timeSeconds = double.tryParse(parts[1]) ?? 0;
          final timeMs = timeSeconds * 1000;

          if (statusCode == 204 || (statusCode >= 200 && statusCode < 300)) {
            return CdnScanResult(
              ip: ip,
              success: true,
              latencyMs: timeMs,
            );
          } else {
            return CdnScanResult(
              ip: ip,
              success: false,
              errorMessage: 'HTTP $statusCode',
            );
          }
        }
      }

      // curl failed
      final stderr = result.stderr.toString().trim();
      return CdnScanResult(
        ip: ip,
        success: false,
        errorMessage: stderr.isNotEmpty ? stderr : 'curl exit code ${result.exitCode}',
      );
    } on TimeoutException {
      return CdnScanResult(
        ip: ip,
        success: false,
        errorMessage: 'Connection timed out',
      );
    } catch (e) {
      return CdnScanResult(
        ip: ip,
        success: false,
        errorMessage: e.toString(),
      );
    }
  }

  /// Test connection through SOCKS5 proxy using native Dart sockets (Android).
  /// Performs SOCKS5 handshake, optional TLS upgrade, and HTTP request.
  Future<CdnScanResult> _testWithSocks5ProxyDart(String ip, int proxyPort) async {
    final stopwatch = Stopwatch()..start();
    Socket? socket;

    try {
      final uri = Uri.parse(config.testUrl);
      final host = uri.host;
      final isHttps = uri.scheme == 'https';
      final targetPort = uri.hasPort
          ? uri.port
          : (isHttps ? 443 : 80);
      final path = uri.path.isEmpty
          ? '/'
          : (uri.hasQuery ? '${uri.path}?${uri.query}' : uri.path);

      debugPrint('[SOCKS5] Connecting to proxy 127.0.0.1:$proxyPort for IP=$ip');

      // 1. Connect to the local SOCKS5 proxy (xray instance)
      socket = await Socket.connect(
        InternetAddress.loopbackIPv4,
        proxyPort,
        timeout: config.timeout,
      );
      debugPrint('[SOCKS5] Connected to proxy');

      // Set up buffered reading from the socket stream
      final buffer = <int>[];
      Completer<void>? dataReady;
      bool socketDone = false;
      Object? socketError;

      final sub = socket.listen(
        (data) {
          buffer.addAll(data);
          dataReady?.complete();
          dataReady = null;
        },
        onError: (e) {
          debugPrint('[SOCKS5] Socket error: $e');
          socketError = e;
          dataReady?.completeError(e);
          dataReady = null;
        },
        onDone: () {
          debugPrint('[SOCKS5] Socket done (closed by remote)');
          socketDone = true;
          dataReady?.complete();
          dataReady = null;
        },
      );

      // Helper: read exactly [n] bytes from the buffered stream
      Future<List<int>> readExactly(int n) async {
        while (buffer.length < n) {
          if (socketDone) throw const SocketException('Socket closed during SOCKS5 handshake');
          if (socketError != null) throw socketError!;
          dataReady = Completer<void>();
          await dataReady!.future.timeout(config.timeout);
        }
        final result = List<int>.from(buffer.sublist(0, n));
        buffer.removeRange(0, n);
        return result;
      }

      // 2. SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=NO_AUTH
      debugPrint('[SOCKS5] Sending greeting...');
      socket.add([0x05, 0x01, 0x00]);
      await socket.flush();

      final greetResp = await readExactly(2);
      debugPrint('[SOCKS5] Greeting response: [${greetResp[0]}, ${greetResp[1]}]');
      if (greetResp[0] != 0x05 || greetResp[1] != 0x00) {
        throw Exception('SOCKS5 auth negotiation failed (got [${greetResp[0]}, ${greetResp[1]}])');
      }

      // 3. SOCKS5 CONNECT request: VER, CMD=CONNECT, RSV, ATYP=DOMAIN
      debugPrint('[SOCKS5] Sending CONNECT to $host:$targetPort');
      final hostBytes = utf8.encode(host);
      socket.add([
        0x05, 0x01, 0x00, 0x03,
        hostBytes.length, ...hostBytes,
        (targetPort >> 8) & 0xFF, targetPort & 0xFF,
      ]);
      await socket.flush();

      // Read CONNECT response header (4 bytes: VER, REP, RSV, ATYP)
      final connResp = await readExactly(4);
      debugPrint('[SOCKS5] CONNECT response: [${connResp.join(', ')}] (REP=${connResp[1]}, ATYP=${connResp[3]})');
      if (connResp[1] != 0x00) {
        final repCodes = {
          0x01: 'general SOCKS server failure',
          0x02: 'connection not allowed by ruleset',
          0x03: 'network unreachable',
          0x04: 'host unreachable',
          0x05: 'connection refused',
          0x06: 'TTL expired',
          0x07: 'command not supported',
          0x08: 'address type not supported',
        };
        final reason = repCodes[connResp[1]] ?? 'unknown';
        throw Exception('SOCKS5 CONNECT failed: code ${connResp[1]} ($reason)');
      }

      // Skip the bound address based on address type
      switch (connResp[3]) {
        case 0x01: // IPv4: 4 bytes addr + 2 bytes port
          await readExactly(6);
        case 0x03: // Domain: 1 byte len + domain + 2 bytes port
          final domLen = await readExactly(1);
          await readExactly(domLen[0] + 2);
        case 0x04: // IPv6: 16 bytes addr + 2 bytes port
          await readExactly(18);
      }
      debugPrint('[SOCKS5] CONNECT handshake complete');

      // 4. Pause (not cancel!) the stream subscription before TLS upgrade.
      // Cancelling a single-subscription stream triggers onCancel which tears
      // down the socket's internal RawSocket listener, making it unusable for
      // SecureSocket.secure(). Pausing keeps the internals alive so
      // SecureSocket.secure() can detach the raw socket properly.
      sub.pause();
      debugPrint('[SOCKS5] Stream subscription paused');

      Socket httpSocket;
      if (isHttps) {
        debugPrint('[SOCKS5] Upgrading to TLS for host=$host...');
        try {
          httpSocket = await SecureSocket.secure(
            socket,
            host: host,
            onBadCertificate: (_) => true,
          ).timeout(config.timeout);
          debugPrint('[SOCKS5] TLS upgrade successful');
        } catch (e) {
          debugPrint('[SOCKS5] TLS upgrade FAILED: $e');
          rethrow;
        }
      } else {
        // For plain HTTP, resume the subscription so we can read the response
        // via the stream in the await-for loop below.
        sub.resume();
        httpSocket = socket;
      }

      // 5. Send HTTP request
      final httpReq = 'GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n';
      debugPrint('[SOCKS5] Sending HTTP request: GET $path -> $host');
      httpSocket.write(httpReq);
      await httpSocket.flush();

      // 6. Read response until we get the status line
      final respBuffer = StringBuffer();
      await for (final chunk in httpSocket.timeout(config.timeout)) {
        respBuffer.write(utf8.decode(chunk, allowMalformed: true));
        if (respBuffer.toString().contains('\r\n')) break;
      }

      stopwatch.stop();
      final timeMs = stopwatch.elapsedMilliseconds.toDouble();
      final responseStr = respBuffer.toString();
      debugPrint('[SOCKS5] HTTP response (first line): ${responseStr.split('\r\n').firstOrNull}');
      final statusMatch = RegExp(r'HTTP/[\d.]+ (\d+)').firstMatch(responseStr);
      final statusCode = int.tryParse(statusMatch?.group(1) ?? '') ?? 0;
      debugPrint('[SOCKS5] Status=$statusCode, latency=${timeMs.toStringAsFixed(0)}ms');

      if (statusCode == 204 || (statusCode >= 200 && statusCode < 300)) {
        return CdnScanResult(ip: ip, success: true, latencyMs: timeMs);
      }
      return CdnScanResult(ip: ip, success: false, errorMessage: 'HTTP $statusCode');
    } on TimeoutException catch (e) {
      debugPrint('[SOCKS5] TIMEOUT for IP=$ip after ${stopwatch.elapsedMilliseconds}ms: $e');
      return CdnScanResult(ip: ip, success: false, errorMessage: 'Connection timed out');
    } catch (e) {
      debugPrint('[SOCKS5] ERROR for IP=$ip: $e');
      return CdnScanResult(ip: ip, success: false, errorMessage: e.toString());
    } finally {
      stopwatch.stop();
      try {
        socket?.destroy();
      } catch (_) {}
    }
  }

  /// Start scanning IPs
  Stream<CdnScanProgress> scanIps(
    List<String> ips,
    Map<String, dynamic> baseConfig,
  ) {
    final controller = StreamController<CdnScanProgress>();
    _runScan(ips, baseConfig, controller);
    return controller.stream;
  }

  Future<void> _runScan(
    List<String> ips,
    Map<String, dynamic> baseConfig,
    StreamController<CdnScanProgress> controller,
  ) async {
    if (ips.isEmpty) {
      await controller.close();
      return;
    }

    _isScanning = true;
    _shouldStop = false;
    int completed = 0;
    int successful = 0;
    final total = ips.length;
    final results = <CdnScanResult>[];

    try {
      // Initialize process manager
      _processManager = XrayProcessManager(
        binaryService: _binaryService,
        basePort: config.basePort,
        enableProcessLogs: config.enableXrayLogs,
      );

      final ipQueue = List<String>.from(ips);
      int ipIndex = 0;
      final maxConcurrency = _effectiveConcurrency();
      Future<void> progressChain = Future.value();

      Future<void> runWorker() async {
        while (true) {
          if (_shouldStop || controller.isClosed) return;
          if (ipIndex >= ipQueue.length) return;

          final ip = ipQueue[ipIndex];
          ipIndex++;

          final result = await _scanSingleIp(ip, baseConfig);

          progressChain = progressChain.then((_) async {
            if (_shouldStop || controller.isClosed) return;
            completed++;
            if (result.success) {
              successful++;
              results.add(result);
              results.sort((a, b) =>
                  (a.latencyMs ?? double.infinity).compareTo(b.latencyMs ?? double.infinity));
            }

            controller.add(CdnScanProgress(
              result: result,
              completed: completed,
              total: total,
              successful: successful,
              results: List.unmodifiable(results),
            ));
          });

          await progressChain;
        }
      }

      final workers = List.generate(maxConcurrency, (_) => runWorker());
      await Future.wait(workers);
    } on PortInUseException {
      rethrow;
    } on XrayStartupException {
      rethrow;
    } catch (e) {
      controller.addError(e);
    } finally {
      await _cleanup();
      _isScanning = false;
      if (!controller.isClosed) {
        await controller.close();
      }
    }
  }

  int _effectiveConcurrency() {
    return config.concurrentInstances > 0 ? config.concurrentInstances : 1;
  }

  /// Test a single IP by spawning and killing a dedicated xray instance
  Future<CdnScanResult> _scanSingleIp(
    String ip,
    Map<String, dynamic> baseConfig,
  ) async {
    XrayInstance? instance;
    try {
      if (Platform.isAndroid) {
        debugPrint('[CdnScan] Starting xray instance for IP=$ip');
      }
      instance = await _processManager!.startInstanceForIp(baseConfig, ip);
      if (Platform.isAndroid) {
        debugPrint('[CdnScan] Xray started for IP=$ip, port=${instance.port}, pid=${instance.process.pid}');
        debugPrint('[CdnScan] Waiting ${config.startupDelay.inMilliseconds}ms for xray startup...');
      }
      await Future.delayed(config.startupDelay);

      if (_shouldStop) {
        return CdnScanResult(
          ip: ip,
          success: false,
          errorMessage: 'Scan stopped',
        );
      }

      // On Android, check if xray process is still alive before testing
      if (Platform.isAndroid) {
        final exitCodeFuture = instance.process.exitCode;
        final aliveCheck = await Future.any([
          exitCodeFuture.then((code) => 'exited:$code'),
          Future.delayed(const Duration(milliseconds: 100), () => 'alive'),
        ]);
        debugPrint('[CdnScan] Xray process status before test: $aliveCheck');
        if (aliveCheck.startsWith('exited:')) {
          final code = aliveCheck.split(':')[1];
          debugPrint('[CdnScan] ERROR: xray died before proxy test! exit=$code, errors: ${instance.errorLog}');
          return CdnScanResult(
            ip: ip,
            success: false,
            errorMessage: 'Xray process died (exit=$code)',
          );
        }
      }

      final result = await _testWithSocks5Proxy(ip, instance.port);
      if (Platform.isAndroid) {
        debugPrint('[CdnScan] Test result for IP=$ip: success=${result.success}, '
            'latency=${result.latencyMs}ms, error=${result.errorMessage}');
      }
      return result;
    } on XrayStartupException catch (e) {
      debugPrint('[CdnScan] XrayStartupException for IP=$ip: ${e.message}');
      return CdnScanResult(
        ip: ip,
        success: false,
        errorMessage: 'Xray start failed: ${e.message}',
      );
    } catch (e) {
      debugPrint('[CdnScan] Exception for IP=$ip: $e');
      return CdnScanResult(
        ip: ip,
        success: false,
        errorMessage: e.toString(),
      );
    } finally {
      if (instance != null) {
        await _processManager?.stopInstance(instance);
      }
    }
  }


  /// Clean up all resources
  Future<void> _cleanup() async {
    // Stop all xray instances
    if (_processManager != null) {
      await _processManager!.stopAll();
      _processManager = null;
    }
  }

  /// Stop the current scan
  Future<void> stopScan() async {
    _shouldStop = true;
    await _cleanup();
  }

  /// Dispose resources
  Future<void> dispose() async {
    _shouldStop = true;
    await _cleanup();
  }
}
