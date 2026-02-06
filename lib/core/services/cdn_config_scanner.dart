import 'dart:async';
import 'dart:io';

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
  final String testUrl;
  final int basePort;

  const CdnScanConfig({
    this.concurrentInstances = 5,
    this.timeout = const Duration(seconds: 10),
    this.testUrl = 'https://www.gstatic.com/generate_204',
    this.basePort = 10808,
  });

  CdnScanConfig copyWith({
    int? concurrentInstances,
    Duration? timeout,
    String? testUrl,
    int? basePort,
  }) {
    return CdnScanConfig(
      concurrentInstances: concurrentInstances ?? this.concurrentInstances,
      timeout: timeout ?? this.timeout,
      testUrl: testUrl ?? this.testUrl,
      basePort: basePort ?? this.basePort,
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

  /// Test connection through SOCKS5 proxy using curl command
  /// This feature is only available on desktop (Linux/Windows)
  Future<CdnScanResult> _testWithSocks5Proxy(String ip, int proxyPort) async {
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

  /// Start scanning IPs
  Stream<CdnScanProgress> scanIps(
    List<String> ips,
    Map<String, dynamic> baseConfig,
  ) {
    final controller = StreamController<CdnScanProgress>();
    _runScan(ips, baseConfig, controller);
    return controller.stream;
  }

  // Track failed instances to avoid using them
  final Set<int> _failedInstanceIds = {};
  // Track consecutive failures per instance for recovery
  final Map<int, int> _instanceFailureCount = {};
  // Lock for serializing instance restarts
  bool _restartInProgress = false;

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
    _failedInstanceIds.clear();
    _instanceFailureCount.clear();

    int completed = 0;
    int successful = 0;
    final total = ips.length;
    final results = <CdnScanResult>[];

    try {
      // Initialize process manager
      _processManager = XrayProcessManager(
        binaryService: _binaryService,
        basePort: config.basePort,
      );

      // Start xray instances - this will throw if ports are in use or xray fails
      await _processManager!.startInstances(baseConfig, config.concurrentInstances);

      // Process IPs one at a time per instance to avoid overwhelming the system
      // Use a work-stealing approach where each instance processes IPs sequentially
      final ipQueue = List<String>.from(ips);
      int ipIndex = 0;
      
      // Get available instances (excluding failed ones)
      List<XrayInstance> getAvailableInstances() {
        return _processManager!.instances
            .where((i) => !_failedInstanceIds.contains(i.id))
            .toList();
      }

      while (ipIndex < ipQueue.length && !_shouldStop && !controller.isClosed) {
        final availableInstances = getAvailableInstances();
        
        if (availableInstances.isEmpty) {
          // All instances failed, try to recover one
          final recovered = await _tryRecoverInstance(baseConfig);
          if (!recovered) {
            // Can't recover, fail remaining IPs
            while (ipIndex < ipQueue.length) {
              completed++;
              controller.add(CdnScanProgress(
                result: CdnScanResult(
                  ip: ipQueue[ipIndex],
                  success: false,
                  errorMessage: 'All xray instances failed',
                ),
                completed: completed,
                total: total,
                successful: successful,
                results: List.unmodifiable(results),
              ));
              ipIndex++;
            }
            break;
          }
          continue;
        }

        // Calculate batch size based on available instances
        final batchSize = availableInstances.length.clamp(1, ipQueue.length - ipIndex);
        
        // Process batch - one IP per instance
        final batchFutures = <Future<CdnScanResult>>[];
        final batchIps = <String>[];

        for (var j = 0; j < batchSize && (ipIndex + j) < ipQueue.length; j++) {
          if (_shouldStop || controller.isClosed) break;

          final ip = ipQueue[ipIndex + j];
          batchIps.add(ip);
          
          if (j < availableInstances.length) {
            final instance = availableInstances[j];
            batchFutures.add(_testIpWithInstanceSafe(instance, ip, baseConfig));
          }
        }

        if (batchFutures.isEmpty) continue;

        // Wait for batch to complete with a timeout
        List<CdnScanResult> batchResults;
        try {
          batchResults = await Future.wait(batchFutures)
              .timeout(config.timeout * 2 + const Duration(seconds: 10));
        } on TimeoutException {
          // If batch times out, create failure results
          batchResults = batchIps
              .map((ip) => CdnScanResult(
                    ip: ip,
                    success: false,
                    errorMessage: 'Batch timeout',
                  ))
              .toList();
        }

        // Update progress
        for (final result in batchResults) {
          if (_shouldStop || controller.isClosed) break;

          completed++;
          if (result.success) {
            successful++;
            results.add(result);
            // Keep results sorted by latency
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
        }

        ipIndex += batchResults.length;
        
        // Small delay between batches to let the system breathe
        if (ipIndex < ipQueue.length) {
          await Future.delayed(const Duration(milliseconds: 50));
        }
      }
    } on PortInUseException {
      rethrow;
    } on XrayStartupException {
      rethrow;
    } catch (e) {
      controller.addError(e);
    } finally {
      await _cleanup();
      _isScanning = false;
      _failedInstanceIds.clear();
      _instanceFailureCount.clear();
      if (!controller.isClosed) {
        await controller.close();
      }
    }
  }

  /// Try to recover a failed instance by waiting and restarting it
  Future<bool> _tryRecoverInstance(Map<String, dynamic> baseConfig) async {
    if (_processManager == null || _failedInstanceIds.isEmpty) return false;
    
    // Find the instance that failed least recently (lowest failure count)
    int? bestInstanceId;
    int lowestFailures = 999;
    
    for (final id in _failedInstanceIds) {
      final failures = _instanceFailureCount[id] ?? 0;
      if (failures < lowestFailures) {
        lowestFailures = failures;
        bestInstanceId = id;
      }
    }
    
    if (bestInstanceId == null) return false;
    
    // Don't try to recover if it's failed too many times
    if (lowestFailures >= 3) return false;
    
    // Wait longer for ports to be released
    await Future.delayed(const Duration(seconds: 2));
    
    final instanceId = bestInstanceId; // Capture for use in catch block
    try {
      final instance = _processManager!.instances.firstWhere((i) => i.id == instanceId);
      // Try a dummy restart to see if the port is available
      final originalAddress = _processManager!.extractOutboundAddress(baseConfig) ?? 'placeholder';
      await _processManager!.updateInstanceAddress(instance, originalAddress, baseConfig);
      
      // Success - remove from failed set
      _failedInstanceIds.remove(instanceId);
      _instanceFailureCount[instanceId] = 0;
      return true;
    } catch (e) {
      // Still failed, increment failure count
      _instanceFailureCount[instanceId] = (_instanceFailureCount[instanceId] ?? 0) + 1;
      return false;
    }
  }

  /// Test an IP with an instance, handling failures gracefully
  Future<CdnScanResult> _testIpWithInstanceSafe(
    XrayInstance instance,
    String ip,
    Map<String, dynamic> baseConfig,
  ) async {
    // Check if instance is already marked as failed
    if (_failedInstanceIds.contains(instance.id)) {
      return CdnScanResult(
        ip: ip,
        success: false,
        errorMessage: 'Instance unavailable',
      );
    }

    // Serialize restarts to avoid overwhelming the system
    while (_restartInProgress) {
      await Future.delayed(const Duration(milliseconds: 50));
      if (_shouldStop) {
        return CdnScanResult(
          ip: ip,
          success: false,
          errorMessage: 'Scan stopped',
        );
      }
    }

    try {
      _restartInProgress = true;
      
      // Update the instance to use the new IP
      await _processManager!.updateInstanceAddress(instance, ip, baseConfig);
      
      _restartInProgress = false;
      
      // Reset failure count on successful restart
      _instanceFailureCount[instance.id] = 0;

      // Test through the proxy
      return await _testWithSocks5Proxy(ip, instance.port);
    } on XrayStartupException catch (e) {
      _restartInProgress = false;
      
      // Track this failure
      _instanceFailureCount[instance.id] = (_instanceFailureCount[instance.id] ?? 0) + 1;
      
      // Mark instance as failed after multiple failures
      if ((_instanceFailureCount[instance.id] ?? 0) >= 2) {
        _failedInstanceIds.add(instance.id);
      }
      
      return CdnScanResult(
        ip: ip,
        success: false,
        errorMessage: 'Xray restart failed: ${e.message}',
      );
    } catch (e) {
      _restartInProgress = false;
      return CdnScanResult(
        ip: ip,
        success: false,
        errorMessage: e.toString(),
      );
    }
  }


  /// Clean up all resources
  Future<void> _cleanup() async {
    _restartInProgress = false;

    // Clear tracking state
    _failedInstanceIds.clear();
    _instanceFailureCount.clear();

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
