import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import 'xray_binary_service.dart';

/// Represents a running xray instance
class XrayInstance {
  final int id;
  final int port;
  final Process process;
  final String configPath;
  bool isAvailable;

  XrayInstance({
    required this.id,
    required this.port,
    required this.process,
    required this.configPath,
    this.isAvailable = true,
  });
}

/// Manages multiple xray process instances for parallel testing
class XrayProcessManager {
  final XrayBinaryService _binaryService;
  final List<XrayInstance> _instances = [];
  final int basePort;
  
  Directory? _tempConfigDir;
  
  XrayProcessManager({
    XrayBinaryService? binaryService,
    this.basePort = 10808,
  }) : _binaryService = binaryService ?? XrayBinaryService();

  /// Get all running instances
  List<XrayInstance> get instances => List.unmodifiable(_instances);
  
  /// Get number of running instances
  int get instanceCount => _instances.length;

  /// Parse and validate a config JSON, returning the parsed map
  Map<String, dynamic> parseConfig(String configJson) {
    try {
      final config = json.decode(configJson) as Map<String, dynamic>;
      
      // Validate required sections
      if (!config.containsKey('inbounds')) {
        throw FormatException('Config missing "inbounds" section');
      }
      if (!config.containsKey('outbounds')) {
        throw FormatException('Config missing "outbounds" section');
      }
      
      return config;
    } catch (e) {
      if (e is FormatException) rethrow;
      throw FormatException('Invalid JSON: $e');
    }
  }

  /// Extract the original outbound address from config
  String? extractOutboundAddress(Map<String, dynamic> config) {
    final outbounds = config['outbounds'] as List<dynamic>?;
    if (outbounds == null || outbounds.isEmpty) return null;
    
    // Find the proxy outbound (usually the first one or tagged as "proxy")
    for (final outbound in outbounds) {
      final map = outbound as Map<String, dynamic>;
      final protocol = map['protocol'] as String?;
      
      if (protocol == 'vless' || protocol == 'vmess' || protocol == 'trojan') {
        final settings = map['settings'] as Map<String, dynamic>?;
        final vnext = settings?['vnext'] as List<dynamic>?;
        if (vnext != null && vnext.isNotEmpty) {
          final server = vnext[0] as Map<String, dynamic>;
          return server['address'] as String?;
        }
      }
    }
    return null;
  }

  /// Extract the inbound port from config
  int? extractInboundPort(Map<String, dynamic> config) {
    final inbounds = config['inbounds'] as List<dynamic>?;
    if (inbounds == null || inbounds.isEmpty) return null;
    
    for (final inbound in inbounds) {
      final map = inbound as Map<String, dynamic>;
      final protocol = map['protocol'] as String?;
      
      if (protocol == 'socks' || protocol == 'http') {
        return map['port'] as int?;
      }
    }
    return null;
  }

  /// Create a modified config with new port and IP
  Map<String, dynamic> createModifiedConfig(
    Map<String, dynamic> baseConfig,
    int newPort,
    String newAddress,
  ) {
    // Deep copy the config
    final config = json.decode(json.encode(baseConfig)) as Map<String, dynamic>;
    
    // Modify inbound port
    final inbounds = config['inbounds'] as List<dynamic>;
    for (final inbound in inbounds) {
      final map = inbound as Map<String, dynamic>;
      final protocol = map['protocol'] as String?;
      if (protocol == 'socks' || protocol == 'http') {
        map['port'] = newPort;
        break;
      }
    }
    
    // Modify outbound address
    final outbounds = config['outbounds'] as List<dynamic>;
    for (final outbound in outbounds) {
      final map = outbound as Map<String, dynamic>;
      final protocol = map['protocol'] as String?;
      
      if (protocol == 'vless' || protocol == 'vmess' || protocol == 'trojan') {
        final settings = map['settings'] as Map<String, dynamic>;
        final vnext = settings['vnext'] as List<dynamic>;
        if (vnext.isNotEmpty) {
          final server = vnext[0] as Map<String, dynamic>;
          server['address'] = newAddress;
        }
        break;
      }
    }
    
    return config;
  }

  /// Start multiple xray instances
  Future<void> startInstances(
    Map<String, dynamic> baseConfig,
    int count,
  ) async {
    // Ensure we have xray binary
    final xrayPath = await _binaryService.getXrayBinaryPath();
    if (!await File(xrayPath).exists()) {
      throw StateError('Xray binary not found. Please download it first.');
    }
    
    // Create temp directory for configs
    final xrayDir = await _binaryService.getXrayDirectory();
    _tempConfigDir = Directory('${xrayDir.path}/temp_configs');
    if (await _tempConfigDir!.exists()) {
      await _tempConfigDir!.delete(recursive: true);
    }
    await _tempConfigDir!.create();
    
    // Start instances
    for (int i = 0; i < count; i++) {
      final port = basePort + i;
      
      // Create config for this instance (using original address as placeholder)
      final originalAddress = extractOutboundAddress(baseConfig) ?? 'placeholder';
      final instanceConfig = createModifiedConfig(baseConfig, port, originalAddress);
      
      // Write config file
      final configPath = '${_tempConfigDir!.path}/config_$i.json';
      await File(configPath).writeAsString(json.encode(instanceConfig));
      
      // Start xray process
      final process = await Process.start(
        xrayPath,
        ['-c', configPath],
        workingDirectory: xrayDir.path,
      );
      
      // Log stdout/stderr for debugging
      process.stdout.transform(utf8.decoder).listen((data) {
        debugPrint('Xray[$i]: $data');
      });
      process.stderr.transform(utf8.decoder).listen((data) {
        debugPrint('Xray[$i] ERR: $data');
      });
      
      _instances.add(XrayInstance(
        id: i,
        port: port,
        process: process,
        configPath: configPath,
        isAvailable: true,
      ));
    }
    
    // Wait for all ports to be ready
    for (final instance in _instances) {
      await _waitForPort(instance.port, const Duration(seconds: 5));
    }
  }

  /// Update an instance's config to use a new IP address
  Future<void> updateInstanceAddress(XrayInstance instance, String newAddress, Map<String, dynamic> baseConfig) async {
    // Create new config with the new address
    final newConfig = createModifiedConfig(baseConfig, instance.port, newAddress);
    
    // Write updated config
    await File(instance.configPath).writeAsString(json.encode(newConfig));
    
    // Kill and restart the process
    instance.process.kill();
    await instance.process.exitCode;
    
    final xrayPath = await _binaryService.getXrayBinaryPath();
    final xrayDir = await _binaryService.getXrayDirectory();
    
    final newProcess = await Process.start(
      xrayPath,
      ['-c', instance.configPath],
      workingDirectory: xrayDir.path,
    );
    
    // Update instance with new process
    final index = _instances.indexWhere((i) => i.id == instance.id);
    if (index != -1) {
      _instances[index] = XrayInstance(
        id: instance.id,
        port: instance.port,
        process: newProcess,
        configPath: instance.configPath,
        isAvailable: true,
      );
    }
    
    // Wait for the port to be ready
    await _waitForPort(instance.port, const Duration(seconds: 5));
  }
  
  /// Wait for a port to be available (xray listening)
  Future<void> _waitForPort(int port, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      try {
        final socket = await Socket.connect('127.0.0.1', port, 
            timeout: const Duration(milliseconds: 200));
        await socket.close();
        return; // Port is ready
      } catch (_) {
        // Port not ready yet, wait and retry
        await Future.delayed(const Duration(milliseconds: 100));
      }
    }
    debugPrint('Warning: Port $port did not become ready within timeout');
  }

  /// Get an available instance for testing
  XrayInstance? getAvailableInstance() {
    for (final instance in _instances) {
      if (instance.isAvailable) {
        return instance;
      }
    }
    return null;
  }

  /// Mark an instance as busy
  void markInstanceBusy(XrayInstance instance) {
    instance.isAvailable = false;
  }

  /// Mark an instance as available
  void markInstanceAvailable(XrayInstance instance) {
    instance.isAvailable = true;
  }

  /// Stop all xray instances
  Future<void> stopAll() async {
    for (final instance in _instances) {
      try {
        instance.process.kill();
        await instance.process.exitCode.timeout(
          const Duration(seconds: 2),
          onTimeout: () {
            instance.process.kill(ProcessSignal.sigkill);
            return -1;
          },
        );
      } catch (e) {
        debugPrint('Error stopping xray instance ${instance.id}: $e');
      }
    }
    _instances.clear();
    
    // Clean up temp configs
    if (_tempConfigDir != null && await _tempConfigDir!.exists()) {
      try {
        await _tempConfigDir!.delete(recursive: true);
      } catch (e) {
        debugPrint('Error cleaning temp configs: $e');
      }
    }
  }

  /// Dispose and clean up
  Future<void> dispose() async {
    await stopAll();
  }
}

