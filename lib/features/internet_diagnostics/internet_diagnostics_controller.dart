import 'dart:async';
import 'dart:math';
import 'package:flutter/foundation.dart';
import '../../core/services/internet_diagnostics_service.dart';
import '../../core/services/cdn_ips.dart';
import '../../core/services/protocol_accessibility_service.dart';

/// Current state status of the diagnostic engine
enum DiagnosticEngineStatus { idle, running, completed }

/// Progress tracking container for packet loss analysis on a single target
class PacketLossDestinationProgress {
  final String destination;
  final List<bool?> pings; // true = success, false = fail, null = pending
  final List<int?> latencies; // null for lost packets
  int totalSent = 0;
  int totalReceived = 0;
  double lossPercentage = 0.0;
  int maxConsecutiveLoss = 0;
  int? minLatency;
  int? maxLatency;
  int? avgLatency;
  String? statusMessage;

  PacketLossDestinationProgress({
    required this.destination,
    required int pingCount,
  }) : pings = List<bool?>.filled(pingCount, null),
       latencies = List<int?>.filled(pingCount, null);
}

/// Controller that coordinates executing tests and updating diagnostic UI states.
class InternetDiagnosticsController extends ChangeNotifier {
  DiagnosticEngineStatus _engineStatus = DiagnosticEngineStatus.idle;
  int _currentRunId = 0;

  // Track status of individual checks
  bool _dnsSuccess = false;
  bool _ipv4Success = false;
  bool _ipv6Success = false;
  bool _httpsSuccess = false;
  bool _dnsAnalysisSuccess = false;
  bool _tlsAnalysisSuccess = false;
  bool _domesticIpSuccess = false;
  bool _internationalIpSuccess = false;
  bool _overallInternetAccess = false;

  // Hold detailed results
  DiagnosticTestResult? _dnsResult;
  DiagnosticTestResult? _ipv4Result;
  DiagnosticTestResult? _ipv6Result;
  DiagnosticTestResult? _httpsResult;
  DnsAnalysisSummary? _dnsAnalysisSummary;
  TlsAnalysisSummary? _tlsAnalysisSummary;
  DiagnosticTestResult? _domesticIpResult;
  DiagnosticTestResult? _internationalIpResult;
  DiagnosticTestResult? _routingAnalysisResult;

  // Website Reachability State
  List<WebsiteReachabilityResult> _websiteResults = [];
  bool _isScanningWebsites = false;

  // CDN Reachability State
  List<WebsiteReachabilityResult> _cdnResults = [];
  bool _isScanningCdns = false;

  // TLS / HTTPS Analysis State
  bool _isScanningTlsTargets = false;

  // Social Media Reachability State
  List<SocialMediaResult> _socialMediaResults = [];
  bool _isScanningSocialMedia = false;

  // Protocol Accessibility State
  bool _protocolAccessibilitySuccess = false;
  List<ProtocolAccessibilitySummary> _protocolAccessibilitySummaries = [];
  bool _isScanningProtocols = false;
  String _protocolStepName = '';

  // Packet Loss Analysis State
  final List<String> _packetLossDestinations = ['1.1.1.1', '8.8.8.8', 'google.com'];
  bool _isTestingPacketLoss = false;
  List<PacketLossDestinationProgress> _packetLossProgress = [];
  PacketLossSummary? _packetLossSummary;
  bool _packetLossSuccess = false;

  // List of major targets to verify
  static const List<Map<String, String>> targetWebsites = [
    {'name': 'Google', 'domain': 'www.google.com'},
    {'name': 'YouTube', 'domain': 'www.youtube.com'},
    {'name': 'GitHub', 'domain': 'github.com'},
    {'name': 'Wikipedia', 'domain': 'wikipedia.org'},
    {'name': 'Reddit', 'domain': 'www.reddit.com'},
    {'name': 'Stack Overflow', 'domain': 'stackoverflow.com'},
    {'name': 'ChatGPT', 'domain': 'chatgpt.com'},
    {'name': 'Claude', 'domain': 'claude.ai'},
    {'name': 'Gemini', 'domain': 'gemini.google.com'},
  ];

  // List of CDN targets to verify
  static const List<Map<String, dynamic>> targetCdns = [
    {
      'name': 'Cloudflare',
      'domain': 'cloudflare.com',
      'ips': cloudflareIps,
    },
    {
      'name': 'Akamai',
      'domain': 'akamai.com',
      'ips': akamaiIps,
    },
    {
      'name': 'Fastly',
      'domain': 'fastly.com',
      'ips': fastlyIps,
    },
    {
      'name': 'AWS CloudFront',
      'domain': 'aws.amazon.com',
      'ips': cloudfrontIps,
    },
    {
      'name': 'Azure CDN',
      'domain': 'azure.microsoft.com',
      'ips': azureIps,
    },
    {
      'name': 'Google CDN',
      'domain': 'cloud.google.com',
      'ips': googleIps,
    },
  ];

  // List of social media targets to verify
  static const List<Map<String, String>> targetSocialMedia = [
    {
      'name': 'Telegram',
      'primary': 'telegram.org',
      'secondary': 'api.telegram.org',
    },
    {
      'name': 'WhatsApp',
      'primary': 'web.whatsapp.com',
      'secondary': 'graph.whatsapp.com',
    },
    {
      'name': 'Discord',
      'primary': 'discord.com',
      'secondary': 'gateway.discord.gg',
    },
    {
      'name': 'Instagram',
      'primary': 'instagram.com',
      'secondary': 'scontent.cdninstagram.com',
    },
    {'name': 'X (Twitter)', 'primary': 'x.com', 'secondary': 'api.x.com'},
    {
      'name': 'Facebook',
      'primary': 'facebook.com',
      'secondary': 'graph.facebook.com',
    },
    {'name': 'TikTok', 'primary': 'tiktok.com', 'secondary': 'api.tiktokv.com'},
    {
      'name': 'Snapchat',
      'primary': 'snapchat.com',
      'secondary': 'aws.api.snapchat.com',
    },
    {'name': 'Signal', 'primary': 'signal.org', 'secondary': 'chat.signal.org'},
  ];

  // Track progress
  int _completedTestsCount = 0;
  static const int totalTestsCount = 13; // 13 progressive sequence tasks

  // Targets for Protocol Accessibility Checks
  static const List<String> protocolHttpDomains = [
    'google.com',
    'cloudflare.com',
    'wikipedia.org',
    'github.com',
  ];

  static const List<String> protocolHttpsDomains = [
    'google.com',
    'cloudflare.com',
    'wikipedia.org',
    'github.com',
  ];

  static const List<String> protocolUdpDomains = [
    'dns.google',
    'one.one.one.one',
    'time.google.com',
    'time.windows.com',
  ];

  static const List<String> protocolHttp3Domains = [
    'google.com',
    'cloudflare.com',
    'dash.cloudflare.com',
    'one.one.one.one',
    'facebook.com',
  ];


  static const List<String> protocolDohDomains = [
    'dns.google',
    'cloudflare-dns.com',
    'dns.quad9.net',
  ];

  static const List<String> protocolDotDomains = [
    'dns.google',
    'one.one.one.one',
    'dns.quad9.net',
  ];

  static const List<String> protocolPingDomains = [
    'google.com',
    'cloudflare.com',
    'github.com',
    'wikipedia.org',
  ];

  // Getters
  bool get protocolAccessibilitySuccess => _protocolAccessibilitySuccess;
  List<ProtocolAccessibilitySummary> get protocolAccessibilitySummaries => _protocolAccessibilitySummaries;
  bool get isScanningProtocols => _isScanningProtocols;
  String get protocolStepName => _protocolStepName;
  int get supportedProtocolsCount => _protocolAccessibilitySummaries.where((s) => s.isSupported).length;
  int get blockedProtocolsCount => _protocolAccessibilitySummaries.where((s) => s.isBlocked).length;

  // Packet Loss Getters
  List<String> get packetLossDestinations => _packetLossDestinations;
  bool get isTestingPacketLoss => _isTestingPacketLoss;
  List<PacketLossDestinationProgress> get packetLossProgress => _packetLossProgress;
  PacketLossSummary? get packetLossSummary => _packetLossSummary;
  bool get packetLossSuccess => _packetLossSuccess;

  // Getters
  DiagnosticEngineStatus get engineStatus => _engineStatus;
  bool get dnsSuccess => _dnsSuccess;
  bool get ipv4Success => _ipv4Success;
  bool get ipv6Success => _ipv6Success;
  bool get httpsSuccess => _httpsSuccess;
  bool get dnsAnalysisSuccess => _dnsAnalysisSuccess;
  bool get tlsAnalysisSuccess => _tlsAnalysisSuccess;
  bool get domesticIpSuccess => _domesticIpSuccess;
  bool get internationalIpSuccess => _internationalIpSuccess;
  bool get overallInternetAccess => _overallInternetAccess;

  DiagnosticTestResult? get dnsResult => _dnsResult;
  DiagnosticTestResult? get ipv4Result => _ipv4Result;
  DiagnosticTestResult? get ipv6Result => _ipv6Result;
  DiagnosticTestResult? get httpsResult => _httpsResult;
  DnsAnalysisSummary? get dnsAnalysisSummary => _dnsAnalysisSummary;
  TlsAnalysisSummary? get tlsAnalysisSummary => _tlsAnalysisSummary;
  DiagnosticTestResult? get domesticIpResult => _domesticIpResult;
  DiagnosticTestResult? get internationalIpResult => _internationalIpResult;
  DiagnosticTestResult? get routingAnalysisResult => _routingAnalysisResult;

  List<WebsiteReachabilityResult> get websiteResults => _websiteResults;
  bool get isScanningWebsites => _isScanningWebsites;
  bool get isScanningTlsTargets => _isScanningTlsTargets;

  List<WebsiteReachabilityResult> get cdnResults => _cdnResults;
  bool get isScanningCdns => _isScanningCdns;

  List<SocialMediaResult> get socialMediaResults => _socialMediaResults;
  bool get isScanningSocialMedia => _isScanningSocialMedia;

  int get completedTestsCount => _completedTestsCount;
  double get progressFraction => _completedTestsCount / totalTestsCount;

  bool get isIdle => _engineStatus == DiagnosticEngineStatus.idle;
  bool get isRunning => _engineStatus == DiagnosticEngineStatus.running;
  bool get isCompleted => _engineStatus == DiagnosticEngineStatus.completed;

  // Website reachability summary statistics
  int get reachableWebsitesCount => _websiteResults
      .where((w) => w.status == ReachabilityStatus.reachable)
      .length;

  int get blockedWebsitesCount => _websiteResults
      .where((w) => w.status == ReachabilityStatus.blocked)
      .length;

  int get failedWebsitesCount => _websiteResults
      .where(
        (w) =>
            w.status == ReachabilityStatus.dnsFailure ||
            w.status == ReachabilityStatus.tlsFailure ||
            w.status == ReachabilityStatus.timeout,
      )
      .length;

  int get averageWebsiteLatencyMs {
    final latencies = _websiteResults
        .where(
          (w) =>
              w.latencyMs != null && w.status == ReachabilityStatus.reachable,
        )
        .map((w) => w.latencyMs!)
        .toList();
    if (latencies.isEmpty) return 0;
    final total = latencies.reduce((a, b) => a + b);
    return (total / latencies.length).round();
  }

  // CDN reachability summary statistics
  int get reachableCdnsCount => _cdnResults
      .where((w) => w.status == ReachabilityStatus.reachable)
      .length;

  int get blockedCdnsCount => _cdnResults
      .where((w) => w.status == ReachabilityStatus.blocked)
      .length;

  int get failedCdnsCount => _cdnResults
      .where(
        (w) =>
            w.status == ReachabilityStatus.dnsFailure ||
            w.status == ReachabilityStatus.tlsFailure ||
            w.status == ReachabilityStatus.timeout,
      )
      .length;

  int get averageCdnLatencyMs {
    final latencies = _cdnResults
        .where(
          (w) =>
              w.latencyMs != null && w.status == ReachabilityStatus.reachable,
        )
        .map((w) => w.latencyMs!)
        .toList();
    if (latencies.isEmpty) return 0;
    final total = latencies.reduce((a, b) => a + b);
    return (total / latencies.length).round();
  }

  int get tlsHandshakeSuccessCount =>
      _tlsAnalysisSummary?.successfulHandshakes ?? 0;

  int get tlsCertificateMismatchCount =>
      _tlsAnalysisSummary?.certificateMismatches ?? 0;

  int get tlsTraceMismatchCount => _tlsAnalysisSummary?.traceMismatches ?? 0;

  int get averageTlsHandshakeLatencyMs =>
      _tlsAnalysisSummary?.averageHandshakeLatencyMs ?? 0;

  // Social Media accessibility summary statistics
  int get accessibleSocialCount => _socialMediaResults
      .where((w) => w.status == SocialMediaStatus.accessible)
      .length;

  int get partialSocialCount => _socialMediaResults
      .where((w) => w.status == SocialMediaStatus.partial)
      .length;

  int get blockedSocialCount => _socialMediaResults
      .where((w) => w.status == SocialMediaStatus.blocked)
      .length;

  int get averageSocialLatencyMs {
    final latencies = _socialMediaResults
        .where(
          (w) => w.latencyMs != null && w.status != SocialMediaStatus.blocked,
        )
        .map((w) => w.latencyMs!)
        .toList();
    if (latencies.isEmpty) return 0;
    final total = latencies.reduce((a, b) => a + b);
    return (total / latencies.length).round();
  }

  /// Run all tests sequentially to create a gorgeous scanning effect in the UI
  Future<void> runDiagnosticsSuite() async {
    if (_engineStatus == DiagnosticEngineStatus.running) return;

    _currentRunId++;
    final runId = _currentRunId;

    _engineStatus = DiagnosticEngineStatus.running;
    _completedTestsCount = 0;

    _dnsSuccess = false;
    _ipv4Success = false;
    _ipv6Success = false;
    _httpsSuccess = false;
    _dnsAnalysisSuccess = false;
    _tlsAnalysisSuccess = false;
    _domesticIpSuccess = false;
    _internationalIpSuccess = false;
    _overallInternetAccess = false;

    _dnsResult = null;
    _ipv4Result = null;
    _ipv6Result = null;
    _httpsResult = null;
    _dnsAnalysisSummary = null;
    _tlsAnalysisSummary = null;
    _domesticIpResult = null;
    _internationalIpResult = null;
    _routingAnalysisResult = null;
    _websiteResults = [];
    _isScanningWebsites = false;
    _isScanningTlsTargets = false;
    _cdnResults = [];
    _isScanningCdns = false;
    _socialMediaResults = [];
    _isScanningSocialMedia = false;
    _isTestingPacketLoss = false;
    _packetLossProgress = [];
    _packetLossSummary = null;
    _packetLossSuccess = false;

    notifyListeners();

    // 1. DNS Resolution Test
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _dnsResult = await InternetDiagnosticsService.checkDnsResolution();
    if (runId != _currentRunId) return;
    _dnsSuccess = _dnsResult!.success;
    _completedTestsCount++;
    notifyListeners();

    // 2. IPv4 Connectivity Test
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _ipv4Result = await InternetDiagnosticsService.checkIpv4Connectivity();
    if (runId != _currentRunId) return;
    _ipv4Success = _ipv4Result!.success;
    _completedTestsCount++;
    notifyListeners();

    // 3. IPv6 Connectivity Test
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _ipv6Result = await InternetDiagnosticsService.checkIpv6Connectivity();
    if (runId != _currentRunId) return;
    _ipv6Success = _ipv6Result!.success;
    _completedTestsCount++;
    notifyListeners();

    // 4. HTTPS Traffic Test
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _httpsResult = await InternetDiagnosticsService.checkHttpsTraffic();
    if (runId != _currentRunId) return;
    _httpsSuccess = _httpsResult!.success;
    _completedTestsCount++;
    notifyListeners();

    // 5. DNS Provider Analysis
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _dnsAnalysisSummary =
        await InternetDiagnosticsService.analyzeDnsProviders();
    if (runId != _currentRunId) return;
    _dnsAnalysisSuccess = _dnsAnalysisSummary!.success;
    _completedTestsCount++;
    notifyListeners();

    // 6. Domestic IP Discovery Test
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _domesticIpResult = await InternetDiagnosticsService.fetchPublicIp(
      domestic: true,
    );
    if (runId != _currentRunId) return;
    _domesticIpSuccess = _domesticIpResult!.success;
    _completedTestsCount++;
    notifyListeners();

    // 7. International IP Discovery Test
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _internationalIpResult = await InternetDiagnosticsService.fetchPublicIp(
      domestic: false,
    );
    if (runId != _currentRunId) return;
    _internationalIpSuccess = _internationalIpResult!.success;
    _completedTestsCount++;
    notifyListeners();

    // 8. Perform IP Routing and Discrepancy Analysis
    _routingAnalysisResult = InternetDiagnosticsService.analyzePublicIps(
      domesticResult: _domesticIpResult!,
      internationalResult: _internationalIpResult!,
    );
    notifyListeners();

    // 9. TLS / HTTPS Analysis Step
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _isScanningTlsTargets = true;
    _completedTestsCount++;
    notifyListeners();

    final tlsSummary = await InternetDiagnosticsService.analyzeTlsTargets(
      publicIp:
          _extractRetrievedIp(_internationalIpResult) ??
          _extractRetrievedIp(_domesticIpResult),
    );
    if (runId != _currentRunId) return;
    _tlsAnalysisSummary = tlsSummary;
    _tlsAnalysisSuccess = _tlsAnalysisSummary!.success;
    _isScanningTlsTargets = false;
    notifyListeners();

    // 10. Website Reachability Scan Step
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _isScanningWebsites = true;
    _completedTestsCount++;
    notifyListeners();

    for (final target in targetWebsites) {
      if (runId != _currentRunId) return;
      final name = target['name']!;
      final domain = target['domain']!;

      final result = await InternetDiagnosticsService.testWebsiteReachability(
        name,
        domain,
      );
      if (runId != _currentRunId) return;
      _websiteResults.add(result);
      notifyListeners();

      // Subtle stagger delay between sequential checks to render scanning effect
      await Future<void>.delayed(const Duration(milliseconds: 150));
      if (runId != _currentRunId) return;
    }

    _isScanningWebsites = false;
    notifyListeners();

    // 10. CDN Reachability Scan Step
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _isScanningCdns = true;
    _completedTestsCount++;
    notifyListeners();

    for (final target in targetCdns) {
      if (runId != _currentRunId) return;
      final name = target['name']!;
      final domain = target['domain']!;
      final List<String> ips = target['ips'] as List<String>;

      // Pick a random list of 50 IPs from each CDN
      final random = Random();
      final List<String> shuffledIps = List<String>.from(ips)..shuffle(random);
      final List<String> selectedIps = shuffledIps.take(50).toList();

      final scanResult = await InternetDiagnosticsService.scanCdnIps(
        selectedIps,
        maxConcurrency: 50,
        timeout: const Duration(milliseconds: 500),
      );
      if (runId != _currentRunId) return;

      final isReachable = scanResult.reachable > 0;
      final accessibilityPercent = (scanResult.accessibilityRate * 100).toStringAsFixed(1);
      
      final detailsText = 'Edge IP Range Scan Results (Tested 50 Random IPs):\n'
          'Total tested random IPs: ${scanResult.totalTested}\n'
          'Reachable edge IPs: ${scanResult.reachable}\n'
          'Failed IPs: ${scanResult.totalTested - scanResult.reachable}\n'
          'CDN Accessibility: $accessibilityPercent%\n'
          'Average Handshake Latency: ${scanResult.averageLatencyMs}ms\n\n'
          'Note: This test scanned 50 randomly selected IPs from the CDN\'s public ranges to determine edge network accessibility and performance.';

      final result = WebsiteReachabilityResult(
        name: name,
        domain: domain,
        status: isReachable ? ReachabilityStatus.reachable : ReachabilityStatus.blocked,
        latencyMs: scanResult.averageLatencyMs,
        errorDetails: detailsText,
        statusCode: isReachable ? 200 : null,
      );

      _cdnResults.add(result);
      notifyListeners();

      // Subtle stagger delay between sequential checks to render scanning effect
      await Future<void>.delayed(const Duration(milliseconds: 150));
      if (runId != _currentRunId) return;
    }

    _isScanningCdns = false;
    notifyListeners();

    // 11. Social Media Accessibility Scan Step
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _isScanningSocialMedia = true;
    _completedTestsCount++;
    notifyListeners();

    for (final target in targetSocialMedia) {
      if (runId != _currentRunId) return;
      final name = target['name']!;
      final primary = target['primary']!;
      final secondary = target['secondary']!;

      final result =
          await InternetDiagnosticsService.testSocialMediaAccessibility(
            name: name,
            primaryDomain: primary,
            secondaryDomain: secondary,
          );
      if (runId != _currentRunId) return;
      _socialMediaResults.add(result);
      notifyListeners();

      // Subtle stagger delay between sequential checks to render scanning effect
      await Future<void>.delayed(const Duration(milliseconds: 150));
      if (runId != _currentRunId) return;
    }

    _isScanningSocialMedia = false;
    notifyListeners();

    // 12. Protocol Accessibility Scan Step
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _isScanningProtocols = true;
    _completedTestsCount++;
    notifyListeners();

    final testTimeout = const Duration(seconds: 4);
    final List<ProtocolAccessibilitySummary> summaries = [];

    Future<ProtocolAccessibilitySummary> runProtocolStep(
      String name,
      String description,
      List<String> targets,
      Future<ProtocolTestResult> Function(String, Duration) tester,
    ) async {
      _protocolStepName = 'Testing $name...';
      notifyListeners();
      final futures = targets.map((domain) => tester(domain, testTimeout)).toList();
      final results = await Future.wait(futures);
      return ProtocolAccessibilitySummary(
        protocolName: name,
        isSupported: results.any((r) => r.success),
        isBlocked: false, // updated below
        results: results,
        description: description,
      );
    }

    try {
      summaries.add(await runProtocolStep(
        'TCP HTTP',
        'Plain HTTP connectivity on TCP port 80',
        protocolHttpDomains,
        ProtocolAccessibilityService.testHttpDomain,
      ));
      if (runId != _currentRunId) return;

      summaries.add(await runProtocolStep(
        'TCP HTTPS',
        'Secure HTTPS connectivity on TCP port 443',
        protocolHttpsDomains,
        ProtocolAccessibilityService.testHttpsDomain,
      ));
      if (runId != _currentRunId) return;

      summaries.add(await runProtocolStep(
        'UDP Connectivity',
        'Generic UDP traffic via NTP and DNS',
        protocolUdpDomains,
        ProtocolAccessibilityService.testUdpDomain,
      ));
      if (runId != _currentRunId) return;

      summaries.add(await runProtocolStep(
        'HTTP/3 (QUIC)',
        'Forced HTTP/3 over QUIC on UDP port 443',
        protocolHttp3Domains,
        ProtocolAccessibilityService.testHttp3Domain,
      ));
      if (runId != _currentRunId) return;


      summaries.add(await runProtocolStep(
        'DNS-over-HTTPS',
        'DNS queries routed securely inside HTTPS request',
        protocolDohDomains,
        ProtocolAccessibilityService.testDoHDomain,
      ));
      if (runId != _currentRunId) return;

      summaries.add(await runProtocolStep(
        'DNS-over-TLS',
        'DNS queries secure wrapping in TLS port 853',
        protocolDotDomains,
        ProtocolAccessibilityService.testDoTDomain,
      ));
      if (runId != _currentRunId) return;

      summaries.add(await runProtocolStep(
        'ICMP Ping',
        'Standard ICMP Echo ping reachability',
        protocolPingDomains,
        ProtocolAccessibilityService.testIcmpDomain,
      ));
    } catch (e) {
      debugPrint('Protocol Accessibility scan error: $e');
    }

    if (runId != _currentRunId) return;

    // Compute Overall Internet Access
    final hasProtocolSupport = summaries.any((s) => s.isSupported);
    _overallInternetAccess =
        _dnsSuccess ||
        _ipv4Success ||
        _ipv6Success ||
        _httpsSuccess ||
        _dnsAnalysisSuccess ||
        _tlsAnalysisSuccess ||
        _domesticIpSuccess ||
        _internationalIpSuccess ||
        _websiteResults.any((w) => w.status == ReachabilityStatus.reachable) ||
        _cdnResults.any((c) => c.status == ReachabilityStatus.reachable) ||
        _socialMediaResults.any(
          (s) =>
              s.status == SocialMediaStatus.accessible ||
              s.status == SocialMediaStatus.partial,
        ) ||
        hasProtocolSupport;

    // Calculate blocked status for protocols based on network online status
    final online = _overallInternetAccess || _httpsSuccess || _dnsSuccess;
    _protocolAccessibilitySummaries = summaries.map((s) {
      final isBlocked = !s.isSupported && online;
      return ProtocolAccessibilitySummary(
        protocolName: s.protocolName,
        isSupported: s.isSupported,
        isBlocked: isBlocked,
        results: s.results,
        description: s.description,
      );
    }).toList();

    _protocolAccessibilitySuccess = hasProtocolSupport;
    _isScanningProtocols = false;
    notifyListeners();

    // 13. Packet Loss Analysis Step
    await Future<void>.delayed(const Duration(milliseconds: 400));
    if (runId != _currentRunId) return;
    _completedTestsCount++;
    notifyListeners();

    await runPacketLossAnalysis(pingCount: 10);
    if (runId != _currentRunId) return;

    _engineStatus = DiagnosticEngineStatus.completed;
    notifyListeners();
  }

  void addPacketLossDestination(String destination) {
    if (destination.trim().isEmpty) return;
    final host = destination.trim();
    if (!_packetLossDestinations.contains(host)) {
      _packetLossDestinations.add(host);
      notifyListeners();
    }
  }

  void removePacketLossDestination(String destination) {
    if (_packetLossDestinations.length <= 1) return;
    _packetLossDestinations.remove(destination);
    notifyListeners();
  }

  /// Runs packet loss test to multiple destinations in a staggered parallel manner.
  Future<void> runPacketLossAnalysis({int pingCount = 10}) async {
    _isTestingPacketLoss = true;
    _packetLossSummary = null;
    _packetLossSuccess = false;
    _packetLossProgress = _packetLossDestinations
        .map((t) => PacketLossDestinationProgress(destination: t, pingCount: pingCount))
        .toList();
    notifyListeners();

    final List<Future<void>> futures = [];
    for (int i = 0; i < _packetLossDestinations.length; i++) {
      futures.add(_runPacketLossForTarget(i, pingCount));
    }
    await Future.wait(futures);

    // Compute final summary
    final destinationResults = _packetLossProgress.map((p) {
      return PacketLossDestinationResult(
        destination: p.destination,
        latencies: p.latencies,
        totalSent: p.totalSent,
        totalReceived: p.totalReceived,
        lossPercentage: p.lossPercentage,
        maxConsecutiveLoss: p.maxConsecutiveLoss,
        minLatency: p.minLatency,
        maxLatency: p.maxLatency,
        avgLatency: p.avgLatency,
        errorMessage: p.totalReceived == 0 && p.totalSent > 0
            ? 'All pings failed or command timed out'
            : null,
      );
    }).toList();

    _packetLossSuccess = destinationResults.any((r) => r.totalReceived > 0);
    _packetLossSummary = PacketLossSummary(
      results: destinationResults,
      success: _packetLossSuccess,
    );

    _isTestingPacketLoss = false;
    notifyListeners();
  }

  Future<void> _runPacketLossForTarget(int targetIndex, int pingCount) async {
    final progress = _packetLossProgress[targetIndex];
    final destination = progress.destination;

    // Stagger start time of each target to prevent CPU/IO spikes
    await Future.delayed(Duration(milliseconds: targetIndex * 150));

    for (int step = 0; step < pingCount; step++) {
      // 200ms delay between successive pings to the same target
      if (step > 0) {
        await Future.delayed(const Duration(milliseconds: 200));
      }

      progress.totalSent++;
      progress.statusMessage = 'Pinging...';
      notifyListeners();

      try {
        final res = await ProtocolAccessibilityService.testIcmpDomain(
          destination,
          const Duration(seconds: 1),
        );

        progress.pings[step] = res.success;
        progress.latencies[step] = res.success ? res.latencyMs : null;

        if (res.success) {
          progress.totalReceived++;
        }
      } catch (e) {
        progress.pings[step] = false;
        progress.latencies[step] = null;
      }

      _recomputePacketLossMetrics(progress);
      notifyListeners();
    }

    progress.statusMessage = 'Completed';
    notifyListeners();
  }

  void _recomputePacketLossMetrics(PacketLossDestinationProgress progress) {
    final receivedCount = progress.pings.where((p) => p == true).length;
    final sentCount = progress.pings.where((p) => p != null).length;
    if (sentCount == 0) return;

    progress.lossPercentage = ((sentCount - receivedCount) / sentCount) * 100;

    int currentConsecutive = 0;
    int maxConsecutive = 0;
    for (final ping in progress.pings) {
      if (ping == false) {
        currentConsecutive++;
        if (currentConsecutive > maxConsecutive) {
          maxConsecutive = currentConsecutive;
        }
      } else if (ping == true) {
        currentConsecutive = 0;
      }
    }
    progress.maxConsecutiveLoss = maxConsecutive;

    final activeLatencies = progress.latencies.whereType<int>().toList();
    if (activeLatencies.isNotEmpty) {
      progress.minLatency = activeLatencies.reduce(min);
      progress.maxLatency = activeLatencies.reduce(max);
      progress.avgLatency = (activeLatencies.reduce((a, b) => a + b) / activeLatencies.length).round();
    } else {
      progress.minLatency = null;
      progress.maxLatency = null;
      progress.avgLatency = null;
    }
  }

  /// Reset the engine state
  void resetSuite() {
    _currentRunId++; // Increment to cancel any active runs
    _engineStatus = DiagnosticEngineStatus.idle;
    _completedTestsCount = 0;

    _dnsSuccess = false;
    _ipv4Success = false;
    _ipv6Success = false;
    _httpsSuccess = false;
    _dnsAnalysisSuccess = false;
    _tlsAnalysisSuccess = false;
    _domesticIpSuccess = false;
    _internationalIpSuccess = false;
    _overallInternetAccess = false;

    _dnsResult = null;
    _ipv4Result = null;
    _ipv6Result = null;
    _httpsResult = null;
    _dnsAnalysisSummary = null;
    _tlsAnalysisSummary = null;
    _domesticIpResult = null;
    _internationalIpResult = null;
    _routingAnalysisResult = null;
    _websiteResults = [];
    _isScanningWebsites = false;
    _isScanningTlsTargets = false;
    _cdnResults = [];
    _isScanningCdns = false;
    _socialMediaResults = [];
    _isScanningSocialMedia = false;

    _protocolAccessibilitySuccess = false;
    _protocolAccessibilitySummaries = [];
    _isScanningProtocols = false;
    _protocolStepName = '';

    _isTestingPacketLoss = false;
    _packetLossProgress = [];
    _packetLossSummary = null;
    _packetLossSuccess = false;

    notifyListeners();
  }

  String? _extractRetrievedIp(DiagnosticTestResult? result) {
    if (result == null || !result.success) return null;
    return result.message.replaceFirst('IP retrieved: ', '').trim();
  }

  /// Generates a comprehensive markdown-formatted plain text report of the
  /// entire diagnostic suite's results to copy/paste into AI tools.
  String generateDiagnosticReport() {
    final buffer = StringBuffer();
    buffer.writeln('==================================================');
    buffer.writeln('NETWORK CHECKER DIAGNOSTIC REPORT');
    buffer.writeln('Generated at: ${DateTime.now().toLocal()}');
    buffer.writeln('==================================================\n');

    // 1. Overview
    buffer.writeln('### OVERVIEW');
    String statusTitle = 'Unknown';
    String statusDesc = 'No results available';
    if (isCompleted) {
      if (overallInternetAccess) {
        if (dnsSuccess &&
            ipv4Success &&
            ipv6Success &&
            httpsSuccess &&
            dnsAnalysisSuccess &&
            tlsAnalysisSuccess &&
            domesticIpSuccess &&
            internationalIpSuccess &&
            blockedWebsitesCount == 0 &&
            blockedCdnsCount == 0) {
          statusTitle = 'Excellent Access';
          statusDesc = 'Unrestricted IPv4 & IPv6 internet connection';
        } else {
          statusTitle = 'Partial Internet';
          statusDesc = 'Unrestricted access, but some checks failed';
        }
      } else {
        statusTitle = 'Offline / Blocked';
        statusDesc = 'No active route to the internet detected';
      }
    } else if (isRunning) {
      statusTitle = 'Running';
      statusDesc = 'Diagnostics are currently in progress';
    } else {
      statusTitle = 'Idle';
      statusDesc = 'Ready to analyze';
    }
    buffer.writeln('Overall Status: $statusTitle ($statusDesc)');
    buffer.writeln('IPv4 Connectivity: ${ipv4Success ? "Available" : "Unavailable"}');
    buffer.writeln('IPv6 Connectivity: ${ipv6Success ? "Available" : "Unavailable"}');
    buffer.writeln('HTTPS Connection & TLS: ${httpsSuccess ? "Success" : "Failed"}');
    buffer.writeln('DNS Resolution: ${dnsSuccess ? "Success" : "Failed"}\n');

    // 2. DNS Resolution Details
    if (_dnsResult != null) {
      buffer.writeln('### DNS RESOLUTION');
      buffer.writeln('Status: ${_dnsResult!.success ? "SUCCESS" : "FAILED"}');
      buffer.writeln('Message: ${_dnsResult!.message}');
      buffer.writeln('Latency: ${_dnsResult!.latencyMs} ms');
      if (_dnsResult!.details != null && _dnsResult!.details!.isNotEmpty) {
        buffer.writeln('Details:\n${_dnsResult!.details}');
      }
      buffer.writeln();
    }

    // 3. IPv4 Connectivity Details
    if (_ipv4Result != null) {
      buffer.writeln('### IPV4 CONNECTIVITY');
      buffer.writeln('Status: ${_ipv4Result!.success ? "SUCCESS" : "FAILED"}');
      buffer.writeln('Message: ${_ipv4Result!.message}');
      buffer.writeln('Latency: ${_ipv4Result!.latencyMs} ms');
      if (_ipv4Result!.details != null && _ipv4Result!.details!.isNotEmpty) {
        buffer.writeln('Details:\n${_ipv4Result!.details}');
      }
      buffer.writeln();
    }

    // 4. IPv6 Connectivity Details
    if (_ipv6Result != null) {
      buffer.writeln('### IPV6 CONNECTIVITY');
      buffer.writeln('Status: ${_ipv6Result!.success ? "SUCCESS" : "FAILED"}');
      buffer.writeln('Message: ${_ipv6Result!.message}');
      buffer.writeln('Latency: ${_ipv6Result!.latencyMs} ms');
      if (_ipv6Result!.details != null && _ipv6Result!.details!.isNotEmpty) {
        buffer.writeln('Details:\n${_ipv6Result!.details}');
      }
      buffer.writeln();
    }

    // 5. HTTPS Traffic Details
    if (_httpsResult != null) {
      buffer.writeln('### HTTPS TRAFFIC');
      buffer.writeln('Status: ${_httpsResult!.success ? "SUCCESS" : "FAILED"}');
      buffer.writeln('Message: ${_httpsResult!.message}');
      buffer.writeln('Latency: ${_httpsResult!.latencyMs} ms');
      if (_httpsResult!.details != null && _httpsResult!.details!.isNotEmpty) {
        buffer.writeln('Details:\n${_httpsResult!.details}');
      }
      buffer.writeln();
    }

    // 6. DNS Analysis Details
    if (_dnsAnalysisSummary != null) {
      buffer.writeln('### DNS PROVIDER ANALYSIS');
      buffer.writeln('Status: ${_dnsAnalysisSummary!.success ? "SUCCESS" : "FAILED"}');
      buffer.writeln('Successful Providers: ${_dnsAnalysisSummary!.successfulProviders} / ${_dnsAnalysisSummary!.providerResults.length}');
      buffer.writeln('Average Latency: ${_dnsAnalysisSummary!.averageLatencyMs} ms');
      buffer.writeln('Consistency Score: ${(_dnsAnalysisSummary!.consistencyScore * 100).toStringAsFixed(1)}%');
      buffer.writeln('Tampering Score: ${_dnsAnalysisSummary!.tamperingScore} / 100');
      buffer.writeln('Findings:');
      if (_dnsAnalysisSummary!.findings.isEmpty) {
        buffer.writeln('- No strong DNS tampering indicators detected.');
      } else {
        for (final finding in _dnsAnalysisSummary!.findings) {
          buffer.writeln('- $finding');
        }
      }
      buffer.writeln('Provider Results:');
      for (final res in _dnsAnalysisSummary!.providerResults) {
        buffer.writeln('- ${res.provider.name} (${res.provider.address}): Success Rate: ${(res.successRate * 100).toStringAsFixed(1)}%, Avg Latency: ${res.averageLatencyMs ?? "--"} ms');
        for (final qr in res.queryResults) {
          buffer.writeln('  * Domain: ${qr.domain}, Resolved: ${qr.success}, IPs: ${qr.ipAddresses.join(", ")}, Latency: ${qr.latencyMs} ms${qr.error != null ? " (Error: ${qr.error})" : ""}');
          if (qr.suspiciousReasons.isNotEmpty) {
            buffer.writeln('    Suspicious indicators: ${qr.suspiciousReasons.join(", ")}');
          }
        }
      }
      buffer.writeln();
    }

    // 7. Gateways and public IPs
    buffer.writeln('### PUBLIC IP & GATEWAY ROUTING ANALYSIS');
    if (_domesticIpResult != null) {
      buffer.writeln('Domestic IP query success: ${_domesticIpResult!.success}');
      buffer.writeln('Domestic IP message: ${_domesticIpResult!.message}');
      if (_domesticIpResult!.details != null && _domesticIpResult!.details!.isNotEmpty) {
        buffer.writeln('Domestic details:\n${_domesticIpResult!.details}');
      }
    }
    if (_internationalIpResult != null) {
      buffer.writeln('International IP query success: ${_internationalIpResult!.success}');
      buffer.writeln('International IP message: ${_internationalIpResult!.message}');
      if (_internationalIpResult!.details != null && _internationalIpResult!.details!.isNotEmpty) {
        buffer.writeln('International details:\n${_internationalIpResult!.details}');
      }
    }
    if (_routingAnalysisResult != null) {
      buffer.writeln('Routing Analysis status: ${_routingAnalysisResult!.message}');
      if (_routingAnalysisResult!.details != null && _routingAnalysisResult!.details!.isNotEmpty) {
        buffer.writeln('Routing Diagnosis:\n${_routingAnalysisResult!.details}');
      }
    }
    buffer.writeln();

    // 8. TLS HTTPS Interception Details
    if (_tlsAnalysisSummary != null) {
      buffer.writeln('### TLS / HTTPS INTERCEPTION ANALYSIS');
      buffer.writeln('Successful Handshakes: ${_tlsAnalysisSummary!.successfulHandshakes} / ${_tlsAnalysisSummary!.results.length}');
      buffer.writeln('Valid Certificates: ${_tlsAnalysisSummary!.validCertificates}');
      buffer.writeln('Certificate Mismatches: ${_tlsAnalysisSummary!.certificateMismatches}');
      buffer.writeln('Cloudflare Trace Mismatches: ${_tlsAnalysisSummary!.traceMismatches}');
      buffer.writeln('Average Handshake Latency: ${_tlsAnalysisSummary!.averageHandshakeLatencyMs} ms');
      buffer.writeln('Average Tampering Score: ${_tlsAnalysisSummary!.averageTamperingScore} / 100');
      buffer.writeln('Findings:');
      if (_tlsAnalysisSummary!.findings.isEmpty) {
        buffer.writeln('- No strong TLS interception indicators detected.');
      } else {
        for (final finding in _tlsAnalysisSummary!.findings) {
          buffer.writeln('- $finding');
        }
      }
      buffer.writeln('Target Details:');
      for (final res in _tlsAnalysisSummary!.results) {
        buffer.writeln('- ${res.target.domain} (Expected IP: ${res.target.expectedIp}):');
        buffer.writeln('  * Handshake Success: ${res.handshakeSuccess}');
        buffer.writeln('  * Handshake Latency: ${res.handshakeLatencyMs} ms');
        buffer.writeln('  * TLS Version: ${res.tlsVersion}');
        buffer.writeln('  * Certificate Valid: ${res.certificateValid}');
        buffer.writeln('  * Certificate Mismatch: ${res.certificateMismatch}');
        if (res.certificateSubject != null) {
          buffer.writeln('  * Cert Subject: ${res.certificateSubject}');
        }
        if (res.certificateIssuer != null) {
          buffer.writeln('  * Cert Issuer: ${res.certificateIssuer}');
        }
        buffer.writeln('  * Resolved IPs: ${res.resolvedIps.join(", ")}');
        if (res.traceResult != null) {
          final tr = res.traceResult!;
          buffer.writeln('  * Cloudflare Trace Available: ${tr.traceAvailable}');
          if (tr.traceIp != null) buffer.writeln('    - Trace IP: ${tr.traceIp}');
          if (tr.expectedPublicIp != null) buffer.writeln('    - Expected Public IP: ${tr.expectedPublicIp}');
          if (tr.traceMatchesPublicIp != null) buffer.writeln('    - Trace Matches Public IP: ${tr.traceMatchesPublicIp}');
          if (tr.colo != null) buffer.writeln('    - Colo: ${tr.colo}');
          if (tr.httpProtocol != null) buffer.writeln('    - HTTP Protocol: ${tr.httpProtocol}');
          if (tr.tlsProtocol != null) buffer.writeln('    - TLS Protocol: ${tr.tlsProtocol}');
        }
        if (res.findings.isNotEmpty) {
          buffer.writeln('  * Findings: ${res.findings.join(", ")}');
        }
        if (res.error != null) {
          buffer.writeln('  * Error: ${res.error}');
        }
      }
      buffer.writeln();
    }

    // 9. Website Reachability details
    if (_websiteResults.isNotEmpty) {
      buffer.writeln('### WEBSITE REACHABILITY SCAN');
      buffer.writeln('Reachable: $reachableWebsitesCount');
      buffer.writeln('Blocked: $blockedWebsitesCount');
      buffer.writeln('Failed/DNS/TLS/Timeout: $failedWebsitesCount');
      buffer.writeln('Average Latency: $averageWebsiteLatencyMs ms');
      buffer.writeln('Website Details:');
      for (final res in _websiteResults) {
        buffer.writeln('- ${res.name} (${res.domain}): Status: ${res.status.name}, Latency: ${res.latencyMs ?? "--"} ms${res.statusCode != null ? ", Status Code: ${res.statusCode}" : ""}${res.errorDetails != null ? " (Details: ${res.errorDetails})" : ""}');
      }
      buffer.writeln();
    }

    // 10. CDN Reachability details
    if (_cdnResults.isNotEmpty) {
      buffer.writeln('### CDN REACHABILITY SCAN');
      buffer.writeln('Reachable: $reachableCdnsCount');
      buffer.writeln('Blocked: $blockedCdnsCount');
      buffer.writeln('Failed/DNS/TLS/Timeout: $failedCdnsCount');
      buffer.writeln('Average Latency: $averageCdnLatencyMs ms');
      buffer.writeln('CDN Details:');
      for (final res in _cdnResults) {
        buffer.writeln('- ${res.name} (${res.domain}): Status: ${res.status.name}, Latency: ${res.latencyMs ?? "--"} ms${res.errorDetails != null ? "\n  (Edge Details: ${res.errorDetails})" : ""}');
      }
      buffer.writeln();
    }

    // 11. Social Media details
    if (_socialMediaResults.isNotEmpty) {
      buffer.writeln('### SOCIAL MEDIA ACCESSIBILITY SCAN');
      buffer.writeln('Fully Accessible: $accessibleSocialCount');
      buffer.writeln('Partially Accessible: $partialSocialCount');
      buffer.writeln('Blocked/Censored: $blockedSocialCount');
      buffer.writeln('Average Latency: $averageSocialLatencyMs ms');
      buffer.writeln('Platform Details:');
      for (final res in _socialMediaResults) {
        buffer.writeln('- ${res.name}: Status: ${res.status.name}, Latency: ${res.latencyMs ?? "--"} ms');
        buffer.writeln('  * Primary (${res.primaryResult.domain}): ${res.primaryResult.status.name} (${res.primaryResult.latencyMs ?? "--"} ms)');
        buffer.writeln('  * Secondary (${res.secondaryResult.domain}): ${res.secondaryResult.status.name} (${res.secondaryResult.latencyMs ?? "--"} ms)');
      }
      buffer.writeln();
    }

    // 12. Protocol Accessibility Scan Details
    if (_protocolAccessibilitySummaries.isNotEmpty) {
      buffer.writeln('### PROTOCOL ACCESSIBILITY SCAN');
      buffer.writeln('Supported: $supportedProtocolsCount');
      buffer.writeln('Blocked: $blockedProtocolsCount');
      buffer.writeln('Protocol Details:');
      for (final summary in _protocolAccessibilitySummaries) {
        buffer.writeln('- ${summary.protocolName} (${summary.description}):');
        buffer.writeln('  * Status: ${summary.isSupported ? "Supported" : (summary.isBlocked ? "Blocked" : "Unsupported")}, Avg Latency: ${summary.averageLatencyMs} ms');
        buffer.writeln('  * Domain Results:');
        for (final res in summary.results) {
          buffer.writeln('    - ${res.domain}: ${res.success ? "Success" : "Failed"}${res.latencyMs != null ? " (${res.latencyMs} ms)" : ""}${res.errorMessage != null ? " [Error: ${res.errorMessage}]" : ""}${res.details != null ? " [Details: ${res.details}]" : ""}');
        }
      }
      buffer.writeln();
    }

    // 13. Packet Loss Analysis Details
    if (_packetLossSummary != null) {
      buffer.writeln('### PACKET LOSS ANALYSIS');
      buffer.writeln('Status: ${packetLossSuccess ? "SUCCESS" : "FAILED"}');
      buffer.writeln('Target Details:');
      for (final r in _packetLossSummary!.results) {
        buffer.writeln('- Target: ${r.destination}:');
        buffer.writeln('  * Loss: ${r.lossPercentage.toStringAsFixed(1)}% (${r.totalSent - r.totalReceived}/${r.totalSent} lost)');
        buffer.writeln('  * Consecutive Drops Max: ${r.maxConsecutiveLoss}');
        buffer.writeln('  * Latency: ${r.avgLatency != null ? "${r.avgLatency} ms" : "--"} avg (min: ${r.minLatency != null ? "${r.minLatency} ms" : "--"}, max: ${r.maxLatency != null ? "${r.maxLatency} ms" : "--"})');
        if (r.errorMessage != null) {
          buffer.writeln('  * Error: ${r.errorMessage}');
        }
      }
      buffer.writeln();
    }

    return buffer.toString().trim();
  }
}
