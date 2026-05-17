import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Data class for isolate communication
class _NetlifyGenerationInput {
  final String uuid;
  final String path;
  final String netlifyDomain;
  final String xhttpObject;
  final List<String> snis;
  final List<String> ips;

  _NetlifyGenerationInput({
    required this.uuid,
    required this.path,
    required this.netlifyDomain,
    required this.xhttpObject,
    required this.snis,
    required this.ips,
  });
}

// ============= TOP-LEVEL FUNCTIONS FOR ISOLATES =============

/// Generates configs in isolate
List<String> _generateNetlifyConfigsIsolate(_NetlifyGenerationInput input) {
  final results = <String>[];
  
  final encodedPath = Uri.encodeComponent(input.path);
  final encodedExtra = Uri.encodeComponent(input.xhttpObject);
  
  for (final ip in input.ips) {
    for (final sni in input.snis) {
      final config = 'vless://${input.uuid}@$ip:443'
          '?encryption=none'
          '&security=tls'
          '&sni=$sni'
          '&fp=chrome'
          '&alpn=h2%2Chttp%2F1.1'
          '&insecure=1'
          '&allowInsecure=1'
          '&type=xhttp'
          '&host=${input.netlifyDomain}'
          '&path=$encodedPath'
          '&mode=auto'
          '&extra=$encodedExtra'
          '#Netlify';
      results.add(config);
    }
  }
  
  return results;
}

// ============= CONTROLLER =============

class NetlifyGeneratorController extends ChangeNotifier {
  String _uuid = '';
  String _path = '';
  String _netlifyDomain = '';
  String _xhttpObject = '';
  String _sniInput = '';
  String _ipInput = '';
  
  List<String> _generatedConfigs = [];
  String? _errorMessage;
  bool _isProcessing = false;
  String _progressMessage = '';

  // Pagination for large lists
  static const int _pageSize = 100;
  int _displayedCount = _pageSize;

  // Getters
  String get uuid => _uuid;
  String get path => _path;
  String get netlifyDomain => _netlifyDomain;
  String get xhttpObject => _xhttpObject;
  String get sniInput => _sniInput;
  String get ipInput => _ipInput;
  
  List<String> get generatedConfigs => _generatedConfigs;
  List<String> get displayedConfigs => _generatedConfigs.take(_displayedCount).toList();
  bool get hasMore => _displayedCount < _generatedConfigs.length;
  String? get errorMessage => _errorMessage;
  bool get isProcessing => _isProcessing;
  String get progressMessage => _progressMessage;
  
  int get totalGeneratedCount => _generatedConfigs.length;

  void setUuid(String value) {
    _uuid = value;
    notifyListeners();
  }

  void setPath(String value) {
    _path = value;
    notifyListeners();
  }

  void setNetlifyDomain(String value) {
    _netlifyDomain = value;
    notifyListeners();
  }

  void setXhttpObject(String value) {
    _xhttpObject = value;
    notifyListeners();
  }

  void setSniInput(String value) {
    _sniInput = value;
    notifyListeners();
  }

  void setIpInput(String value) {
    _ipInput = value;
    notifyListeners();
  }

  /// Loads more configs for display (pagination)
  void loadMore() {
    if (_displayedCount < _generatedConfigs.length) {
      _displayedCount = (_displayedCount + _pageSize).clamp(0, _generatedConfigs.length);
      notifyListeners();
    }
  }

  Future<void> generateConfigs() async {
    if (_isProcessing) return;

    if (_uuid.isEmpty || _path.isEmpty || _netlifyDomain.isEmpty || _xhttpObject.isEmpty || _sniInput.isEmpty || _ipInput.isEmpty) {
      _errorMessage = 'Please fill all fields';
      notifyListeners();
      return;
    }
    
    _isProcessing = true;
    _errorMessage = null;
    _progressMessage = 'Generating Netlify configs...';
    _displayedCount = _pageSize;
    notifyListeners();

    try {
      final snis = _sniInput.split('\n').map((e) => e.trim()).where((e) => e.isNotEmpty).toList();
      final ips = _ipInput.split('\n').map((e) => e.trim()).where((e) => e.isNotEmpty).toList();

      final input = _NetlifyGenerationInput(
        uuid: _uuid,
        path: _path,
        netlifyDomain: _netlifyDomain,
        xhttpObject: _xhttpObject,
        snis: snis,
        ips: ips,
      );

      _generatedConfigs = await compute(_generateNetlifyConfigsIsolate, input);

      _progressMessage = '';
      _isProcessing = false;
      notifyListeners();
    } catch (e) {
      _errorMessage = 'Error generating configs: $e';
      _isProcessing = false;
      _progressMessage = '';
      notifyListeners();
    }
  }

  Future<void> copyAllToClipboard() async {
    if (_generatedConfigs.isEmpty) return;
    
    String text;
    if (_generatedConfigs.length > 10000) {
      text = await compute((List<String> configs) => configs.join('\n'), _generatedConfigs);
    } else {
      text = _generatedConfigs.join('\n');
    }
    
    await Clipboard.setData(ClipboardData(text: text));
  }

  void clear() {
    _uuid = '';
    _path = '';
    _netlifyDomain = '';
    _xhttpObject = '{"xPaddingBytes":"1-1"}';
    _sniInput = '';
    _ipInput = '';
    _generatedConfigs = [];
    _errorMessage = null;
    _progressMessage = '';
    _displayedCount = _pageSize;
    notifyListeners();
  }
}
