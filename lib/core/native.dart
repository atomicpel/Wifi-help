import 'package:flutter/services.dart';

import 'log.dart';

/// Мост к нативной части (MainActivity.kt).
class Native {
  static const MethodChannel _ch = MethodChannel('wifihelp/native');
  static void Function(int sent, int total, int found)? onPingProgress;

  static void init() {
    _ch.setMethodCallHandler((call) async {
      if (call.method == 'pingProgress') {
        final m = Map<String, dynamic>.from(call.arguments as Map);
        onPingProgress?.call(_int(m['sent']), _int(m['total']), _int(m['found']));
      }
      return null;
    });
  }

  static int _int(Object? v) => v is int ? v : (v is num ? v.toInt() : 0);

  static Future<Map<String, dynamic>> _map(String method, [Map<String, dynamic>? args]) async {
    final sw = Stopwatch()..start();
    try {
      final m = await _ch.invokeMethod<Map>(method, args);
      Log.d('native', '$method → ok за ${sw.elapsedMilliseconds} мс');
      return m == null ? <String, dynamic>{} : Map<String, dynamic>.from(m);
    } catch (e, st) {
      Log.e('native', '$method упал', e, st);
      rethrow;
    }
  }

  static Future<String> filesDir() async => (await _ch.invokeMethod<String>('filesDir')) ?? '';

  static Future<Map<String, dynamic>> deviceInfo() => _map('deviceInfo');

  static Future<Map<String, dynamic>> networkInfo() => _map('networkInfo');

  static Future<Map<String, dynamic>> ensurePermissions() => _map('ensurePermissions');

  static Future<Map<String, dynamic>> wifiScan() => _map('wifiScan');

  static Future<Map<String, dynamic>> pingSweep(
          List<List<int>> ranges, int pps, int waitMs, List<int> exclude) =>
      _map('pingSweep', {'ranges': ranges, 'pps': pps, 'waitMs': waitMs, 'exclude': exclude});

  static Future<Map<String, dynamic>> arpTable() => _map('arpTable');

  static Future<void> multicastLock(bool on) async {
    try {
      await _ch.invokeMethod('multicastLock', {'on': on});
    } catch (e) {
      Log.w('native', 'multicastLock($on)', e);
    }
  }

  static Future<String> encrypt(String text) async =>
      (await _ch.invokeMethod<String>('encrypt', {'text': text})) ?? '';

  static Future<String> decrypt(String data) async =>
      (await _ch.invokeMethod<String>('decrypt', {'data': data})) ?? '';

  static Future<bool> openUrl(String url) async =>
      (await _ch.invokeMethod<bool>('openUrl', {'url': url})) ?? false;

  static Future<bool> openWeb(String url, String title, {String? user, String? pass}) async =>
      (await _ch.invokeMethod<bool>('openWeb', {
        'url': url,
        'title': title,
        if (user != null) 'user': user,
        if (pass != null) 'pass': pass,
      })) ??
      false;

  static Future<bool> shareText(String subject, String text) async =>
      (await _ch.invokeMethod<bool>('shareText', {'subject': subject, 'text': text})) ?? false;

  static Future<String> saveDownload(String name, String text) async =>
      (await _ch.invokeMethod<String>('saveDownload', {'name': name, 'text': text})) ?? '';
}
