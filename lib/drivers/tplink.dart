import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../core/log.dart';
import '../core/models.dart';
import '../scan/fingerprint.dart';
import 'driver.dart';

/// TP-Link / Mercusys. У разных линеек совершенно разный вход:
///  • legacy (старые TL-WR / некоторые Archer) — HTTP Basic;
///  • modern Archer / AX — зашифрованный вход (RSA+AES, сессия stok);
///  • Deco — своё облачное/локальное API.
/// Эта версия определяет схему, пробует legacy-вход и читает что может,
/// подробно пишет в журнал всё для точной доводки под конкретную модель,
/// а настройки меняет через встроенный веб-интерфейс.
class TplinkDriver extends RouterDriver {
  TplinkDriver(super.host, super.cred);

  @override
  Vendor get vendor => Vendor.tplink;
  @override
  bool get canChangePassword => false;
  @override
  bool get canSetChannel => false;

  final HttpClient _client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 5)
    ..badCertificateCallback = ((X509Certificate c, String h, int p) => true);
  String _scheme = 'unknown';
  String _base = '';

  String get _tag => 'tplink $host';

  Future<String> _detectScheme() async {
    final https = !await _portOpen(80) && await _portOpen(443);
    _base = https ? 'https://$host' : 'http://$host';
    final r = await Fingerprint.get('$_base/', maxBytes: 120000, timeout: const Duration(seconds: 6));
    if (r == null) {
      _scheme = 'unreachable';
      return _scheme;
    }
    final low = '${r.body} ${r.headers['server'] ?? ''} ${r.headers['www-authenticate'] ?? ''}'.toLowerCase();
    if (low.contains('deco')) {
      _scheme = 'deco';
    } else if ((r.headers['www-authenticate'] ?? '').toLowerCase().contains('basic')) {
      _scheme = 'legacy-basic';
    } else if (low.contains('encrypt') || low.contains('rsa') || low.contains('/webpages/') || low.contains('jsencrypt') || low.contains('data-encrypt')) {
      _scheme = 'modern-encrypted';
    } else if (low.contains('tp-link') || low.contains('mercusys') || low.contains('archer')) {
      _scheme = 'modern-encrypted';
    } else {
      _scheme = 'unknown';
    }
    Log.i(_tag, 'Схема входа определена как «$_scheme» (база $_base). '
        'Заголовки: server=${r.headers['server'] ?? '-'}, auth=${r.headers['www-authenticate'] ?? '-'}');
    return _scheme;
  }

  Future<bool> _portOpen(int port) async {
    try {
      final s = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
      s.destroy();
      return true;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<void> login() async {
    await _detectScheme();
    switch (_scheme) {
      case 'legacy-basic':
        final auth = base64.encode(utf8.encode('${cred.login}:${cred.password}'));
        final r = await _rawGet('$_base/', headers: {HttpHeaders.authorizationHeader: 'Basic $auth'});
        if (r != null && r.statusCode == 200) {
          Log.i(_tag, 'Вход (legacy basic) выполнен');
          return;
        }
        throw DriverException('TP-Link (старая прошивка): неверный логин/пароль или другой формат входа. '
            'Открой роутер кнопкой «Веб-интерфейс».');
      case 'modern-encrypted':
        throw DriverException('TP-Link (современная прошивка Archer/AX): нужен зашифрованный вход, '
            'который я ещё не настроил под твою модель. Нажми «Разведка для журнала» и пришли журнал — '
            'добавлю автоматический вход. Пока управляй через кнопку «Веб-интерфейс» (логин подставится).');
      case 'deco':
        throw DriverException('TP-Link Deco: отдельное API, пока не поддержано. Управляй через приложение Deco '
            'или кнопку «Веб-интерфейс».');
      case 'unreachable':
        throw DriverException('TP-Link: веб-интерфейс не отвечает по $_base');
      default:
        throw DriverException('TP-Link: не удалось распознать веб-интерфейс. Нажми «Разведка для журнала».');
    }
  }

  Future<HttpClientResponseLite?> _rawGet(String url, {Map<String, String>? headers}) async {
    try {
      final req = await _client.getUrl(Uri.parse(url)).timeout(const Duration(seconds: 8));
      headers?.forEach(req.headers.set);
      final resp = await req.close().timeout(const Duration(seconds: 12));
      final body = await resp.transform(const Utf8Decoder(allowMalformed: true)).join();
      return HttpClientResponseLite(resp.statusCode, body);
    } catch (e) {
      Log.d(_tag, 'GET $url: $e');
      return null;
    }
  }

  @override
  Future<RouterInfo> collect() async {
    // Полноценное API-чтение TP-Link появится после доводки под модель.
    // Пока возвращаем то, что видно снаружи, чтобы роутер занял место на карте.
    final info = RouterInfo()
      ..model = 'TP-Link ($_scheme)'
      ..addrs.add(IfAddr('lan', host, 24));
    Log.w(_tag, 'Полный опрос TP-Link пока не реализован (схема $_scheme) — только адрес');
    return info;
  }

  @override
  Future<BackupData> backup() async {
    final snap = await _rawGet('$_base/');
    final content = StringBuffer()
      ..writeln('# TP-Link $host — снимок страницы ${DateTime.now().toIso8601String()}')
      ..writeln('# Схема входа: $_scheme')
      ..writeln('# Полный бэкап пока только через веб-интерфейс (System Tools → Backup).')
      ..writeln(snap?.body ?? '(страница не прочитана)');
    return BackupData(content.toString(), 'снимок страницы входа (для доводки драйвера)', ext: 'html');
  }

  @override
  Future<void> changePassword(String newPassword) async =>
      throw DriverException('TP-Link: автоматическая смена пароля для этой модели ещё не настроена. '
          'Смени через «Веб-интерфейс»; пришли «Разведку для журнала» — добавлю.');

  @override
  Future<void> setChannel(RadioInfo radio, int channel) async =>
      throw DriverException('TP-Link: смена канала для этой модели ещё не настроена.');

  @override
  Future<void> close() async => _client.close(force: true);
}

class HttpClientResponseLite {
  HttpClientResponseLite(this.statusCode, this.body);
  final int statusCode;
  final String body;
}
