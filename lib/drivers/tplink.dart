import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../core/ip.dart';
import '../core/log.dart';
import '../core/models.dart';
import '../core/util.dart';
import '../scan/fingerprint.dart';
import 'driver.dart';

/// TP-Link / Mercusys. Схемы входа разные:
///  • «legacy» (TL-WR740/841/845 и т.п.) — cookie Authorization: Basic
///    base64(user:md5(pароль)); страницы /userRpm/*.htm отдают данные в
///    JS-массивах. Эту схему читаем.
///  • «modern» (Archer/AX, есть encrypt.js) — зашифрованный вход RSA+AES,
///    пока открываем встроенный веб-интерфейс.
///  • Deco — отдельное API.
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
  String _token = ''; // путь-токен сессии у части прошивок: /XXXX/userRpm/...
  String _cookie = '';

  String get _tag => 'tplink $host';

  Future<bool> _portOpen(int port) async {
    try {
      final s = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
      s.destroy();
      return true;
    } catch (_) {
      return false;
    }
  }

  Future<String> _detectScheme() async {
    final https = !await _portOpen(80) && await _portOpen(443);
    _base = https ? 'https://$host' : 'http://$host';
    final r = await Fingerprint.get('$_base/', maxBytes: 120000, timeout: const Duration(seconds: 6));
    if (r == null) {
      _scheme = 'unreachable';
      return _scheme;
    }
    final low = '${r.body} ${r.headers['server'] ?? ''}'.toLowerCase();
    if (low.contains('deco')) {
      _scheme = 'deco';
    } else if (low.contains('encrypt.js') || low.contains('jsencrypt') || low.contains('rsa') || low.contains('securityencoder')) {
      _scheme = 'modern';
    } else if (low.contains('pcpassword') || low.contains('userrpm') || low.contains('oid_str') || low.contains('loginrpm')) {
      _scheme = 'legacy';
    } else if (low.contains('tp-link') || low.contains('mercusys')) {
      _scheme = 'modern';
    } else {
      _scheme = 'unknown';
    }
    Log.i(_tag, 'Схема входа: «$_scheme» (база $_base, server ${r.headers['server'] ?? '-'})');
    return _scheme;
  }

  Future<({int status, String body, String? location})> _get(String url, {bool auth = false}) async {
    final sw = Stopwatch()..start();
    final req = await _client.getUrl(Uri.parse(url)).timeout(const Duration(seconds: 8));
    req.followRedirects = false;
    if (auth && _cookie.isNotEmpty) {
      req.headers.set(HttpHeaders.cookieHeader, _cookie);
      req.headers.set(HttpHeaders.refererHeader, '$_base/');
    }
    final resp = await req.close().timeout(const Duration(seconds: 12));
    final body = await resp.transform(const Utf8Decoder(allowMalformed: true)).join();
    final loc = resp.headers.value(HttpHeaders.locationHeader);
    Log.d(_tag, 'GET ${Uri.parse(url).path} → ${resp.statusCode}, ${body.length} б, ${sw.elapsedMilliseconds} мс'
        '${loc != null ? ', → $loc' : ''}');
    return (status: resp.statusCode, body: body, location: loc);
  }

  String _basicCookie(bool escaped) {
    final md5hex = md5.convert(utf8.encode(cred.password)).toString();
    final b64 = base64.encode(utf8.encode('${cred.login}:$md5hex'));
    final v = 'Basic $b64';
    return 'Authorization=${escaped ? Uri.encodeComponent(v) : v}';
  }

  bool _looksLikeData(String body) =>
      body.contains('new Array(') &&
      (body.contains('wanPara') || body.contains('lanPara') || body.contains('statusPara') || body.contains('wlanPara') || body.contains('DHCPDynList'));

  @override
  Future<void> login() async {
    await _detectScheme();
    if (_scheme == 'modern') {
      throw DriverException('TP-Link (современная прошивка Archer/AX, 192.168.x): зашифрованный вход RSA пока '
          'не настроен под эту модель. Управляй через «Веб-интерфейс» (логин подставится). Жду доводки.');
    }
    if (_scheme == 'deco') {
      throw DriverException('TP-Link Deco: отдельное API, не поддержано. Управляй через приложение Deco или «Веб-интерфейс».');
    }
    if (_scheme == 'unreachable') {
      throw DriverException('TP-Link: веб-интерфейс не отвечает по $_base');
    }
    // legacy / unknown — пробуем cookie-схему (TL-WR...)
    for (final escaped in [false, true]) {
      _cookie = _basicCookie(escaped);
      final home = await _get('$_base/', auth: true);
      // путь-токен сессии, если прошивка его использует
      final m = RegExp(r'/([A-Za-z]{16})/userRpm').firstMatch(home.body) ??
          (home.location != null ? RegExp(r'/([A-Za-z]{16})/').firstMatch(home.location!) : null);
      _token = m != null ? '/${m.group(1)}' : '';
      final status = await _get('$_base$_token/userRpm/StatusRpm.htm', auth: true);
      if (status.status == 200 && _looksLikeData(status.body)) {
        Log.i(_tag, 'Вход (legacy cookie${escaped ? ', escaped' : ''}${_token.isNotEmpty ? ', token' : ''}) выполнен');
        return;
      }
      if (status.status == 401) continue;
    }
    throw DriverException('TP-Link (TL-WR...): вход не прошёл — проверь логин/пароль. '
        'Если не помогает, открой «Веб-интерфейс» и пришли «Разведку для журнала».');
  }

  static List<String> _arrayIps(String body, String name) {
    final m = RegExp('var\\s+$name\\w*\\s*=\\s*new Array\\(([\\s\\S]*?)\\);', caseSensitive: false).firstMatch(body);
    if (m == null) return const [];
    final tokens = RegExp(r'"([^"]*)"').allMatches(m.group(1)!).map((x) => x.group(1)!).toList();
    return tokens;
  }

  @override
  Future<RouterInfo> collect() async {
    if (_cookie.isEmpty) await login();
    final info = RouterInfo()..addrs.add(IfAddr('lan', host, 24));

    final status = await _get('$_base$_token/userRpm/StatusRpm.htm', auth: true);
    // текст страницы — в журнал, чтобы доводить парсер под модели
    final clean = status.body.replaceAll(RegExp(r'<[^>]+>'), ' ').replaceAll(RegExp(r'\s+'), ' ').trim();
    Log.d(_tag, 'StatusRpm (${status.body.length} б): ${clean.length > 1400 ? '${clean.substring(0, 1400)}…' : clean}');

    final title = Fingerprint.title(status.body);
    final model = RegExp(r'(TL-\w+|Archer\s+\w+|TD-\w+)', caseSensitive: false).firstMatch(status.body)?.group(0);
    if (model != null) info.model = model;
    if (info.model.isEmpty && title != null) info.model = title;

    // WAN: [ip, mask, gateway, dns...] — ставим шлюз только если раскладка уверенная
    final wan = _arrayIps(status.body, 'wan');
    final wanIps = wan.where((t) => Ip.parse(t) != null).toList();
    if (wanIps.length >= 3) {
      final ip = wanIps[0];
      final mask = wanIps[1];
      final gw = wanIps[2];
      final gwInt = Ip.parse(gw);
      if (mask.startsWith('255.') && gwInt != null && Ip.isPrivate(gwInt) && gw != ip) {
        info.gateway = gw;
        info.nat = true;
        info.addrs.add(IfAddr('wan', ip, Ip.prefixFromMask(mask)));
        Log.i(_tag, 'WAN: ip $ip, шлюз $gw');
      }
    }

    // Клиенты из таблицы DHCP
    final dh = await _get('$_base$_token/userRpm/AssignedIpAddrListRpm.htm', auth: true);
    final toks = _arrayIps(dh.body, 'DHCPDynList');
    for (var i = 0; i + 3 < toks.length; i += 4) {
      final mac = toks[i + 1];
      final ip = Ip.extract(toks[i + 2]);
      if (ip != null && mac.isNotEmpty) info.arp.add(ArpEntry(ip, normMac(mac), 'lan'));
    }

    Log.i(_tag, 'Опрос TL: модель ${info.model.isEmpty ? '-' : info.model}, шлюз ${info.gateway ?? 'не определён'}, '
        'клиентов ${info.arp.length}');
    return info;
  }

  @override
  Future<BackupData> backup() async {
    if (_cookie.isEmpty) await login();
    final b = StringBuffer()
      ..writeln('# TP-Link $host — снимок страниц ${DateTime.now().toIso8601String()}')
      ..writeln('# Полный бэкап: веб-интерфейс → «Системные инструменты» → «Резервная копия».');
    for (final p in ['StatusRpm.htm', 'WanStaticIpCfgRpm.htm', 'NetworkCfgRpm.htm', 'AssignedIpAddrListRpm.htm']) {
      final r = await _get('$_base$_token/userRpm/$p', auth: true);
      b
        ..writeln('# ===== $p (${r.status}) =====')
        ..writeln(r.body);
    }
    return BackupData(b.toString(), 'снимок страниц роутера', ext: 'html');
  }

  @override
  Future<void> changePassword(String newPassword) async =>
      throw DriverException('TP-Link TL-WR: автоматическая смена пароля пока не настроена. '
          'Смени через «Веб-интерфейс» (Системные инструменты → Пароль).');

  @override
  Future<void> setChannel(RadioInfo radio, int channel) async =>
      throw DriverException('TP-Link: смена канала для этой модели пока не настроена.');

  @override
  Future<void> close() async => _client.close(force: true);
}
