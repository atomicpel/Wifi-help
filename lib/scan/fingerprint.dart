import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../core/log.dart';
import '../core/models.dart';

class HttpResult {
  HttpResult(this.status, this.headers, this.body, this.finalUrl, this.ms);
  final int status;
  final Map<String, String> headers;
  final String body;
  final String finalUrl;
  final int ms;
}

enum ProbeResult { open, closed, timeout }

/// TCP-проверка порта. «Отказ в соединении» = хост жив, порт закрыт.
Future<ProbeResult> tcpProbe(String ip, int port, Duration timeout) async {
  try {
    final s = await Socket.connect(ip, port, timeout: timeout);
    s.destroy();
    return ProbeResult.open;
  } on SocketException catch (e) {
    final code = e.osError?.errorCode;
    if (code == 111 || code == 61 || code == 10061) return ProbeResult.closed;
    return ProbeResult.timeout;
  } catch (_) {
    return ProbeResult.timeout;
  }
}

/// Опознание устройства по веб-интерфейсу.
class Fingerprint {
  static final HttpClient _client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 3)
    ..badCertificateCallback = ((X509Certificate c, String h, int p) => true)
    ..userAgent = 'Mozilla/5.0 (Linux; Android) WifiHelp/0.1';

  static Future<HttpResult?> get(String url,
      {int maxBytes = 65536, Duration timeout = const Duration(seconds: 4), bool log = true}) async {
    final sw = Stopwatch()..start();
    try {
      final req = await _client.getUrl(Uri.parse(url)).timeout(timeout);
      req.followRedirects = true;
      req.maxRedirects = 4;
      final resp = await req.close().timeout(timeout);
      final headers = <String, String>{};
      resp.headers.forEach((name, values) => headers[name.toLowerCase()] = values.join(', '));
      final bytes = <int>[];
      await for (final chunk in resp.timeout(timeout)) {
        bytes.addAll(chunk);
        if (bytes.length >= maxBytes) break;
      }
      final finalUrl = resp.redirects.isEmpty ? url : resp.redirects.last.location.toString();
      final r = HttpResult(resp.statusCode, headers, utf8.decode(bytes, allowMalformed: true),
          finalUrl, sw.elapsedMilliseconds);
      if (log) {
        Log.d('http', 'GET $url → ${r.status}, ${bytes.length} б, ${r.ms} мс'
            '${finalUrl != url ? ' (редирект → $finalUrl)' : ''}'
            '${headers['server'] != null ? ', server: ${headers['server']}' : ''}');
      }
      return r;
    } catch (e) {
      if (log) Log.d('http', 'GET $url → ошибка за ${sw.elapsedMilliseconds} мс: $e');
      return null;
    }
  }

  static const List<(Vendor, List<String>)> _rules = [
    (Vendor.keenetic, ['keenetic', 'netcraze', 'ndms']),
    (Vendor.mikrotik, ['mikrotik', 'routeros', 'webfig']),
    (Vendor.xiaomi, ['xiaomi', 'miwifi', 'mi router', 'redmi router', 'xiaoqiang']),
    (Vendor.tplink, ['tp-link', 'tplink', 'tp_link', 'mercusys']),
    (Vendor.dlink, ['d-link', 'dlink']),
    (Vendor.eltex, ['eltex', 'элтекс']),
    (Vendor.huawei, ['huawei', 'echolife']),
    (Vendor.zte, ['zxhn', 'zxv10', 'zte corporation', '>zte<']),
    (Vendor.asus, ['asuswrt', 'asus router', 'rt-ac', 'rt-ax']),
    (Vendor.tenda, ['tenda']),
    (Vendor.netis, ['netis']),
    (Vendor.zyxel, ['zyxel']),
    (Vendor.ubiquiti, ['ubiquiti', 'unifi', 'airos', 'edgeos']),
    (Vendor.openwrt, ['openwrt', 'cgi-bin/luci', 'luci-static']),
    (Vendor.cisco, ['cisco']),
    (Vendor.netgear, ['netgear']),
    (Vendor.hikvision, ['hikvision', 'doc/page/login.asp']),
    (Vendor.dahua, ['dahua']),
  ];

  static const List<String> _routerWords = [
    'router',
    'роутер',
    'маршрутизатор',
    'wireless',
    'wi-fi',
    'access point',
    'точка доступа',
    'gateway',
  ];

  static Vendor detectVendor(String lowText) {
    for (final r in _rules) {
      for (final k in r.$2) {
        if (lowText.contains(k)) return r.$1;
      }
    }
    return Vendor.unknown;
  }

  static String? title(String body) {
    final m = RegExp(r'<title[^>]*>([^<]*)</title>', caseSensitive: false).firstMatch(body);
    if (m == null) return null;
    var t = m.group(1)!.replaceAll(RegExp(r'\s+'), ' ').trim();
    t = t.replaceAll('&amp;', '&').replaceAll('&nbsp;', ' ').replaceAll('&#45;', '-');
    if (t.isEmpty) return null;
    return t.length > 80 ? t.substring(0, 80) : t;
  }

  static Future<void> identify(Device d) async {
    final urls = <String>[
      if (d.ports.contains(80)) 'http://${d.ip}/',
      if (d.ports.contains(8080)) 'http://${d.ip}:8080/',
      if (d.ports.contains(443)) 'https://${d.ip}/',
      if (d.ports.contains(8443)) 'https://${d.ip}:8443/',
    ];
    final texts = <String>[];
    for (final u in urls.take(2)) {
      final r = await get(u);
      if (r == null) continue;
      final t = title(r.body);
      if (t != null) d.httpTitle ??= t;
      final server = r.headers['server'];
      if (server != null) d.server ??= server;
      final auth = r.headers['www-authenticate'];
      if (auth != null) {
        final realm = RegExp(r'realm="([^"]*)"', caseSensitive: false).firstMatch(auth)?.group(1);
        if (realm != null && realm.trim().isNotEmpty) d.authRealm ??= realm.trim();
      }
      if (r.headers.containsKey('x-ndm-realm')) {
        d.vendor = Vendor.keenetic;
        d.model ??= r.headers['x-ndm-realm'];
      }
      final body = r.body.length > 40000 ? r.body.substring(0, 40000) : r.body;
      texts.add([t ?? '', server ?? '', auth ?? '', r.headers['x-powered-by'] ?? '', r.finalUrl, body].join(' '));
    }

    // Keenetic отвечает на /auth кодом 401 с заголовком X-NDM-Realm (там же модель).
    if ((d.vendor == Vendor.unknown || d.vendor == Vendor.zyxel || d.vendor == Vendor.keenetic) &&
        d.ports.contains(80)) {
      final r = await get('http://${d.ip}/auth', maxBytes: 2048);
      final realm = r?.headers['x-ndm-realm'];
      if (realm != null) {
        d.vendor = Vendor.keenetic;
        if (realm.isNotEmpty) d.model = realm;
      }
    }

    final low = texts.join(' ').toLowerCase();
    if (d.vendor == Vendor.unknown) d.vendor = detectVendor(low);
    if (d.vendor == Vendor.unknown && d.authRealm != null) {
      d.vendor = detectVendor(d.authRealm!.toLowerCase());
    }
    if (!d.routerHint) d.routerHint = _routerWords.any(low.contains);
    if (d.model == null && d.authRealm != null) d.model = d.authRealm;
    Log.d('ident', '${d.ip}: ${d.vendor.label}, модель «${d.model ?? '-'}», заголовок «${d.httpTitle ?? '-'}», '
        'server «${d.server ?? '-'}», realm «${d.authRealm ?? '-'}», похоже на роутер: ${d.routerHint}');
  }

  static void byPorts(Device d) {
    if (d.vendor == Vendor.unknown && (d.ports.contains(8291) || d.ports.contains(8728))) {
      d.vendor = Vendor.mikrotik;
    }
  }

  /// Разведка веб-интерфейса для журнала: что за страница входа, какие
  /// скрипты и поля формы. Только обычные GET-запросы, как у браузера.
  static Future<String> survey(Device d) async {
    final b = StringBuffer('Разведка ${d.ip} (${d.effectiveVendor.label}, ${d.model ?? d.httpTitle ?? '-'})\n');
    final base = d.ports.contains(80) || !d.ports.contains(443) ? 'http://${d.ip}' : 'https://${d.ip}';
    final r = await get('$base/', maxBytes: 200000, timeout: const Duration(seconds: 6));
    if (r == null) {
      b.writeln('  / не ответил');
      return b.toString();
    }
    b.writeln('  / → ${r.status}, ${r.body.length} б, итоговый адрес ${r.finalUrl}');
    r.headers.forEach((k, v) {
      if (k != 'set-cookie' && k != 'date') b.writeln('  заголовок $k: $v');
    });
    if (r.headers.containsKey('set-cookie')) b.writeln('  ставит cookie: да');
    b.writeln('  title: ${title(r.body) ?? '-'}');
    final scripts = RegExp(r'''<script[^>]+src=["']([^"']+)["']''', caseSensitive: false)
        .allMatches(r.body)
        .map((m) => m.group(1)!)
        .take(25)
        .toList();
    if (scripts.isNotEmpty) b.writeln('  скрипты: ${scripts.join(', ')}');
    final inputs = RegExp(r'''<input[^>]*(?:name|id)=["']([^"']+)["'][^>]*>''', caseSensitive: false)
        .allMatches(r.body)
        .map((m) => m.group(1)!)
        .toSet()
        .take(25)
        .toList();
    if (inputs.isNotEmpty) b.writeln('  поля формы: ${inputs.join(', ')}');
    final forms = RegExp(r'''<form[^>]*action=["']([^"']*)["']''', caseSensitive: false)
        .allMatches(r.body)
        .map((m) => m.group(1)!)
        .take(5)
        .toList();
    if (forms.isNotEmpty) b.writeln('  формы → ${forms.join(', ')}');
    final metaRefresh = RegExp(r'''http-equiv=["']refresh["'][^>]*content=["'][^"']*url=([^"']+)''', caseSensitive: false)
        .firstMatch(r.body)
        ?.group(1);
    if (metaRefresh != null) b.writeln('  meta refresh → $metaRefresh');
    final jsRedirect = RegExp(r'''location(?:\.href)?\s*=\s*["']([^"']+)["']''').firstMatch(r.body)?.group(1);
    if (jsRedirect != null) b.writeln('  js-переход → $jsRedirect');
    final snippet = r.body.replaceAll(RegExp(r'\s+'), ' ');
    b.writeln('  начало страницы: ${snippet.length > 600 ? snippet.substring(0, 600) : snippet}');
    final text = b.toString();
    Log.i('survey', text);
    return text;
  }
}
