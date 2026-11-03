import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../core/ip.dart';
import '../core/log.dart';
import '../core/models.dart';
import '../core/util.dart';
import 'driver.dart';

class _Resp {
  _Resp(this.status, this.headers, this.body);
  final int status;
  final HttpHeaders headers;
  final String body;
}

/// Keenetic / Netcraze через RCI — JSON-зеркало командной строки KeeneticOS.
/// Вход: challenge-response (X-NDM-Realm / X-NDM-Challenge), сессия в cookie.
class KeeneticDriver extends RouterDriver {
  KeeneticDriver(super.host, super.cred);

  @override
  Vendor get vendor => Vendor.keenetic;
  @override
  bool get canSaveConfig => true;

  final HttpClient _client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 5)
    ..badCertificateCallback = ((X509Certificate c, String h, int p) => true);
  final Map<String, String> _cookies = {};
  bool _authed = false;
  String _runningConfig = '';

  String get _base {
    final p = cred.port;
    return (p == null || p == 80) ? 'http://$host' : 'http://$host:$p';
  }

  String get _tag => 'keenetic $host';

  Future<_Resp> _req(String method, String path, {Object? json}) async {
    final sw = Stopwatch()..start();
    final req = await _client.openUrl(method, Uri.parse('$_base$path')).timeout(const Duration(seconds: 8));
    req.followRedirects = false;
    if (_cookies.isNotEmpty) {
      req.headers.set(HttpHeaders.cookieHeader, _cookies.entries.map((e) => '${e.key}=${e.value}').join('; '));
    }
    if (json != null) {
      final bytes = utf8.encode(jsonEncode(json));
      req.headers.contentType = ContentType.json;
      req.contentLength = bytes.length;
      req.add(bytes);
    }
    final resp = await req.close().timeout(const Duration(seconds: 15));
    for (final sc in resp.headers[HttpHeaders.setCookieHeader] ?? const <String>[]) {
      final first = sc.split(';').first;
      final i = first.indexOf('=');
      if (i > 0) _cookies[first.substring(0, i).trim()] = first.substring(i + 1).trim();
    }
    final body = await resp
        .transform(const Utf8Decoder(allowMalformed: true))
        .join()
        .timeout(const Duration(seconds: 25));
    final snippet = body.length > 300 ? '${body.substring(0, 300)}…' : body;
    Log.d(_tag, '$method $path${json != null && path != '/auth' ? ' ${jsonEncode(json)}' : ''} → '
        '${resp.statusCode}, ${body.length} б, ${sw.elapsedMilliseconds} мс | ${snippet.replaceAll('\n', ' ')}');
    return _Resp(resp.statusCode, resp.headers, body);
  }

  Future<void> _auth() async {
    final r = await _req('GET', '/auth');
    if (r.status == 200) {
      _authed = true;
      return;
    }
    if (r.status != 401) throw DriverException('Keenetic: /auth ответил ${r.status}');
    final realm = r.headers['x-ndm-realm']?.first;
    final challenge = r.headers['x-ndm-challenge']?.first;
    if (realm == null || challenge == null) {
      throw DriverException('Keenetic: нет заголовков X-NDM — это точно Keenetic? (порт ${cred.port ?? 80})');
    }
    final m5 = md5.convert(utf8.encode('${cred.login}:$realm:${cred.password}')).toString();
    final key = sha256.convert(utf8.encode('$challenge$m5')).toString();
    final r2 = await _req('POST', '/auth', json: {'login': cred.login, 'password': key});
    if (r2.status != 200) throw DriverException('Keenetic: неверный логин или пароль');
    _authed = true;
    Log.i(_tag, 'Вход выполнен (модель по realm: $realm)');
  }

  Future<_Resp> _call(String method, String path, {Object? json}) async {
    if (!_authed) await _auth();
    var r = await _req(method, path, json: json);
    if (r.status == 401) {
      Log.d(_tag, 'Сессия истекла, вхожу заново');
      _authed = false;
      await _auth();
      r = await _req(method, path, json: json);
    }
    return r;
  }

  Future<dynamic> _get(String path) async {
    final r = await _call('GET', path);
    if (r.status == 404) return null;
    if (r.status != 200) throw DriverException('Keenetic: $path → HTTP ${r.status}');
    try {
      return jsonDecode(r.body);
    } catch (_) {
      return r.body;
    }
  }

  Future<String?> _text(String path) async {
    final r = await _call('GET', path);
    return r.status == 200 ? r.body : null;
  }

  Future<dynamic> _rci(List<Map<String, dynamic>> cmds) async {
    final r = await _call('POST', '/rci/', json: cmds);
    if (r.status != 200) throw DriverException('Keenetic: RCI → HTTP ${r.status}');
    dynamic data;
    try {
      data = jsonDecode(r.body);
    } catch (_) {
      data = r.body;
    }
    final err = _findError(data);
    if (err != null) throw DriverException('Keenetic: $err');
    return data;
  }

  static String? _findError(dynamic x) {
    if (x is Map) {
      final st = x['status'];
      if (st is List) {
        for (final s in st) {
          if (s is Map && s['status'] == 'error') return '${s['message'] ?? 'ошибка'}';
        }
      }
      for (final v in x.values) {
        final e = _findError(v);
        if (e != null) return e;
      }
    } else if (x is List) {
      for (final v in x) {
        final e = _findError(v);
        if (e != null) return e;
      }
    }
    return null;
  }

  @override
  Future<void> login() => _auth();

  /// Строки блока конфигурации, начинающегося с заголовка.
  static List<String> _block(String config, String header) {
    final lines = config.split('\n');
    final out = <String>[];
    var inside = false;
    for (final raw in lines) {
      final line = raw.replaceAll('\r', '');
      if (!inside) {
        if (line.trim() == header && !line.startsWith(' ')) inside = true;
        continue;
      }
      if (line.startsWith(' ') || line.startsWith('\t')) {
        out.add(line.trim());
      } else {
        break;
      }
    }
    return out;
  }

  Future<String> _loadRunningConfig() async {
    var rc = await _text('/ci/running-config.txt');
    if (rc == null || rc.trim().isEmpty) {
      final x = await _get('/rci/show/running-config');
      if (x is Map && x['message'] is List) {
        rc = (x['message'] as List).map((e) => '$e').join('\n');
      } else if (x is List) {
        rc = x.map((e) => '$e').join('\n');
      }
    }
    _runningConfig = rc ?? '';
    return _runningConfig;
  }

  @override
  Future<RouterInfo> collect() async {
    if (!_authed) await _auth();
    final info = RouterInfo();
    final ver = await _get('/rci/show/version');
    if (ver is Map) {
      info.model = '${ver['model'] ?? ver['device'] ?? ver['hw_id'] ?? ''}';
      info.firmware = '${ver['title'] ?? ver['release'] ?? ''}';
    }
    final sys = await _get('/rci/show/system');
    if (sys is Map) info.identity = '${sys['hostname'] ?? ''}';

    final ifs = await _get('/rci/show/interface');
    final ssidByMaster = <String, String>{};
    final macByMaster = <String, String>{};
    if (ifs is Map) {
      ifs.forEach((k, v) {
        if (v is! Map) return;
        final id = '${v['id'] ?? k}';
        final addr = asStr(v['address']);
        final mask = asStr(v['mask']);
        if (addr != null && mask != null && addr != '0.0.0.0' && Ip.parse(addr) != null) {
          info.addrs.add(IfAddr(id, addr, Ip.prefixFromMask(mask)));
        }
        final ap = RegExp(r'^(WifiMaster\d+)/AccessPoint\d+$').firstMatch(id);
        if (ap != null && '${v['state']}' == 'up') {
          final master = ap.group(1)!;
          final ssid = asStr(v['ssid']);
          if (ssid != null) ssidByMaster.putIfAbsent(master, () => ssid);
          final mac = asStr(v['mac']);
          if (mac != null) macByMaster.putIfAbsent(master, () => normMac(mac));
        }
      });
      final seenPorts = <String>{};
      walkJson(ifs, (m, key) {
        if (!m.containsKey('duplex')) return;
        final name = '${m['label'] ?? m['id'] ?? m['name'] ?? key}';
        if (!seenPorts.add(name)) return;
        final link = '${m['link'] ?? ''}';
        if (link.isEmpty) return;
        info.ports.add(PortLink(
          id: name,
          name: 'порт $name',
          up: link == 'up',
          speedMbps: asInt(m['speed']),
          fullDuplex: '${m['duplex']}' == 'full',
        ));
      });
    }

    final rc = await _loadRunningConfig();
    if (ifs is Map) {
      ifs.forEach((k, v) {
        if (v is! Map) return;
        final id = '${v['id'] ?? k}';
        if (!RegExp(r'^WifiMaster\d+$').hasMatch(id)) return;
        final chLine = _block(rc, 'interface $id').findFirst((l) => l.startsWith('channel '));
        final cfgCh = chLine?.substring(8).trim();
        final ch = asInt(v['channel']) ?? asInt(cfgCh);
        final band = id == 'WifiMaster0' ? '2.4' : (ch != null && ch <= 14 ? '2.4' : '5');
        info.radios.add(RadioInfo(
          id: id,
          name: band == '2.4' ? 'Wi-Fi 2,4 ГГц' : 'Wi-Fi 5 ГГц',
          band: band,
          channel: ch,
          width: asStr(v['bandwidth']) ?? asStr(v['ht']),
          ssid: ssidByMaster[id],
          enabled: '${v['state']}' == 'up' || '${v['link']}' == 'up',
          mac: macByMaster[id],
          autoChannel: cfgCh == null || cfgCh == 'auto',
        ));
      });
    }

    final routes = await _get('/rci/show/ip/route');
    walkJson(routes, (m, key) {
      if (info.gateway != null) return;
      final dst = '${m['destination'] ?? ''}';
      final gw = Ip.extract(asStr(m['gateway']));
      final isDefault = dst == '0.0.0.0/0' || (dst == '0.0.0.0' && '${m['mask'] ?? '0.0.0.0'}' == '0.0.0.0');
      if (isDefault && gw != null && gw != '0.0.0.0') info.gateway = gw;
    });

    try {
      final arp = await _get('/rci/show/ip/arp');
      walkJson(arp, (m, key) {
        final ip = Ip.extract(asStr(m['ip']));
        final mac = asStr(m['mac']);
        if (ip != null && mac != null) {
          info.arp.add(ArpEntry(ip, normMac(mac), '${m['interface'] ?? m['name'] ?? ''}'));
        }
      });
    } catch (e) {
      Log.w(_tag, 'ARP не прочитан', e);
    }

    // DHCP-пулы и NAT — по тексту конфигурации
    final lines = rc.split('\n');
    for (final raw in lines) {
      final m = RegExp(r'^ip dhcp pool (\S+)').firstMatch(raw.trim());
      if (m == null || raw.startsWith(' ')) continue;
      final name = m.group(1)!;
      final block = _block(rc, raw.trim());
      final bind = block.findFirst((l) => l.startsWith('bind '))?.substring(5).trim() ?? 'Bridge0';
      final range = block.findFirst((l) => l.startsWith('range '))?.substring(6).trim();
      final enabled = block.any((l) => l == 'enable');
      info.dhcp.add(DhcpServerInfo(name, name, bind, enabled, range: range));
    }
    info.nat = lines.any((l) => l.startsWith('ip nat '));

    try {
      final lc = await _get('/rci/show/last-change');
      walkJson(lc, (m, key) {
        if (m['unsaved'] == true) info.unsaved = true;
      });
    } catch (_) {}

    Log.i(_tag, 'Опрос: ${info.model} ${info.firmware}, адресов ${info.addrs.length}, шлюз ${info.gateway}, '
        'DHCP ${info.dhcp.map((d) => '${d.name}:${d.enabled ? 'вкл' : 'выкл'}').join(',')}, '
        'радио ${info.radios.map((r) => '${r.id} ch${r.channel}').join(',')}, портов ${info.ports.length}, ARP ${info.arp.length}, NAT ${info.nat}');
    return info;
  }

  @override
  Future<BackupData> backup() async {
    if (!_authed) await _auth();
    final startup = await _text('/ci/startup-config.txt');
    final running = await _text('/ci/running-config.txt');
    if ((startup == null || startup.isEmpty) && (running == null || running.isEmpty)) {
      throw DriverException('Keenetic: не удалось выгрузить конфигурацию для бэкапа');
    }
    final b = StringBuffer()
      ..writeln('! Keenetic $host — бэкап ${DateTime.now().toIso8601String()}')
      ..writeln('! Восстановление: веб-интерфейс → «Системные файлы» → startup-config → заменить этим файлом.')
      ..writeln('! ===== startup-config =====')
      ..writeln(startup ?? '(нет)')
      ..writeln('! ===== running-config =====')
      ..writeln(running ?? '(нет)');
    return BackupData(b.toString(), 'startup-config и running-config выгружены в телефон');
  }

  Future<bool> _verifyLogin(String password) async {
    final d = KeeneticDriver(host, Credential(login: cred.login, password: password, port: cred.port));
    try {
      await d.login();
      return true;
    } catch (_) {
      return false;
    } finally {
      await d.close();
    }
  }

  @override
  Future<void> changePassword(String newPassword) async {
    if (!_authed) await _auth();
    Log.addSecret(newPassword);
    final attempts = <List<Map<String, dynamic>>>[
      [
        {
          'user': {'name': cred.login, 'password': newPassword}
        }
      ],
      [
        {'parse': 'user ${cred.login} password $newPassword'}
      ],
    ];
    String? lastErr;
    for (final a in attempts) {
      try {
        await _rci(a);
      } catch (e) {
        lastErr = '$e';
        Log.w(_tag, 'Вариант смены пароля не принят', e);
        continue;
      }
      if (await _verifyLogin(newPassword)) {
        await saveConfig();
        Log.i(_tag, 'Пароль изменён и проверен входом');
        return;
      }
      Log.w(_tag, 'Команда принята, но вход с новым паролем не прошёл — пробую иначе');
    }
    throw DriverException('Keenetic: пароль не изменён (${lastErr ?? 'вход с новым паролем не прошёл'}). '
        'Конфигурация не сохранялась — после перезагрузки роутера останется старый пароль.');
  }

  Future<bool> _channelIs(String iface, int ch) async {
    final rc = await _loadRunningConfig();
    return _block(rc, 'interface $iface').any((l) => l == 'channel $ch');
  }

  @override
  Future<void> setChannel(RadioInfo radio, int channel) async {
    if (!_authed) await _auth();
    final attempts = <List<Map<String, dynamic>>>[
      [
        {
          'interface': {'name': radio.id, 'channel': channel}
        }
      ],
      [
        {'parse': 'interface ${radio.id} channel $channel'}
      ],
    ];
    for (final a in attempts) {
      try {
        await _rci(a);
      } catch (e) {
        Log.w(_tag, 'Вариант смены канала не принят', e);
        continue;
      }
      await Future<void>.delayed(const Duration(seconds: 2));
      if (await _channelIs(radio.id, channel)) {
        await saveConfig();
        return;
      }
    }
    throw DriverException('Keenetic: канал $channel на ${radio.id} не применился');
  }

  @override
  Future<void> saveConfig() async {
    await _rci([
      {
        'system': {
          'configuration': {'save': <String, dynamic>{}}
        }
      }
    ]);
    Log.i(_tag, 'Конфигурация сохранена');
  }

  @override
  Future<void> close() async {
    _client.close(force: true);
  }
}
