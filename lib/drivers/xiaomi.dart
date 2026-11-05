import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';

import '../core/ip.dart';
import '../core/log.dart';
import '../core/models.dart';
import '../core/util.dart';
import 'driver.dart';

/// Xiaomi / Redmi (прошивки MiWiFi и HyperOS) через внутренний API luci.
/// Вход: nonce + двойной хеш пароля (sha256 на новых, sha1 на старых —
/// определяется автоматически). Пароль администратора НЕ меняем (на стоке
/// нет единого безопасного способа, можно потерять доступ) — сообщаем честно.
class XiaomiDriver extends RouterDriver {
  XiaomiDriver(super.host, super.cred);

  static const String _publicKey = 'a2ffa5c9be07488bbb04a3a47d3c5f6a';

  @override
  Vendor get vendor => Vendor.xiaomi;
  @override
  bool get canChangePassword => false;
  @override
  bool get canSetChannel => true;
  @override
  bool get canSetWidth => true;

  final HttpClient _client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 5)
    ..badCertificateCallback = ((X509Certificate c, String h, int p) => true);
  String? _token;
  final Map<int, Map<String, dynamic>> _wifiRaw = {};

  String get _base => 'http://$host/cgi-bin/luci';
  String get _tag => 'xiaomi $host';

  Future<dynamic> _get(String path, {bool auth = true}) async {
    final url = auth ? '$_base/;stok=$_token/api/$path' : '$_base/api/$path';
    final sw = Stopwatch()..start();
    final req = await _client.getUrl(Uri.parse(url)).timeout(const Duration(seconds: 8));
    final resp = await req.close().timeout(const Duration(seconds: 15));
    final body = await resp.transform(const Utf8Decoder(allowMalformed: true)).join();
    final snippet = body.length > 220 ? '${body.substring(0, 220)}…' : body;
    Log.d(_tag, 'GET $path → ${resp.statusCode}, ${sw.elapsedMilliseconds} мс | ${snippet.replaceAll('\n', ' ')}');
    if (resp.statusCode == 401) throw DriverException('Xiaomi: сессия недействительна (401)');
    try {
      return jsonDecode(body);
    } catch (_) {
      return body;
    }
  }

  String _hash(String nonce, bool sha256mode) {
    String sha(String s) =>
        sha256mode ? sha256.convert(utf8.encode(s)).toString() : sha1.convert(utf8.encode(s)).toString();
    return sha(nonce + sha(cred.password + _publicKey));
  }

  String _nonce() {
    final r = Random();
    final mac = [for (var i = 0; i < 6; i++) (r.nextInt(256)).toRadixString(16).padLeft(2, '0')].join(':');
    final t = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return '0_${mac}_${t}_${(r.nextDouble() * 1000).toInt()}';
  }

  Future<bool> _tryLogin(bool sha256mode) async {
    final nonce = _nonce();
    final form = {
      'username': cred.login.isEmpty ? 'admin' : cred.login,
      'logtype': '2',
      'password': _hash(nonce, sha256mode),
      'nonce': nonce,
    };
    final sw = Stopwatch()..start();
    final req = await _client.postUrl(Uri.parse('$_base/api/xqsystem/login')).timeout(const Duration(seconds: 8));
    req.headers.contentType = ContentType('application', 'x-www-form-urlencoded', charset: 'utf-8');
    final bytes = utf8.encode(form.entries.map((e) => '${e.key}=${Uri.encodeQueryComponent(e.value)}').join('&'));
    req.contentLength = bytes.length;
    req.add(bytes);
    final resp = await req.close().timeout(const Duration(seconds: 12));
    final body = await resp.transform(const Utf8Decoder(allowMalformed: true)).join();
    Log.d(_tag, 'login (${sha256mode ? 'sha256' : 'sha1'}) → ${resp.statusCode}, ${sw.elapsedMilliseconds} мс | '
        '${body.length > 200 ? body.substring(0, 200) : body}');
    try {
      final j = jsonDecode(body);
      if (j is Map && j['token'] != null && (j['code'] == 0 || j['code'] == null)) {
        _token = '${j['token']}';
        return true;
      }
    } catch (_) {}
    return false;
  }

  @override
  Future<void> login() async {
    // новые прошивки — sha256, старые — sha1; пробуем обе
    try {
      if (await _tryLogin(true)) {
        Log.i(_tag, 'Вход выполнен (схема sha256)');
        return;
      }
    } catch (e) {
      Log.d(_tag, 'sha256 вход: $e');
    }
    if (await _tryLogin(false)) {
      Log.i(_tag, 'Вход выполнен (схема sha1)');
      return;
    }
    throw DriverException('Xiaomi: неверный пароль или веб-API закрыт. '
        'Проверь, что заходишь на роутер в браузере по http://$host с этим паролем.');
  }

  @override
  Future<RouterInfo> collect() async {
    if (_token == null) await login();
    final info = RouterInfo();

    final init = await _safe(() => _get('xqsystem/init_info'));
    if (init is Map) {
      info.model = '${init['model'] ?? init['hardware'] ?? ''}';
      info.firmware = '${init['romversion'] ?? init['version'] ?? ''}';
      if ('${init['routername'] ?? ''}'.isNotEmpty) info.identity = '${init['routername']}';
    }
    final status = await _safe(() => _get('misystem/status'));
    if (status is Map && status['hardware'] is Map) {
      final hw = status['hardware'] as Map;
      if (info.model.isEmpty) info.model = '${hw['platform'] ?? hw['version'] ?? ''}';
    }

    // WAN — это путь «вверх», к интернету. На MiWiFi адрес и шлюз лежат
    // внутри info.details (а не прямо в info).
    final wan = await _safe(() => _get('xqnetwork/wan_info'));
    if (wan is Map && wan['info'] is Map) {
      final w = wan['info'] as Map;
      final det = w['details'] is Map ? w['details'] as Map : const {};
      final gw = Ip.extract(asStr(det['gateway']) ?? asStr(w['gateway']));
      if (gw != null && gw != '0.0.0.0') info.gateway = gw;
      String? ip = asStr(det['ipaddr']) ?? asStr(w['ipaddr']);
      String? mask = asStr(det['mask']) ?? asStr(w['mask']);
      if (ip == null && w['ipv4'] is List && (w['ipv4'] as List).isNotEmpty) {
        final f = (w['ipv4'] as List).first;
        ip = asStr(f is Map ? f['ip'] : f);
        mask = asStr(f is Map ? f['mask'] : null) ?? mask;
      }
      if (ip != null && Ip.parse(ip) != null) {
        info.addrs.add(IfAddr('wan', ip, mask != null ? Ip.prefixFromMask(mask) : 24));
      }
      final wanType = asStr(det['wanType']) ?? asStr(w['wanType']);
      // роутер с WAN-шлюзом или типом pppoe/dhcp/static — это NAT; режим «lan»/мост — нет
      info.nat = (gw != null && gw != '0.0.0.0') || (wanType != null && wanType != 'lan' && wanType != 'none' && wanType != '');
    }

    // LAN — адрес в info.ipv4[0]
    final lan = await _safe(() => _get('xqnetwork/lan_info'));
    if (lan is Map && lan['info'] is Map) {
      final l = lan['info'] as Map;
      String ip = host;
      String? mask;
      if (l['ipv4'] is List && (l['ipv4'] as List).isNotEmpty && (l['ipv4'] as List).first is Map) {
        ip = asStr((l['ipv4'] as List).first['ip']) ?? host;
        mask = asStr((l['ipv4'] as List).first['mask']);
      } else {
        ip = asStr(l['ip']) ?? host;
        mask = asStr(l['mask']);
      }
      info.addrs.add(IfAddr('lan', ip, mask != null ? Ip.prefixFromMask(mask) : 24));
    } else {
      info.addrs.add(IfAddr('lan', host, 24));
    }

    // DHCP-сервер LAN (если прошивка отдаёт)
    final dh = await _safe(() => _get('xqnetwork/dhcp'));
    if (dh is Map && (dh['dhcp'] is Map || dh['info'] is Map)) {
      final d = (dh['dhcp'] ?? dh['info']) as Map;
      final on = asBool(d['open'] ?? d['on'] ?? d['ignore'] == null);
      info.dhcp.add(DhcpServerInfo('lan', 'LAN DHCP', 'lan', on,
          range: d['start'] != null ? '${d['start']}–${d['end'] ?? ''}' : null));
    }

    // Wi-Fi
    final wifi = await _safe(() => _get('xqnetwork/wifi_detail_all'));
    if (wifi is Map && wifi['info'] is List) {
      for (final raw in wifi['info'] as List) {
        if (raw is! Map) continue;
        final ifname = '${raw['ifname'] ?? ''}';
        final idx = _wifiIndex(ifname);
        if (idx == 0) continue;
        _wifiRaw[idx] = Map<String, dynamic>.from(raw);
        final ch = asInt(raw['channelInfo'] is Map ? raw['channelInfo']['channel'] : raw['channel']);
        final bw = asStr(raw['channelInfo'] is Map ? raw['channelInfo']['bandwidth'] : raw['bandwidth']);
        final band = ifname == 'wl1' ? '2.4' : (ch != null && ch <= 14 ? '2.4' : '5');
        info.radios.add(RadioInfo(
          id: idx.toString(),
          name: band == '2.4' ? 'Wi-Fi 2,4 ГГц' : (ifname == 'wl2' ? 'Wi-Fi 5 ГГц (игровой)' : 'Wi-Fi 5 ГГц'),
          band: band,
          channel: ch,
          width: bw,
          ssid: asStr(raw['ssid']),
          enabled: asBool(raw['status']),
          autoChannel: ch == null || ch == 0,
        ));
      }
    }

    // клиенты/соседи
    final dev = await _safe(() => _get('misystem/devicelist'));
    if (dev is Map && dev['list'] is List) {
      for (final d in dev['list'] as List) {
        if (d is! Map) continue;
        final mac = normMac('${d['mac'] ?? ''}');
        String? ip;
        if (d['ip'] is List && (d['ip'] as List).isNotEmpty) {
          ip = Ip.extract(asStr((d['ip'] as List).first is Map ? (d['ip'] as List).first['ip'] : (d['ip'] as List).first));
        }
        ip ??= Ip.extract(asStr(d['ip']));
        if (ip != null && mac.isNotEmpty) info.arp.add(ArpEntry(ip, mac, '${d['ifname'] ?? ''}'));
      }
    }

    Log.i(_tag, 'Опрос: ${info.model} ${info.firmware}, WAN-шлюз ${info.gateway}, '
        'Wi-Fi ${info.radios.map((r) => '${r.name} ch${r.channel}').join(',')}, '
        'клиентов ${info.arp.length}, NAT ${info.nat}');
    return info;
  }

  static int _wifiIndex(String ifname) => switch (ifname) {
        'wl1' => 1, // 2.4
        'wl0' => 2, // 5
        'wl2' => 3, // 5 game
        _ => 0,
      };

  Future<dynamic> _safe(Future<dynamic> Function() f) async {
    try {
      return await f();
    } catch (e) {
      Log.d(_tag, 'необязательный запрос не удался: $e');
      return null;
    }
  }

  @override
  Future<BackupData> backup() async {
    if (_token == null) await login();
    final snap = <String, dynamic>{};
    for (final p in ['xqsystem/init_info', 'misystem/status', 'xqnetwork/wan_info', 'xqnetwork/lan_info', 'xqnetwork/wifi_detail_all']) {
      snap[p] = await _safe(() => _get(p));
    }
    final content = StringBuffer()
      ..writeln('# Xiaomi $host — снимок настроек ${DateTime.now().toIso8601String()}')
      ..writeln('# Это снимок для записи, не файл восстановления (у Xiaomi нет восстановления через API).')
      ..writeln('# Для полного бэкапа используй веб-интерфейс роутера.')
      ..writeln(const JsonEncoder.withIndent('  ').convert(snap));
    return BackupData(content.toString(), 'снимок настроек (не восстановимый файл)', ext: 'json');
  }

  @override
  Future<void> changePassword(String newPassword) async {
    throw DriverException('Xiaomi: смена пароля администратора через API не поддерживается безопасно '
        '(разные прошивки, риск потерять доступ). Смени пароль в веб-интерфейсе — кнопка «Веб-интерфейс» на карточке.');
  }

  @override
  Future<void> setChannel(RadioInfo radio, int channel) async {
    if (_token == null) await login();
    final idx = int.tryParse(radio.id) ?? 1;
    await _applyWifi(idx, {'channel': '$channel'});
    await Future<void>.delayed(const Duration(seconds: 2));
    final check = await _safe(() => _get('xqnetwork/wifi_detail_all'));
    if (check is Map && check['info'] is List) {
      for (final raw in check['info'] as List) {
        if (raw is Map && _wifiIndex('${raw['ifname']}') == idx) {
          final now = asInt(raw['channelInfo'] is Map ? raw['channelInfo']['channel'] : raw['channel']);
          if (now == channel) return;
          throw DriverException('Xiaomi: канал не применился (сейчас $now, хотел $channel)');
        }
      }
    }
  }

  @override
  Future<void> setWidth20(RadioInfo radio) async {
    if (_token == null) await login();
    final idx = int.tryParse(radio.id) ?? 1;
    await _applyWifi(idx, {'bandwidth': '20'});
  }

  Future<void> _applyWifi(int idx, Map<String, String> changes) async {
    final cur = _wifiRaw[idx] ?? {};
    final params = <String, String>{'wifiIndex': '$idx'};
    void copy(String key, String to) {
      final v = key.contains('.')
          ? (cur[key.split('.').first] is Map ? cur[key.split('.').first][key.split('.').last] : null)
          : cur[key];
      if (v != null) params[to] = '$v';
    }

    copy('ssid', 'ssid');
    copy('encryption', 'encryption');
    copy('pwd', 'pwd');
    copy('channelInfo.channel', 'channel');
    copy('channelInfo.bandwidth', 'bandwidth');
    copy('txpwr', 'txpwr');
    copy('hidden', 'hidden');
    copy('status', 'on');
    params.addAll(changes);
    final qs = params.entries.map((e) => '${e.key}=${Uri.encodeQueryComponent(e.value)}').join('&');
    final r = await _get('xqnetwork/set_wifi?$qs');
    if (r is Map && r['code'] != null && r['code'] != 0) {
      throw DriverException('Xiaomi: set_wifi вернул код ${r['code']} ${r['msg'] ?? ''}');
    }
  }

  @override
  Future<void> close() async => _client.close(force: true);
}
