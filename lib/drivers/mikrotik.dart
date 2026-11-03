import 'dart:convert';
import 'dart:io';

import '../core/ip.dart';
import '../core/log.dart';
import '../core/models.dart';
import '../core/util.dart';
import 'driver.dart';
import 'routeros_api.dart';

/// MikroTik через RouterOS API (IP → Services → api, порт 8728).
class MikrotikDriver extends RouterDriver {
  MikrotikDriver(super.host, super.cred);

  @override
  Vendor get vendor => Vendor.mikrotik;
  @override
  bool get canSetWidth => true;
  @override
  bool get canDisableDhcp => true;
  @override
  bool get canAutoNeg => true;

  RosApi? _api;
  String _wifiMenu = '';
  final Map<String, dynamic> _raw = {};

  int get _port => cred.port ?? 8728;
  String get _tag => 'mikrotik $host';

  @override
  Future<void> login() async {
    try {
      _api = await RosApi.connect(host, _port);
    } on SocketException catch (e) {
      throw DriverException('MikroTik: порт API $_port недоступен (${e.message}). '
          'Включи сервис api: IP → Services → api, и разреши доступ с адреса телефона.');
    }
    try {
      await _api!.login(cred.login, cred.password);
      Log.i(_tag, 'Вход выполнен');
    } on RosException catch (e) {
      await close();
      throw DriverException('MikroTik: вход не выполнен — ${e.message}');
    }
  }

  RosApi get _a => _api ?? (throw DriverException('MikroTik: нет подключения'));

  Future<List<Map<String, String>>> _p(List<String> w) async => (await _a.cmd(w)).rows;

  Future<List<Map<String, String>>?> _try(List<String> w) async {
    try {
      return await _p(w);
    } on RosException {
      return null;
    }
  }

  static int? _speed(String? rate) {
    if (rate == null) return null;
    final m = RegExp(r'([\d.]+)\s*([GM])bps', caseSensitive: false).firstMatch(rate);
    if (m == null) return null;
    final v = double.tryParse(m.group(1)!) ?? 0;
    return m.group(2)!.toUpperCase() == 'G' ? (v * 1000).round() : v.round();
  }

  static int? _leadFreq(String? s) {
    if (s == null) return null;
    final m = RegExp(r'^(\d{4})').firstMatch(s.trim());
    return m == null ? null : int.tryParse(m.group(1)!);
  }

  @override
  Future<RouterInfo> collect() async {
    if (_api == null) await login();
    final info = RouterInfo();
    final ident = await _try(['/system/identity/print']) ?? [];
    final res = await _try(['/system/resource/print']) ?? [];
    final addrs = await _try(['/ip/address/print']) ?? [];
    final routes = await _try(['/ip/route/print', '?dst-address=0.0.0.0/0']) ?? [];
    final dhcp = await _try(['/ip/dhcp-server/print']) ?? [];
    final arp = await _try(['/ip/arp/print']) ?? [];
    final nat = await _try(['/ip/firewall/nat/print', '?action=masquerade']);
    final eth = await _try(['/interface/ethernet/print']) ?? [];

    if (ident.isNotEmpty) info.identity = ident.first['name'] ?? '';
    if (res.isNotEmpty) {
      info.model = res.first['board-name'] ?? '';
      info.firmware = res.first['version'] ?? '';
    }
    for (final a in addrs) {
      if (a['disabled'] == 'true' || a['invalid'] == 'true') continue;
      final parts = (a['address'] ?? '').split('/');
      if (parts.length != 2 || Ip.parse(parts[0]) == null) continue;
      info.addrs.add(IfAddr(a['interface'] ?? '?', parts[0], int.tryParse(parts[1]) ?? 24));
    }
    final active = routes.findFirst((r) => r['active'] == 'true') ?? (routes.isEmpty ? null : routes.first);
    if (active != null) {
      info.gateway = Ip.extract(active['gateway']) ?? Ip.extract(active['immediate-gw']);
    }
    for (final s in dhcp) {
      info.dhcp.add(DhcpServerInfo(
        s['.id'] ?? '',
        s['name'] ?? '',
        s['interface'] ?? '',
        s['disabled'] != 'true' && s['invalid'] != 'true',
        range: s['address-pool'],
      ));
    }
    for (final e in arp) {
      final ip = Ip.extract(e['address']);
      final mac = e['mac-address'];
      if (ip != null && mac != null && mac.isNotEmpty) info.arp.add(ArpEntry(ip, normMac(mac), e['interface'] ?? ''));
    }
    info.nat = nat == null ? null : nat.isNotEmpty;

    // Ethernet: реальная скорость/дуплекс из monitor
    var monitored = 0;
    for (final e in eth) {
      final name = e['name'] ?? '';
      if (name.isEmpty) continue;
      final autoNeg = e['auto-negotiation'] == null ? null : e['auto-negotiation'] == 'true';
      final running = e['running'] != 'false' && e['disabled'] != 'true';
      if (!running || monitored >= 32) {
        info.ports.add(PortLink(id: e['.id'] ?? name, name: name, up: false, autoNeg: autoNeg));
        continue;
      }
      monitored++;
      final mon = await _try(['/interface/ethernet/monitor', '=numbers=$name', '=once=']);
      final m = (mon == null || mon.isEmpty) ? <String, String>{} : mon.first;
      final up = (m['status'] ?? '') == 'link-ok';
      info.ports.add(PortLink(
        id: e['.id'] ?? name,
        name: name,
        up: up,
        speedMbps: _speed(m['rate']),
        fullDuplex: m['full-duplex'] == null ? null : m['full-duplex'] == 'true',
        autoNeg: autoNeg,
      ));
    }

    // Wi-Fi: wifi (v7) / wifiwave2 / wireless (v6)
    var wl = <Map<String, String>>[];
    for (final menu in ['/interface/wifi', '/interface/wifiwave2', '/interface/wireless']) {
      final r = await _try(['$menu/print']);
      if (r != null && r.isNotEmpty) {
        _wifiMenu = menu;
        wl = r;
        break;
      }
    }
    for (final w in wl) {
      final name = w['name'] ?? '';
      final legacy = _wifiMenu == '/interface/wireless';
      final cfgFreq = legacy ? w['frequency'] : w['channel.frequency'];
      final bandStr = (legacy ? w['band'] : w['channel.band']) ?? '';
      final width = legacy ? w['channel-width'] : w['channel.width'];
      final ssid = legacy ? w['ssid'] : (w['configuration.ssid'] ?? w['ssid']);
      final disabled = w['disabled'] == 'true';
      int? freq = _leadFreq(cfgFreq);
      if (!disabled) {
        final mon = await _try(['$_wifiMenu/monitor', '=numbers=$name', '=once=']);
        if (mon != null && mon.isNotEmpty) {
          freq = _leadFreq(mon.first['channel']) ?? _leadFreq(mon.first['frequency']) ?? freq;
        }
      }
      String band;
      if (bandStr.contains('2ghz')) {
        band = '2.4';
      } else if (bandStr.contains('5ghz')) {
        band = '5';
      } else if (freq != null) {
        band = bandOfFreq(freq);
      } else {
        band = '?';
      }
      info.radios.add(RadioInfo(
        id: w['.id'] ?? name,
        name: name,
        band: band,
        channel: freq == null ? null : chFromFreq(freq),
        width: width,
        ssid: ssid,
        enabled: !disabled,
        mac: w['mac-address'] == null ? null : normMac(w['mac-address']),
        autoChannel: cfgFreq == null || cfgFreq.isEmpty || cfgFreq == 'auto',
      ));
    }

    _raw
      ..clear()
      ..['identity'] = ident
      ..['resource'] = res
      ..['ip-address'] = addrs
      ..['default-route'] = routes
      ..['dhcp-server'] = dhcp
      ..['nat-masquerade'] = nat
      ..['ethernet'] = eth
      ..['wifi-menu'] = _wifiMenu
      ..['wifi'] = wl;

    Log.i(_tag, 'Опрос: ${info.model} ${info.firmware} «${info.identity}», адресов ${info.addrs.length}, '
        'шлюз ${info.gateway}, DHCP ${info.dhcp.map((d) => '${d.name}:${d.enabled ? 'вкл' : 'выкл'}').join(',')}, '
        'Wi-Fi ($_wifiMenu) ${info.radios.map((r) => '${r.name} ch${r.channel}').join(',')}, '
        'портов ${info.ports.length}, ARP ${info.arp.length}, NAT ${info.nat}');
    return info;
  }

  @override
  Future<BackupData> backup() async {
    if (_api == null) await login();
    final ts = DateTime.now();
    final name = 'wifihelp-${stamp(ts)}';
    final notes = <String>[];
    var saved = false;
    try {
      await _p(['/system/backup/save', '=name=$name', '=dont-encrypt=yes']);
      saved = true;
    } catch (e) {
      try {
        await _p(['/system/backup/save', '=name=$name']);
        saved = true;
      } catch (e2) {
        notes.add('файл .backup на роутере не создан: $e2');
      }
    }
    if (saved) notes.add('на роутере в Files сохранён $name.backup');
    try {
      await _p(['/export', '=file=$name']);
      notes.add('и текстовый экспорт $name.rsc');
    } catch (e) {
      Log.d(_tag, '/export file= не выполнился: $e');
    }
    if (_raw.isEmpty) await collect();
    if (!saved && _raw.isEmpty) throw DriverException('MikroTik: бэкап не удался');
    final content = StringBuffer()
      ..writeln('# MikroTik $host — снимок настроек ${ts.toIso8601String()}')
      ..writeln('# ${notes.join('; ')}')
      ..writeln('# Полное восстановление: Files → $name.backup → Restore (или /import $name.rsc)')
      ..writeln(const JsonEncoder.withIndent('  ').convert(_raw));
    return BackupData(content.toString(), notes.join('; '), ext: 'json');
  }

  Future<bool> _verifyLogin(String password) async {
    final d = MikrotikDriver(host, Credential(login: cred.login, password: password, port: cred.port));
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
    if (_api == null) await login();
    Log.addSecret(newPassword);
    final users = await _p(['/user/print', '?name=${cred.login}']);
    if (users.isEmpty) throw DriverException('MikroTik: пользователь ${cred.login} не найден');
    final id = users.first['.id'] ?? (throw DriverException('MikroTik: у пользователя нет .id'));
    await _p(['/user/set', '=.id=$id', '=password=$newPassword']);
    if (!await _verifyLogin(newPassword)) {
      throw DriverException('MikroTik: пароль установлен, но вход с новым паролем не прошёл — проверь вручную');
    }
    Log.i(_tag, 'Пароль изменён и проверен входом');
  }

  Future<void> _ensureWifiMenu() async {
    if (_wifiMenu.isEmpty) await collect();
    if (_wifiMenu.isEmpty) throw DriverException('MikroTik: Wi-Fi интерфейсы не найдены');
  }

  @override
  Future<void> setChannel(RadioInfo radio, int channel) async {
    await _ensureWifiMenu();
    final f = freqFromCh(channel, radio.band == '?' ? bandOfChannel(channel) : radio.band);
    if (_wifiMenu == '/interface/wireless') {
      await _p(['/interface/wireless/set', '=.id=${radio.id}', '=frequency=$f']);
    } else {
      await _p(['$_wifiMenu/set', '=.id=${radio.id}', '=channel.frequency=$f']);
    }
  }

  @override
  Future<void> setWidth20(RadioInfo radio) async {
    await _ensureWifiMenu();
    if (_wifiMenu == '/interface/wireless') {
      await _p(['/interface/wireless/set', '=.id=${radio.id}', '=channel-width=20mhz']);
    } else {
      await _p(['$_wifiMenu/set', '=.id=${radio.id}', '=channel.width=20mhz']);
    }
  }

  @override
  Future<void> setDhcpEnabled(DhcpServerInfo server, bool enabled) async {
    if (_api == null) await login();
    await _p(['/ip/dhcp-server/set', '=.id=${server.id}', '=disabled=${enabled ? 'no' : 'yes'}']);
  }

  @override
  Future<void> enableAutoNeg(PortLink port) async {
    if (_api == null) await login();
    await _p(['/interface/ethernet/set', '=.id=${port.id}', '=auto-negotiation=yes']);
  }

  @override
  Future<void> close() async {
    final a = _api;
    _api = null;
    if (a != null) await a.close();
  }
}
