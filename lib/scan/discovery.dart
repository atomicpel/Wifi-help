import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../core/log.dart';
import '../core/models.dart';
import '../core/native.dart';
import '../core/util.dart';
import 'fingerprint.dart';

class DiscoveredInfo {
  DiscoveredInfo(this.ip, this.source);
  final String ip;
  final String source; // mndp | ssdp
  String? mac;
  String? identity;
  String? model;
  String? version;
  String? manufacturer;
  Vendor? vendor;
  bool igd = false;
  String? location;
}

/// Широковещательное обнаружение: MikroTik MNDP (UDP 5678) и UPnP/SSDP.
class Discovery {
  static Future<List<DiscoveredInfo>> run(Duration listen, List<String> broadcasts) async {
    final out = <DiscoveredInfo>[];
    await Native.multicastLock(true);
    try {
      await Future.wait([
        _mndp(listen, broadcasts, out),
        _ssdp(listen, out),
      ]);
    } catch (e, st) {
      Log.e('disc', 'Ошибка обнаружения', e, st);
    } finally {
      await Native.multicastLock(false);
    }
    await _describeUpnp(out);
    Log.i('disc', 'Обнаружение: MNDP ${out.where((x) => x.source == 'mndp').length}, '
        'SSDP ${out.where((x) => x.source == 'ssdp').length}');
    return out;
  }

  static Future<void> _mndp(Duration listen, List<String> bcasts, List<DiscoveredInfo> out) async {
    RawDatagramSocket? s;
    try {
      s = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 5678, reuseAddress: true);
    } catch (e) {
      Log.w('mndp', 'Порт 5678 занят, слушаю на случайном', e);
      try {
        s = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      } catch (e2) {
        Log.w('mndp', 'Не удалось открыть UDP-сокет', e2);
        return;
      }
    }
    final RawDatagramSocket sock = s;
    sock.broadcastEnabled = true;
    final seen = <String>{};
    final sub = sock.listen((ev) {
      if (ev != RawSocketEvent.read) return;
      final dg = sock.receive();
      if (dg == null) return;
      final info = _parseMndp(dg.data, dg.address.address);
      if (info != null && seen.add(info.ip)) {
        out.add(info);
        Log.d('mndp', '${info.ip}: ${info.identity ?? '-'} ${info.model ?? ''} ${info.version ?? ''} MAC ${info.mac ?? '-'}');
      }
    });
    final req = Uint8List(4);
    final targets = {'255.255.255.255', ...bcasts};
    for (var i = 0; i < 3; i++) {
      for (final b in targets) {
        try {
          sock.send(req, InternetAddress(b), 5678);
        } catch (e) {
          Log.d('mndp', 'send $b: $e');
        }
      }
      await Future<void>.delayed(const Duration(milliseconds: 700));
    }
    final rest = listen - const Duration(milliseconds: 2100);
    if (rest > Duration.zero) await Future<void>.delayed(rest);
    await sub.cancel();
    sock.close();
  }

  static DiscoveredInfo? _parseMndp(Uint8List d, String srcIp) {
    if (d.length < 8) return null;
    var off = 4;
    String? mac, identity, version, platform, board;
    String? ip4;
    while (off + 4 <= d.length) {
      final type = (d[off] << 8) | d[off + 1];
      final len = (d[off + 2] << 8) | d[off + 3];
      off += 4;
      if (off + len > d.length) break;
      final v = d.sublist(off, off + len);
      off += len;
      switch (type) {
        case 1:
          if (v.length == 6) mac = v.map((b) => b.toRadixString(16).padLeft(2, '0')).join(':').toUpperCase();
        case 5:
          identity = utf8.decode(v, allowMalformed: true);
        case 7:
          version = utf8.decode(v, allowMalformed: true);
        case 8:
          platform = utf8.decode(v, allowMalformed: true);
        case 12:
          board = utf8.decode(v, allowMalformed: true);
        case 17:
          if (v.length == 4) ip4 = '${v[0]}.${v[1]}.${v[2]}.${v[3]}';
        default:
          break;
      }
    }
    if (identity == null && platform == null && mac == null) return null;
    final x = DiscoveredInfo(ip4 ?? srcIp, 'mndp');
    x.mac = mac;
    x.identity = identity;
    x.version = version;
    x.model = board;
    x.vendor = (platform ?? '').toLowerCase().contains('mikrotik') ? Vendor.mikrotik : Vendor.unknown;
    return x;
  }

  static Future<void> _ssdp(Duration listen, List<DiscoveredInfo> out) async {
    RawDatagramSocket s;
    try {
      s = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    } catch (e) {
      Log.w('ssdp', 'Не удалось открыть UDP-сокет', e);
      return;
    }
    final seen = <String>{};
    final sub = s.listen((ev) {
      if (ev != RawSocketEvent.read) return;
      final dg = s.receive();
      if (dg == null) return;
      final text = utf8.decode(dg.data, allowMalformed: true);
      final headers = <String, String>{};
      for (final line in text.split('\r\n')) {
        final i = line.indexOf(':');
        if (i > 0) headers[line.substring(0, i).trim().toLowerCase()] = line.substring(i + 1).trim();
      }
      final loc = headers['location'];
      final ip = dg.address.address;
      if (!seen.add('$ip|$loc')) return;
      final x = DiscoveredInfo(ip, 'ssdp');
      x.location = loc;
      final st = '${headers['st'] ?? ''} ${headers['usn'] ?? ''}';
      x.igd = st.contains('InternetGatewayDevice');
      x.manufacturer = headers['server'];
      out.add(x);
      Log.d('ssdp', '$ip: ${headers['server'] ?? '-'} ${x.igd ? '(шлюз IGD)' : ''} $loc');
    });
    String msg(String st) => 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\nMX: 2\r\nST: $st\r\n\r\n';
    final group = InternetAddress('239.255.255.250');
    for (var i = 0; i < 2; i++) {
      for (final st in ['urn:schemas-upnp-org:device:InternetGatewayDevice:1', 'ssdp:all']) {
        try {
          s.send(utf8.encode(msg(st)), group, 1900);
        } catch (e) {
          Log.d('ssdp', 'send: $e');
        }
      }
      await Future<void>.delayed(const Duration(milliseconds: 800));
    }
    final rest = listen - const Duration(milliseconds: 1600);
    if (rest > Duration.zero) await Future<void>.delayed(rest);
    await sub.cancel();
    s.close();
  }

  static String? _tag(String xml, String tag) {
    final m = RegExp('<$tag>([^<]*)</$tag>', caseSensitive: false).firstMatch(xml);
    final v = m?.group(1)?.trim();
    return (v == null || v.isEmpty) ? null : v;
  }

  static Future<void> _describeUpnp(List<DiscoveredInfo> list) async {
    final byLoc = <String, List<DiscoveredInfo>>{};
    for (final x in list) {
      final l = x.location;
      if (x.source == 'ssdp' && l != null && l.startsWith('http')) byLoc.putIfAbsent(l, () => []).add(x);
    }
    final locs = byLoc.keys.take(40).toList();
    await runPool<String>(locs, 8, (loc) async {
      final r = await Fingerprint.get(loc, maxBytes: 32768, timeout: const Duration(seconds: 3));
      if (r == null) return;
      final manu = _tag(r.body, 'manufacturer');
      final modelName = _tag(r.body, 'modelName');
      final modelNumber = _tag(r.body, 'modelNumber');
      final friendly = _tag(r.body, 'friendlyName');
      final devType = _tag(r.body, 'deviceType') ?? '';
      var model = modelName ?? '';
      if (modelNumber != null && !model.contains(modelNumber)) model = '$model $modelNumber'.trim();
      final v = Fingerprint.detectVendor('${manu ?? ''} $model ${friendly ?? ''}'.toLowerCase());
      for (final x in byLoc[loc]!) {
        x.manufacturer = manu ?? x.manufacturer;
        if (model.isNotEmpty) x.model = model;
        x.identity = friendly;
        if (devType.contains('InternetGatewayDevice')) x.igd = true;
        if (v != Vendor.unknown) x.vendor = v;
      }
      Log.d('upnp', '$loc: $manu / $model / $friendly / $devType');
    });
  }
}
