import 'ip.dart';
import 'util.dart';

enum Vendor {
  keenetic('Keenetic', 0xFF1E88E5, true),
  mikrotik('MikroTik', 0xFFE53935, true),
  tplink('TP-Link', 0xFF00897B, true),
  xiaomi('Xiaomi', 0xFFFB8C00, true),
  dlink('D-Link', 0xFF3949AB, true),
  eltex('Eltex', 0xFF8E24AA, true),
  huawei('Huawei', 0xFFD81B60, true),
  zte('ZTE', 0xFF5E35B1, true),
  asus('ASUS', 0xFF546E7A, true),
  tenda('Tenda', 0xFFF4511E, true),
  netis('Netis', 0xFF43A047, true),
  zyxel('Zyxel', 0xFF0277BD, true),
  ubiquiti('Ubiquiti', 0xFF00ACC1, true),
  openwrt('OpenWrt', 0xFF6D4C41, true),
  cisco('Cisco', 0xFF00838F, true),
  netgear('Netgear', 0xFF7CB342, true),
  hikvision('Hikvision', 0xFFC62828, false),
  dahua('Dahua', 0xFFAD1457, false),
  unknown('Неизвестно', 0xFF9E9E9E, false);

  const Vendor(this.label, this.color, this.routerVendor);
  final String label;
  final int color;
  final bool routerVendor;

  /// Есть ли драйвер (вход/опрос), пусть и с разными возможностями.
  bool get supported =>
      this == Vendor.keenetic || this == Vendor.mikrotik || this == Vendor.xiaomi || this == Vendor.tplink;

  int get defaultPort => this == Vendor.mikrotik ? 8728 : 80;

  String get portHint => switch (this) {
        Vendor.mikrotik => 'API, по умолчанию 8728',
        _ => 'веб, по умолчанию 80',
      };

  static Vendor byName(String? n) {
    for (final v in Vendor.values) {
      if (v.name == n) return v;
    }
    return Vendor.unknown;
  }
}

class IfAddr {
  IfAddr(this.iface, this.ip, this.prefix);
  final String iface;
  final String ip;
  final int prefix;

  String get cidr => Ip.cidr(Ip.parse(ip) ?? 0, prefix);

  Map<String, dynamic> toJson() => {'iface': iface, 'ip': ip, 'prefix': prefix};
  factory IfAddr.fromJson(Map<String, dynamic> j) =>
      IfAddr('${j['iface']}', '${j['ip']}', asInt(j['prefix']) ?? 24);
}

class DhcpServerInfo {
  DhcpServerInfo(this.id, this.name, this.iface, this.enabled, {this.range});
  final String id;
  final String name;
  final String iface;
  final bool enabled;
  final String? range;

  Map<String, dynamic> toJson() =>
      {'id': id, 'name': name, 'iface': iface, 'enabled': enabled, 'range': range};
  factory DhcpServerInfo.fromJson(Map<String, dynamic> j) => DhcpServerInfo(
      '${j['id']}', '${j['name']}', '${j['iface']}', j['enabled'] == true,
      range: asStr(j['range']));
}

class RadioInfo {
  RadioInfo({
    required this.id,
    required this.name,
    required this.band,
    this.channel,
    this.width,
    this.ssid,
    this.enabled = true,
    this.mac,
    this.autoChannel = false,
  });
  final String id;
  final String name;
  final String band; // '2.4' | '5' | '6' | '?'
  final int? channel;
  final String? width;
  final String? ssid;
  final bool enabled;
  final String? mac;
  final bool autoChannel;

  int? get widthMhz {
    final w = width;
    if (w == null) return null;
    final m = RegExp(r'(\d{2,3})').firstMatch(w);
    return m == null ? null : int.tryParse(m.group(1)!);
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'band': band,
        'channel': channel,
        'width': width,
        'ssid': ssid,
        'enabled': enabled,
        'mac': mac,
        'auto': autoChannel,
      };
  factory RadioInfo.fromJson(Map<String, dynamic> j) => RadioInfo(
        id: '${j['id']}',
        name: '${j['name']}',
        band: '${j['band']}',
        channel: asInt(j['channel']),
        width: asStr(j['width']),
        ssid: asStr(j['ssid']),
        enabled: j['enabled'] != false,
        mac: asStr(j['mac']),
        autoChannel: j['auto'] == true,
      );
}

class ArpEntry {
  ArpEntry(this.ip, this.mac, this.iface);
  final String ip;
  final String mac;
  final String iface;
  Map<String, dynamic> toJson() => {'ip': ip, 'mac': mac, 'iface': iface};
  factory ArpEntry.fromJson(Map<String, dynamic> j) =>
      ArpEntry('${j['ip']}', '${j['mac']}', '${j['iface'] ?? ''}');
}

class PortLink {
  PortLink({required this.id, required this.name, required this.up, this.speedMbps, this.fullDuplex, this.autoNeg});
  final String id;
  final String name;
  final bool up;
  final int? speedMbps;
  final bool? fullDuplex;
  final bool? autoNeg;

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'up': up,
        'speed': speedMbps,
        'full': fullDuplex,
        'autoneg': autoNeg,
      };
  factory PortLink.fromJson(Map<String, dynamic> j) => PortLink(
        id: '${j['id']}',
        name: '${j['name']}',
        up: j['up'] == true,
        speedMbps: asInt(j['speed']),
        fullDuplex: j['full'] is bool ? j['full'] as bool : null,
        autoNeg: j['autoneg'] is bool ? j['autoneg'] as bool : null,
      );
}

/// Нормализованные данные, полученные с роутера после входа.
class RouterInfo {
  RouterInfo({
    this.model = '',
    this.firmware = '',
    this.identity = '',
    List<IfAddr>? addrs,
    this.gateway,
    List<DhcpServerInfo>? dhcp,
    List<RadioInfo>? radios,
    List<ArpEntry>? arp,
    List<PortLink>? ports,
    this.nat,
    this.unsaved = false,
    DateTime? at,
  })  : addrs = addrs ?? [],
        dhcp = dhcp ?? [],
        radios = radios ?? [],
        arp = arp ?? [],
        ports = ports ?? [],
        at = at ?? DateTime.now();

  String model;
  String firmware;
  String identity;
  final List<IfAddr> addrs;
  String? gateway;
  final List<DhcpServerInfo> dhcp;
  final List<RadioInfo> radios;
  final List<ArpEntry> arp;
  final List<PortLink> ports;
  bool? nat;
  bool unsaved;
  final DateTime at;

  /// Адрес, через который роутер видит свой шлюз (WAN или «вверх»).
  IfAddr? get upAddr {
    final g = Ip.parse(gateway);
    if (g == null) return null;
    return addrs.findFirst((a) {
      final ip = Ip.parse(a.ip);
      return ip != null && Ip.sameNet(ip, g, a.prefix);
    });
  }

  List<IfAddr> get lanAddrs {
    final up = upAddr;
    return addrs.where((a) => !identical(a, up) && !a.ip.startsWith('127.')).toList();
  }

  String get modeLabel {
    if (nat == true) return 'роутер (NAT)';
    if (nat == false) return 'без NAT (точка доступа/мост)';
    return 'режим не определён';
  }

  Map<String, dynamic> toJson() => {
        'model': model,
        'firmware': firmware,
        'identity': identity,
        'addrs': addrs.map((e) => e.toJson()).toList(),
        'gateway': gateway,
        'dhcp': dhcp.map((e) => e.toJson()).toList(),
        'radios': radios.map((e) => e.toJson()).toList(),
        'arp': arp.map((e) => e.toJson()).toList(),
        'ports': ports.map((e) => e.toJson()).toList(),
        'nat': nat,
        'unsaved': unsaved,
        'at': at.toIso8601String(),
      };

  static List<T> _list<T>(dynamic v, T Function(Map<String, dynamic>) f) =>
      (v as List? ?? []).map((e) => f(Map<String, dynamic>.from(e as Map))).toList();

  factory RouterInfo.fromJson(Map<String, dynamic> j) => RouterInfo(
        model: '${j['model'] ?? ''}',
        firmware: '${j['firmware'] ?? ''}',
        identity: '${j['identity'] ?? ''}',
        addrs: _list(j['addrs'], IfAddr.fromJson),
        gateway: asStr(j['gateway']),
        dhcp: _list(j['dhcp'], DhcpServerInfo.fromJson),
        radios: _list(j['radios'], RadioInfo.fromJson),
        arp: _list(j['arp'], ArpEntry.fromJson),
        ports: _list(j['ports'], PortLink.fromJson),
        nat: j['nat'] is bool ? j['nat'] as bool : null,
        unsaved: j['unsaved'] == true,
        at: DateTime.tryParse('${j['at']}'),
      );
}

class Device {
  Device(this.ip);
  final String ip;
  String? mac;
  Vendor vendor = Vendor.unknown;
  Vendor? vendorOverride;
  String? model;
  String? httpTitle;
  String? server;
  String? authRealm;
  String? identity;
  String? upnpManufacturer;
  final Set<int> ports = {};
  bool icmp = false;
  int? rttMs;
  bool isGateway = false;
  bool upnpGateway = false;
  bool routerHint = false;
  bool offline = false;

  /// Если это второй адрес уже известного роутера (например, его WAN) —
  /// IP основного. Такие адреса не опрашиваются и не рисуются отдельно.
  String? aliasOf;
  final Set<String> sources = {};
  RouterInfo? info;
  String? lastError;
  DateTime? infoAt;

  Vendor get effectiveVendor => vendorOverride ?? vendor;

  bool get isCamera =>
      effectiveVendor == Vendor.hikvision ||
      effectiveVendor == Vendor.dahua ||
      (ports.contains(554) && !effectiveVendor.routerVendor && !isGateway);

  bool get isRouter =>
      aliasOf == null &&
      !isCamera &&
      (isGateway ||
          upnpGateway ||
          info != null ||
          sources.contains('mndp') ||
          effectiveVendor.routerVendor ||
          routerHint);

  int get sortKey => Ip.sortKey(ip);

  String get subnet24 {
    final i = ip.lastIndexOf('.');
    return i < 0 ? ip : '${ip.substring(0, i)}.0/24';
  }

  String get title {
    final candidates = [info?.identity, identity, info?.model, model, httpTitle];
    for (final c in candidates) {
      if (c != null && c.trim().isNotEmpty) return c.trim();
    }
    return effectiveVendor == Vendor.unknown ? 'Устройство' : effectiveVendor.label;
  }

  /// Сохраняет то, что не даёт новый скан: ручной выбор производителя,
  /// данные с роутера, MAC и имена.
  void keepFrom(Device o) {
    // На этом IP теперь другое устройство (другая сеть) — старые данные не берём.
    final ov = o.effectiveVendor;
    if (vendor != Vendor.unknown && ov != Vendor.unknown && vendor != ov && o.vendorOverride == null) {
      return;
    }
    vendorOverride ??= o.vendorOverride;
    info ??= o.info;
    infoAt ??= o.infoAt;
    lastError ??= o.lastError;
    aliasOf ??= o.aliasOf;
    mac ??= o.mac;
    identity ??= o.identity;
    model ??= o.model;
    if (vendor == Vendor.unknown) vendor = o.vendor;
  }

  Map<String, dynamic> toJson() => {
        'ip': ip,
        'mac': mac,
        'vendor': vendor.name,
        'vendorOverride': vendorOverride?.name,
        'model': model,
        'httpTitle': httpTitle,
        'server': server,
        'authRealm': authRealm,
        'identity': identity,
        'upnpManufacturer': upnpManufacturer,
        'ports': ports.toList(),
        'icmp': icmp,
        'rtt': rttMs,
        'isGateway': isGateway,
        'upnpGateway': upnpGateway,
        'routerHint': routerHint,
        'offline': offline,
        'aliasOf': aliasOf,
        'sources': sources.toList(),
        'info': info?.toJson(),
        'lastError': lastError,
        'infoAt': infoAt?.toIso8601String(),
      };

  factory Device.fromJson(Map<String, dynamic> j) {
    final d = Device('${j['ip']}');
    d.mac = asStr(j['mac']);
    d.vendor = Vendor.byName(asStr(j['vendor']));
    final vo = asStr(j['vendorOverride']);
    d.vendorOverride = vo == null ? null : Vendor.byName(vo);
    d.model = asStr(j['model']);
    d.httpTitle = asStr(j['httpTitle']);
    d.server = asStr(j['server']);
    d.authRealm = asStr(j['authRealm']);
    d.identity = asStr(j['identity']);
    d.upnpManufacturer = asStr(j['upnpManufacturer']);
    for (final p in (j['ports'] as List? ?? [])) {
      final v = asInt(p);
      if (v != null) d.ports.add(v);
    }
    d.icmp = j['icmp'] == true;
    d.rttMs = asInt(j['rtt']);
    d.isGateway = j['isGateway'] == true;
    d.upnpGateway = j['upnpGateway'] == true;
    d.routerHint = j['routerHint'] == true;
    d.offline = j['offline'] == true;
    d.aliasOf = asStr(j['aliasOf']);
    for (final s in (j['sources'] as List? ?? [])) {
      d.sources.add('$s');
    }
    final info = j['info'];
    if (info is Map) d.info = RouterInfo.fromJson(Map<String, dynamic>.from(info));
    d.lastError = asStr(j['lastError']);
    d.infoAt = DateTime.tryParse('${j['infoAt']}');
    return d;
  }
}

class Credential {
  Credential({required this.login, required this.password, this.port, this.vendor});
  final String login;
  final String password;
  final int? port;

  /// Для какого производителя сохранён пароль: если на этом адресе теперь
  /// другой роутер (другая сеть), пароль не подставляется.
  final String? vendor;

  Credential copyWith({String? password}) =>
      Credential(login: login, password: password ?? this.password, port: port, vendor: vendor);

  Map<String, dynamic> toJson() => {'login': login, 'password': password, 'port': port, 'vendor': vendor};
  factory Credential.fromJson(Map<String, dynamic> j) => Credential(
      login: '${j['login']}', password: '${j['password']}', port: asInt(j['port']), vendor: asStr(j['vendor']));
}

class NetInfo {
  NetInfo({
    this.ip,
    this.prefix = 24,
    this.gateway,
    this.ssid,
    this.bssid,
    this.freq,
    this.linkSpeed,
    this.transport,
    this.iface,
    List<String>? dns,
    this.locationOn = false,
    this.bound = false,
  }) : dns = dns ?? [];
  final String? ip;
  final int prefix;
  final String? gateway;
  final String? ssid;
  final String? bssid;
  final int? freq;
  final int? linkSpeed;
  final String? transport;
  final String? iface;
  final List<String> dns;
  final bool locationOn;
  final bool bound;

  String get subnet {
    final v = Ip.parse(ip);
    return v == null ? '—' : Ip.cidr(v, prefix);
  }

  Map<String, dynamic> toJson() => {
        'ip': ip,
        'prefix': prefix,
        'gateway': gateway,
        'ssid': ssid,
        'bssid': bssid,
        'freq': freq,
        'linkSpeed': linkSpeed,
        'transport': transport,
        'iface': iface,
        'dns': dns,
        'locationOn': locationOn,
        'bound': bound,
      };

  factory NetInfo.fromMap(Map<String, dynamic> m) => NetInfo(
        ip: asStr(m['ip']),
        prefix: asInt(m['prefix']) ?? 24,
        gateway: asStr(m['gateway']),
        ssid: asStr(m['ssid']),
        bssid: asStr(m['bssid']),
        freq: asInt(m['freq']),
        linkSpeed: asInt(m['linkSpeed']),
        transport: asStr(m['transport']),
        iface: asStr(m['iface']),
        dns: (m['dns'] as List?)?.map((e) => '$e').toList(),
        locationOn: m['locationOn'] == true,
        bound: m['bound'] == true,
      );
}

class WifiAp {
  WifiAp({required this.ssid, required this.bssid, required this.freq, required this.level, required this.caps, required this.widthCode});
  final String ssid;
  final String bssid;
  final int freq;
  final int level;
  final String caps;
  final int widthCode;

  int get channel => chFromFreq(freq);
  String get band => bandOfFreq(freq);

  int get widthMhz => switch (widthCode) {
        0 => 20,
        1 => 40,
        2 => 80,
        3 => 160,
        4 => 160,
        5 => 320,
        _ => 20,
      };

  String get security {
    final c = caps.toUpperCase();
    if (c.contains('SAE') || c.contains('WPA3')) return c.contains('PSK') ? 'WPA2/WPA3' : 'WPA3';
    if (c.contains('RSN') || c.contains('WPA2')) return 'WPA2';
    if (c.contains('WPA')) return 'WPA';
    if (c.contains('WEP')) return 'WEP';
    return 'Открытая';
  }

  Map<String, dynamic> toJson() =>
      {'ssid': ssid, 'bssid': bssid, 'freq': freq, 'level': level, 'caps': caps, 'width': widthCode};

  factory WifiAp.fromMap(Map<String, dynamic> m) => WifiAp(
        ssid: '${m['ssid'] ?? ''}',
        bssid: normMac('${m['bssid'] ?? ''}'),
        freq: asInt(m['freq']) ?? 0,
        level: asInt(m['level']) ?? -100,
        caps: '${m['caps'] ?? ''}',
        widthCode: asInt(m['width']) ?? 0,
      );
}

class Settings {
  int pps = 8000;
  bool scan16 = true;
  String extraRanges = '';
  int tcpTimeoutMs = 500;
  bool autoQuery = true;
  bool verboseLog = true;

  Map<String, dynamic> toJson() => {
        'pps': pps,
        'scan16': scan16,
        'extraRanges': extraRanges,
        'tcpTimeoutMs': tcpTimeoutMs,
        'autoQuery': autoQuery,
        'verboseLog': verboseLog,
      };

  static Settings fromJson(Map<String, dynamic> j) {
    final s = Settings();
    s.pps = asInt(j['pps']) ?? 8000;
    s.scan16 = j['scan16'] != false;
    s.extraRanges = '${j['extraRanges'] ?? ''}';
    s.tcpTimeoutMs = asInt(j['tcpTimeoutMs']) ?? 500;
    s.autoQuery = j['autoQuery'] != false;
    s.verboseLog = j['verboseLog'] != false;
    return s;
  }
}

enum Severity { critical, warning, info }

enum FixKind { setChannel, setWidth20, disableDhcp, enableAutoNeg, saveConfig }

class FixAction {
  FixAction({required this.ip, required this.kind, required this.targetId, this.value, required this.text});
  final String ip;
  final FixKind kind;
  final String targetId;
  final int? value;
  final String text;

  String get key => '$ip|${kind.name}|$targetId|${value ?? ''}';
}

class Issue {
  Issue({
    required this.id,
    required this.severity,
    required this.title,
    required this.details,
    List<String>? ips,
    List<FixAction>? fixes,
    this.hint,
  })  : ips = ips ?? [],
        fixes = fixes ?? [];
  final String id;
  final Severity severity;
  final String title;
  final String details;
  final List<String> ips;
  final List<FixAction> fixes;
  final String? hint;
}

class BackupData {
  BackupData(this.content, this.note, {this.ext = 'txt'});
  final String content;
  final String note;
  final String ext;
}
