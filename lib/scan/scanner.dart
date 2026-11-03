import 'dart:async';

import '../core/ip.dart';
import '../core/log.dart';
import '../core/models.dart';
import '../core/native.dart';
import '../core/util.dart';
import 'discovery.dart';
import 'fingerprint.dart';

class ScanReport {
  ScanReport(this.net, this.devices, this.notes, this.duration);
  final NetInfo net;
  final Map<String, Device> devices;
  final List<String> notes;
  final Duration duration;
}

/// Скан сети в несколько фаз:
///  1) ICMP по всему диапазону (нативно, тысячи пакетов в секунду);
///  2) TCP по живым хостам + «слепая» проверка тех, кто молчит на ping
///     (своя подсеть целиком и .1/.254 каждой /24 — там обычно роутеры);
///  3) MNDP (MikroTik) и SSDP/UPnP параллельно с пингом;
///  4) ARP-таблица телефона (если Android даст);
///  5) опознание по веб-интерфейсу.
class Scanner {
  Scanner(this.settings, this.onProgress);
  final Settings settings;
  final void Function(String phase, double? fraction) onProgress;
  bool _cancelled = false;

  void cancel() {
    _cancelled = true;
    Log.w('scan', 'Скан остановлен пользователем');
  }

  bool get cancelled => _cancelled;

  static const List<int> fullPorts = [80, 443, 8080, 8443, 22, 23, 8291, 8728, 554, 8000];

  Future<ScanReport> run() async {
    final total = Stopwatch()..start();
    final notes = <String>[];
    Log.i('scan', '===== Начало скана =====');
    try {
      final p = await Native.ensurePermissions();
      Log.d('scan', 'Разрешения: $p');
    } catch (_) {}

    final netMap = await Native.networkInfo();
    final net = NetInfo.fromMap(netMap);
    Log.i('scan', 'Сеть: ${net.transport ?? '?'} ${net.iface ?? ''}, IP ${net.ip}/${net.prefix}, '
        'шлюз ${net.gateway}, SSID ${net.ssid ?? '(скрыт — нет геолокации)'}, BSSID ${net.bssid ?? '-'}, '
        'частота ${net.freq ?? '-'} МГц, скорость ${net.linkSpeed ?? '-'} Мбит/с, DNS ${net.dns.join(', ')}, '
        'привязка к сети: ${net.bound}');
    if (netMap['bindError'] != null) Log.w('scan', 'Не удалось привязаться к сети: ${netMap['bindError']}');
    if (net.transport == 'cellular' || net.ip == null) {
      notes.add('Телефон не подключён к Wi-Fi или Ethernet — сканировать нечего.');
      Log.w('scan', 'Нет локальной сети (transport=${net.transport})');
      return ScanReport(net, {}, notes, total.elapsed);
    }

    final found = <String, Device>{};
    Device dev(String ip) => found.putIfAbsent(ip, () => Device(ip));

    final myIp = Ip.parse(net.ip);
    final ranges = <List<int>>[];
    int? ownStart;
    int? ownEnd;
    if (myIp != null) {
      final pfx = net.prefix < 16 ? 22 : net.prefix;
      ownStart = Ip.network(myIp, pfx);
      ownEnd = Ip.broadcast(myIp, pfx);
      ranges.add([ownStart, ownEnd]);
    }
    if (settings.scan16) ranges.add([0xC0A80000, 0xC0A8FFFF]);
    for (final part in settings.extraRanges.split(RegExp(r'[,;\s]+'))) {
      if (part.trim().isEmpty) continue;
      final r = Ip.parseRange(part);
      if (r == null) {
        notes.add('Не понял диапазон «$part»');
        continue;
      }
      if (r.$2 - r.$1 > 70000) {
        notes.add('Диапазон $part слишком большой (максимум /16)');
        continue;
      }
      ranges.add([r.$1, r.$2]);
    }
    final merged = _merge(ranges);
    final count = merged.fold<int>(0, (s, r) => s + (r[1] - r[0] + 1));
    Log.i('scan', 'Диапазоны: ${merged.map((r) => '${Ip.str(r[0])}–${Ip.str(r[1])}').join(', ')} ($count адресов)');

    // --- обнаружение запускаем параллельно с пингом
    final bcasts = <String>[];
    if (myIp != null) {
      final pfx = net.prefix < 8 ? 8 : (net.prefix > 30 ? 30 : net.prefix);
      bcasts.add(Ip.str(Ip.broadcast(myIp, pfx)));
    }
    final discFuture = Discovery.run(const Duration(seconds: 5), bcasts);

    // --- фаза 1: ICMP
    final sw = Stopwatch()..start();
    onProgress('Пинг-скан $count адресов…', 0);
    Native.onPingProgress = (sent, tot, f) =>
        onProgress('Пинг-скан: $sent из $tot, ответили $f', tot == 0 ? null : sent / tot);
    Map<String, dynamic> ping;
    try {
      ping = await Native.pingSweep(merged, settings.pps, 1500, [if (myIp != null) myIp]);
    } catch (e) {
      ping = {'error': '$e'};
    }
    Native.onPingProgress = null;
    if (ping['error'] != null) {
      notes.add('ICMP-скан недоступен (${ping['error']}), ищу только по TCP.');
      Log.w('scan', 'ICMP недоступен: ${ping['error']}');
    }
    for (final e in (ping['alive'] as List? ?? [])) {
      final m = Map<String, dynamic>.from(e as Map);
      final d = dev('${m['ip']}');
      d.icmp = true;
      d.rttMs = asInt(m['rtt']);
      d.sources.add('ping');
    }
    Log.i('scan', 'ICMP: отправлено ${ping['sent'] ?? 0}, ошибок отправки ${ping['sendErrors'] ?? 0}, '
        'ответили ${found.length} за ${sw.elapsedMilliseconds} мс');
    if (_cancelled) return ScanReport(net, found, notes, total.elapsed);

    // --- фаза 2: TCP
    sw.reset();
    final probes = <(String, int, int)>[];
    for (final d in found.values) {
      for (final p in fullPorts) {
        probes.add((d.ip, p, settings.tcpTimeoutMs + 300));
      }
    }
    final blind = <int>{};
    if (ownStart != null && ownEnd != null && ownEnd - ownStart < 1100) {
      for (var i = ownStart + 1; i < ownEnd; i++) {
        blind.add(i);
      }
    }
    for (final r in merged) {
      for (var n24 = r[0] & 0xFFFFFF00; n24 <= r[1]; n24 += 256) {
        blind.add(n24 + 1);
        blind.add(n24 + 254);
      }
    }
    var blindCount = 0;
    for (final ipInt in blind) {
      final ip = Ip.str(ipInt);
      if (ipInt == myIp || found.containsKey(ip)) continue;
      blindCount++;
      probes.add((ip, 80, settings.tcpTimeoutMs));
      probes.add((ip, 443, settings.tcpTimeoutMs));
    }
    Log.i('scan', 'TCP: ${found.length} живых × ${fullPorts.length} портов + $blindCount «молчащих» адресов × 2 порта');
    var done = 0;
    await runPool<(String, int, int)>(probes, 300, (p) async {
      final r = await tcpProbe(p.$1, p.$2, Duration(milliseconds: p.$3));
      done++;
      if (done % 64 == 0) onProgress('Порты: $done из ${probes.length}', done / probes.length);
      if (r == ProbeResult.timeout) return;
      final d = dev(p.$1);
      if (d.sources.add('tcp') && !d.icmp) Log.d('scan', '${p.$1}: найден по TCP (на ping не отвечает)');
      if (r == ProbeResult.open) d.ports.add(p.$2);
    }, cancelled: () => _cancelled);
    Log.i('scan', 'TCP готов за ${sw.elapsedMilliseconds} мс, устройств ${found.length}');
    if (_cancelled) return ScanReport(net, found, notes, total.elapsed);

    // --- фаза 3: результаты обнаружения
    onProgress('Слушаю MikroTik MNDP и UPnP…', null);
    final disc = await discFuture;
    for (final x in disc) {
      final d = dev(x.ip);
      d.sources.add(x.source);
      if (x.mac != null) d.mac ??= x.mac;
      if (x.identity != null && x.identity!.isNotEmpty) d.identity ??= x.identity;
      if (x.model != null && x.model!.isNotEmpty) d.model ??= x.model;
      final v = x.vendor;
      if (v != null && v != Vendor.unknown) d.vendor = v;
      if (x.igd) d.upnpGateway = true;
      if (x.manufacturer != null) d.upnpManufacturer ??= x.manufacturer;
    }

    // --- фаза 4: ARP
    try {
      final arp = await Native.arpTable();
      final entries = (arp['entries'] as List? ?? []);
      Log.i('scan', 'ARP телефона: ${entries.length} записей (источник ${arp['source']}${arp['error'] != null ? ', ${arp['error']}' : ''})');
      for (final e in entries) {
        final m = Map<String, dynamic>.from(e as Map);
        final ip = '${m['ip']}';
        final mac = normMac('${m['mac']}');
        if (mac.isEmpty || mac == '00:00:00:00:00:00') continue;
        final d = found[ip];
        if (d != null) {
          d.mac ??= mac;
        } else {
          final ipInt = Ip.parse(ip);
          if (ipInt != null && ipInt != myIp) {
            final nd = dev(ip);
            nd.mac = mac;
            nd.sources.add('arp');
          }
        }
      }
      if (entries.isEmpty) {
        notes.add('Android не дал прочитать ARP-таблицу, поэтому MAC-адреса подтянутся из роутеров после ввода паролей.');
      }
    } catch (e) {
      Log.w('scan', 'ARP не прочитан', e);
    }

    // --- фаза 5: опознание
    if (net.gateway != null) {
      final g = dev(net.gateway!);
      g.isGateway = true;
      g.sources.add('gateway');
    }
    found.remove(net.ip);
    final web = found.values
        .where((d) => d.ports.contains(80) || d.ports.contains(8080) || d.ports.contains(443) || d.ports.contains(8443))
        .toList();
    var fp = 0;
    sw.reset();
    await runPool<Device>(web, 24, (d) async {
      try {
        await Fingerprint.identify(d);
      } catch (e, st) {
        Log.e('ident', '${d.ip}: ошибка опознания', e, st);
      }
      fp++;
      onProgress('Опознаю: $fp из ${web.length}', web.isEmpty ? null : fp / web.length);
    }, cancelled: () => _cancelled);
    for (final d in found.values) {
      Fingerprint.byPorts(d);
    }
    Log.i('scan', 'Опознание ${web.length} веб-интерфейсов за ${sw.elapsedMilliseconds} мс');

    final routers = found.values.where((d) => d.isRouter).toList()..sort((a, b) => a.sortKey.compareTo(b.sortKey));
    Log.i('scan', '===== Скан завершён за ${total.elapsed.inMilliseconds} мс: устройств ${found.length}, '
        'роутеров ${routers.length} =====');
    for (final d in routers) {
      Log.i('scan', 'роутер ${d.ip}: ${d.effectiveVendor.label} «${d.title}» порты ${d.ports.toList()..sort()} '
          'MAC ${d.mac ?? '-'} источники ${d.sources.join(',')}');
    }
    return ScanReport(net, found, notes, total.elapsed);
  }

  static List<List<int>> _merge(List<List<int>> r) {
    final s = [...r]..sort((a, b) => a[0].compareTo(b[0]));
    final out = <List<int>>[];
    for (final x in s) {
      if (out.isNotEmpty && x[0] <= out.last[1] + 1) {
        if (x[1] > out.last[1]) out.last[1] = x[1];
      } else {
        out.add([x[0], x[1]]);
      }
    }
    return out;
  }
}
