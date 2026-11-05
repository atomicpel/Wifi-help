import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../analysis/analyzer.dart';
import '../drivers/driver.dart';
import '../drivers/registry.dart';
import '../scan/fingerprint.dart';
import '../scan/scanner.dart';
import 'ip.dart';
import 'log.dart';
import 'models.dart';
import 'native.dart';
import 'util.dart';
import 'vault.dart';

class BackupEntry {
  BackupEntry(this.file, this.ip, this.vendor, this.time);
  final File file;
  final String ip;
  final String vendor;
  final DateTime time;
  String get name => file.uri.pathSegments.last;
}

class AppState extends ChangeNotifier {
  String dir = '';
  final Vault vault = Vault();
  Settings settings = Settings();
  NetInfo? net;
  final Map<String, Device> devices = {};
  DateTime? lastScan;
  Duration? lastScanTook;
  List<String> scanNotes = [];
  List<WifiAp> wifi = [];
  DateTime? wifiAt;
  String? wifiError;
  List<Issue> issues = [];
  DateTime? analyzedAt;
  final Set<String> selectedFixes = {};
  Scanner? _scanner;
  String status = '';
  double? progress;
  bool working = false;
  String? initError;
  Map<String, dynamic> phone = {};

  bool get scanning => _scanner != null;
  bool get busy => scanning || working;

  List<Device> get sortedDevices => devices.values.toList()..sort((a, b) => a.sortKey.compareTo(b.sortKey));
  List<Device> get routers => sortedDevices.where((d) => d.isRouter).toList();

  void refresh() => notifyListeners();

  void _status(String s, [double? p]) {
    status = s;
    progress = p;
    notifyListeners();
  }

  // --------------------------------------------------------------- init
  Future<void> init() async {
    try {
      dir = await Native.filesDir();
      await Log.init(dir);
      vault.vendorOf = (ip) => devices[ip]?.effectiveVendor.name;
      try {
        phone = await Native.deviceInfo();
      } catch (_) {}
      Log.i('app', 'WiFi Помощник 0.1, телефон ${phone['manufacturer']} ${phone['model']}, '
          'Android ${phone['release']} (SDK ${phone['sdk']})');
      await Directory('$dir/backups').create(recursive: true);
      final sf = File('$dir/settings.json');
      if (await sf.exists()) {
        settings = Settings.fromJson(jsonDecode(await sf.readAsString()) as Map<String, dynamic>);
      }
      Log.verbose = settings.verboseLog;
      await vault.load(dir);
      final st = File('$dir/state.json');
      if (await st.exists()) _loadState(jsonDecode(await st.readAsString()) as Map<String, dynamic>);
      analyzeLocal();
    } catch (e, st) {
      initError = '$e';
      Log.e('app', 'Ошибка запуска', e, st);
    }
  }

  void _loadState(Map<String, dynamic> j) {
    final n = j['net'];
    if (n is Map) net = NetInfo.fromMap(Map<String, dynamic>.from(n));
    for (final d in (j['devices'] as List? ?? [])) {
      final dev = Device.fromJson(Map<String, dynamic>.from(d as Map));
      devices[dev.ip] = dev;
    }
    lastScan = DateTime.tryParse('${j['lastScan']}');
    wifi = (j['wifi'] as List? ?? []).map((e) => WifiAp.fromMap(Map<String, dynamic>.from(e as Map))).toList();
    wifiAt = DateTime.tryParse('${j['wifiAt']}');
    Log.i('app', 'Загружено из прошлого скана: устройств ${devices.length}');
  }

  Future<void> saveState() async {
    try {
      final j = {
        'net': net?.toJson(),
        'devices': devices.values.map((d) => d.toJson()).toList(),
        'lastScan': lastScan?.toIso8601String(),
        'wifi': wifi.map((w) => w.toJson()).toList(),
        'wifiAt': wifiAt?.toIso8601String(),
      };
      await File('$dir/state.json').writeAsString(jsonEncode(j), flush: true);
    } catch (e, st) {
      Log.e('app', 'Не удалось сохранить состояние', e, st);
    }
  }

  Future<void> saveSettings() async {
    Log.verbose = settings.verboseLog;
    await File('$dir/settings.json').writeAsString(jsonEncode(settings.toJson()));
    Log.i('app', 'Настройки: ${jsonEncode(settings.toJson())}');
    notifyListeners();
  }

  // --------------------------------------------------------------- scan
  Future<void> scan() async {
    if (busy) return;
    final s = Scanner(settings, (phase, frac) => _status(phase, frac));
    _scanner = s;
    _status('Подготовка…');
    try {
      final rep = await s.run();
      net = rep.net;
      scanNotes = rep.notes;
      lastScanTook = rep.duration;
      final old = Map<String, Device>.from(devices);
      devices
        ..clear()
        ..addAll(rep.devices);
      for (final d in devices.values) {
        final o = old[d.ip];
        if (o != null) d.keepFrom(o);
      }
      for (final o in old.values) {
        if (!devices.containsKey(o.ip) && vault.get(o.ip) != null) {
          o.offline = true;
          devices[o.ip] = o;
          Log.w('scan', '${o.ip} (${o.title}) с сохранённым паролем не ответил');
        }
      }
      lastScan = DateTime.now();
      status = s.cancelled
          ? 'Скан остановлен. Найдено ${devices.length}'
          : 'Найдено устройств: ${devices.length}, роутеров: ${routers.length} за ${(rep.duration.inMilliseconds / 1000).toStringAsFixed(1)} с';
      await saveState();
    } catch (e, st) {
      status = 'Ошибка скана: $e';
      Log.e('scan', 'Скан упал', e, st);
    } finally {
      _scanner = null;
      progress = null;
      notifyListeners();
    }
    if (settings.autoQuery && devices.values.any((d) => vault.get(d.ip) != null)) {
      await queryAll();
    }
    analyzeLocal();
  }

  void cancelScan() => _scanner?.cancel();

  // -------------------------------------------------------------- query
  Future<String?> queryRouter(Device d) async {
    if (d.aliasOf != null) return '${d.ip} — второй адрес роутера ${d.aliasOf}, опрашиваю его по основному адресу';
    final cred = vault.get(d.ip);
    if (cred == null) return 'Нет логина/пароля';
    final drv = driverFor(d, cred);
    if (drv == null) return 'Для ${d.effectiveVendor.label} автонастройка пока не поддерживается';
    Log.i('query', 'Опрос ${d.ip} (${d.effectiveVendor.label})');
    try {
      RouterInfo info;
      try {
        await drv.login();
        info = await drv.collect();
      } on SocketException catch (e) {
        // сеть сменилась (VPN переподключился: tun0 → tun1) — привязываемся заново и повторяем
        final code = e.osError?.errorCode;
        if (code != 1 && code != 64 && code != 101 && code != 113) rethrow;
        Log.w('query', '${d.ip}: сеть сменилась ($code), привязываюсь заново');
        await rebindNetwork();
        await drv.close();
        return await _queryOnce(d, cred);
      }
      d.info = info;
      d.infoAt = DateTime.now();
      d.lastError = null;
      d.offline = false;
      _learnFromRouter(d, info);
      return null;
    } catch (e, st) {
      d.lastError = '$e';
      Log.e('query', '${d.ip}: опрос не удался', e, e is DriverException ? null : st);
      return '$e';
    } finally {
      await drv.close();
      notifyListeners();
    }
  }

  Future<void> rebindNetwork() async {
    try {
      net = NetInfo.fromMap(await Native.networkInfo());
    } catch (e) {
      Log.w('net', 'Не удалось заново привязаться к сети', e);
    }
  }

  Future<String?> _queryOnce(Device d, Credential cred) async {
    final drv = driverFor(d, cred)!;
    try {
      await drv.login();
      final info = await drv.collect();
      d.info = info;
      d.infoAt = DateTime.now();
      d.lastError = null;
      d.offline = false;
      _learnFromRouter(d, info);
      return null;
    } catch (e, st) {
      d.lastError = '$e';
      Log.e('query', '${d.ip}: опрос не удался', e, e is DriverException ? null : st);
      return '$e';
    } finally {
      await drv.close();
    }
  }

  /// ARP-таблицы роутеров показывают устройства и в других подсетях.
  void _learnFromRouter(Device r, RouterInfo info) {
    // другие адреса этого же роутера (WAN, второй LAN) — склеиваем с ним
    for (final a in info.addrs) {
      final other = devices[a.ip];
      if (other != null && other.ip != r.ip && other.aliasOf != r.ip) {
        other.aliasOf = r.ip;
        Log.i('query', '${a.ip} — это ${a.iface}-адрес роутера ${r.ip} (${r.title}), склеиваю');
      }
    }
    var added = 0;
    for (final e in info.arp) {
      final ipInt = Ip.parse(e.ip);
      if (ipInt == null || !Ip.isPrivate(ipInt) || e.ip == net?.ip) continue;
      final x = devices[e.ip];
      if (x == null) {
        final nd = Device(e.ip);
        nd.mac = normMac(e.mac);
        nd.sources.add('arp:${r.ip}');
        devices[e.ip] = nd;
        added++;
      } else if (x.mac == null || x.mac!.isEmpty) {
        x.mac = normMac(e.mac);
      }
    }
    if (added > 0) Log.i('query', '${r.ip}: из ARP добавлено новых устройств: $added');
  }

  Future<void> queryAll() async {
    if (working) return;
    working = true;
    _status('Опрашиваю роутеры…');
    await rebindNetwork();
    try {
      final targets = devices.values
          .where((d) => d.aliasOf == null && vault.get(d.ip) != null && d.effectiveVendor.supported)
          .toList();
      var n = 0;
      var errs = 0;
      await runPool<Device>(targets, 4, (d) async {
        final e = await queryRouter(d);
        n++;
        if (e != null) errs++;
        _status('Опрошено $n из ${targets.length}', targets.isEmpty ? null : n / targets.length);
      });
      status = targets.isEmpty
          ? 'Нет роутеров с паролями (для Keenetic/MikroTik) — введи их на вкладке «Устройства»'
          : 'Опрошено роутеров: ${targets.length}, с ошибкой: $errs';
      await saveState();
    } finally {
      working = false;
      progress = null;
      notifyListeners();
    }
  }

  // --------------------------------------------------------------- wifi
  Future<void> wifiScan() async {
    try {
      final p = await Native.ensurePermissions();
      if (p['granted'] != true) {
        wifiError = 'Нужно разрешение «Местоположение» — без него Android не показывает сети вокруг.';
        notifyListeners();
        return;
      }
      if (p['locationOn'] != true) {
        wifiError = 'Включи геолокацию (GPS) в шторке — без неё Android не отдаёт список сетей.';
        notifyListeners();
        return;
      }
      final r = await Native.wifiScan();
      if (r['error'] != null) {
        wifiError = 'Скан эфира: ${r['error']}';
        notifyListeners();
        return;
      }
      final list = (r['results'] as List? ?? [])
          .map((e) => WifiAp.fromMap(Map<String, dynamic>.from(e as Map)))
          .toList()
        ..sort((a, b) => b.level.compareTo(a.level));
      wifi = list;
      wifiAt = DateTime.now();
      wifiError = r['fresh'] == true
          ? null
          : 'Android разрешает 4 скана за 2 минуты — показан последний доступный результат.';
      Log.i('wifi', 'Эфир: ${list.length} точек (свежий: ${r['fresh']})');
      for (final a in list) {
        Log.d('wifi', '«${a.ssid}» ${a.bssid} ch${a.channel} ${a.band}ГГц ${a.level}дБм ${a.widthMhz}МГц ${a.security}');
      }
      await saveState();
    } catch (e, st) {
      wifiError = 'Ошибка скана эфира: $e';
      Log.e('wifi', 'Скан эфира упал', e, st);
    }
    notifyListeners();
  }

  // ------------------------------------------------------------ analyze
  Future<void> analyze() async {
    if (busy) return;
    Log.i('analyze', '===== Проверка сети =====');
    await queryAll();
    _status('Сканирую эфир…');
    await wifiScan();
    analyzeLocal();
    status = 'Проверка завершена: проблем ${issues.length}';
    notifyListeners();
  }

  void analyzeLocal() {
    issues = Analyzer(sortedDevices, wifi, net, (ip) => vault.get(ip) != null).run();
    analyzedAt = DateTime.now();
    final valid = issues.expand((i) => i.fixes).map((f) => f.key).toSet();
    selectedFixes.removeWhere((k) => !valid.contains(k));
    notifyListeners();
  }

  List<FixAction> get allFixes => issues.expand((i) => i.fixes).toList();

  // ------------------------------------------------------------ backups
  Future<String> _saveBackup(Device d, BackupData b) async {
    final name = '${d.ip}_${d.effectiveVendor.name}_${stamp(DateTime.now())}.${b.ext}';
    final f = File('$dir/backups/$name');
    await f.writeAsString(b.content, flush: true);
    Log.i('backup', '${d.ip}: бэкап $name (${b.content.length} б). ${b.note}');
    return name;
  }

  Future<String> backupNow(Device d) async {
    final cred = vault.get(d.ip);
    if (cred == null) return 'Нет логина/пароля';
    final drv = driverFor(d, cred);
    if (drv == null) return 'Для ${d.effectiveVendor.label} бэкап пока не поддерживается';
    try {
      await drv.login();
      final b = await drv.backup();
      final name = await _saveBackup(d, b);
      return 'Сохранено: $name. ${b.note}';
    } catch (e, st) {
      Log.e('backup', '${d.ip}: бэкап не удался', e, st);
      return 'Ошибка: $e';
    } finally {
      await drv.close();
    }
  }

  List<BackupEntry> listBackups() {
    final out = <BackupEntry>[];
    try {
      for (final f in Directory('$dir/backups').listSync().whereType<File>()) {
        final name = f.uri.pathSegments.last;
        final parts = name.split('_');
        out.add(BackupEntry(f, parts.isNotEmpty ? parts[0] : '?', parts.length > 1 ? parts[1] : '?', f.statSync().modified));
      }
    } catch (e) {
      Log.w('backup', 'Не прочитать папку бэкапов', e);
    }
    out.sort((a, b) => b.time.compareTo(a.time));
    return out;
  }

  // -------------------------------------------------------------- apply
  Future<void> _applyOne(RouterDriver drv, Device d, FixAction f) async {
    final info = d.info;
    if (info == null) throw DriverException('нет данных о роутере');
    RadioInfo radio() =>
        info.radios.findFirst((x) => x.id == f.targetId) ?? (throw DriverException('радио ${f.targetId} не найдено'));
    switch (f.kind) {
      case FixKind.setChannel:
        await drv.setChannel(radio(), f.value!);
      case FixKind.setWidth20:
        await drv.setWidth20(radio());
      case FixKind.disableDhcp:
        final srv = info.dhcp.findFirst((x) => x.id == f.targetId) ??
            (throw DriverException('DHCP-сервер ${f.targetId} не найден'));
        await drv.setDhcpEnabled(srv, false);
      case FixKind.enableAutoNeg:
        final port = info.ports.findFirst((x) => x.id == f.targetId) ??
            (throw DriverException('порт ${f.targetId} не найден'));
        await drv.enableAutoNeg(port);
      case FixKind.saveConfig:
        await drv.saveConfig();
    }
  }

  /// Применяет исправления: по каждому роутеру сначала бэкап, без бэкапа —
  /// никаких изменений.
  Future<void> applyFixes(List<FixAction> fixes, void Function(String) log) async {
    if (busy) return;
    working = true;
    notifyListeners();
    Log.i('apply', '===== Применение ${fixes.length} исправлений =====');
    try {
      final byIp = <String, List<FixAction>>{};
      for (final f in fixes) {
        byIp.putIfAbsent(f.ip, () => []).add(f);
      }
      for (final entry in byIp.entries) {
        final d = devices[entry.key];
        final cred = vault.get(entry.key);
        void out(String s) {
          log(s);
          Log.i('apply', s);
        }

        if (d == null || cred == null) {
          out('✖ ${entry.key}: нет данных или пароля — пропуск');
          continue;
        }
        final drv = driverFor(d, cred);
        if (drv == null) {
          out('✖ ${d.ip}: для ${d.effectiveVendor.label} нет драйвера');
          continue;
        }
        out('● ${d.title} (${d.ip})');
        var backedUp = false;
        try {
          await drv.login();
          d.info ??= await drv.collect();
          out('  бэкап…');
          final name = await _saveBackup(d, await drv.backup());
          backedUp = true;
          out('  бэкап сохранён: $name');
          for (final f in entry.value) {
            try {
              await _applyOne(drv, d, f);
              out('  ✔ ${f.text}');
            } catch (e) {
              out('  ✖ ${f.text}: $e');
            }
          }
          d.info = await drv.collect();
          d.infoAt = DateTime.now();
        } catch (e, st) {
          Log.e('apply', '${d.ip}: ошибка', e, st);
          out(backedUp ? '  ✖ ошибка: $e' : '  ✖ $e — бэкап не сделан, поэтому изменения не вносились');
        } finally {
          await drv.close();
        }
      }
      await saveState();
      analyzeLocal();
      log('Готово.');
    } finally {
      working = false;
      selectedFixes.clear();
      notifyListeners();
    }
  }

  Future<void> changePasswordAll(List<String> ips, String newPassword, void Function(String) log) async {
    if (busy) return;
    working = true;
    notifyListeners();
    Log.addSecret(newPassword);
    Log.i('passwd', '===== Смена пароля на ${ips.length} роутерах =====');
    var ok = 0;
    try {
      for (final ip in ips) {
        final d = devices[ip];
        final cred = vault.get(ip);
        void out(String s) {
          log(s);
          Log.i('passwd', s);
        }

        if (d == null || cred == null) {
          out('✖ $ip: нет пароля — пропуск');
          continue;
        }
        final drv = driverFor(d, cred);
        if (drv == null) {
          out('✖ $ip: ${d.effectiveVendor.label} пока не поддерживается');
          continue;
        }
        out('● ${d.title} ($ip)');
        try {
          await drv.login();
          out('  бэкап…');
          final name = await _saveBackup(d, await drv.backup());
          out('  бэкап сохранён: $name');
          await drv.changePassword(newPassword);
          await vault.set(ip, cred.copyWith(password: newPassword));
          out('  ✔ пароль изменён, вход с новым паролем проверен');
          ok++;
        } catch (e, st) {
          Log.e('passwd', '$ip: не удалось', e, e is DriverException ? null : st);
          out('  ✖ $e');
        } finally {
          await drv.close();
        }
      }
      log('Готово: изменён на $ok из ${ips.length}.');
    } finally {
      working = false;
      notifyListeners();
    }
  }

  Device ensureDevice(String ip) {
    final d = devices.putIfAbsent(ip, () => Device(ip));
    return d;
  }

  /// Быстрое опознание одного адреса (для пошагового обхода сети).
  Future<void> probeDevice(Device d) async {
    final t = settings.tcpTimeoutMs + 300;
    await runPool<int>(const [80, 443, 8080, 8443, 8291, 8728, 22], 7, (p) async {
      final r = await tcpProbe(d.ip, p, Duration(milliseconds: t));
      if (r == ProbeResult.open) d.ports.add(p);
    });
    if (d.ports.contains(80) || d.ports.contains(443) || d.ports.contains(8080) || d.ports.contains(8443)) {
      await Fingerprint.identify(d);
    }
    Fingerprint.byPorts(d);
    notifyListeners();
  }

  // ---------------------------------------------------------- misc
  Future<String> survey(Device d) async {
    try {
      return await Fingerprint.survey(d);
    } catch (e, st) {
      Log.e('survey', d.ip, e, st);
      return 'Ошибка: $e';
    }
  }

  /// Отчёт для разработчика: сводка + полный журнал.
  Future<String> report() async {
    final b = StringBuffer()
      ..writeln('WiFi Помощник — отчёт ${DateTime.now().toIso8601String()}')
      ..writeln('Телефон: ${phone['manufacturer']} ${phone['model']}, Android ${phone['release']} (SDK ${phone['sdk']})')
      ..writeln('Сеть: ${jsonEncode(net?.toJson())}')
      ..writeln('Последний скан: ${lastScan?.toIso8601String()} за ${lastScanTook?.inMilliseconds} мс')
      ..writeln('Заметки скана: ${scanNotes.join(' | ')}')
      ..writeln()
      ..writeln('=== Устройства (${devices.length}) ===');
    for (final d in sortedDevices) {
      b.writeln('${d.ip}\t${d.effectiveVendor.label}${d.vendorOverride != null ? ' (вручную)' : ''}\t'
          'роутер=${d.isRouter}\tMAC=${d.mac ?? '-'}\tпорты=${(d.ports.toList()..sort()).join(',')}\t'
          'модель=${d.model ?? '-'}\ttitle=${d.httpTitle ?? '-'}\tserver=${d.server ?? '-'}\trealm=${d.authRealm ?? '-'}\t'
          'upnp=${d.upnpManufacturer ?? '-'}\tисточники=${d.sources.join(',')}\tпароль=${vault.get(d.ip) != null ? 'есть' : 'нет'}'
          '${d.lastError != null ? '\tошибка=${d.lastError}' : ''}');
      final info = d.info;
      if (info != null) b.writeln('    данные роутера: ${jsonEncode(info.toJson()..remove('arp'))}');
    }
    b
      ..writeln()
      ..writeln('=== Проблемы (${issues.length}) ===');
    for (final i in issues) {
      b.writeln('[${i.severity.name}] ${i.title}: ${i.details.replaceAll('\n', ' / ')}');
    }
    b
      ..writeln()
      ..writeln('=== Журнал ===')
      ..write(await Log.fileText());
    return Log.mask(b.toString());
  }
}

final AppState app = AppState();
