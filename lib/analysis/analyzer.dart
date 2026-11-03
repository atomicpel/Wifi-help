import '../core/ip.dart';
import '../core/log.dart';
import '../core/models.dart';
import '../core/util.dart';
import '../drivers/registry.dart';

/// Ищет то, что обычно ломает сети с кучей роутеров, и готовит исправления.
class Analyzer {
  Analyzer(this.devices, this.wifi, this.net, this.hasCred);
  final List<Device> devices;
  final List<WifiAp> wifi;
  final NetInfo? net;
  final bool Function(String ip) hasCred;
  final List<Issue> _issues = [];

  List<Device> get _withInfo => devices.where((d) => d.info != null).toList();

  List<Issue> run() {
    final steps = <String, void Function()>{
      'dhcp': _dhcp,
      'ip': _ipConflicts,
      'nat': _cascade,
      'ports': _ports,
      'channels': _channels,
      'ssid': _ssidSecurity,
      'scan': _scanHeuristics,
      'access': _access,
      'unsaved': _unsaved,
    };
    steps.forEach((name, f) {
      try {
        f();
      } catch (e, st) {
        Log.e('analyze', 'Проверка «$name» упала', e, st);
      }
    });
    _issues.sort((a, b) => a.severity.index.compareTo(b.severity.index));
    Log.i('analyze', 'Найдено проблем: ${_issues.length} '
        '(критичных ${_issues.where((i) => i.severity == Severity.critical).length}, '
        'предупреждений ${_issues.where((i) => i.severity == Severity.warning).length})');
    for (final i in _issues) {
      Log.d('analyze', '[${i.severity.name}] ${i.title} | ${i.details.replaceAll('\n', ' / ')} | исправлений: ${i.fixes.length}');
    }
    return _issues;
  }

  String _name(Device d) => '${d.title} (${d.ip})';

  // ---------------------------------------------------------------- DHCP
  void _dhcp() {
    final bySubnet = <String, List<(Device, DhcpServerInfo)>>{};
    for (final d in _withInfo) {
      for (final s in d.info!.dhcp.where((s) => s.enabled)) {
        final a = d.info!.addrs.findFirst((a) => a.iface == s.iface);
        if (a == null) continue;
        bySubnet.putIfAbsent(a.cidr, () => []).add((d, s));
      }
    }
    bySubnet.forEach((subnet, list) {
      if (list.length < 2) return;
      final gw = net?.gateway;
      var keepIdx = list.indexWhere((x) => x.$1.ip == gw || x.$1.info!.addrs.any((a) => a.ip == gw));
      if (keepIdx < 0) keepIdx = list.indexWhere((x) => x.$1.info!.nat == true);
      if (keepIdx < 0) keepIdx = 0;
      final keep = list[keepIdx];
      final fixes = <FixAction>[];
      final manual = <String>[];
      for (var i = 0; i < list.length; i++) {
        if (i == keepIdx) continue;
        final x = list[i];
        if (capsOf(x.$1.effectiveVendor).dhcp) {
          fixes.add(FixAction(
            ip: x.$1.ip,
            kind: FixKind.disableDhcp,
            targetId: x.$2.id,
            text: 'Выключить DHCP «${x.$2.name}» на ${_name(x.$1)}',
          ));
        } else {
          manual.add(_name(x.$1));
        }
      }
      _issues.add(Issue(
        id: 'dhcp-$subnet',
        severity: Severity.critical,
        title: 'Несколько DHCP-серверов в сети $subnet',
        details: 'Адреса раздают сразу: ${list.map((x) => _name(x.$1)).join(', ')}. '
            'Клиенты получают случайный шлюз — отсюда «есть Wi-Fi, нет интернета» и обрывы.\n'
            'Оставить нужно только ${_name(keep.$1)}.',
        ips: list.map((x) => x.$1.ip).toList(),
        fixes: fixes,
        hint: manual.isEmpty
            ? null
            : 'Вручную на ${manual.join(', ')}: переведи роутер в режим «Точка доступа» '
                '(Keenetic: «Общие настройки» → «Режим работы»), кабель от основного роутера — в LAN-порт.',
      ));
    });
  }

  // --------------------------------------------------------- IP conflicts
  void _ipConflicts() {
    final map = <String, Map<String, Set<String>>>{};
    for (final d in _withInfo) {
      for (final e in d.info!.arp) {
        final mac = normMac(e.mac);
        if (mac.isEmpty || mac == '00:00:00:00:00:00' || mac == 'FF:FF:FF:FF:FF:FF') continue;
        final ipInt = Ip.parse(e.ip);
        if (ipInt == null || !Ip.isPrivate(ipInt)) continue;
        map.putIfAbsent(e.ip, () => {}).putIfAbsent(mac, () => {}).add(d.ip);
      }
    }
    map.forEach((ip, macs) {
      if (macs.length < 2) return;
      _issues.add(Issue(
        id: 'ipconf-$ip',
        severity: Severity.critical,
        title: 'Конфликт IP-адреса $ip',
        details: 'Один адрес у разных устройств: '
            '${macs.entries.map((e) => '${e.key} (видит ${e.value.join(', ')})').join('; ')}.',
        ips: macs.values.expand((s) => s).toSet().toList(),
        hint: 'Найди устройство со статическим адресом и выдай ему адрес вне диапазона DHCP '
            'или закрепи аренду на роутере.',
      ));
    });
  }

  // --------------------------------------------- cascade / double NAT
  void _cascade() {
    final byIp = {for (final d in devices) d.ip: d};
    for (final d in _withInfo) {
      final info = d.info!;
      final up = info.upAddr;
      final lans = info.lanAddrs;
      if (up != null) {
        final upInt = Ip.parse(up.ip)!;
        for (final l in lans) {
          final li = Ip.parse(l.ip);
          if (li != null && l.iface != up.iface && Ip.overlap(li, l.prefix, upInt, up.prefix)) {
            _issues.add(Issue(
              id: 'overlap-${d.ip}-${l.iface}',
              severity: Severity.critical,
              title: 'У ${_name(d)} локальная сеть совпадает с внешней',
              details: 'LAN ${l.cidr} (${l.iface}) пересекается с подсетью шлюза ${up.cidr} (${up.iface}). '
                  'Маршрутизация через такой роутер работает непредсказуемо.',
              ips: [d.ip],
              hint: 'Смени LAN-подсеть этого роутера (например, на 192.168.${100 + (Ip.parse(d.ip)! & 0x3F)}.0/24) '
                  'или переведи его в режим точки доступа.',
            ));
          }
        }
      }
      final gw = info.gateway;
      final parent = gw == null ? null : byIp[gw];
      if (info.nat == true && lans.isNotEmpty && parent != null) {
        _issues.add(Issue(
          id: 'dnat-${d.ip}',
          severity: Severity.warning,
          title: 'Двойной NAT: ${_name(d)} стоит за ${_name(parent)}',
          details: 'Роутер получает интернет от другого роутера вашей сети и делает ещё один NAT '
              '(своя подсеть ${lans.map((a) => a.cidr).join(', ')}). Устройства за ним не видят остальную сеть, '
              'ломаются проброс портов, звонки, игры и роуминг между точками.',
          ips: [d.ip, parent.ip],
          hint: 'Правильно для сети из многих роутеров: основной роутер раздаёт адреса, остальные — '
              'точки доступа (кабель от основного в LAN-порт, DHCP выключен, режим «Точка доступа»).',
        ));
      }
    }
  }

  // ----------------------------------------------------- ports / duplex
  void _ports() {
    for (final d in _withInfo) {
      for (final p in d.info!.ports.where((p) => p.up)) {
        if (p.fullDuplex == false) {
          final canFix = capsOf(d.effectiveVendor).autoneg && p.autoNeg == false;
          _issues.add(Issue(
            id: 'duplex-${d.ip}-${p.id}',
            severity: Severity.critical,
            title: 'Полудуплекс на ${_name(d)}, ${p.name}',
            details: 'Порт работает в half-duplex${p.speedMbps != null ? ' на ${p.speedMbps} Мбит/с' : ''}. '
                'Это коллизии, потери и «тормоза» под нагрузкой.'
                '${p.autoNeg == false ? ' Автосогласование на порту выключено.' : ''}',
            ips: [d.ip],
            fixes: canFix
                ? [
                    FixAction(
                        ip: d.ip,
                        kind: FixKind.enableAutoNeg,
                        targetId: p.id,
                        text: 'Включить автосогласование на ${p.name} (${d.ip})')
                  ]
                : [],
            hint: 'На обоих концах кабеля должно быть «авто». Если не помогло — переобжать или заменить кабель.',
          ));
        } else if (p.speedMbps != null && p.speedMbps! <= 10) {
          _issues.add(Issue(
            id: 'speed10-${d.ip}-${p.id}',
            severity: Severity.warning,
            title: 'Порт ${p.name} на ${_name(d)} поднялся на 10 Мбит/с',
            details: 'Почти всегда это плохой кабель, коннектор или порт.',
            ips: [d.ip],
            hint: 'Замени патч-корд, проверь обжим.',
          ));
        } else if (p.speedMbps == 100) {
          _issues.add(Issue(
            id: 'speed100-${d.ip}-${p.id}',
            severity: Severity.info,
            title: 'Порт ${p.name} на ${_name(d)} работает на 100 Мбит/с',
            details: 'Если оба устройства гигабитные — кабель, скорее всего, использует только 2 пары из 4.',
            ips: [d.ip],
          ));
        }
      }
    }
  }

  // ----------------------------------------------------------- channels
  Set<String> get _ownSsids {
    final s = <String>{};
    for (final d in _withInfo) {
      for (final r in d.info!.radios) {
        if (r.ssid != null && r.ssid!.isNotEmpty) s.add(r.ssid!);
      }
    }
    final n = net?.ssid;
    if (n != null && n.isNotEmpty) s.add(n);
    return s;
  }

  bool _isOwnAp(WifiAp ap, Set<String> ssids, Set<String> macs) =>
      ssids.contains(ap.ssid) || macs.contains(ap.bssid);

  void _channels() {
    final ssids = _ownSsids;
    final macs = <String>{};
    final own24 = <(Device, RadioInfo)>[];
    final own5 = <(Device, RadioInfo)>[];
    for (final d in _withInfo) {
      for (final r in d.info!.radios.where((r) => r.enabled)) {
        if (r.mac != null) macs.add(r.mac!);
        if (r.band == '2.4') own24.add((d, r));
        if (r.band == '5') own5.add((d, r));
      }
    }
    own24.sort((a, b) => a.$1.sortKey.compareTo(b.$1.sortKey));
    own5.sort((a, b) => a.$1.sortKey.compareTo(b.$1.sortKey));

    // --- нагрузка от чужих сетей на каналы 1/6/11
    final load = {1: 0, 6: 0, 11: 0};
    for (final ap in wifi.where((a) => a.band == '2.4' && !_isOwnAp(a, ssids, macs))) {
      final w = ap.level > -60 ? 3 : (ap.level > -75 ? 2 : 1);
      for (final c in load.keys.toList()) {
        if ((ap.channel - c).abs() < 5) load[c] = load[c]! + w;
      }
    }

    if (own24.isNotEmpty) {
      final bad = own24.where((x) => x.$2.channel != null && ![1, 6, 11].contains(x.$2.channel)).toList();
      final counts = <int, int>{};
      for (final x in own24) {
        final c = x.$2.channel;
        if (c != null) counts[c] = (counts[c] ?? 0) + 1;
      }
      final shared = counts.entries.where((e) => e.value > 1).map((e) => e.key).toList();
      final autos = own24.where((x) => x.$2.autoChannel).toList();
      if (bad.isNotEmpty || shared.isNotEmpty || (own24.length > 1 && autos.isNotEmpty)) {
        final order = load.keys.toList()..sort((a, b) => load[a]!.compareTo(load[b]!));
        final fixes = <FixAction>[];
        final plan = <String>[];
        for (var i = 0; i < own24.length; i++) {
          final (d, r) = own24[i];
          final target = order[i % order.length];
          plan.add('${_name(d)}: ${r.channel ?? '?'}${r.autoChannel ? ' (авто)' : ''} → $target');
          if (r.channel != target || r.autoChannel) {
            fixes.add(FixAction(
              ip: d.ip,
              kind: FixKind.setChannel,
              targetId: r.id,
              value: target,
              text: '2,4 ГГц на ${_name(d)}: канал ${r.channel ?? '?'} → $target',
            ));
          }
        }
        _issues.add(Issue(
          id: 'ch24',
          severity: shared.isNotEmpty || bad.isNotEmpty ? Severity.warning : Severity.info,
          title: 'Каналы 2,4 ГГц мешают друг другу',
          details: [
            if (bad.isNotEmpty)
              'Не на 1/6/11 (перекрываются с соседями): ${bad.map((x) => '${_name(x.$1)} — ${x.$2.channel}').join(', ')}.',
            if (shared.isNotEmpty) 'Свои точки на одном канале: ${shared.join(', ')}.',
            if (autos.isNotEmpty && own24.length > 1)
              'На ${autos.length} точках «авто» — несколько точек в авто часто сходятся на один канал.',
            'Загрузка чужими сетями: ${order.map((c) => 'канал $c — ${load[c]}').join(', ')}.',
            'План: ${plan.join('; ')}.',
          ].join('\n'),
          ips: own24.map((x) => x.$1.ip).toSet().toList(),
          fixes: fixes,
        ));
      }

      final wide = own24.where((x) => (x.$2.widthMhz ?? 20) >= 40).toList();
      if (wide.isNotEmpty) {
        _issues.add(Issue(
          id: 'w24',
          severity: Severity.warning,
          title: 'Ширина 40 МГц в диапазоне 2,4 ГГц',
          details: '${wide.map((x) => _name(x.$1)).join(', ')}: 40 МГц занимают почти весь диапазон, '
              'при нескольких точках это гарантированные помехи.',
          ips: wide.map((x) => x.$1.ip).toList(),
          fixes: [
            for (final x in wide)
              if (capsOf(x.$1.effectiveVendor).width)
                FixAction(
                    ip: x.$1.ip,
                    kind: FixKind.setWidth20,
                    targetId: x.$2.id,
                    text: 'Ширина 20 МГц на ${_name(x.$1)} (${x.$2.name})')
          ],
          hint: 'На роутерах без автонастройки выставь 20 МГц вручную.',
        ));
      }
    }

    if (own5.length > 1) {
      final counts = <int, int>{};
      for (final x in own5) {
        final c = x.$2.channel;
        if (c != null) counts[c] = (counts[c] ?? 0) + 1;
      }
      final shared = counts.entries.where((e) => e.value > 1).map((e) => e.key).toList();
      if (shared.isNotEmpty) {
        final maxW = own5.map((x) => x.$2.widthMhz ?? 20).fold<int>(20, (a, b) => b > a ? b : a);
        final pool = maxW >= 80
            ? [36, 149]
            : (maxW >= 40 ? [36, 149, 44, 157] : [36, 149, 44, 157, 40, 153, 48, 161]);
        final fixes = <FixAction>[];
        for (var i = 0; i < own5.length; i++) {
          final (d, r) = own5[i];
          final target = pool[i % pool.length];
          if (r.channel != target) {
            fixes.add(FixAction(
              ip: d.ip,
              kind: FixKind.setChannel,
              targetId: r.id,
              value: target,
              text: '5 ГГц на ${_name(d)}: канал ${r.channel ?? '?'} → $target',
            ));
          }
        }
        _issues.add(Issue(
          id: 'ch5',
          severity: Severity.warning,
          title: 'Свои точки 5 ГГц на одном канале',
          details: 'Каналы ${shared.join(', ')} заняты несколькими вашими точками. '
              'Разнесу по каналам без радарного режима (DFS) с учётом ширины $maxW МГц.',
          ips: own5.map((x) => x.$1.ip).toSet().toList(),
          fixes: fixes,
        ));
      }
    }

    // --- если паролей нет, оцениваем только по эфиру
    if (own24.isEmpty && wifi.isNotEmpty) {
      final mine = wifi.where((a) => a.band == '2.4' && ssids.contains(a.ssid)).toList();
      final odd = mine.where((a) => ![1, 6, 11].contains(a.channel)).toList();
      if (odd.isNotEmpty) {
        _issues.add(Issue(
          id: 'ch24-scan',
          severity: Severity.warning,
          title: 'Ваши точки 2,4 ГГц на перекрывающихся каналах (по эфиру)',
          details: odd.map((a) => '«${a.ssid}» ${a.bssid} — канал ${a.channel}').join('\n'),
          hint: 'Введи пароли роутеров — тогда план каналов применится автоматически (для поддерживаемых моделей).',
        ));
      }
    }
    final cur = net?.freq;
    if (cur != null && cur > 0 && cur < 3000) {
      final ch = chFromFreq(cur);
      final around = wifi.where((a) => a.band == '2.4' && (a.channel - ch).abs() < 5 && !ssids.contains(a.ssid)).length;
      if (around >= 6) {
        _issues.add(Issue(
          id: 'busy',
          severity: Severity.info,
          title: 'Эфир 2,4 ГГц вокруг канала $ch забит',
          details: 'Рядом $around чужих сетей на этом и соседних каналах. Переводи устройства на 5 ГГц, где возможно.',
        ));
      }
    }
  }

  // ------------------------------------------------- SSID / security
  void _ssidSecurity() {
    final bySsid = <String, Set<String>>{};
    for (final ap in wifi) {
      if (ap.ssid.isEmpty) continue;
      bySsid.putIfAbsent(ap.ssid, () => {}).add(ap.security);
    }
    final own = _ownSsids;
    bySsid.forEach((ssid, secs) {
      if (secs.length > 1 && own.contains(ssid)) {
        _issues.add(Issue(
          id: 'sec-$ssid',
          severity: Severity.warning,
          title: 'Сеть «$ssid» с разной защитой на разных точках',
          details: 'Найдено: ${secs.join(', ')}. Телефоны не смогут бесшовно переходить между точками.',
          hint: 'Сделай одинаковые SSID, пароль и тип защиты (WPA2 или WPA2/WPA3) на всех точках.',
        ));
      }
      if (own.contains(ssid) && (secs.contains('Открытая') || secs.contains('WEP'))) {
        _issues.add(Issue(
          id: 'open-$ssid',
          severity: Severity.critical,
          title: 'Сеть «$ssid» без нормальной защиты',
          details: 'Обнаружено: ${secs.join(', ')}.',
          hint: 'Включи WPA2-PSK (AES) или WPA2/WPA3.',
        ));
      }
    });
  }

  // ---------------------------------------- scan-only heuristics
  void _scanHeuristics() {
    final n = net;
    if (n == null || n.ip == null) return;
    final my = Ip.parse(n.ip)!;
    final local = devices.where((d) {
      final ip = Ip.parse(d.ip);
      return d.isRouter && ip != null && Ip.sameNet(ip, my, n.prefix);
    }).toList();
    if (local.length >= 2 && local.every((d) => d.info == null)) {
      _issues.add(Issue(
        id: 'many-routers',
        severity: Severity.info,
        title: 'В подсети ${n.subnet} найдено роутеров: ${local.length}',
        details: '${local.map(_name).join(', ')}.\nЕсли DHCP включён больше чем на одном — будут конфликты. '
            'Введи пароли, чтобы программа проверила это сама.',
        ips: local.map((d) => d.ip).toList(),
      ));
    }
  }

  void _access() {
    final routers = devices.where((d) => d.isRouter).toList();
    final noCred = routers.where((d) => d.effectiveVendor.supported && !hasCred(d.ip)).toList();
    if (noCred.isNotEmpty) {
      _issues.add(Issue(
        id: 'nocred',
        severity: Severity.info,
        title: 'Нет пароля для ${noCred.length} роутеров',
        details: '${noCred.map(_name).join(', ')} — без входа проверка неполная.',
        ips: noCred.map((d) => d.ip).toList(),
      ));
    }
    final unsupported = <String, int>{};
    for (final d in routers.where((d) => !d.effectiveVendor.supported)) {
      unsupported[d.effectiveVendor.label] = (unsupported[d.effectiveVendor.label] ?? 0) + 1;
    }
    if (unsupported.isNotEmpty) {
      _issues.add(Issue(
        id: 'unsupported',
        severity: Severity.info,
        title: 'Без автонастройки пока: ${unsupported.entries.map((e) => '${e.key} ×${e.value}').join(', ')}',
        details: 'Для них работают поиск, карта, анализ эфира и вход в веб-интерфейс. '
            'Чтобы добавить драйвер — открой роутер, нажми «Разведка для журнала» и пришли журнал.',
      ));
    }
    for (final d in routers.where((d) => d.lastError != null)) {
      _issues.add(Issue(
        id: 'err-${d.ip}',
        severity: Severity.warning,
        title: 'Не удалось опросить ${_name(d)}',
        details: d.lastError!,
        ips: [d.ip],
      ));
    }
  }

  void _unsaved() {
    for (final d in _withInfo.where((d) => d.info!.unsaved && capsOf(d.effectiveVendor).save)) {
      _issues.add(Issue(
        id: 'unsaved-${d.ip}',
        severity: Severity.info,
        title: 'Несохранённые изменения на ${_name(d)}',
        details: 'После перезагрузки они пропадут.',
        ips: [d.ip],
        fixes: [
          FixAction(ip: d.ip, kind: FixKind.saveConfig, targetId: 'config', text: 'Сохранить конфигурацию ${_name(d)}')
        ],
      ));
    }
  }
}
