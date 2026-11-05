import 'dart:async';

import 'package:flutter/foundation.dart';

import '../drivers/registry.dart';
import 'app_state.dart';
import 'ip.dart';
import 'log.dart';
import 'models.dart';
import 'native.dart';

enum HopStatus { pending, working, needPassword, needNextHop, unreachable, ok, skipped, edge, failed }

class WalkHop {
  WalkHop(this.ip);
  final String ip;
  Device? device;
  HopStatus status = HopStatus.pending;
  String? upstream;
  String note = '';
  int clients = 0;
}

/// Пошаговый обход сети к интернету. На каждом хопе: опознаём роутер,
/// спрашиваем пароль (если нужно), заходим, читаем WAN-шлюз (куда идти
/// дальше) и клиентов. Доходим до роутера на краю интернета — это и есть
/// «самый дальний». Потом карта строится сама.
///
/// Если телефон подключён без обычного шлюза (VPN-туннель, как tun1 у
/// Павла), с чего начать — спрашиваем: показываем список роутеров из скана.
class WalkController extends ChangeNotifier {
  final List<WalkHop> hops = [];
  bool running = false;
  bool finished = false;
  bool pickStart = false;
  List<Device> startCandidates = [];
  String message = '';
  WalkHop? waiting;
  Completer<_Act>? _act;

  final Set<String> _visited = {};

  void _log(String s) {
    message = s;
    Log.i('walk', s);
    notifyListeners();
  }

  Future<void> reset() async {
    hops.clear();
    _visited.clear();
    running = false;
    finished = false;
    pickStart = false;
    startCandidates = [];
    waiting = null;
    message = '';
    notifyListeners();
  }

  Future<void> start() async {
    if (running) return;
    await reset();
    running = true;
    notifyListeners();
    try {
      _log('Определяю, с какого роутера начать…');
      final netMap = await Native.networkInfo();
      app.net = NetInfo.fromMap(netMap);
      final gw = app.net?.gateway;
      if (gw != null && Ip.parse(gw) != null) {
        await _climb(gw);
        return;
      }
      // нет обычного шлюза (VPN/туннель) — просим выбрать старт
      startCandidates = app.routers;
      if (startCandidates.isEmpty) {
        _log('Не из чего начать: сначала просканируй сеть на вкладке «Карта».');
        finished = true;
        running = false;
        notifyListeners();
        return;
      }
      pickStart = true;
      running = false;
      _log('Телефон подключён без обычного шлюза (похоже, VPN-туннель). '
          'Выбери роутер, с которого начать обход — обычно ближний к тебе или самый дальний.');
      notifyListeners();
    } catch (e, st) {
      Log.e('walk', 'Старт обхода упал', e, st);
      _log('Ошибка: $e');
      running = false;
      notifyListeners();
    }
  }

  Future<void> startFrom(String ip) async {
    if (running) return;
    pickStart = false;
    running = true;
    notifyListeners();
    await _climb(ip);
  }

  Future<void> _climb(String first) async {
    try {
      var current = first;
      var guard = 0;
      while (guard++ < 16) {
        final cur = current;
        if (!_visited.add(cur)) {
          _log('Пришёл по кругу на $cur — останавливаюсь.');
          break;
        }
        final next = await _handleHop(cur);
        if (next == null) break;
        current = next;
      }
      finished = true;
      final done = hops.where((h) => h.status == HopStatus.ok || h.status == HopStatus.edge).length;
      _log('Обход завершён: пройдено роутеров $done, всего хопов ${hops.length}. Карта построена.');
      await app.saveState();
      app.analyzeLocal();
    } catch (e, st) {
      Log.e('walk', 'Обход упал', e, st);
      _log('Ошибка обхода: $e');
    } finally {
      running = false;
      waiting = null;
      notifyListeners();
    }
  }

  /// Возвращает IP следующего хопа вверх, либо null — закончить.
  Future<String?> _handleHop(String ip) async {
    final hop = WalkHop(ip);
    hops.add(hop);
    hop.status = HopStatus.working;
    hop.device = app.ensureDevice(ip);
    _log('Хоп ${hops.length}: $ip — опознаю…');
    notifyListeners();

    final d = hop.device!;
    if (d.effectiveVendor == Vendor.unknown || d.ports.isEmpty) {
      await app.probeDevice(d);
    }
    hop.note = d.effectiveVendor.label;

    if (d.ports.isEmpty && !d.icmp) {
      hop.status = HopStatus.unreachable;
      _log('$ip (${d.title}) не отвечает отсюда.');
      final act = await _ask(hop, HopStatus.unreachable);
      return act.nextHop;
    }

    final caps = capsOf(d.effectiveVendor);
    if (!caps.query) {
      hop.status = HopStatus.needNextHop;
      hop.note = '${d.effectiveVendor.label}: вход по API пока не настроен';
      _log('$ip — ${d.effectiveVendor.label}: не могу зайти по API. Открой веб-интерфейс и подскажи следующий роутер.');
      final act = await _ask(hop, HopStatus.needNextHop);
      return act.nextHop;
    }

    if (app.vault.get(ip) == null) {
      hop.status = HopStatus.needPassword;
      _log('$ip (${d.effectiveVendor.label}) — нужен логин и пароль.');
      final act = await _ask(hop, HopStatus.needPassword);
      if (act.skip || app.vault.get(ip) == null) {
        hop.status = HopStatus.skipped;
        return act.nextHop;
      }
    }

    hop.status = HopStatus.working;
    _log('$ip — захожу и читаю…');
    notifyListeners();
    final err = await app.queryRouter(d);
    if (err != null) {
      hop.status = HopStatus.failed;
      hop.note = err;
      _log('$ip — не удалось: $err');
      final act = await _ask(hop, HopStatus.needNextHop);
      return act.nextHop;
    }

    final info = d.info!;
    hop.clients = info.arp.length;
    hop.upstream = info.gateway;
    _log('$ip (${d.title}) — ок. Клиентов: ${hop.clients}. Вверх: ${info.gateway ?? 'не виден'}');

    final up = info.gateway;
    final upInt = Ip.parse(up ?? '');
    if (up != null && upInt != null) {
      if (!Ip.isPrivate(upInt)) {
        hop.status = HopStatus.edge;
        hop.note = 'дальше интернет ($up)';
        _log('$ip — самый дальний роутер: за ним интернет ($up).');
        return null;
      }
      if (_visited.contains(up)) {
        hop.status = HopStatus.ok;
        hop.note = 'вверх ведёт к уже пройденному $up';
        return null;
      }
      hop.status = HopStatus.ok;
      return up;
    }

    // WAN-шлюз не прочитан (точка доступа, мост или драйвер не достал) —
    // спросим пользователя: указать следующий роутер или завершить.
    hop.status = HopStatus.ok;
    hop.note = 'клиентов ${hop.clients}; шлюз вверх не виден';
    final act = await _ask(hop, HopStatus.needNextHop);
    return act.nextHop;
  }

  Future<_Act> _ask(WalkHop hop, HopStatus kind) async {
    waiting = hop;
    hop.status = kind;
    notifyListeners();
    _act = Completer<_Act>();
    final a = await _act!.future;
    waiting = null;
    notifyListeners();
    return a;
  }

  // --- вызовы из интерфейса
  void resumeAfterPassword() => _act?.complete(const _Act());

  void provideNextHop(String? ip) => _act?.complete(_Act(nextHop: ip));

  void skipAndContinue(String? nextHop) => _act?.complete(_Act(skip: true, nextHop: nextHop));

  void finishNow() => _act?.complete(const _Act());
}

class _Act {
  const _Act({this.nextHop, this.skip = false});
  final String? nextHop;
  final bool skip;
}

final WalkController walk = WalkController();
