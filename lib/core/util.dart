import 'dart:math';

extension IterableFind<T> on Iterable<T> {
  T? findFirst(bool Function(T e) test) {
    for (final e in this) {
      if (test(e)) return e;
    }
    return null;
  }
}

/// Выполняет задачи с ограничением параллельности. Ошибки отдельных задач
/// не роняют весь пул — их надо ловить внутри task.
Future<void> runPool<T>(
  List<T> items,
  int concurrency,
  Future<void> Function(T item) task, {
  bool Function()? cancelled,
}) async {
  if (items.isEmpty) return;
  var next = 0;
  Future<void> worker() async {
    while (true) {
      if (cancelled != null && cancelled()) return;
      final i = next++;
      if (i >= items.length) return;
      try {
        await task(items[i]);
      } catch (_) {}
    }
  }

  final n = min(concurrency, items.length);
  await Future.wait([for (var i = 0; i < n; i++) worker()]);
}

String two(int v) => v.toString().padLeft(2, '0');

String stamp(DateTime t) =>
    '${t.year}${two(t.month)}${two(t.day)}-${two(t.hour)}${two(t.minute)}${two(t.second)}';

String human(DateTime t) =>
    '${two(t.day)}.${two(t.month)} ${two(t.hour)}:${two(t.minute)}';

String clock(DateTime t) =>
    '${two(t.hour)}:${two(t.minute)}:${two(t.second)}.${t.millisecond.toString().padLeft(3, '0')}';

String normMac(String? m) {
  if (m == null) return '';
  final h = m.toUpperCase().replaceAll(RegExp(r'[^0-9A-F]'), '');
  if (h.length != 12) return m.toUpperCase();
  return [for (var i = 0; i < 12; i += 2) h.substring(i, i + 2)].join(':');
}

String? asStr(dynamic v) {
  if (v == null) return null;
  final s = '$v';
  return s.isEmpty ? null : s;
}

int? asInt(dynamic v) {
  if (v == null) return null;
  if (v is int) return v;
  if (v is num) return v.toInt();
  return int.tryParse('$v'.trim());
}

bool asBool(dynamic v) {
  if (v is bool) return v;
  final s = '$v'.toLowerCase();
  return s == 'true' || s == 'yes' || s == 'up' || s == '1' || s == 'on';
}

/// Обходит произвольный JSON и вызывает visit для каждого объекта.
void walkJson(dynamic x, void Function(Map<dynamic, dynamic> m, String key) visit,
    [String key = '']) {
  if (x is Map) {
    visit(x, key);
    x.forEach((k, v) => walkJson(v, visit, '$k'));
  } else if (x is List) {
    for (final v in x) {
      walkJson(v, visit, key);
    }
  }
}

/// Канал Wi-Fi по частоте (МГц).
int chFromFreq(int f) {
  if (f == 2484) return 14;
  if (f >= 2412 && f <= 2472) return (f - 2407) ~/ 5;
  if (f >= 5000 && f <= 5900) return (f - 5000) ~/ 5;
  if (f >= 5955 && f <= 7115) return (f - 5950) ~/ 5;
  return 0;
}

int freqFromCh(int ch, String band) {
  if (band == '2.4') return ch == 14 ? 2484 : 2407 + ch * 5;
  if (band == '6') return 5950 + ch * 5;
  return 5000 + ch * 5;
}

String bandOfFreq(int f) => f < 3000 ? '2.4' : (f < 5925 ? '5' : '6');

String bandOfChannel(int ch) => ch <= 14 ? '2.4' : '5';
