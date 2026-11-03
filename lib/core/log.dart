import 'dart:io';

import 'package:flutter/foundation.dart';

import 'util.dart';

enum LogLevel { debug, info, warn, error }

class LogLine {
  LogLine(this.t, this.level, this.tag, this.msg);
  final DateTime t;
  final LogLevel level;
  final String tag;
  final String msg;

  String get levelChar => switch (level) {
        LogLevel.debug => 'D',
        LogLevel.info => 'I',
        LogLevel.warn => 'W',
        LogLevel.error => 'E',
      };

  String format() => '${clock(t)} $levelChar [$tag] $msg';
}

/// Полный журнал работы: всё пишется в память (для экрана «Журнал») и в файл
/// app.log в папке приложения (с ротацией). Пароли и токены маскируются.
class Log {
  static final List<LogLine> lines = [];
  static final ValueNotifier<int> version = ValueNotifier<int>(0);
  static final Set<String> _secrets = {};
  static RandomAccessFile? _file;
  static String? _path;
  static int _size = 0;
  static const int _maxMemory = 4000;
  static const int _maxFile = 3 * 1024 * 1024;
  static bool verbose = true;

  static Future<void> init(String dir) async {
    _path = '$dir/app.log';
    try {
      final f = File(_path!);
      _size = await f.exists() ? await f.length() : 0;
      _file = await f.open(mode: FileMode.append);
      _writeRaw('\n===== Запуск ${DateTime.now().toIso8601String()} =====\n');
    } catch (e) {
      _file = null;
      debugPrint('Log init failed: $e');
    }
  }

  static void addSecret(String? s) {
    if (s != null && s.length >= 3) _secrets.add(s);
  }

  static final RegExp _kv = RegExp(
      r'(password|passwd|pwd|pass|token|stok|secret|key)("?\s*[=:]\s*"?)([^&\s",;}]+)',
      caseSensitive: false);

  static String mask(String s) {
    var r = s;
    for (final x in _secrets) {
      r = r.replaceAll(x, '***');
    }
    r = r.replaceAllMapped(_kv, (m) => '${m[1]}${m[2]}***');
    return r;
  }

  static void d(String tag, String msg) {
    if (verbose) _add(LogLevel.debug, tag, msg);
  }

  static void i(String tag, String msg) => _add(LogLevel.info, tag, msg);

  static void w(String tag, String msg, [Object? err]) =>
      _add(LogLevel.warn, tag, err == null ? msg : '$msg — $err');

  static void e(String tag, String msg, [Object? err, StackTrace? st]) {
    final b = StringBuffer(msg);
    if (err != null) b.write(' — $err');
    if (st != null) {
      final s = st.toString().split('\n').take(12).join('\n    ');
      b.write('\n    $s');
    }
    _add(LogLevel.error, tag, b.toString());
  }

  static void _add(LogLevel level, String tag, String msg) {
    final line = LogLine(DateTime.now(), level, tag, mask(msg));
    lines.add(line);
    if (lines.length > _maxMemory) lines.removeRange(0, lines.length - _maxMemory);
    _writeRaw('${line.format()}\n');
    version.value++;
  }

  static void _writeRaw(String s) {
    final f = _file;
    if (f == null) return;
    try {
      f.writeStringSync(s);
      _size += s.length;
      if (_size > _maxFile) _rotate();
    } catch (_) {}
  }

  static void _rotate() {
    final p = _path;
    if (p == null) return;
    try {
      _file?.closeSync();
      final old = File('$p.1');
      if (old.existsSync()) old.deleteSync();
      File(p).renameSync('$p.1');
      _file = File(p).openSync(mode: FileMode.append);
      _size = 0;
    } catch (_) {}
  }

  /// Текст журнала целиком (предыдущий файл + текущий).
  static Future<String> fileText() async {
    final p = _path;
    if (p == null) return lines.map((l) => l.format()).join('\n');
    final b = StringBuffer();
    try {
      final old = File('$p.1');
      if (await old.exists()) b.write(await old.readAsString());
      final cur = File(p);
      if (await cur.exists()) b.write(await cur.readAsString());
    } catch (e) {
      b.write('\n(ошибка чтения журнала: $e)\n');
    }
    return b.toString();
  }

  static Future<void> clear() async {
    lines.clear();
    final p = _path;
    if (p != null) {
      try {
        _file?.closeSync();
        final old = File('$p.1');
        if (await old.exists()) await old.delete();
        await File(p).writeAsString('');
        _file = await File(p).open(mode: FileMode.append);
        _size = 0;
      } catch (_) {}
    }
    version.value++;
  }
}
