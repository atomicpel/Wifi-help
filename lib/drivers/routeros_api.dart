import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../core/log.dart';

class RosException implements Exception {
  RosException(this.message);
  final String message;
  @override
  String toString() => message;
}

class RosReply {
  RosReply(this.rows, this.done);
  final List<Map<String, String>> rows;
  final Map<String, String> done;
}

/// Клиент MikroTik RouterOS API (порт 8728) по официальному описанию
/// протокола: слова с префиксом длины, предложения до пустого слова.
class RosApi {
  RosApi._(this._socket, this._tag) : _it = StreamIterator<Uint8List>(_socket);

  final Socket _socket;
  final StreamIterator<Uint8List> _it;
  final String _tag;
  final List<int> _buf = [];
  int _pos = 0;

  static Future<RosApi> connect(String host, int port, {Duration timeout = const Duration(seconds: 5)}) async {
    final s = await Socket.connect(host, port, timeout: timeout);
    s.setOption(SocketOption.tcpNoDelay, true);
    return RosApi._(s, 'routeros $host');
  }

  Future<void> _need(int n) async {
    while (_buf.length - _pos < n) {
      if (_pos > 0 && _pos == _buf.length) {
        _buf.clear();
        _pos = 0;
      }
      final ok = await _it.moveNext().timeout(const Duration(seconds: 25));
      if (!ok) throw RosException('Роутер закрыл соединение');
      _buf.addAll(_it.current);
    }
  }

  Future<int> _byte() async {
    await _need(1);
    return _buf[_pos++];
  }

  Future<int> _readLen() async {
    final b = await _byte();
    if ((b & 0x80) == 0) return b;
    if ((b & 0xC0) == 0x80) {
      final b2 = await _byte();
      return ((b & 0x3F) << 8) | b2;
    }
    if ((b & 0xE0) == 0xC0) {
      final b2 = await _byte();
      final b3 = await _byte();
      return ((b & 0x1F) << 16) | (b2 << 8) | b3;
    }
    if ((b & 0xF0) == 0xE0) {
      final b2 = await _byte();
      final b3 = await _byte();
      final b4 = await _byte();
      return ((b & 0x0F) << 24) | (b2 << 16) | (b3 << 8) | b4;
    }
    if (b == 0xF0) {
      final b2 = await _byte();
      final b3 = await _byte();
      final b4 = await _byte();
      final b5 = await _byte();
      return (b2 << 24) | (b3 << 16) | (b4 << 8) | b5;
    }
    throw RosException('Неверная длина слова в ответе API');
  }

  static List<int> _encLen(int l) {
    if (l < 0x80) return [l];
    if (l < 0x4000) {
      final v = l | 0x8000;
      return [(v >> 8) & 0xFF, v & 0xFF];
    }
    if (l < 0x200000) {
      final v = l | 0xC00000;
      return [(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF];
    }
    if (l < 0x10000000) {
      final v = l | 0xE0000000;
      return [(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF];
    }
    return [0xF0, (l >> 24) & 0xFF, (l >> 16) & 0xFF, (l >> 8) & 0xFF, l & 0xFF];
  }

  Future<String> _readWord() async {
    final len = await _readLen();
    if (len == 0) return '';
    await _need(len);
    final bytes = _buf.sublist(_pos, _pos + len);
    _pos += len;
    return utf8.decode(bytes, allowMalformed: true);
  }

  Future<List<String>> _readSentence() async {
    final words = <String>[];
    while (true) {
      final w = await _readWord();
      if (w.isEmpty) return words;
      words.add(w);
    }
  }

  static Map<String, String> _attrs(Iterable<String> words) {
    final m = <String, String>{};
    for (final w in words) {
      if (w.startsWith('=')) {
        final i = w.indexOf('=', 1);
        if (i > 0) {
          m[w.substring(1, i)] = w.substring(i + 1);
        } else {
          m[w.substring(1)] = '';
        }
      } else if (w.startsWith('.tag=')) {
        m['.tag'] = w.substring(5);
      }
    }
    return m;
  }

  Future<RosReply> cmd(List<String> words) async {
    final sw = Stopwatch()..start();
    final bb = BytesBuilder();
    for (final w in words) {
      final e = utf8.encode(w);
      bb.add(_encLen(e.length));
      bb.add(e);
    }
    bb.addByte(0);
    _socket.add(bb.takeBytes());
    await _socket.flush();
    final shown = words.first == '/login' ? '/login' : words.join(' ');
    final rows = <Map<String, String>>[];
    String? trap;
    while (true) {
      final s = await _readSentence();
      if (s.isEmpty) continue;
      final type = s.first;
      final attrs = _attrs(s.skip(1));
      switch (type) {
        case '!re':
          rows.add(attrs);
        case '!trap':
          trap ??= attrs['message'] ?? 'ошибка';
        case '!fatal':
          final msg = s.length > 1 ? s[1] : 'fatal';
          Log.w(_tag, '$shown → FATAL $msg');
          throw RosException(msg);
        case '!done':
          if (trap != null) {
            Log.d(_tag, '$shown → ошибка «$trap» (${sw.elapsedMilliseconds} мс)');
            throw RosException(trap);
          }
          Log.d(_tag, '$shown → ${rows.length} строк (${sw.elapsedMilliseconds} мс)');
          return RosReply(rows, attrs);
        default:
          break;
      }
    }
  }

  Future<void> login(String user, String password) async {
    await cmd(['/login', '=name=$user', '=password=$password']);
  }

  Future<void> close() async {
    try {
      await _it.cancel();
    } catch (_) {}
    _socket.destroy();
  }
}
