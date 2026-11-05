import 'dart:convert';
import 'dart:io';

import 'log.dart';
import 'models.dart';
import 'native.dart';

/// Логины и пароли роутеров. Хранятся зашифрованными ключом из Android
/// Keystore (ключ не покидает телефон), в файле vault.bin.
class Vault {
  final Map<String, Credential> _byIp = {};
  String _path = '';
  String? loadError;

  Map<String, Credential> get all => Map.unmodifiable(_byIp);

  /// Подсказка: какой производитель сейчас на этом адресе (ставит AppState).
  String? Function(String ip)? vendorOf;

  Credential? get(String ip) {
    final c = _byIp[ip];
    if (c == null || c.vendor == null || vendorOf == null) return c;
    final now = vendorOf!(ip);
    if (now == null || now == 'unknown' || now == c.vendor) return c;
    return null; // пароль от другого роутера, который раньше был на этом IP
  }

  /// Сохранён ли пароль хоть какой-то (даже от другого роутера).
  Credential? raw(String ip) => _byIp[ip];

  Future<void> load(String dir) async {
    _path = '$dir/vault.bin';
    final f = File(_path);
    if (!await f.exists()) {
      Log.i('vault', 'Хранилище паролей пустое');
      return;
    }
    try {
      final enc = (await f.readAsString()).trim();
      final text = await Native.decrypt(enc);
      if (text.isEmpty) return;
      final m = jsonDecode(text) as Map<String, dynamic>;
      m.forEach((ip, v) {
        final c = Credential.fromJson(Map<String, dynamic>.from(v as Map));
        _byIp[ip] = c;
        Log.addSecret(c.password);
      });
      Log.i('vault', 'Загружено учётных записей: ${_byIp.length}');
    } catch (e, st) {
      loadError = '$e';
      Log.e('vault', 'Не удалось расшифровать хранилище паролей', e, st);
    }
  }

  Future<void> _save() async {
    final text = jsonEncode(_byIp.map((k, v) => MapEntry(k, v.toJson())));
    final enc = await Native.encrypt(text);
    await File(_path).writeAsString(enc, flush: true);
  }

  Future<void> set(String ip, Credential c) async {
    Log.addSecret(c.password);
    _byIp[ip] = c;
    await _save();
    Log.i('vault', 'Сохранён логин для $ip (пользователь ${c.login})');
  }

  Future<void> remove(String ip) async {
    _byIp.remove(ip);
    await _save();
    Log.i('vault', 'Удалён логин для $ip');
  }
}
