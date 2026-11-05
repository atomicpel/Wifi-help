import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Криптография протокола TP-Link /cgi_gdpr (Archer C50, TL-WR841N v14 и
/// родственные): RSA-512 для подписи и AES-128-CBC (PKCS7) для данных.
class TplinkCrypto {
  static final Random _rnd = Random.secure();

  /// 16-символьный ключ/IV из цифр, как делает веб-интерфейс.
  static String aesParam() {
    final ts = DateTime.now().millisecondsSinceEpoch.toString();
    final r = (100000000 + _rnd.nextInt(899999999)).toString();
    return (ts + r).substring(0, 16);
  }

  static String aesEncrypt(String text, String key, String iv) {
    final c = PaddedBlockCipherImpl(PKCS7Padding(), CBCBlockCipher(AESEngine()));
    c.init(
      true,
      PaddedBlockCipherParameters<CipherParameters?, CipherParameters?>(
        ParametersWithIV<KeyParameter>(KeyParameter(Uint8List.fromList(utf8.encode(key))), Uint8List.fromList(utf8.encode(iv))),
        null,
      ),
    );
    return base64.encode(c.process(Uint8List.fromList(utf8.encode(text))));
  }

  static String aesDecrypt(String b64, String key, String iv) {
    final c = PaddedBlockCipherImpl(PKCS7Padding(), CBCBlockCipher(AESEngine()));
    c.init(
      false,
      PaddedBlockCipherParameters<CipherParameters?, CipherParameters?>(
        ParametersWithIV<KeyParameter>(KeyParameter(Uint8List.fromList(utf8.encode(key))), Uint8List.fromList(utf8.encode(iv))),
        null,
      ),
    );
    return utf8.decode(c.process(base64.decode(b64.trim())), allowMalformed: true);
  }

  static BigInt _toInt(List<int> bytes) {
    var r = BigInt.zero;
    for (final b in bytes) {
      r = (r << 8) | BigInt.from(b);
    }
    return r;
  }

  static String _hex(BigInt v, int bytes) => v.toRadixString(16).padLeft(bytes * 2, '0');

  /// RSA PKCS#1 v1.5 (flag=1 в tpEncrypt.js): блоки по 53 байта.
  static String rsaPkcs1(String data, String nn, String ee) {
    final n = BigInt.parse(nn, radix: 16);
    final e = BigInt.parse(ee, radix: 16);
    final k = (n.bitLength + 7) ~/ 8;
    final out = StringBuffer();
    final msg = utf8.encode(data);
    final chunk = k - 11;
    for (var i = 0; i < msg.length; i += chunk) {
      final m = msg.sublist(i, min(i + chunk, msg.length));
      final ps = List<int>.generate(k - 3 - m.length, (_) => 1 + _rnd.nextInt(255));
      final em = <int>[0, 2, ...ps, 0, ...m];
      out.write(_hex(_toInt(em).modPow(e, n), k));
    }
    return out.toString();
  }

  /// «Сырой» RSA без паддинга (flag=0, TL-WR841N v14): блоки по 64 байта,
  /// данные выравниваются влево и добиваются нулями.
  static String rsaRaw(String data, String nn, String ee) {
    final n = BigInt.parse(nn, radix: 16);
    final e = BigInt.parse(ee, radix: 16);
    final k = (n.bitLength + 7) ~/ 8;
    final out = StringBuffer();
    final msg = utf8.encode(data);
    for (var i = 0; i < msg.length; i += k) {
      final m = msg.sublist(i, min(i + k, msg.length));
      final em = [...m, ...List<int>.filled(k - m.length, 0)];
      out.write(_hex(_toInt(em).modPow(e, n), k));
    }
    return out.toString();
  }
}
