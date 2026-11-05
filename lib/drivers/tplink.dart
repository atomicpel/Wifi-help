import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../core/ip.dart';
import '../core/log.dart';
import '../core/models.dart';
import '../core/util.dart';
import 'driver.dart';
import 'tplink_crypto.dart';

class _Resp {
  _Resp(this.status, this.body, this.location);
  final int status;
  final String body;
  final String? location;
}

/// TP-Link. Схема определяется сама:
///  • legacy — TL-WR740/840/841/845 старых ревизий: cookie
///    «Authorization: Basic base64(логин:md5(пароль))», затем
///    /userRpm/LoginRpm.htm?Save=Save отдаёт токен сессии, и все страницы
///    идут по /ТОКЕН/userRpm/… Данные — в JS-массивах. Важно: у этих
///    роутеров одно место для администратора, поэтому всегда выходим.
///  • gdpr — Archer C50/C20, TL-WR841N v14 и родня: /cgi/getParm даёт
///    RSA-512, данные идут в /cgi_gdpr, зашифрованные AES-128-CBC.
///  • прочие (Archer с /cgi-bin/luci;stok, Deco) — пока веб-интерфейс.
class TplinkDriver extends RouterDriver {
  TplinkDriver(super.host, super.cred);

  @override
  Vendor get vendor => Vendor.tplink;
  @override
  bool get canChangePassword => false;
  @override
  bool get canSetChannel => false;

  final HttpClient _client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 5)
    ..badCertificateCallback = ((X509Certificate c, String h, int p) => true);
  final Map<String, String> _cookies = {};
  String _scheme = 'unknown';
  String _base = '';
  bool _loggedIn = false;

  // legacy
  String _token = '';
  // cgi (0.9.1)
  String _cgiToken = '';
  // gdpr
  String _nn = '';
  String _ee = '';
  int _seq = 0;
  String _aesKey = '';
  String _aesIv = '';
  bool _rawRsa = false;

  String get _tag => 'tplink $host';
  String get scheme => _scheme;

  static const _ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0';

  Future<_Resp> _req(String method, String url, {String? body, Map<String, String>? headers, bool log = true}) async {
    final sw = Stopwatch()..start();
    final req = await _client.openUrl(method, Uri.parse(url)).timeout(const Duration(seconds: 8));
    req.followRedirects = false;
    req.headers.set(HttpHeaders.userAgentHeader, _ua);
    if (_cookies.isNotEmpty) {
      req.headers.set(HttpHeaders.cookieHeader, _cookies.entries.map((e) => '${e.key}=${e.value}').join('; '));
    }
    headers?.forEach(req.headers.set);
    if (body != null) {
      final b = utf8.encode(body);
      req.headers.set(HttpHeaders.contentTypeHeader, 'text/plain');
      req.contentLength = b.length;
      req.add(b);
    }
    final resp = await req.close().timeout(const Duration(seconds: 15));
    for (final sc in resp.headers[HttpHeaders.setCookieHeader] ?? const <String>[]) {
      final first = sc.split(';').first;
      final i = first.indexOf('=');
      if (i > 0) _cookies[first.substring(0, i).trim()] = first.substring(i + 1).trim();
    }
    final text = await resp.transform(const Utf8Decoder(allowMalformed: true)).join().timeout(const Duration(seconds: 20));
    final loc = resp.headers.value(HttpHeaders.locationHeader);
    if (log) {
      Log.d(_tag, '$method ${Uri.parse(url).path}${Uri.parse(url).query.isNotEmpty ? '?…' : ''} → ${resp.statusCode}, '
          '${text.length} б, ${sw.elapsedMilliseconds} мс${loc != null ? ' → $loc' : ''}');
    }
    return _Resp(resp.statusCode, text, loc);
  }

  Future<bool> _portOpen(int port) async {
    try {
      final s = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
      s.destroy();
      return true;
    } catch (_) {
      return false;
    }
  }

  // ------------------------------------------------------------ detection
  Future<void> _detect() async {
    final https = !await _portOpen(80) && await _portOpen(443);
    _base = https ? 'https://$host' : 'http://$host';
    final home = await _req('GET', '$_base/', headers: {'Accept': 'text/html,*/*', 'Referer': '$_base/'});
    final low = home.body.toLowerCase();
    if (low.contains('deco')) {
      _scheme = 'deco';
    } else if (low.contains('encrypt.js') || low.contains('tpencrypt') || low.contains('cgi_gdpr') || low.contains('oid_str.js') && low.contains('pc-login')) {
      final p = await _req('POST', '$_base/cgi/getParm', headers: {'Referer': '$_base/', 'Accept': '*/*'});
      final nn = RegExp(r'var nn="([0-9a-fA-F]+)"').firstMatch(p.body)?.group(1);
      final ee = RegExp(r'var ee="([0-9a-fA-F]+)"').firstMatch(p.body)?.group(1);
      final seq = RegExp(r'var seq="(\d+)"').firstMatch(p.body)?.group(1);
      if (nn != null && ee != null && seq != null) {
        _scheme = 'gdpr';
        _nn = nn;
        _ee = ee;
        _seq = int.parse(seq);
        // какой RSA: смотрим, как веб-страница вызывает $.rsa.encrypt(..., flag)
        _rawRsa = await _detectRawRsa(home.body);
      } else if (low.contains('luci') || low.contains('stok')) {
        _scheme = 'luci';
      } else {
        _scheme = 'modern-unknown';
      }
    } else if (low.contains('userrpm') || low.contains('loginrpm')) {
      _scheme = 'legacy';
    } else {
      // 0.9.1-прошивки (TL-WR840N v4/v5, TL-WR845N v4…): cookie + TokenID + /cgi?
      _scheme = 'cgi';
    }
    Log.i(_tag, 'Схема входа: «$_scheme»${_scheme == 'gdpr' ? ' (RSA ${_rawRsa ? 'без паддинга' : 'PKCS#1'}, ключ ${_nn.length * 4} бит)' : ''}');
  }

  Future<bool> _detectRawRsa(String homeBody) async {
    final srcs = RegExp(r'''<script[^>]+src=["']([^"']+)["']''', caseSensitive: false)
        .allMatches(homeBody)
        .map((m) => m.group(1)!)
        .where((s) => s.contains('ncrypt') || s.contains('lib') || s.contains('login'))
        .toList();
    for (final s in srcs) {
      final path = s.replaceFirst(RegExp(r'^(\.\./|\./)+'), '/');
      try {
        final r = await _req('GET', path.startsWith('http') ? path : '$_base${path.startsWith('/') ? '' : '/'}$path', log: false);
        final m = RegExp(r'rsa\.encrypt\([^)]*?,\s*\d+\s*,\s*([01])\s*\)').firstMatch(r.body);
        if (m != null) return m.group(1) == '0';
      } catch (_) {}
    }
    return false;
  }

  // --------------------------------------------------------------- login
  @override
  Future<void> login() async {
    await _detect();
    switch (_scheme) {
      case 'cgi':
        await _cgiLogin();
      case 'legacy':
        await _legacyLogin();
      case 'gdpr':
        await _gdprLogin();
      case 'deco':
        throw DriverException('TP-Link Deco: отдельное API, пока не поддержано. Управляй через приложение Deco.');
      case 'luci':
        throw DriverException('TP-Link Archer (вход через luci/stok): этот вариант пока не поддержан. '
            'Нажми «Разведка для журнала» и пришли журнал.');
      default:
        throw DriverException('TP-Link: не распознал вариант прошивки. Нажми «Разведка для журнала».');
    }
    _loggedIn = true;
  }

  // ---- cgi (0.9.1: TL-WR840N v4, TL-WR845N v4 и т.п.)
  Future<bool> _cgiTokenFromHome() async {
    final r = await _req('GET', '$_base/', headers: {'Referer': '$_base/', 'Accept': 'text/html,*/*'});
    final t = RegExp(r'var\s+token\s*=\s*"([^"]+)"').firstMatch(r.body)?.group(1);
    if (t != null && t.isNotEmpty) {
      _cgiToken = t;
      return true;
    }
    final low = r.body.toLowerCase();
    if (low.contains('only one') || low.contains('одно подключ')) _busy = true;
    return false;
  }

  bool _busy = false;

  Future<void> _cgiLogin() async {
    _busy = false;
    final b64plain = base64.encode(utf8.encode('${cred.login}:${cred.password}'));
    final md5hex = md5.convert(utf8.encode(cred.password)).toString();
    final b64md5 = base64.encode(utf8.encode('${cred.login}:$md5hex'));
    final variants = <(String, String)>[
      ('Basic $b64plain', 'cookie base64(логин:пароль)'),
      ('Basic $b64md5', 'cookie base64(логин:md5)'),
    ];
    for (final v in variants) {
      _cookies
        ..clear()
        ..['Authorization'] = v.$1;
      if (await _cgiTokenFromHome()) {
        Log.i(_tag, 'Вход (${v.$2}) выполнен, TokenID получен');
        return;
      }
      if (_busy) break;
    }
    // вариант MR200: RSA-вход через /cgi/login
    if (!_busy) {
      _cookies.clear();
      final p = await _req('GET', '$_base/cgi/getParm', headers: {'Referer': '$_base/'});
      final nn = RegExp(r'var nn="([0-9a-fA-F]+)"').firstMatch(p.body)?.group(1);
      final ee = RegExp(r'var ee="([0-9a-fA-F]+)"').firstMatch(p.body)?.group(1);
      if (nn != null && ee != null) {
        final u = TplinkCrypto.rsaPkcs1(cred.login, nn, ee);
        final pw = TplinkCrypto.rsaPkcs1(base64.encode(utf8.encode(cred.password)), nn, ee);
        await _req('POST', '$_base/cgi/login?UserName=$u&Passwd=$pw&Action=1&LoginStatus=0', headers: {'Referer': '$_base/'});
        if (await _cgiTokenFromHome()) {
          Log.i(_tag, 'Вход (RSA /cgi/login) выполнен, TokenID получен');
          return;
        }
      }
    }
    // последняя попытка — старая схема userRpm
    if (!_busy) {
      try {
        await _legacyLogin();
        _scheme = 'legacy';
        return;
      } catch (_) {}
    }
    await _dumpLoginJs();
    throw DriverException(_busy
        ? 'TP-Link: к роутеру уже подключён другой администратор (браузер или «Веб-интерфейс» в программе). '
            'Закрой его и подожди ~5 минут — роутер пускает только одного.'
        : 'TP-Link: ни один вариант входа не подошёл. Проверь пароль; если верный — пришли «Отчёт», '
            'я записал в журнал код входа этой прошивки.');
  }

  /// Пишет в журнал фрагменты lib.js/login-скриптов, отвечающие за вход.
  Future<void> _dumpLoginJs() async {
    final home = await _req('GET', '$_base/', log: false);
    final srcs = RegExp(r'''<script[^>]+src=["']([^"']+)["']''', caseSensitive: false)
        .allMatches(home.body)
        .map((m) => m.group(1)!)
        .toList();
    final inline = RegExp(r'<script[^>]*>([\s\S]*?)</script>', caseSensitive: false)
        .allMatches(home.body)
        .map((m) => m.group(1)!)
        .join('\n');
    final texts = <String, String>{'(страница)': inline};
    for (final s0 in srcs.take(8)) {
      final path = s0.replaceFirst(RegExp(r'^(\.\./|\./)+'), '/');
      try {
        final r = await _req('GET', '$_base${path.startsWith('/') ? '' : '/'}$path', log: false);
        texts[path] = r.body;
      } catch (_) {}
    }
    texts.forEach((name, body) {
      for (final key in ['Authorization', 'token', 'cgi/login', 'Base64', 'PCSubWin', 'getParm', 'rsa.encrypt']) {
        var from = 0;
        var n = 0;
        while (n < 3) {
          final i = body.indexOf(key, from);
          if (i < 0) break;
          final a = i - 200 < 0 ? 0 : i - 200;
          final b = i + 300 > body.length ? body.length : i + 300;
          Log.i(_tag, 'код входа [$name, «$key»]: ${body.substring(a, b).replaceAll(RegExp(r'\s+'), ' ')}');
          from = i + key.length;
          n++;
        }
      }
    });
  }

  // ---- legacy (TL-WR8xx)
  String _escape(String s) => s.replaceAll('%', '%25').replaceAll(' ', '%20').replaceAll('=', '%3D').replaceAll('+', '%2B');

  String get _legacyReferer => '$_base/$_token/userRpm/MenuRpm.htm';

  bool _isReauth(String doc) {
    final m = RegExp(r'<script[^>]*>([\s\S]*?)</script>', caseSensitive: false).firstMatch(doc);
    final first = m?.group(1) ?? doc;
    return first.contains('cookie="Authorization=;path=/"') || first.contains("cookie='Authorization=;path=/'");
  }

  Future<void> _legacyLogin() async {
    final md5hex = md5.convert(utf8.encode(cred.password)).toString();
    final b64 = base64.encode(utf8.encode('${cred.login}:$md5hex'));
    String? busyText;
    for (final escaped in [false, true]) {
      _cookies
        ..clear()
        ..['Authorization'] = escaped ? _escape('Basic $b64') : 'Basic $b64';
      final r = await _req('GET', '$_base/userRpm/LoginRpm.htm?Save=Save', headers: {'Referer': '$_base/'});
      final m = RegExp('${RegExp.escape(host)}/(\\w+)/').firstMatch(r.body);
      if (m == null) {
        final low = r.body.toLowerCase();
        if (low.contains('only one') || low.contains('одно подключ') || low.contains('httpautherrorcode') && low.contains('7')) {
          busyText = 'роутер занят другим админ-входом';
        }
        final flat = r.body.replaceAll(RegExp(r'\s+'), ' ');
        Log.d(_tag, 'LoginRpm без токена (cookie ${escaped ? 'escaped' : 'raw'}): '
            '${flat.length > 300 ? flat.substring(0, 300) : flat}');
        continue;
      }
      _token = m.group(1)!;
      final idx = await _req('GET', '$_base/$_token/userRpm/Index.htm', headers: {'Referer': '$_base/'});
      if (idx.status == 200 && !_isReauth(idx.body)) {
        Log.i(_tag, 'Вход (legacy, токен сессии) выполнен');
        return;
      }
    }
    throw DriverException(busyText != null
        ? 'TP-Link: к роутеру уже подключён другой администратор (браузер или телефон). '
            'Закрой его веб-интерфейс или подожди ~5 минут и повтори.'
        : 'TP-Link (TL-WR): вход не прошёл — проверь логин/пароль. '
            'Если в браузере открыт веб-интерфейс этого роутера — закрой его (роутер пускает только одного админа).');
  }

  Future<String> _legacyPage(String name) async {
    final r = await _req('GET', '$_base/$_token/userRpm/$name.htm', headers: {'Referer': _legacyReferer});
    if (r.status != 200 || _isReauth(r.body)) throw DriverException('TP-Link: страница $name недоступна (${r.status})');
    return r.body;
  }

  /// Значения JS-массива `var name = new Array(...)`.
  static List<dynamic>? jsArray(String doc, String name) {
    final m = RegExp('var\\s+$name\\s*=\\s*new\\s+Array\\s*\\(').firstMatch(doc);
    if (m == null) return null;
    final out = <dynamic>[];
    var i = m.end;
    while (i < doc.length) {
      final c = doc[i];
      if (c == ')') break;
      if (c == ',' || c.trim().isEmpty) {
        i++;
        continue;
      }
      if (c == '"' || c == "'") {
        final q = c;
        final sb = StringBuffer();
        i++;
        while (i < doc.length && doc[i] != q) {
          if (doc[i] == '\\' && i + 1 < doc.length) i++;
          sb.write(doc[i]);
          i++;
        }
        i++;
        out.add(sb.toString());
        continue;
      }
      final start = i;
      while (i < doc.length && doc[i] != ',' && doc[i] != ')') {
        i++;
      }
      final raw = doc.substring(start, i).trim();
      out.add(int.tryParse(raw) ?? raw);
    }
    return out;
  }

  static int _n(dynamic v) => v is int ? v : (int.tryParse('$v'.trim()) ?? 0);

  Future<RouterInfo> _legacyCollect() async {
    final info = RouterInfo();
    final st = await _legacyPage('StatusRpm');
    final status = jsArray(st, 'statusPara') ?? const [];
    final lan = jsArray(st, 'lanPara') ?? const [];
    final wlan = jsArray(st, 'wlanPara') ?? const [];
    final wan = jsArray(st, 'wanPara') ?? const [];
    Log.d(_tag, 'StatusRpm: statusPara=$status | lanPara=$lan | wlanPara=$wlan | wanPara=$wan');

    if (status.length > 6) {
      info.firmware = '${status[5]}'.trim();
      info.model = '${status[6]}'.trim().split(RegExp(r'\s+')).take(2).join(' ');
    }
    if (lan.length >= 3) {
      final ip = '${lan[1]}';
      if (Ip.parse(ip) != null) info.addrs.add(IfAddr('lan', ip, Ip.prefixFromMask('${lan[2]}')));
    } else {
      info.addrs.add(IfAddr('lan', host, 24));
    }
    if (status.length > 2 && wan.isNotEmpty) {
      final count = _n(status[1]);
      final per = _n(status[2]);
      for (var k = 0; k < count && per >= 8 && (k + 1) * per <= wan.length; k++) {
        final b = k * per;
        final ip = '${wan[b + 2]}';
        final mask = '${wan[b + 4]}';
        final gw = '${wan[b + 7]}';
        if (Ip.parse(ip) != null && ip != '0.0.0.0') info.addrs.add(IfAddr('wan', ip, Ip.prefixFromMask(mask)));
        if (Ip.parse(gw) != null && gw != '0.0.0.0') {
          info.gateway ??= gw;
        }
      }
      info.nat = _n(status.length > 7 ? status[7] : 1) != 4; // 4 = режим точки доступа
    }
    if (wlan.length > 9 && (status.isEmpty || _n(status[0]) != 0)) {
      final manual = _n(wlan[2]);
      final auto = _n(wlan[9]);
      final ch = manual == 15 || manual == 0 ? auto : manual;
      final width = switch (_n(wlan[6])) { 1 => '20MHz', 3 => '40MHz', 2 => 'auto', _ => null };
      info.radios.add(RadioInfo(
        id: 'wlan0',
        name: 'Wi-Fi 2,4 ГГц',
        band: '2.4',
        channel: ch > 0 ? ch : null,
        width: width,
        ssid: '${wlan[1]}',
        enabled: _n(wlan[0]) == 1,
        mac: normMac('${wlan[4]}'),
        autoChannel: manual == 15 || manual == 0,
      ));
    }

    try {
      final dh = await _legacyPage('AssignedIpAddrListRpm');
      final para = jsArray(dh, 'DHCPDynPara') ?? const [];
      final list = jsArray(dh, 'DHCPDynList') ?? const [];
      final per = para.length > 1 ? _n(para[1]) : 4;
      for (var i = 0; i + 2 < list.length && per >= 3; i += per) {
        final ip = Ip.extract('${list[i + 2]}');
        if (ip != null) info.arp.add(ArpEntry(ip, normMac('${list[i + 1]}'), 'lan'));
      }
    } catch (e) {
      Log.w(_tag, 'Список DHCP не прочитан', e);
    }
    try {
      final lanCfg = await _legacyPage('LanDhcpServerRpm');
      final p = jsArray(lanCfg, 'DHCPPara') ?? const [];
      if (p.isNotEmpty) {
        info.dhcp.add(DhcpServerInfo('lan', 'DHCP', 'lan', _n(p[0]) == 1,
            range: p.length > 2 ? '${p[1]}–${p[2]}' : null));
      }
    } catch (_) {}
    return info;
  }

  Future<void> _legacyLogout() async {
    if (_token.isEmpty) return;
    try {
      await _req('GET', '$_base/$_token/userRpm/LogoutRpm.htm', headers: {'Referer': _legacyReferer});
      Log.d(_tag, 'Выход выполнен');
    } catch (_) {}
  }

  // ---- gdpr (Archer C50/C20, WR841N v14)
  String get _hash => md5.convert(utf8.encode('${cred.login}${cred.password}')).toString();

  String _sign(String s) => _rawRsa ? TplinkCrypto.rsaRaw(s, _nn, _ee) : TplinkCrypto.rsaPkcs1(s, _nn, _ee);

  Map<String, String> get _gdprHeaders => {'Accept': '*/*', 'Referer': '$_base/'};

  Future<void> _gdprLogin() async {
    for (var attempt = 0; attempt < 2; attempt++) {
      _aesKey = TplinkCrypto.aesParam();
      await Future<void>.delayed(const Duration(milliseconds: 3));
      _aesIv = TplinkCrypto.aesParam();
      final plain = '8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=${cred.login}\r\npassword=${cred.password}\r\n';
      final enc = TplinkCrypto.aesEncrypt(plain, _aesKey, _aesIv);
      final sign = _sign('key=$_aesKey&iv=$_aesIv&h=$_hash&s=${_seq + enc.length}');
      final r = await _req('POST', '$_base/cgi_gdpr', body: 'sign=$sign\r\ndata=$enc\r\n', headers: _gdprHeaders);
      String dec = '';
      if (r.status == 200 && r.body.trim().isNotEmpty) {
        try {
          dec = TplinkCrypto.aesDecrypt(r.body, _aesKey, _aesIv);
        } catch (e) {
          Log.d(_tag, 'Ответ входа не расшифровался: $e');
        }
      }
      Log.d(_tag, 'вход cgi_gdpr (RSA ${_rawRsa ? 'raw' : 'pkcs1'}) → HTTP ${r.status}, ответ: ${dec.replaceAll('\r\n', ' ')}');
      if (dec.contains(r'$.ret=0')) {
        await _req('GET', '$_base/', headers: {'Accept': 'text/html,*/*', 'Referer': '$_base/'});
        Log.i(_tag, 'Вход (cgi_gdpr) выполнен');
        return;
      }
      final code = RegExp(r'\$\.ret=(\d+)').firstMatch(dec)?.group(1);
      if (code == '71233') throw DriverException('TP-Link: неверный логин или пароль.');
      if (code == '71234') throw DriverException('TP-Link: роутер временно заблокировал вход после ошибок — подожди несколько минут.');
      // не тот вариант RSA — пробуем другой, с новым ключом
      _rawRsa = !_rawRsa;
      final p = await _req('POST', '$_base/cgi/getParm', headers: _gdprHeaders);
      final seq = RegExp(r'var seq="(\d+)"').firstMatch(p.body)?.group(1);
      if (seq != null) _seq = int.parse(seq);
    }
    throw DriverException('TP-Link (cgi_gdpr): вход не прошёл. Если в браузере открыт веб-интерфейс этого роутера — закрой его и повтори.');
  }

  Future<Map<String, List<Map<String, String>>>> _act(List<(int, String, String, List<String>)> acts) async {
    final types = acts.map((a) => '${a.$1}').join('&');
    final sb = StringBuffer();
    for (var i = 0; i < acts.length; i++) {
      final a = acts[i];
      sb.write('[${a.$2}#${a.$3}#0,0,0,0,0,0]$i,${a.$4.length}\r\n${a.$4.join('\r\n')}\r\n');
    }
    if (_scheme == 'cgi') {
      final r = await _req('POST', '$_base/cgi?$types', body: sb.toString(),
          headers: {'Referer': '$_base/', 'TokenID': _cgiToken, 'Accept': '*/*'});
      if (r.status != 200) throw DriverException('TP-Link: запрос данных → HTTP ${r.status}');
      return _parseActs(r.body);
    }
    final data = '$types\r\n$sb';
    final enc = TplinkCrypto.aesEncrypt(data, _aesKey, _aesIv);
    final sign = _sign('h=$_hash&s=${_seq + enc.length}');
    _Resp r = _Resp(0, '', null);
    for (var t = 0; t < 3; t++) {
      r = await _req('POST', '$_base/cgi_gdpr', body: 'sign=$sign\r\ndata=$enc\r\n', headers: _gdprHeaders);
      if (r.status != 500 && r.status != 406) break;
      await Future<void>.delayed(const Duration(milliseconds: 500));
    }
    if (r.status != 200) throw DriverException('TP-Link: запрос данных → HTTP ${r.status}');
    return _parseActs(TplinkCrypto.aesDecrypt(r.body, _aesKey, _aesIv));
  }

  Map<String, List<Map<String, String>>> _parseActs(String dec) {
    Log.d(_tag, 'cgi ← ${dec.length > 900 ? '${dec.substring(0, 900)}…' : dec}'.replaceAll('\r\n', ' | ').replaceAll('\n', ' | '));
    final res = <String, List<Map<String, String>>>{};
    Map<String, String>? obj;
    for (final line in dec.split('\n')) {
      final l = line.trimRight();
      final h = RegExp(r'^\[\d+,\d+,\d+,\d+,\d+,\d+\](\d+)').firstMatch(l);
      if (h != null) {
        obj = {};
        res.putIfAbsent(h.group(1)!, () => []).add(obj);
        continue;
      }
      final eq = l.indexOf('=');
      if (obj != null && eq > 0 && !l.startsWith(r'$.')) obj[l.substring(0, eq)] = l.substring(eq + 1);
    }
    return res;
  }

  static String? _v(Map<String, String> m, String key) {
    for (final e in m.entries) {
      if (e.key.toLowerCase() == key.toLowerCase()) return e.value;
    }
    return null;
  }

  Future<RouterInfo> _gdprCollect() async {
    final info = RouterInfo();
    try {
      final dev = await _act([(1, 'IGD_DEV_INFO', '0,0,0,0,0,0', ['hardwareVersion', 'modelName', 'softwareVersion'])]);
      final d = dev['0']?.firstOrNull ?? {};
      info.model = _v(d, 'modelName') ?? '';
      info.firmware = _v(d, 'softwareVersion') ?? '';
    } catch (e) {
      Log.w(_tag, 'Модель не прочитана', e);
    }

    final net = await _act([
      (6, 'LAN_IP_INTF', '0,0,0,0,0,0', ['X_TP_MACAddress', 'IPInterfaceIPAddress', 'IPInterfaceSubnetMask']),
      (1, 'LAN_HOST_CFG', '1,0,0,0,0,0', ['DHCPServerEnable', 'minAddress', 'maxAddress']),
      (6, 'WAN_IP_CONN', '0,0,0,0,0,0', ['enable', 'externalIPAddress', 'defaultGateway', 'subnetMask', 'name', 'NATEnabled']),
    ]);
    for (final l in net['0'] ?? const <Map<String, String>>[]) {
      final ip = _v(l, 'IPInterfaceIPAddress');
      if (ip != null && Ip.parse(ip) != null && ip != '0.0.0.0') {
        info.addrs.add(IfAddr('lan', ip, Ip.prefixFromMask(_v(l, 'IPInterfaceSubnetMask'))));
      }
    }
    if (info.addrs.isEmpty) info.addrs.add(IfAddr('lan', host, 24));
    final hc = net['1']?.firstOrNull;
    if (hc != null) {
      final min = _v(hc, 'minAddress');
      info.dhcp.add(DhcpServerInfo('lan', 'DHCP', 'lan', _v(hc, 'DHCPServerEnable') == '1',
          range: min != null ? '$min–${_v(hc, 'maxAddress') ?? ''}' : null));
    }
    for (final w in net['2'] ?? const <Map<String, String>>[]) {
      final ip = _v(w, 'externalIPAddress');
      final gw = _v(w, 'defaultGateway');
      final on = _v(w, 'enable') != '0';
      if (!on && (net['2']?.length ?? 0) > 1) continue;
      if (ip != null && Ip.parse(ip) != null && ip != '0.0.0.0') {
        info.addrs.add(IfAddr('wan', ip, Ip.prefixFromMask(_v(w, 'subnetMask'))));
      }
      if (gw != null && Ip.parse(gw) != null && gw != '0.0.0.0') info.gateway ??= gw;
      final nat = _v(w, 'NATEnabled');
      if (nat != null) info.nat = nat == '1';
    }
    info.nat ??= info.gateway != null;

    try {
      final hosts = await _act([(5, 'LAN_HOST_ENTRY', '0,0,0,0,0,0', ['IPAddress', 'MACAddress', 'hostName'])]);
      for (final h in hosts['0'] ?? const <Map<String, String>>[]) {
        final ip = Ip.extract(_v(h, 'IPAddress'));
        final mac = _v(h, 'MACAddress');
        if (ip != null && mac != null) info.arp.add(ArpEntry(ip, normMac(mac), 'lan'));
      }
    } catch (e) {
      Log.w(_tag, 'Клиенты не прочитаны', e);
    }
    try {
      final wl = await _act([(5, 'LAN_WLAN', '0,0,0,0,0,0', ['enable', 'SSID', 'channel', 'autoChannelEnable', 'X_TP_Band', 'X_TP_Bandwidth'])]);
      var n = 0;
      for (final w in wl['0'] ?? const <Map<String, String>>[]) {
        final bandRaw = (_v(w, 'X_TP_Band') ?? '').toLowerCase();
        final ch = int.tryParse(_v(w, 'channel') ?? '');
        final band = bandRaw.contains('5') ? '5' : (ch != null && ch > 14 ? '5' : '2.4');
        info.radios.add(RadioInfo(
          id: 'wlan${n++}',
          name: band == '5' ? 'Wi-Fi 5 ГГц' : 'Wi-Fi 2,4 ГГц',
          band: band,
          channel: ch == 0 ? null : ch,
          width: _v(w, 'X_TP_Bandwidth'),
          ssid: _v(w, 'SSID'),
          enabled: _v(w, 'enable') != '0',
          autoChannel: _v(w, 'autoChannelEnable') == '1' || ch == 0,
        ));
      }
    } catch (e) {
      Log.w(_tag, 'Wi-Fi не прочитан', e);
    }
    return info;
  }

  Future<void> _gdprLogout() async {
    try {
      await _act([(8, '/cgi/logout', '0,0,0,0,0,0', const [])]);
      Log.d(_tag, 'Выход выполнен');
    } catch (_) {}
  }

  // ---------------------------------------------------------------- api
  @override
  Future<RouterInfo> collect() async {
    if (!_loggedIn) await login();
    final info = (_scheme == 'gdpr' || _scheme == 'cgi') ? await _gdprCollect() : await _legacyCollect();
    Log.i(_tag, 'Опрос ($_scheme): ${info.model} ${info.firmware}, шлюз вверх ${info.gateway ?? 'нет'}, '
        'NAT ${info.nat}, DHCP ${info.dhcp.map((d) => d.enabled ? 'вкл' : 'выкл').join(',')}, '
        'Wi-Fi ${info.radios.map((r) => '${r.ssid} ch${r.channel}').join(',')}, клиентов ${info.arp.length}');
    return info;
  }

  @override
  Future<BackupData> backup() async {
    if (!_loggedIn) await login();
    final info = (_scheme == 'gdpr' || _scheme == 'cgi') ? await _gdprCollect() : await _legacyCollect();
    final content = StringBuffer()
      ..writeln('# TP-Link $host ($_scheme) — снимок настроек ${DateTime.now().toIso8601String()}')
      ..writeln('# Это снимок для записи. Полный бэкап: веб-интерфейс → Системные инструменты → Резервная копия.')
      ..writeln(const JsonEncoder.withIndent('  ').convert(info.toJson()));
    return BackupData(content.toString(), 'снимок настроек', ext: 'json');
  }

  @override
  Future<void> changePassword(String newPassword) async =>
      throw DriverException('TP-Link: автоматическая смена пароля пока не включена — смени через «Веб-интерфейс».');

  @override
  Future<void> setChannel(RadioInfo radio, int channel) async =>
      throw DriverException('TP-Link: смена канала пока не включена.');

  @override
  Future<void> close() async {
    if (_loggedIn) {
      if (_scheme == 'legacy') await _legacyLogout();
      if (_scheme == 'gdpr' || _scheme == 'cgi') await _gdprLogout();
    }
    _loggedIn = false;
    _client.close(force: true);
  }

  /// Для «Разведки»: какую схему видит драйвер (без входа).
  static Future<String> probeScheme(String host) async {
    final d = TplinkDriver(host, Credential(login: '', password: ''));
    try {
      await d._detect();
      return d._scheme;
    } finally {
      d._client.close(force: true);
    }
  }
}

