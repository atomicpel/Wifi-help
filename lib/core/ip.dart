/// Работа с IPv4 как с целыми числами.
class Ip {
  static int? parse(String? s) {
    if (s == null) return null;
    final p = s.trim().split('.');
    if (p.length != 4) return null;
    var v = 0;
    for (final x in p) {
      final n = int.tryParse(x);
      if (n == null || n < 0 || n > 255) return null;
      v = (v << 8) | n;
    }
    return v;
  }

  static String str(int v) =>
      '${(v >> 24) & 255}.${(v >> 16) & 255}.${(v >> 8) & 255}.${v & 255}';

  static int maskOf(int prefix) {
    if (prefix <= 0) return 0;
    if (prefix >= 32) return 0xFFFFFFFF;
    return (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
  }

  static int network(int ip, int prefix) => ip & maskOf(prefix);

  static int broadcast(int ip, int prefix) =>
      network(ip, prefix) | ((~maskOf(prefix)) & 0xFFFFFFFF);

  static int prefixFromMask(String? mask) {
    final m = parse(mask);
    if (m == null) return 24;
    var c = 0;
    for (var i = 31; i >= 0; i--) {
      if (((m >> i) & 1) == 1) {
        c++;
      } else {
        break;
      }
    }
    return c;
  }

  static bool sameNet(int a, int b, int prefix) =>
      network(a, prefix) == network(b, prefix);

  static bool isPrivate(int ip) =>
      (ip >> 24) == 10 || (ip >> 20) == 0xAC1 || (ip >> 16) == 0xC0A8;

  static String cidr(int ip, int prefix) => '${str(network(ip, prefix))}/$prefix';

  /// Пересекаются ли две подсети.
  static bool overlap(int a, int pa, int b, int pb) {
    final p = pa < pb ? pa : pb;
    return network(a, p) == network(b, p);
  }

  /// "192.168.0.0/16", "10.0.0.1-10.0.0.50" или один адрес.
  static (int, int)? parseRange(String s) {
    final t = s.trim();
    if (t.contains('/')) {
      final parts = t.split('/');
      final ip = parse(parts[0]);
      final pr = int.tryParse(parts[1]);
      if (ip == null || pr == null || pr < 8 || pr > 32) return null;
      final n = network(ip, pr);
      return (n, broadcast(ip, pr));
    }
    if (t.contains('-')) {
      final parts = t.split('-');
      final a = parse(parts[0]);
      final b = parse(parts[1]);
      if (a == null || b == null || b < a) return null;
      return (a, b);
    }
    final one = parse(t);
    if (one == null) return null;
    return (one, one);
  }

  static final RegExp _re = RegExp(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})');

  static String? extract(String? s) {
    if (s == null) return null;
    final m = _re.firstMatch(s);
    if (m == null) return null;
    final v = m.group(1)!;
    return parse(v) == null ? null : v;
  }

  static int sortKey(String ip) => parse(ip) ?? 0;
}
