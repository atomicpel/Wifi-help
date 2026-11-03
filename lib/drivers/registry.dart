import '../core/models.dart';
import 'driver.dart';
import 'keenetic.dart';
import 'mikrotik.dart';
import 'tplink.dart';
import 'xiaomi.dart';

RouterDriver? driverFor(Device d, Credential c) => switch (d.effectiveVendor) {
      Vendor.keenetic => KeeneticDriver(d.ip, c),
      Vendor.mikrotik => MikrotikDriver(d.ip, c),
      Vendor.xiaomi => XiaomiDriver(d.ip, c),
      Vendor.tplink => TplinkDriver(d.ip, c),
      _ => null,
    };

class Caps {
  const Caps({
    this.query = false,
    this.backup = false,
    this.password = false,
    this.channel = false,
    this.width = false,
    this.dhcp = false,
    this.autoneg = false,
    this.save = false,
  });
  final bool query;
  final bool backup;
  final bool password;
  final bool channel;
  final bool width;
  final bool dhcp;
  final bool autoneg;
  final bool save;
}

/// Что умеет драйвер производителя — для подсказок и блокировки кнопок.
Caps capsOf(Vendor v) => switch (v) {
      Vendor.mikrotik =>
        const Caps(query: true, backup: true, password: true, channel: true, width: true, dhcp: true, autoneg: true),
      Vendor.keenetic => const Caps(query: true, backup: true, password: true, channel: true, save: true),
      Vendor.xiaomi => const Caps(query: true, backup: true, channel: true, width: true),
      Vendor.tplink => const Caps(query: true, backup: true),
      _ => const Caps(),
    };
