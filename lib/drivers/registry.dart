import '../core/models.dart';
import 'driver.dart';
import 'keenetic.dart';
import 'mikrotik.dart';

RouterDriver? driverFor(Device d, Credential c) => switch (d.effectiveVendor) {
      Vendor.keenetic => KeeneticDriver(d.ip, c),
      Vendor.mikrotik => MikrotikDriver(d.ip, c),
      _ => null,
    };

/// Что умеет драйвер производителя (для подсказок в интерфейсе).
({bool dhcp, bool width, bool autoneg, bool save}) capsOf(Vendor v) => switch (v) {
      Vendor.mikrotik => (dhcp: true, width: true, autoneg: true, save: false),
      Vendor.keenetic => (dhcp: false, width: false, autoneg: false, save: true),
      _ => (dhcp: false, width: false, autoneg: false, save: false),
    };
