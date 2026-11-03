import '../core/models.dart';

class DriverException implements Exception {
  DriverException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// Общий интерфейс драйвера роутера. Любое изменение настроек вызывается
/// только после бэкапа (это гарантирует AppState).
abstract class RouterDriver {
  RouterDriver(this.host, this.cred);
  final String host;
  final Credential cred;

  Vendor get vendor;

  bool get canChangePassword => true;
  bool get canSetChannel => true;
  bool get canSetWidth => false;
  bool get canDisableDhcp => false;
  bool get canAutoNeg => false;
  bool get canSaveConfig => false;

  Future<void> login();
  Future<RouterInfo> collect();
  Future<BackupData> backup();

  /// Должен сам проверить, что вход с новым паролем работает.
  Future<void> changePassword(String newPassword);

  Future<void> setChannel(RadioInfo radio, int channel);

  Future<void> setWidth20(RadioInfo radio) async =>
      throw DriverException('${vendor.label}: смена ширины канала пока не поддерживается');

  Future<void> setDhcpEnabled(DhcpServerInfo server, bool enabled) async =>
      throw DriverException('${vendor.label}: управление DHCP пока не поддерживается');

  Future<void> enableAutoNeg(PortLink port) async =>
      throw DriverException('${vendor.label}: настройка портов пока не поддерживается');

  Future<void> saveConfig() async {}

  Future<void> close();
}
