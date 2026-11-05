import 'package:flutter/material.dart';

import '../core/app_state.dart';
import '../core/log.dart';
import '../core/models.dart';
import '../drivers/registry.dart';

/// Ввод логина/пароля для одного или нескольких устройств.
Future<bool> showCredsDialog(BuildContext context, List<Device> targets) async {
  final r = await showDialog<bool>(
    context: context,
    builder: (_) => _CredsDialog(targets: targets),
  );
  return r == true;
}

class _CredsDialog extends StatefulWidget {
  const _CredsDialog({required this.targets});
  final List<Device> targets;

  @override
  State<_CredsDialog> createState() => _CredsDialogState();
}

class _CredsDialogState extends State<_CredsDialog> {
  late final TextEditingController _login;
  late final TextEditingController _pass;
  late final TextEditingController _port;
  bool _show = false;
  bool _testing = false;
  String? _result;

  Device get _first => widget.targets.first;
  bool get _single => widget.targets.length == 1;

  @override
  void initState() {
    super.initState();
    final c = app.vault.get(_first.ip);
    _login = TextEditingController(text: c?.login ?? 'admin');
    _pass = TextEditingController(text: c?.password ?? '');
    _port = TextEditingController(text: c?.port?.toString() ?? '');
  }

  @override
  void dispose() {
    _login.dispose();
    _pass.dispose();
    _port.dispose();
    super.dispose();
  }

  Credential get _cred => Credential(
        login: _login.text.trim(),
        password: _pass.text,
        port: int.tryParse(_port.text.trim()),
      );

  Future<void> _test() async {
    final drv = driverFor(_first, _cred);
    if (drv == null) {
      setState(() => _result = 'Для ${_first.effectiveVendor.label} проверка входа пока не поддерживается — '
          'пароль просто сохранится (пригодится для веб-интерфейса).');
      return;
    }
    setState(() {
      _testing = true;
      _result = null;
    });
    Log.addSecret(_pass.text);
    try {
      await drv.login();
      _result = '✔ Вход выполнен';
    } catch (e) {
      _result = '✖ $e';
    } finally {
      await drv.close();
    }
    if (mounted) setState(() => _testing = false);
  }

  Future<void> _save() async {
    if (_cred.login.isEmpty || _cred.password.isEmpty) {
      setState(() => _result = 'Введи логин и пароль');
      return;
    }
    for (final d in widget.targets) {
      final c = _cred;
      await app.vault.set(d.ip,
          Credential(login: c.login, password: c.password, port: c.port, vendor: d.effectiveVendor.name));
    }
    app.analyzeLocal();
    if (mounted) Navigator.pop(context, true);
  }

  @override
  Widget build(BuildContext context) {
    final v = _first.effectiveVendor;
    return AlertDialog(
      title: Text(_single ? 'Вход: ${_first.ip}' : 'Вход для ${widget.targets.length} устройств'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (_single) Text('${v.label} · ${_first.title}', style: Theme.of(context).textTheme.bodySmall),
            if (!_single)
              Text(widget.targets.map((d) => d.ip).join(', '), style: Theme.of(context).textTheme.bodySmall),
            const SizedBox(height: 12),
            TextField(
              controller: _login,
              decoration: const InputDecoration(labelText: 'Логин', border: OutlineInputBorder()),
              autocorrect: false,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _pass,
              obscureText: !_show,
              autocorrect: false,
              enableSuggestions: false,
              decoration: InputDecoration(
                labelText: 'Пароль',
                border: const OutlineInputBorder(),
                suffixIcon: IconButton(
                  icon: Icon(_show ? Icons.visibility_off : Icons.visibility),
                  onPressed: () => setState(() => _show = !_show),
                ),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _port,
              keyboardType: TextInputType.number,
              decoration: InputDecoration(
                labelText: 'Порт (необязательно)',
                helperText: v.portHint,
                border: const OutlineInputBorder(),
              ),
            ),
            if (_result != null) ...[
              const SizedBox(height: 12),
              Text(_result!),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Отмена')),
        if (_single)
          TextButton(
            onPressed: _testing ? null : _test,
            child: _testing
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                : const Text('Проверить'),
          ),
        FilledButton(onPressed: _save, child: const Text('Сохранить')),
      ],
    );
  }
}
