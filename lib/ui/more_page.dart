import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../core/app_state.dart';
import '../core/log.dart';
import '../core/models.dart';
import '../core/native.dart';
import '../core/util.dart';
import 'creds_dialog.dart';
import 'widgets.dart';

class MorePage extends StatelessWidget {
  const MorePage({super.key});

  void _go(BuildContext context, Widget page) =>
      Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => page));

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Ещё')),
      body: ListView(
        children: [
          ListTile(
            leading: const Icon(Icons.password),
            title: const Text('Сменить пароль на всех роутерах'),
            subtitle: const Text('Один пароль администратора для выбранных роутеров'),
            onTap: () => _go(context, const PasswordPage()),
          ),
          ListTile(
            leading: const Icon(Icons.key),
            title: const Text('Сохранённые логины'),
            onTap: () => _go(context, const CredsListPage()),
          ),
          ListTile(
            leading: const Icon(Icons.backup),
            title: const Text('Бэкапы конфигураций'),
            onTap: () => _go(context, const BackupsPage()),
          ),
          ListTile(
            leading: const Icon(Icons.receipt_long),
            title: const Text('Журнал'),
            subtitle: const Text('Полный лог работы — для поиска проблем'),
            onTap: () => _go(context, const LogPage()),
          ),
          ListTile(
            leading: const Icon(Icons.tune),
            title: const Text('Настройки скана'),
            onTap: () => _go(context, const SettingsPage()),
          ),
          ListTile(
            leading: const Icon(Icons.info_outline),
            title: const Text('Что умеет программа'),
            onTap: () => _go(context, const AboutPage()),
          ),
        ],
      ),
    );
  }
}

// ------------------------------------------------------------ password

class PasswordPage extends StatefulWidget {
  const PasswordPage({super.key});

  @override
  State<PasswordPage> createState() => _PasswordPageState();
}

class _PasswordPageState extends State<PasswordPage> {
  final _p1 = TextEditingController();
  final _p2 = TextEditingController();
  final Set<String> _sel = {};
  bool _show = false;
  bool _init = false;

  @override
  void dispose() {
    _p1.dispose();
    _p2.dispose();
    super.dispose();
  }

  String? get _error {
    final p = _p1.text;
    if (p.isEmpty) return null;
    if (p.length < 8) return 'Минимум 8 символов';
    if (p.contains(' ')) return 'Без пробелов';
    if (p != _p2.text) return 'Пароли не совпадают';
    return null;
  }

  Future<void> _run() async {
    final ips = _sel.toList()..sort((a, b) => Ip2.cmp(a, b));
    final ok = await confirm(
      context,
      'Сменить пароль на ${ips.length} роутерах?',
      '${ips.join(', ')}\n\nНа каждом: бэкап → смена пароля → проверка входа с новым паролем → '
          'сохранение в хранилище. Если на каком-то роутере не получится — остальные это не остановит.',
      ok: 'Сменить',
    );
    if (!ok || !mounted) return;
    final pw = _p1.text;
    await RunLogSheet.show(context, 'Смена пароля', (log) => app.changePasswordAll(ips, pw, log));
    if (mounted) {
      _p1.clear();
      _p2.clear();
      setState(() {});
    }
  }

  @override
  Widget build(BuildContext context) {
    final routers = app.routers;
    final ready = routers.where((d) => d.effectiveVendor.supported && app.vault.get(d.ip) != null).toList();
    final notReady = routers.where((d) => !ready.contains(d)).toList();
    if (!_init) {
      _sel.addAll(ready.map((d) => d.ip));
      _init = true;
    }
    final canRun = _sel.isNotEmpty && _p1.text.isNotEmpty && _error == null && !app.busy;
    return Scaffold(
      appBar: AppBar(title: const Text('Смена пароля')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          TextField(
            controller: _p1,
            obscureText: !_show,
            autocorrect: false,
            enableSuggestions: false,
            onChanged: (_) => setState(() {}),
            decoration: InputDecoration(
              labelText: 'Новый пароль',
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                icon: Icon(_show ? Icons.visibility_off : Icons.visibility),
                onPressed: () => setState(() => _show = !_show),
              ),
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _p2,
            obscureText: !_show,
            autocorrect: false,
            enableSuggestions: false,
            onChanged: (_) => setState(() {}),
            decoration: InputDecoration(
              labelText: 'Повтори пароль',
              border: const OutlineInputBorder(),
              errorText: _error,
            ),
          ),
          const SectionTitle('Роутеры'),
          if (ready.isEmpty)
            const Text('Нет роутеров с сохранённым паролем и поддержкой автонастройки (Keenetic, MikroTik).'),
          for (final d in ready)
            CheckboxListTile(
              value: _sel.contains(d.ip),
              onChanged: (v) => setState(() => v == true ? _sel.add(d.ip) : _sel.remove(d.ip)),
              title: Text('${d.ip}  ${d.title}'),
              subtitle: Text('${d.effectiveVendor.label} · пользователь ${app.vault.get(d.ip)!.login}'),
            ),
          if (notReady.isNotEmpty) ...[
            const SectionTitle('Пропущены'),
            for (final d in notReady)
              ListTile(
                dense: true,
                enabled: false,
                title: Text('${d.ip}  ${d.title}'),
                subtitle: Text(!d.effectiveVendor.supported
                    ? '${d.effectiveVendor.label}: автонастройка пока не поддерживается'
                    : 'нет сохранённого пароля'),
              ),
          ],
          const SizedBox(height: 16),
          FilledButton.icon(
            onPressed: canRun ? _run : null,
            icon: const Icon(Icons.lock_reset),
            label: Text('Сменить на выбранных (${_sel.length})'),
          ),
        ],
      ),
    );
  }
}

class Ip2 {
  static int cmp(String a, String b) {
    int k(String s) => s.split('.').fold<int>(0, (v, p) => (v << 8) + (int.tryParse(p) ?? 0));
    return k(a).compareTo(k(b));
  }
}

// --------------------------------------------------------- credentials

class CredsListPage extends StatelessWidget {
  const CredsListPage({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        final entries = app.vault.all.entries.toList()..sort((a, b) => Ip2.cmp(a.key, b.key));
        return Scaffold(
          appBar: AppBar(title: const Text('Сохранённые логины')),
          body: entries.isEmpty
              ? const Center(child: Text('Пока пусто. Пароли вводятся на карточке роутера.'))
              : ListView(
                  children: [
                    if (app.vault.loadError != null)
                      Padding(
                        padding: const EdgeInsets.all(16),
                        child: Text('Ошибка хранилища: ${app.vault.loadError}', style: const TextStyle(color: Colors.red)),
                      ),
                    for (final e in entries)
                      ListTile(
                        leading: const Icon(Icons.key),
                        title: Text(e.key),
                        subtitle: Text('${app.devices[e.key]?.title ?? 'нет в последнем скане'} · ${e.value.login}'
                            '${e.value.port != null ? ' · порт ${e.value.port}' : ''}'),
                        onTap: () {
                          final d = app.devices[e.key] ?? Device(e.key);
                          showCredsDialog(context, [d]);
                        },
                        trailing: IconButton(
                          icon: const Icon(Icons.delete_outline),
                          onPressed: () async {
                            final ok = await confirm(context, 'Удалить логин ${e.key}?', 'Пароль будет удалён с телефона.',
                                ok: 'Удалить');
                            if (ok) {
                              await app.vault.remove(e.key);
                              app.analyzeLocal();
                            }
                          },
                        ),
                      ),
                  ],
                ),
        );
      },
    );
  }
}

// ------------------------------------------------------------- backups

class BackupsPage extends StatefulWidget {
  const BackupsPage({super.key});

  @override
  State<BackupsPage> createState() => _BackupsPageState();
}

class _BackupsPageState extends State<BackupsPage> {
  @override
  Widget build(BuildContext context) {
    final list = app.listBackups();
    return Scaffold(
      appBar: AppBar(title: const Text('Бэкапы')),
      body: list.isEmpty
          ? const Center(
              child: Padding(
              padding: EdgeInsets.all(32),
              child: Text('Бэкапы появятся перед любым изменением настроек или по кнопке «Бэкап» на карточке роутера.',
                  textAlign: TextAlign.center),
            ))
          : ListView(
              children: [
                for (final b in list)
                  ListTile(
                    leading: const Icon(Icons.description_outlined),
                    title: Text('${b.ip} · ${b.vendor}'),
                    subtitle: Text('${human(b.time)} · ${b.name}'),
                    onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(
                        builder: (_) => TextViewPage(title: b.name, load: () => b.file.readAsString()))),
                  ),
              ],
            ),
    );
  }
}

/// Просмотр текста с кнопками «копировать / поделиться / в Загрузки».
class TextViewPage extends StatefulWidget {
  const TextViewPage({super.key, required this.title, required this.load});
  final String title;
  final Future<String> Function() load;

  @override
  State<TextViewPage> createState() => _TextViewPageState();
}

class _TextViewPageState extends State<TextViewPage> {
  String? _text;

  @override
  void initState() {
    super.initState();
    widget.load().then((t) {
      if (mounted) setState(() => _text = t);
    }).catchError((Object e) {
      if (mounted) setState(() => _text = 'Ошибка: $e');
    });
  }

  @override
  Widget build(BuildContext context) {
    final t = _text;
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title, maxLines: 1, overflow: TextOverflow.ellipsis),
        actions: t == null
            ? null
            : [
                IconButton(
                  tooltip: 'Копировать',
                  icon: const Icon(Icons.copy),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: t));
                    toast(context, 'Скопировано');
                  },
                ),
                IconButton(
                  tooltip: 'Поделиться',
                  icon: const Icon(Icons.share),
                  onPressed: () => Native.shareText(widget.title, t.length > 400000 ? t.substring(t.length - 400000) : t),
                ),
                IconButton(
                  tooltip: 'Сохранить в Загрузки',
                  icon: const Icon(Icons.download),
                  onPressed: () async {
                    try {
                      final name = widget.title.contains('.') ? widget.title : '${widget.title}.txt';
                      final p = await Native.saveDownload(name, t);
                      if (context.mounted) toast(context, 'Сохранено: $p');
                    } catch (e) {
                      if (context.mounted) toast(context, 'Ошибка: $e');
                    }
                  },
                ),
              ],
      ),
      body: t == null
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.all(12),
              child: SelectableText(t, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
            ),
    );
  }
}

// ----------------------------------------------------------------- log

class LogPage extends StatelessWidget {
  const LogPage({super.key});

  Color? _color(LogLine l) => switch (l.level) {
        LogLevel.error => Colors.red,
        LogLevel.warn => Colors.orange.shade800,
        LogLevel.debug => Colors.grey,
        LogLevel.info => null,
      };

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Журнал'),
        actions: [
          IconButton(
            tooltip: 'Отчёт целиком (сводка + весь журнал)',
            icon: const Icon(Icons.summarize),
            onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(
                builder: (_) => TextViewPage(title: 'wifihelp-report-${stamp(DateTime.now())}.txt', load: app.report))),
          ),
          IconButton(
            tooltip: 'Очистить',
            icon: const Icon(Icons.delete_sweep),
            onPressed: () async {
              final ok = await confirm(context, 'Очистить журнал?', 'Файл журнала будет удалён.', ok: 'Очистить');
              if (ok) await Log.clear();
            },
          ),
        ],
      ),
      body: ValueListenableBuilder<int>(
        valueListenable: Log.version,
        builder: (context, _, __) {
          final lines = Log.lines;
          if (lines.isEmpty) return const Center(child: Text('Журнал пуст'));
          return ListView.builder(
            reverse: true,
            itemCount: lines.length,
            itemBuilder: (_, i) {
              final l = lines[lines.length - 1 - i];
              return Padding(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 1),
                child: Text(l.format(), style: TextStyle(fontFamily: 'monospace', fontSize: 11.5, color: _color(l))),
              );
            },
          );
        },
      ),
      bottomNavigationBar: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(8),
          child: Text(
            'Пароли и токены в журнале заменяются на ***. Кнопка «Отчёт» вверху собирает всё в один файл — '
            'его можно сохранить в Загрузки или отправить.',
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ),
      ),
    );
  }
}

// ------------------------------------------------------------ settings

class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  late final TextEditingController _ranges = TextEditingController(text: app.settings.extraRanges);

  @override
  void dispose() {
    _ranges.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    app.settings.extraRanges = _ranges.text.trim();
    await app.saveSettings();
  }

  @override
  Widget build(BuildContext context) {
    final s = app.settings;
    return Scaffold(
      appBar: AppBar(title: const Text('Настройки скана')),
      body: ListView(
        padding: const EdgeInsets.symmetric(vertical: 8),
        children: [
          SwitchListTile(
            value: s.scan16,
            onChanged: (v) => setState(() {
              s.scan16 = v;
              _save();
            }),
            title: const Text('Сканировать весь 192.168.0.0/16'),
            subtitle: const Text('65 536 адресов. Своя подсеть сканируется всегда.'),
          ),
          ListTile(
            title: Text('Скорость пинг-скана: ${s.pps} пакетов/с'),
            subtitle: Slider(
              value: s.pps.toDouble(),
              min: 1000,
              max: 20000,
              divisions: 19,
              label: '${s.pps}',
              onChanged: (v) => setState(() => s.pps = v.round()),
              onChangeEnd: (_) => _save(),
            ),
          ),
          ListTile(
            title: Text('Ожидание ответа по TCP: ${s.tcpTimeoutMs} мс'),
            subtitle: Slider(
              value: s.tcpTimeoutMs.toDouble(),
              min: 200,
              max: 2000,
              divisions: 18,
              label: '${s.tcpTimeoutMs}',
              onChanged: (v) => setState(() => s.tcpTimeoutMs = v.round()),
              onChangeEnd: (_) => _save(),
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(16),
            child: TextField(
              controller: _ranges,
              decoration: const InputDecoration(
                labelText: 'Дополнительные диапазоны',
                helperText: 'Через запятую: 10.0.0.0/24, 172.16.5.0/24, 10.1.1.1-10.1.1.50 (каждый до /16)',
                border: OutlineInputBorder(),
              ),
              onSubmitted: (_) => _save(),
              onEditingComplete: _save,
            ),
          ),
          SwitchListTile(
            value: s.autoQuery,
            onChanged: (v) => setState(() {
              s.autoQuery = v;
              _save();
            }),
            title: const Text('После скана сразу опрашивать роутеры с паролями'),
          ),
          SwitchListTile(
            value: s.verboseLog,
            onChanged: (v) => setState(() {
              s.verboseLog = v;
              _save();
            }),
            title: const Text('Подробный журнал'),
            subtitle: const Text('Каждый запрос к роутерам и устройствам. Нужен для поиска проблем.'),
          ),
        ],
      ),
    );
  }
}

// --------------------------------------------------------------- about

class AboutPage extends StatelessWidget {
  const AboutPage({super.key});

  @override
  Widget build(BuildContext context) {
    const text = '''
WiFi Помощник 0.1

Поиск
• Пинг-скан своей подсети и всего 192.168.0.0/16 через ping-сокет Android (без root), тысячи адресов в секунду.
• TCP-проверка портов 80, 443, 8080, 8443, 22, 23, 8291, 8728, 554, 8000 — находит и тех, кто не отвечает на ping.
• MikroTik MNDP и UPnP/SSDP — модели и имена без пароля.
• Опознание по веб-интерфейсу: Keenetic, MikroTik, TP-Link, Xiaomi, D-Link, Eltex, Huawei, ZTE, ASUS и др.
• Карта: Интернет → шлюз → роутеры; с паролями связи строятся по реальным маршрутам.

Автонастройка (с бэкапом перед каждым изменением)
• MikroTik (RouterOS API, порт 8728): опрос, бэкап, смена пароля, каналы и ширина Wi-Fi, выключение лишнего DHCP, автосогласование портов.
• Keenetic (RCI): опрос, бэкап, смена пароля, каналы Wi-Fi, сохранение конфигурации.
• TP-Link, Xiaomi и остальные: поиск, карта, эфир, встроенный веб-интерфейс. Драйверы добавляются по журналу «Разведки».

Проверки
• Несколько DHCP-серверов в одной сети.
• Конфликты IP по ARP-таблицам роутеров.
• Двойной NAT и совпадение LAN/WAN подсетей.
• Полудуплекс, 10/100 Мбит/с на портах.
• Каналы 2,4 ГГц не на 1/6/11, свои точки на одном канале, 40 МГц в 2,4 ГГц, коллизии 5 ГГц.
• Разная защита у одной сети, открытые сети.

Безопасность
• Пароли зашифрованы ключом Android Keystore и не покидают телефон.
• В журнале пароли и токены заменяются на ***.
• Изменения — только по твоей команде, после бэкапа и подтверждения.
''';
    return Scaffold(
      appBar: AppBar(title: const Text('Что умеет программа')),
      body: const SingleChildScrollView(padding: EdgeInsets.all(16), child: SelectableText(text)),
    );
  }
}
