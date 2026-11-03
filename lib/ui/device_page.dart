import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../core/app_state.dart';
import '../core/models.dart';
import '../core/native.dart';
import '../core/util.dart';
import 'creds_dialog.dart';
import 'widgets.dart';

class DevicePage extends StatefulWidget {
  const DevicePage({super.key, required this.ip});
  final String ip;

  @override
  State<DevicePage> createState() => _DevicePageState();
}

class _DevicePageState extends State<DevicePage> {
  bool _busy = false;

  Future<void> _run(Future<String?> Function() f) async {
    setState(() => _busy = true);
    String? msg;
    try {
      msg = await f();
    } catch (e) {
      msg = 'Ошибка: $e';
    }
    if (!mounted) return;
    setState(() => _busy = false);
    if (msg != null && msg.isNotEmpty) toast(context, msg);
  }

  Future<void> _openWeb(Device d) async {
    final c = app.vault.get(d.ip);
    final https = !d.ports.contains(80) && d.ports.contains(443);
    final port8080 = !d.ports.contains(80) && !https && d.ports.contains(8080);
    final url = https ? 'https://${d.ip}/' : (port8080 ? 'http://${d.ip}:8080/' : 'http://${d.ip}/');
    final ok = await Native.openWeb(url, '${d.title} — ${d.ip}', user: c?.login, pass: c?.password);
    if (!ok && mounted) toast(context, 'Не удалось открыть $url');
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        final d = app.devices[widget.ip];
        if (d == null) {
          return Scaffold(appBar: AppBar(), body: const Center(child: Text('Устройство не найдено')));
        }
        final hasCred = app.vault.get(d.ip) != null;
        final supported = d.effectiveVendor.supported;
        final t = Theme.of(context).textTheme;
        return Scaffold(
          appBar: AppBar(
            title: Text(d.title),
            bottom: _busy || app.working
                ? const PreferredSize(preferredSize: Size.fromHeight(4), child: LinearProgressIndicator())
                : null,
          ),
          body: ListView(
            padding: const EdgeInsets.only(bottom: 32),
            children: [
              ListTile(
                leading: VendorAvatar(d.effectiveVendor, size: 48, icon: d.isCamera ? Icons.videocam : null),
                title: Text('${d.ip}${d.isGateway ? '  · шлюз' : ''}', style: t.titleMedium),
                subtitle: Text([
                  d.effectiveVendor.label,
                  if (d.model != null) d.model!,
                  if (d.mac != null) d.mac!,
                  if (d.rttMs != null) 'ping ${d.rttMs} мс',
                  if (d.offline) 'не ответил при последнем скане',
                ].join(' · ')),
              ),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    FilledButton.tonalIcon(
                      onPressed: () async {
                        final ok = await showCredsDialog(context, [d]);
                        if (ok && supported) await _run(() async => await app.queryRouter(d) ?? 'Данные получены');
                      },
                      icon: Icon(hasCred ? Icons.key : Icons.key_off),
                      label: Text(hasCred ? 'Логин/пароль' : 'Ввести пароль'),
                    ),
                    FilledButton.tonalIcon(
                      onPressed: _busy || !hasCred || !supported
                          ? null
                          : () => _run(() async => await app.queryRouter(d) ?? 'Данные получены'),
                      icon: const Icon(Icons.sync),
                      label: const Text('Опросить'),
                    ),
                    FilledButton.tonalIcon(
                      onPressed: () => _openWeb(d),
                      icon: const Icon(Icons.open_in_browser),
                      label: const Text('Веб-интерфейс'),
                    ),
                    FilledButton.tonalIcon(
                      onPressed: _busy || !hasCred || !supported ? null : () => _run(() => app.backupNow(d)),
                      icon: const Icon(Icons.save_alt),
                      label: const Text('Бэкап'),
                    ),
                    OutlinedButton.icon(
                      onPressed: _busy
                          ? null
                          : () => _run(() async {
                                await app.survey(d);
                                return 'Разведка записана в журнал («Ещё» → «Журнал»)';
                              }),
                      icon: const Icon(Icons.travel_explore),
                      label: const Text('Разведка для журнала'),
                    ),
                  ],
                ),
              ),
              if (!supported && d.isRouter)
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
                  child: Text(
                    'Автонастройка ${d.effectiveVendor.label} пока не поддерживается. Работают поиск, карта, '
                    'эфир и встроенный веб-интерфейс (логин подставится сам, если сайт спрашивает его окном). '
                    'Нажми «Разведка для журнала» и пришли журнал — по нему добавлю драйвер.',
                    style: t.bodySmall,
                  ),
                ),
              if (d.lastError != null)
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
                  child: Text('Последняя ошибка: ${d.lastError}', style: t.bodySmall?.copyWith(color: Colors.red)),
                ),
              const SectionTitle('Производитель'),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Row(
                  children: [
                    const Expanded(child: Text('Определён неверно? Выбери вручную:')),
                    DropdownButton<Vendor>(
                      value: d.effectiveVendor,
                      items: [
                        for (final v in Vendor.values) DropdownMenuItem(value: v, child: Text(v.label)),
                      ],
                      onChanged: (v) async {
                        if (v == null) return;
                        d.vendorOverride = v == d.vendor ? null : v;
                        await app.saveState();
                        app.analyzeLocal();
                      },
                    ),
                  ],
                ),
              ),
              const SectionTitle('Что видно из сети'),
              _kv('Открытые порты', d.ports.isEmpty ? '—' : (d.ports.toList()..sort()).join(', ')),
              _kv('Заголовок веб-страницы', d.httpTitle ?? '—'),
              _kv('Сервер', d.server ?? '—'),
              if (d.authRealm != null) _kv('Realm авторизации', d.authRealm!),
              if (d.upnpManufacturer != null) _kv('UPnP', d.upnpManufacturer!),
              if (d.identity != null) _kv('Имя (MNDP/UPnP)', d.identity!),
              _kv('Как найден', d.sources.join(', ')),
              ..._infoSections(d),
            ],
          ),
        );
      },
    );
  }

  Widget _kv(String k, String v) => ListTile(
        dense: true,
        title: Text(k),
        subtitle: SelectableText(v),
        onLongPress: () {
          Clipboard.setData(ClipboardData(text: v));
          toast(context, 'Скопировано');
        },
      );

  List<Widget> _infoSections(Device d) {
    final info = d.info;
    if (info == null) return const [];
    return [
      SectionTitle('С роутера (${d.infoAt != null ? human(d.infoAt!) : ''})'),
      _kv('Модель / прошивка', '${info.model} · ${info.firmware}'),
      if (info.identity.isNotEmpty) _kv('Имя', info.identity),
      _kv('Режим', info.modeLabel),
      _kv('Шлюз (вверх)', info.gateway ?? '—'),
      _kv('Адреса', info.addrs.map((a) => '${a.iface}: ${a.ip}/${a.prefix}').join('\n')),
      _kv(
          'DHCP-серверы',
          info.dhcp.isEmpty
              ? 'нет'
              : info.dhcp
                  .map((s) => '${s.name} на ${s.iface}: ${s.enabled ? 'ВКЛЮЧЁН' : 'выключен'}${s.range != null ? ' (${s.range})' : ''}')
                  .join('\n')),
      _kv(
          'Wi-Fi',
          info.radios.isEmpty
              ? 'нет'
              : info.radios
                  .map((r) => '${r.name}: ${r.band} ГГц, канал ${r.channel ?? '?'}${r.autoChannel ? ' (авто)' : ''}, '
                      'ширина ${r.width ?? '?'}, «${r.ssid ?? ''}»${r.enabled ? '' : ' — выключен'}')
                  .join('\n')),
      _kv(
          'Порты',
          info.ports.isEmpty
              ? 'нет данных'
              : info.ports
                  .map((p) => '${p.name}: ${p.up ? 'есть линк' : 'нет линка'}'
                      '${p.speedMbps != null ? ', ${p.speedMbps} Мбит/с' : ''}'
                      '${p.fullDuplex == null ? '' : (p.fullDuplex! ? ', full' : ', HALF-DUPLEX')}'
                      '${p.autoNeg == false ? ', автосогласование выкл' : ''}')
                  .join('\n')),
      _kv('ARP-таблица', '${info.arp.length} записей'),
    ];
  }
}
