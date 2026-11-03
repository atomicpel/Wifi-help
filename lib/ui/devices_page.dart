import 'package:flutter/material.dart';

import '../core/app_state.dart';
import '../core/models.dart';
import 'creds_dialog.dart';
import 'device_page.dart';
import 'widgets.dart';

enum _Filter { routers, cameras, all }

class DevicesPage extends StatefulWidget {
  const DevicesPage({super.key});

  @override
  State<DevicesPage> createState() => _DevicesPageState();
}

class _DevicesPageState extends State<DevicesPage> {
  _Filter _filter = _Filter.routers;
  final Set<String> _selected = {};

  bool get _selecting => _selected.isNotEmpty;

  List<Device> _list() {
    final all = app.sortedDevices;
    return switch (_filter) {
      _Filter.routers => all.where((d) => d.isRouter).toList(),
      _Filter.cameras => all.where((d) => d.isCamera).toList(),
      _Filter.all => all,
    };
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        final list = _list();
        final groups = <String, List<Device>>{};
        for (final d in list) {
          groups.putIfAbsent(d.subnet24, () => []).add(d);
        }
        return Scaffold(
          appBar: _selecting
              ? AppBar(
                  leading: IconButton(icon: const Icon(Icons.close), onPressed: () => setState(_selected.clear)),
                  title: Text('Выбрано: ${_selected.length}'),
                  actions: [
                    IconButton(
                      tooltip: 'Выбрать все роутеры',
                      icon: const Icon(Icons.select_all),
                      onPressed: () => setState(() => _selected.addAll(list.where((d) => d.isRouter).map((d) => d.ip))),
                    ),
                    TextButton.icon(
                      icon: const Icon(Icons.key),
                      label: const Text('Пароль'),
                      onPressed: () async {
                        final targets = _selected.map((ip) => app.devices[ip]).whereType<Device>().toList();
                        if (targets.isEmpty) return;
                        final ok = await showCredsDialog(context, targets);
                        if (ok) {
                          setState(_selected.clear);
                          await app.queryAll();
                          app.analyzeLocal();
                        }
                      },
                    ),
                  ],
                )
              : AppBar(
                  title: const Text('Устройства'),
                  actions: [
                    IconButton(
                      tooltip: 'Опросить роутеры с паролями',
                      icon: const Icon(Icons.sync),
                      onPressed: app.busy ? null : app.queryAll,
                    ),
                  ],
                ),
          body: Column(
            children: [
              const BusyBar(),
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
                child: SegmentedButton<_Filter>(
                  segments: [
                    ButtonSegment(value: _Filter.routers, label: Text('Роутеры ${app.routers.length}')),
                    ButtonSegment(
                        value: _Filter.cameras, label: Text('Камеры ${app.devices.values.where((d) => d.isCamera).length}')),
                    ButtonSegment(value: _Filter.all, label: Text('Все ${app.devices.length}')),
                  ],
                  selected: {_filter},
                  showSelectedIcon: false,
                  onSelectionChanged: (s) => setState(() => _filter = s.first),
                ),
              ),
              if (list.isEmpty)
                const Expanded(child: Center(child: Text('Пусто. Запусти скан на вкладке «Карта».')))
              else
                Expanded(
                  child: ListView(
                    padding: const EdgeInsets.only(bottom: 24),
                    children: [
                      if (_filter == _Filter.routers && !_selecting)
                        const Padding(
                          padding: EdgeInsets.fromLTRB(16, 4, 16, 0),
                          child: Text('Долгое нажатие — выбрать несколько и задать им один логин/пароль.',
                              style: TextStyle(fontSize: 12)),
                        ),
                      for (final g in groups.entries) ...[
                        SectionTitle('${g.key} — ${g.value.length}'),
                        for (final d in g.value) _tile(context, d),
                      ],
                    ],
                  ),
                ),
            ],
          ),
        );
      },
    );
  }

  Widget _tile(BuildContext context, Device d) {
    final hasCred = app.vault.get(d.ip) != null;
    final sel = _selected.contains(d.ip);
    final parts = <String>[
      d.effectiveVendor.label,
      if (d.ports.isNotEmpty) 'порты ${(d.ports.toList()..sort()).join(',')}',
      if (d.rttMs != null) '${d.rttMs} мс',
      if (d.mac != null) d.mac!,
    ];
    return ListTile(
      selected: sel,
      leading: sel
          ? const CircleAvatar(child: Icon(Icons.check))
          : VendorAvatar(d.effectiveVendor, icon: d.isCamera ? Icons.videocam : null),
      title: Text('${d.ip}   ${d.title}', maxLines: 1, overflow: TextOverflow.ellipsis),
      subtitle: Text(parts.join(' · '), maxLines: 2, overflow: TextOverflow.ellipsis),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (d.isGateway) const Icon(Icons.door_front_door_outlined, size: 18),
          if (d.lastError != null) const Icon(Icons.link_off, size: 18, color: Colors.red),
          if (d.info != null && d.lastError == null) const Icon(Icons.check_circle, size: 18, color: Colors.green),
          if (d.isRouter)
            Icon(hasCred ? Icons.key : Icons.key_off,
                size: 18, color: hasCred ? Theme.of(context).colorScheme.primary : Colors.grey),
        ],
      ),
      onTap: () {
        if (_selecting) {
          setState(() => sel ? _selected.remove(d.ip) : _selected.add(d.ip));
        } else {
          Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => DevicePage(ip: d.ip)));
        }
      },
      onLongPress: () => setState(() => _selected.add(d.ip)),
    );
  }
}
