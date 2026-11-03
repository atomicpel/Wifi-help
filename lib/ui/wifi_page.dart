import 'package:flutter/material.dart';

import '../core/app_state.dart';
import '../core/models.dart';
import '../core/util.dart';

class WifiPage extends StatefulWidget {
  const WifiPage({super.key});

  @override
  State<WifiPage> createState() => _WifiPageState();
}

class _WifiPageState extends State<WifiPage> {
  bool _scanning = false;
  String _band = '2.4';

  Set<String> get _ownSsids {
    final s = <String>{};
    final n = app.net?.ssid;
    if (n != null) s.add(n);
    for (final d in app.devices.values) {
      for (final r in d.info?.radios ?? const <RadioInfo>[]) {
        if (r.ssid != null) s.add(r.ssid!);
      }
    }
    return s;
  }

  Future<void> _scan() async {
    setState(() => _scanning = true);
    await app.wifiScan();
    if (mounted) setState(() => _scanning = false);
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        final own = _ownSsids;
        final list = app.wifi.where((a) => a.band == _band).toList();
        return Scaffold(
          appBar: AppBar(
            title: const Text('Эфир Wi-Fi'),
            actions: [
              IconButton(
                onPressed: _scanning ? null : _scan,
                icon: _scanning
                    ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.refresh),
              ),
            ],
          ),
          body: ListView(
            padding: const EdgeInsets.only(bottom: 24),
            children: [
              if (app.wifiError != null)
                Card(
                  margin: const EdgeInsets.all(12),
                  child: Padding(padding: const EdgeInsets.all(12), child: Text(app.wifiError!)),
                ),
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
                child: SegmentedButton<String>(
                  segments: [
                    ButtonSegment(value: '2.4', label: Text('2,4 ГГц (${app.wifi.where((a) => a.band == '2.4').length})')),
                    ButtonSegment(value: '5', label: Text('5 ГГц (${app.wifi.where((a) => a.band == '5').length})')),
                    ButtonSegment(value: '6', label: Text('6 ГГц (${app.wifi.where((a) => a.band == '6').length})')),
                  ],
                  selected: {_band},
                  showSelectedIcon: false,
                  onSelectionChanged: (s) => setState(() => _band = s.first),
                ),
              ),
              if (app.wifi.isEmpty)
                Padding(
                  padding: const EdgeInsets.all(32),
                  child: Column(
                    children: [
                      const Text('Нажми ⟳, чтобы увидеть все сети вокруг: каналы, уровни сигнала, защиту.',
                          textAlign: TextAlign.center),
                      const SizedBox(height: 12),
                      FilledButton.icon(onPressed: _scanning ? null : _scan, icon: const Icon(Icons.wifi_find), label: const Text('Сканировать эфир')),
                    ],
                  ),
                )
              else ...[
                if (app.wifiAt != null)
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
                    child: Text('Скан ${human(app.wifiAt!)} · зелёные — ваши сети',
                        style: Theme.of(context).textTheme.bodySmall),
                  ),
                _ChannelBars(aps: list, own: own, band: _band),
                for (final a in list)
                  ListTile(
                    dense: true,
                    leading: Icon(
                      a.level > -60 ? Icons.wifi : (a.level > -75 ? Icons.wifi_2_bar : Icons.wifi_1_bar),
                      color: own.contains(a.ssid) ? Colors.green : null,
                    ),
                    title: Text(a.ssid.isEmpty ? '(скрытая сеть)' : a.ssid,
                        style: TextStyle(fontWeight: own.contains(a.ssid) ? FontWeight.bold : null)),
                    subtitle: Text('${a.bssid} · канал ${a.channel} · ${a.widthMhz} МГц · ${a.security}'),
                    trailing: Text('${a.level} дБм'),
                  ),
              ],
            ],
          ),
        );
      },
    );
  }
}

class _ChannelBars extends StatelessWidget {
  const _ChannelBars({required this.aps, required this.own, required this.band});
  final List<WifiAp> aps;
  final Set<String> own;
  final String band;

  @override
  Widget build(BuildContext context) {
    final channels = band == '2.4'
        ? List<int>.generate(13, (i) => i + 1)
        : (aps.map((a) => a.channel).toSet().toList()..sort());
    if (channels.isEmpty) return const SizedBox.shrink();
    final total = <int, int>{};
    final mine = <int, int>{};
    for (final a in aps) {
      total[a.channel] = (total[a.channel] ?? 0) + 1;
      if (own.contains(a.ssid)) mine[a.channel] = (mine[a.channel] ?? 0) + 1;
    }
    final maxV = total.values.fold<int>(1, (m, v) => v > m ? v : m);
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(12, 12, 12, 4),
      child: SizedBox(
        height: 120,
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            for (final ch in channels)
              Expanded(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    Text('${total[ch] ?? 0}', style: const TextStyle(fontSize: 10)),
                    const SizedBox(height: 2),
                    Container(
                      height: 80.0 * (total[ch] ?? 0) / maxV,
                      margin: const EdgeInsets.symmetric(horizontal: 2),
                      decoration: BoxDecoration(
                        color: (mine[ch] ?? 0) > 0
                            ? Colors.green
                            : (band == '2.4' && [1, 6, 11].contains(ch) ? cs.primary : cs.outline),
                        borderRadius: BorderRadius.circular(3),
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text('$ch', style: const TextStyle(fontSize: 10)),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }
}
