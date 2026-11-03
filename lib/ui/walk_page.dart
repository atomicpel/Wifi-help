import 'package:flutter/material.dart';

import '../core/app_state.dart';
import '../core/native.dart';
import '../core/walk.dart';
import 'creds_dialog.dart';
import 'device_page.dart';

class WalkPage extends StatelessWidget {
  const WalkPage({super.key, this.onOpenMap});
  final VoidCallback? onOpenMap;

  (IconData, Color) _badge(BuildContext c, HopStatus s) {
    final cs = Theme.of(c).colorScheme;
    return switch (s) {
      HopStatus.ok => (Icons.check_circle, Colors.green),
      HopStatus.edge => (Icons.public, cs.primary),
      HopStatus.working => (Icons.sync, cs.primary),
      HopStatus.needPassword => (Icons.key, Colors.orange),
      HopStatus.needNextHop => (Icons.help_outline, Colors.orange),
      HopStatus.unreachable => (Icons.link_off, Colors.red),
      HopStatus.failed => (Icons.error, Colors.red),
      HopStatus.skipped => (Icons.skip_next, Colors.grey),
      HopStatus.pending => (Icons.more_horiz, Colors.grey),
    };
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: Listenable.merge([walk, app]),
      builder: (context, _) {
        return Scaffold(
          appBar: AppBar(title: const Text('Обход сети')),
          body: Column(
            children: [
              Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      'Пойду от телефона вверх к интернету: на каждом роутере спрошу пароль, зайду, '
                      'прочитаю его клиентов и куда он смотрит дальше — и так до самого дальнего роутера. '
                      'Потом построю карту.',
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                    const SizedBox(height: 12),
                    if (!walk.running)
                      FilledButton.icon(
                        onPressed: walk.start,
                        icon: const Icon(Icons.alt_route),
                        label: Text(walk.hops.isEmpty ? 'Начать обход' : 'Пройти заново'),
                      ),
                    if (walk.message.isNotEmpty)
                      Padding(
                        padding: const EdgeInsets.only(top: 10),
                        child: Row(
                          children: [
                            if (walk.running && walk.waiting == null)
                              const Padding(
                                padding: EdgeInsets.only(right: 10),
                                child: SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)),
                              ),
                            Expanded(child: Text(walk.message, style: Theme.of(context).textTheme.bodySmall)),
                          ],
                        ),
                      ),
                  ],
                ),
              ),
              const Divider(height: 1),
              Expanded(
                child: ListView(
                  children: [
                    for (var i = 0; i < walk.hops.length; i++) _hopTile(context, i, walk.hops[i]),
                    if (walk.waiting != null) _prompt(context, walk.waiting!),
                    if (walk.finished && !walk.running) ...[
                      const SizedBox(height: 16),
                      Center(
                        child: FilledButton.icon(
                          onPressed: onOpenMap,
                          icon: const Icon(Icons.hub),
                          label: const Text('Открыть карту'),
                        ),
                      ),
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

  Widget _hopTile(BuildContext context, int i, WalkHop h) {
    final (icon, color) = _badge(context, h.status);
    final d = h.device;
    return ListTile(
      leading: CircleAvatar(
        backgroundColor: color.withValues(alpha: 0.15),
        foregroundColor: color,
        child: Text('${i + 1}'),
      ),
      title: Text('${h.ip}  ${d?.title ?? ''}'),
      subtitle: Text([
        if (h.note.isNotEmpty) h.note,
        if (h.status == HopStatus.ok || h.status == HopStatus.edge) 'клиентов ${h.clients}',
        if (h.upstream != null) 'вверх → ${h.upstream}',
      ].join(' · ')),
      trailing: Icon(icon, color: color),
      onTap: d == null ? null : () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => DevicePage(ip: d.ip))),
    );
  }

  Widget _prompt(BuildContext context, WalkHop h) {
    final d = h.device!;
    return Card(
      margin: const EdgeInsets.all(12),
      color: Theme.of(context).colorScheme.secondaryContainer,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text('Роутер ${h.ip} (${d.effectiveVendor.label})', style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 4),
            Text(h.note, style: Theme.of(context).textTheme.bodySmall),
            const SizedBox(height: 12),
            if (h.status == HopStatus.needPassword)
              Wrap(
                spacing: 8,
                children: [
                  FilledButton.icon(
                    icon: const Icon(Icons.key),
                    label: const Text('Ввести пароль'),
                    onPressed: () async {
                      final ok = await showCredsDialog(context, [d]);
                      if (ok) walk.resumeAfterPassword();
                    },
                  ),
                  TextButton(onPressed: () => walk.skipAndContinue(null), child: const Text('Пропустить роутер')),
                ],
              )
            else
              _NextHopPrompt(hop: h),
          ],
        ),
      ),
    );
  }
}

class _NextHopPrompt extends StatefulWidget {
  const _NextHopPrompt({required this.hop});
  final WalkHop hop;

  @override
  State<_NextHopPrompt> createState() => _NextHopPromptState();
}

class _NextHopPromptState extends State<_NextHopPrompt> {
  final _c = TextEditingController();

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final d = widget.hop.device!;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text('Не смог пройти этот роутер сам. Открой его веб-интерфейс, посмотри «шлюз»/WAN '
            'и впиши IP следующего роутера (ближе к интернету). Или закончи обход.'),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: TextField(
                controller: _c,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(labelText: 'IP следующего роутера', border: OutlineInputBorder(), isDense: true),
              ),
            ),
            const SizedBox(width: 8),
            IconButton.filled(
              icon: const Icon(Icons.open_in_browser),
              tooltip: 'Веб-интерфейс',
              onPressed: () {
                final c = app.vault.get(d.ip);
                Native.openWeb('http://${d.ip}/', '${d.title} — ${d.ip}', user: c?.login, pass: c?.password);
              },
            ),
          ],
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          children: [
            FilledButton(
              onPressed: () {
                final ip = _c.text.trim();
                walk.provideNextHop(ip.isEmpty ? null : ip);
              },
              child: const Text('Дальше'),
            ),
            TextButton(onPressed: () => walk.finishNow(), child: const Text('Закончить обход')),
          ],
        ),
      ],
    );
  }
}
