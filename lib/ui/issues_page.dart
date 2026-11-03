import 'package:flutter/material.dart';

import '../core/app_state.dart';
import '../core/models.dart';
import '../core/util.dart';
import 'widgets.dart';

class IssuesPage extends StatelessWidget {
  const IssuesPage({super.key});

  Future<void> _apply(BuildContext context) async {
    final fixes = app.allFixes.where((f) => app.selectedFixes.contains(f.key)).toList();
    if (fixes.isEmpty) return;
    final routers = fixes.map((f) => f.ip).toSet();
    final ok = await confirm(
      context,
      'Применить ${fixes.length} изменений?',
      '${fixes.map((f) => '• ${f.text}').join('\n')}\n\n'
          'Перед изменениями с каждого роутера (${routers.length}) будет снят бэкап. '
          'Если бэкап не получится — этот роутер не трогаю.\n'
          'Смена канала на несколько секунд отключит клиентов этой точки.',
      ok: 'Применить',
    );
    if (!ok || !context.mounted) return;
    await RunLogSheet.show(context, 'Применяю исправления', (log) => app.applyFixes(fixes, log));
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        final sel = app.selectedFixes.length;
        final crit = app.issues.where((i) => i.severity == Severity.critical).length;
        final warn = app.issues.where((i) => i.severity == Severity.warning).length;
        return Scaffold(
          appBar: AppBar(title: const Text('Проблемы сети')),
          bottomNavigationBar: sel == 0
              ? null
              : SafeArea(
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: FilledButton.icon(
                      onPressed: app.busy ? null : () => _apply(context),
                      icon: const Icon(Icons.auto_fix_high),
                      label: Text('Исправить выбранное ($sel)'),
                    ),
                  ),
                ),
          body: Column(
            children: [
              const BusyBar(),
              Expanded(
                child: ListView(
                  padding: const EdgeInsets.only(bottom: 24),
                  children: [
                    Card(
                      margin: const EdgeInsets.all(12),
                      child: Padding(
                        padding: const EdgeInsets.all(16),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              app.issues.isEmpty
                                  ? 'Проблем не найдено'
                                  : 'Критичных: $crit · предупреждений: $warn · всего: ${app.issues.length}',
                              style: Theme.of(context).textTheme.titleMedium,
                            ),
                            const SizedBox(height: 4),
                            Text(
                              'Проверка: опрос роутеров с паролями (DHCP, адреса, порты, Wi-Fi), ARP-таблицы, скан эфира. '
                              '${app.analyzedAt != null ? 'Последняя: ${human(app.analyzedAt!)}.' : ''}',
                              style: Theme.of(context).textTheme.bodySmall,
                            ),
                            const SizedBox(height: 12),
                            Row(
                              children: [
                                FilledButton.icon(
                                  onPressed: app.busy ? null : app.analyze,
                                  icon: const Icon(Icons.health_and_safety),
                                  label: const Text('Проверить сеть'),
                                ),
                                const SizedBox(width: 8),
                                if (app.allFixes.isNotEmpty)
                                  TextButton(
                                    onPressed: () {
                                      final all = app.allFixes.map((f) => f.key).toSet();
                                      if (app.selectedFixes.length == all.length) {
                                        app.selectedFixes.clear();
                                      } else {
                                        app.selectedFixes.addAll(all);
                                      }
                                      app.refresh();
                                    },
                                    child: const Text('Выбрать всё'),
                                  ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ),
                    for (final i in app.issues) _IssueCard(issue: i),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _IssueCard extends StatelessWidget {
  const _IssueCard({required this.issue});
  final Issue issue;

  @override
  Widget build(BuildContext context) {
    final c = severityColor(context, issue.severity);
    final t = Theme.of(context).textTheme;
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(severityIcon(issue.severity), color: c),
                const SizedBox(width: 10),
                Expanded(child: Text(issue.title, style: t.titleSmall)),
              ],
            ),
            const SizedBox(height: 6),
            Text(issue.details, style: t.bodyMedium),
            if (issue.hint != null) ...[
              const SizedBox(height: 6),
              Text('Что сделать: ${issue.hint}', style: t.bodySmall?.copyWith(fontStyle: FontStyle.italic)),
            ],
            for (final f in issue.fixes)
              CheckboxListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                controlAffinity: ListTileControlAffinity.leading,
                value: app.selectedFixes.contains(f.key),
                onChanged: (v) {
                  if (v == true) {
                    app.selectedFixes.add(f.key);
                  } else {
                    app.selectedFixes.remove(f.key);
                  }
                  app.refresh();
                },
                title: Text(f.text),
              ),
          ],
        ),
      ),
    );
  }
}
