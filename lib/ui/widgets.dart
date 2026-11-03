import 'package:flutter/material.dart';

import '../core/app_state.dart';
import '../core/models.dart';

Color vendorColor(Vendor v) => Color(v.color);

Color severityColor(BuildContext context, Severity s) => switch (s) {
      Severity.critical => Colors.red.shade600,
      Severity.warning => Colors.orange.shade700,
      Severity.info => Theme.of(context).colorScheme.primary,
    };

IconData severityIcon(Severity s) => switch (s) {
      Severity.critical => Icons.error,
      Severity.warning => Icons.warning_amber_rounded,
      Severity.info => Icons.info_outline,
    };

String initials(Vendor v) {
  final l = v.label.replaceAll(RegExp(r'[^A-Za-zА-Яа-я]'), '');
  if (v == Vendor.unknown) return '?';
  return l.length <= 2 ? l : l.substring(0, 2);
}

void toast(BuildContext context, String text) {
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(text), duration: const Duration(seconds: 4)));
}

/// Полоса прогресса и статус фоновой операции.
class BusyBar extends StatelessWidget {
  const BusyBar({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        if (!app.busy && app.status.isEmpty) return const SizedBox.shrink();
        final cs = Theme.of(context).colorScheme;
        return Material(
          color: cs.surfaceContainerHighest,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 8, 8),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    if (app.busy)
                      const Padding(
                        padding: EdgeInsets.only(right: 12),
                        child: SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)),
                      ),
                    Expanded(child: Text(app.status, style: Theme.of(context).textTheme.bodySmall)),
                    if (app.scanning)
                      TextButton(onPressed: app.cancelScan, child: const Text('Стоп'))
                    else if (!app.busy)
                      IconButton(
                        visualDensity: VisualDensity.compact,
                        icon: const Icon(Icons.close, size: 18),
                        onPressed: () {
                          app.status = '';
                          app.refresh();
                        },
                      ),
                  ],
                ),
                if (app.busy) ...[
                  const SizedBox(height: 6),
                  LinearProgressIndicator(value: app.progress),
                ],
              ],
            ),
          ),
        );
      },
    );
  }
}

/// Нижний лист с живым журналом длительной операции.
class RunLogSheet extends StatefulWidget {
  const RunLogSheet({super.key, required this.title, required this.run});
  final String title;
  final Future<void> Function(void Function(String) log) run;

  static Future<void> show(BuildContext context, String title, Future<void> Function(void Function(String) log) run) {
    return showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      isDismissible: false,
      enableDrag: false,
      builder: (_) => RunLogSheet(title: title, run: run),
    );
  }

  @override
  State<RunLogSheet> createState() => _RunLogSheetState();
}

class _RunLogSheetState extends State<RunLogSheet> {
  final List<String> _lines = [];
  bool _done = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _start());
  }

  Future<void> _start() async {
    try {
      await widget.run((s) {
        if (mounted) setState(() => _lines.add(s));
      });
    } catch (e) {
      if (mounted) setState(() => _lines.add('✖ $e'));
    }
    if (mounted) setState(() => _done = true);
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: SizedBox(
        height: MediaQuery.of(context).size.height * 0.75,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  Expanded(child: Text(widget.title, style: Theme.of(context).textTheme.titleMedium)),
                  if (!_done) const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2)),
                ],
              ),
              const SizedBox(height: 12),
              Expanded(
                child: Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: ListView.builder(
                    reverse: true,
                    itemCount: _lines.length,
                    itemBuilder: (_, i) => Text(
                      _lines[_lines.length - 1 - i],
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 12.5),
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 12),
              FilledButton(
                onPressed: _done ? () => Navigator.of(context).pop() : null,
                child: Text(_done ? 'Закрыть' : 'Выполняется…'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

Future<bool> confirm(BuildContext context, String title, String body, {String ok = 'Выполнить'}) async {
  final r = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(title),
      content: SingleChildScrollView(child: Text(body)),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Отмена')),
        FilledButton(onPressed: () => Navigator.pop(ctx, true), child: Text(ok)),
      ],
    ),
  );
  return r == true;
}

class SectionTitle extends StatelessWidget {
  const SectionTitle(this.text, {super.key});
  final String text;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 6),
        child: Text(text,
            style: Theme.of(context).textTheme.titleSmall?.copyWith(color: Theme.of(context).colorScheme.primary)),
      );
}

class VendorAvatar extends StatelessWidget {
  const VendorAvatar(this.vendor, {super.key, this.size = 40, this.icon});
  final Vendor vendor;
  final double size;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final c = vendorColor(vendor);
    return CircleAvatar(
      radius: size / 2,
      backgroundColor: c.withValues(alpha: 0.18),
      foregroundColor: c,
      child: icon != null
          ? Icon(icon, size: size * 0.5)
          : Text(initials(vendor), style: TextStyle(fontWeight: FontWeight.bold, fontSize: size * 0.32)),
    );
  }
}
