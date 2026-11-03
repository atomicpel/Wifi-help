import 'package:flutter/material.dart';

import '../core/app_state.dart';
import '../core/ip.dart';
import '../core/models.dart';
import '../core/util.dart';
import 'device_page.dart';
import 'walk_page.dart';
import 'widgets.dart';

enum TKind { internet, device, group }

class TNode {
  TNode(this.key, {this.device, this.label = '', this.sub = '', this.kind = TKind.device, this.members = const []});
  final String key;
  final Device? device;
  final String label;
  final String sub;
  final TKind kind;
  final List<Device> members;
  final List<TNode> children = [];
  TNode? parent;
  bool dashed = false;
  double x = 0;
  double y = 0;
}

/// Строит дерево: Интернет → шлюз телефона → остальные роутеры.
/// Для роутеров с паролем родитель берётся из их маршрута по умолчанию,
/// для остальных — по подсети.
class Topology {
  static const double w = 156;
  static const double h = 76;
  static const double hgap = 14;
  static const double vgap = 56;

  static (TNode, Size) build(List<Device> all, NetInfo? net, bool showAll) {
    final root = TNode('internet', label: 'Интернет', kind: TKind.internet);
    final routers = all.where((d) => d.isRouter).toList();
    final nodes = <String, TNode>{for (final d in routers) d.ip: TNode(d.ip, device: d)};
    final addrOwner = <String, TNode>{};
    for (final d in routers) {
      addrOwner[d.ip] = nodes[d.ip]!;
      for (final a in d.info?.addrs ?? const <IfAddr>[]) {
        addrOwner.putIfAbsent(a.ip, () => nodes[d.ip]!);
      }
    }
    final gwNode = net?.gateway == null ? null : addrOwner[net!.gateway!];
    final prefix = net?.prefix ?? 24;

    for (final d in routers) {
      final n = nodes[d.ip]!;
      if (identical(n, gwNode)) continue;
      TNode? p;
      final g = d.info?.gateway;
      if (g != null) p = addrOwner[g];
      if (p == null || identical(p, n)) {
        p = gwNode;
        final gd = gwNode?.device;
        final a = Ip.parse(d.ip);
        final b = gd == null ? null : Ip.parse(gd.ip);
        final same = a != null && b != null && Ip.sameNet(a, b, prefix);
        n.dashed = !same;
      }
      n.parent = p;
    }
    // разрываем возможные циклы
    for (final n in nodes.values) {
      final seen = <TNode>{n};
      var p = n.parent;
      while (p != null) {
        if (!seen.add(p)) {
          n.parent = gwNode;
          n.dashed = true;
          break;
        }
        p = p.parent;
      }
    }
    if (gwNode != null) {
      gwNode.parent = root;
      root.children.add(gwNode);
    }
    final ordered = nodes.values.toList()..sort((a, b) => a.device!.sortKey.compareTo(b.device!.sortKey));
    for (final n in ordered) {
      if (identical(n, gwNode)) continue;
      final p = n.parent ?? root;
      if (identical(p, n)) continue;
      n.parent = p;
      p.children.add(n);
    }

    if (showAll) {
      final others = all.where((d) => !d.isRouter).toList();
      final groups = <String, List<Device>>{};
      for (final d in others) {
        groups.putIfAbsent(d.subnet24, () => []).add(d);
      }
      groups.forEach((subnet, list) {
        final net24 = Ip.parse(subnet.split('/').first);
        TNode? head;
        if (net24 != null) {
          head = ordered.findFirst((n) {
            final ip = Ip.parse(n.device!.ip);
            return ip != null && Ip.sameNet(ip, net24, 24) && identical(n, gwNode);
          });
          head ??= ordered.findFirst((n) {
            final ip = Ip.parse(n.device!.ip);
            return ip != null && Ip.sameNet(ip, net24, 24);
          });
        }
        final cams = list.where((d) => d.isCamera).length;
        final g = TNode('group-$subnet',
            kind: TKind.group,
            label: '${list.length} устройств',
            sub: '$subnet${cams > 0 ? ' · камер $cams' : ''}',
            members: list);
        final p = head ?? gwNode ?? root;
        g.parent = p;
        p.children.add(g);
      });
    }

    // раскладка дерева
    var nextX = 0.0;
    var maxDepth = 0;
    void place(TNode n, int depth) {
      if (depth > maxDepth) maxDepth = depth;
      n.y = depth * (h + vgap);
      if (n.children.isEmpty) {
        n.x = nextX;
        nextX += w + hgap;
        return;
      }
      for (final c in n.children) {
        place(c, depth + 1);
      }
      n.x = (n.children.first.x + n.children.last.x) / 2;
    }

    place(root, 0);
    final size = Size(nextX + 40, (maxDepth + 1) * (h + vgap) + 40);
    return (root, size);
  }

  static List<TNode> flatten(TNode root) {
    final out = <TNode>[];
    void walk(TNode n) {
      out.add(n);
      for (final c in n.children) {
        walk(c);
      }
    }

    walk(root);
    return out;
  }
}

class _EdgePainter extends CustomPainter {
  _EdgePainter(this.nodes, this.color);
  final List<TNode> nodes;
  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = color
      ..strokeWidth = 2
      ..style = PaintingStyle.stroke;
    for (final n in nodes) {
      final p = n.parent;
      if (p == null) continue;
      final a = Offset(p.x + 20 + Topology.w / 2, p.y + 20 + Topology.h);
      final b = Offset(n.x + 20 + Topology.w / 2, n.y + 20);
      final midY = (a.dy + b.dy) / 2;
      final pts = [a, Offset(a.dx, midY), Offset(b.dx, midY), b];
      for (var i = 0; i < pts.length - 1; i++) {
        if (n.dashed) {
          _dash(canvas, pts[i], pts[i + 1], paint);
        } else {
          canvas.drawLine(pts[i], pts[i + 1], paint);
        }
      }
    }
  }

  void _dash(Canvas c, Offset a, Offset b, Paint p) {
    final d = (b - a).distance;
    if (d == 0) return;
    final dir = (b - a) / d;
    var t = 0.0;
    while (t < d) {
      final e = (t + 6) > d ? d : t + 6;
      c.drawLine(a + dir * t, a + dir * e, p);
      t += 11;
    }
  }

  @override
  bool shouldRepaint(covariant _EdgePainter old) => true;
}

class MapPage extends StatefulWidget {
  const MapPage({super.key, required this.onOpenDevices});
  final VoidCallback onOpenDevices;

  @override
  State<MapPage> createState() => _MapPageState();
}

class _MapPageState extends State<MapPage> {
  bool _showAll = false;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        return Scaffold(
          appBar: AppBar(
            title: const Text('Карта сети'),
            actions: [
              IconButton(
                tooltip: 'Обход сети от интернета',
                icon: const Icon(Icons.alt_route),
                onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(
                    builder: (_) => WalkPage(onOpenMap: () => Navigator.of(context).pop()))),
              ),
              IconButton(
                tooltip: _showAll ? 'Только роутеры' : 'Показать все устройства',
                icon: Icon(_showAll ? Icons.devices_other : Icons.router),
                onPressed: () => setState(() => _showAll = !_showAll),
              ),
              IconButton(
                tooltip: 'Опросить роутеры',
                icon: const Icon(Icons.sync),
                onPressed: app.busy ? null : app.queryAll,
              ),
            ],
          ),
          floatingActionButton: app.busy
              ? null
              : FloatingActionButton.extended(
                  onPressed: app.scan,
                  icon: const Icon(Icons.radar),
                  label: const Text('Сканировать'),
                ),
          body: Column(
            children: [
              const BusyBar(),
              _header(context),
              Expanded(child: app.devices.isEmpty ? _empty(context) : _map(context)),
            ],
          ),
        );
      },
    );
  }

  Widget _header(BuildContext context) {
    final n = app.net;
    if (n == null) return const SizedBox.shrink();
    final t = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
      child: Wrap(
        spacing: 8,
        runSpacing: 4,
        children: [
          Chip(avatar: const Icon(Icons.wifi, size: 16), label: Text(n.ssid ?? (n.transport ?? 'сеть'), style: t.bodySmall)),
          Chip(label: Text('Я ${n.ip ?? '-'}/${n.prefix}', style: t.bodySmall)),
          Chip(label: Text('Шлюз ${n.gateway ?? '-'}', style: t.bodySmall)),
          Chip(label: Text('Роутеров ${app.routers.length} · всего ${app.devices.length}', style: t.bodySmall)),
          if (app.lastScan != null) Chip(label: Text('Скан ${human(app.lastScan!)}', style: t.bodySmall)),
        ],
      ),
    );
  }

  Widget _empty(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.radar, size: 72, color: Theme.of(context).colorScheme.primary),
            const SizedBox(height: 16),
            Text('Нажми «Сканировать»', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 8),
            const Text(
              'Найду все устройства в своей подсети и во всём 192.168.0.0–192.168.255.255: '
              'ping по 65 тыс. адресов, проверка портов, MikroTik MNDP и UPnP. '
              'Обычно 15–40 секунд.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            OutlinedButton.icon(
              onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(
                  builder: (_) => WalkPage(onOpenMap: () => Navigator.of(context).pop()))),
              icon: const Icon(Icons.alt_route),
              label: const Text('Или пройти сеть по цепочке роутеров'),
            ),
            if (app.scanNotes.isNotEmpty) ...[
              const SizedBox(height: 12),
              for (final s in app.scanNotes) Text(s, textAlign: TextAlign.center, style: const TextStyle(color: Colors.orange)),
            ],
          ],
        ),
      ),
    );
  }

  Widget _map(BuildContext context) {
    final (root, size) = Topology.build(app.sortedDevices, app.net, _showAll);
    final nodes = Topology.flatten(root);
    final cs = Theme.of(context).colorScheme;
    return InteractiveViewer(
      constrained: false,
      boundaryMargin: const EdgeInsets.all(400),
      minScale: 0.25,
      maxScale: 2.5,
      child: SizedBox(
        width: size.width,
        height: size.height,
        child: Stack(
          children: [
            Positioned.fill(child: CustomPaint(painter: _EdgePainter(nodes, cs.outline))),
            for (final n in nodes)
              Positioned(
                left: n.x + 20,
                top: n.y + 20,
                width: Topology.w,
                height: Topology.h,
                child: _NodeCard(node: n, onOpenDevices: widget.onOpenDevices),
              ),
          ],
        ),
      ),
    );
  }
}

class _NodeCard extends StatelessWidget {
  const _NodeCard({required this.node, required this.onOpenDevices});
  final TNode node;
  final VoidCallback onOpenDevices;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final t = Theme.of(context).textTheme;
    if (node.kind == TKind.internet) {
      return Card(
        color: cs.primaryContainer,
        child: Center(
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            Icon(Icons.public, color: cs.onPrimaryContainer),
            const SizedBox(width: 8),
            Text('Интернет', style: t.titleSmall?.copyWith(color: cs.onPrimaryContainer)),
          ]),
        ),
      );
    }
    if (node.kind == TKind.group) {
      return Card(
        child: InkWell(
          onTap: () => _showGroup(context),
          child: Padding(
            padding: const EdgeInsets.all(8),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(node.label, style: t.titleSmall),
                Text(node.sub, style: t.bodySmall, maxLines: 1, overflow: TextOverflow.ellipsis),
              ],
            ),
          ),
        ),
      );
    }
    final d = node.device!;
    final color = vendorColor(d.effectiveVendor);
    final hasCred = app.vault.get(d.ip) != null;
    final problems = app.issues.where((i) => i.ips.contains(d.ip) && i.severity != Severity.info).length;
    return Card(
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => DevicePage(ip: d.ip))),
        child: Row(
          children: [
            Container(width: 6, color: color),
            Expanded(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(8, 6, 6, 6),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(d.title, maxLines: 1, overflow: TextOverflow.ellipsis, style: t.labelLarge),
                    Text(d.ip, style: t.bodySmall),
                    const SizedBox(height: 2),
                    Row(
                      children: [
                        Text(d.effectiveVendor.label, style: t.labelSmall?.copyWith(color: color)),
                        const Spacer(),
                        if (d.isGateway) const Icon(Icons.door_front_door_outlined, size: 14),
                        if (hasCred) Icon(Icons.key, size: 14, color: cs.primary),
                        if (d.info != null && d.lastError == null) const Icon(Icons.check_circle, size: 14, color: Colors.green),
                        if (d.lastError != null || d.offline) const Icon(Icons.link_off, size: 14, color: Colors.red),
                        if (problems > 0) ...[
                          const Icon(Icons.warning_amber_rounded, size: 14, color: Colors.orange),
                          Text('$problems', style: t.labelSmall),
                        ],
                      ],
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showGroup(BuildContext context) {
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => SafeArea(
        child: SizedBox(
          height: MediaQuery.of(ctx).size.height * 0.6,
          child: ListView(
            children: [
              ListTile(title: Text('${node.label} · ${node.sub}')),
              for (final d in node.members)
                ListTile(
                  dense: true,
                  leading: VendorAvatar(d.effectiveVendor, size: 32, icon: d.isCamera ? Icons.videocam : null),
                  title: Text('${d.ip}  ${d.title}'),
                  subtitle: Text([
                    if (d.mac != null) d.mac!,
                    if (d.ports.isNotEmpty) 'порты ${(d.ports.toList()..sort()).join(',')}',
                  ].join(' · ')),
                  onTap: () {
                    Navigator.pop(ctx);
                    Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => DevicePage(ip: d.ip)));
                  },
                ),
            ],
          ),
        ),
      ),
    );
  }
}
