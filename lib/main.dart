import 'dart:async';
import 'dart:ui';

import 'package:flutter/material.dart';

import 'core/app_state.dart';
import 'core/log.dart';
import 'core/native.dart';
import 'ui/devices_page.dart';
import 'ui/issues_page.dart';
import 'ui/map_page.dart';
import 'ui/more_page.dart';
import 'ui/wifi_page.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  FlutterError.onError = (details) {
    Log.e('flutter', details.exceptionAsString(), details.exception, details.stack);
    FlutterError.presentError(details);
  };
  PlatformDispatcher.instance.onError = (error, stack) {
    Log.e('dart', 'Необработанная ошибка', error, stack);
    return true;
  };
  Native.init();
  await app.init();
  runApp(const WifiHelpApp());
}

class WifiHelpApp extends StatelessWidget {
  const WifiHelpApp({super.key});

  ThemeData _theme(Brightness b) => ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF00897B), brightness: b),
        visualDensity: VisualDensity.standard,
      );

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'WiFi Помощник',
      debugShowCheckedModeBanner: false,
      theme: _theme(Brightness.light),
      darkTheme: _theme(Brightness.dark),
      home: const HomeShell(),
    );
  }
}

class HomeShell extends StatefulWidget {
  const HomeShell({super.key});

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _tab = 0;

  @override
  Widget build(BuildContext context) {
    final pages = [
      MapPage(onOpenDevices: () => setState(() => _tab = 1)),
      const DevicesPage(),
      const IssuesPage(),
      const WifiPage(),
      const MorePage(),
    ];
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        final crit = app.issues.where((i) => i.fixes.isNotEmpty || i.severity.index == 0).length;
        return Scaffold(
          body: IndexedStack(index: _tab, children: pages),
          bottomNavigationBar: NavigationBar(
            selectedIndex: _tab,
            onDestinationSelected: (i) => setState(() => _tab = i),
            destinations: [
              const NavigationDestination(icon: Icon(Icons.hub_outlined), selectedIcon: Icon(Icons.hub), label: 'Карта'),
              const NavigationDestination(icon: Icon(Icons.router_outlined), selectedIcon: Icon(Icons.router), label: 'Устройства'),
              NavigationDestination(
                icon: Badge(
                  isLabelVisible: crit > 0,
                  label: Text('$crit'),
                  child: const Icon(Icons.healing_outlined),
                ),
                selectedIcon: const Icon(Icons.healing),
                label: 'Проблемы',
              ),
              const NavigationDestination(icon: Icon(Icons.wifi_find_outlined), selectedIcon: Icon(Icons.wifi_find), label: 'Эфир'),
              const NavigationDestination(icon: Icon(Icons.more_horiz), label: 'Ещё'),
            ],
          ),
        );
      },
    );
  }
}
