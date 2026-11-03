# WiFi Помощник

Android-приложение для настройки сетей с большим количеством Wi-Fi роутеров:
быстро находит все роутеры и устройства, рисует карту, хранит пароли администраторов,
находит то, что делает сеть нестабильной, и по команде исправляет настройки —
каждый раз с бэкапом перед изменением.

## Установка

1. Открой [Releases](../../releases/latest) на телефоне и скачай `WiFiHelp-N.apk`.
2. Установи (разреши установку из браузера/файлового менеджера).
3. При первом скане разреши «Местоположение» — без него Android не отдаёт имя сети и список сетей вокруг.

APK собирается автоматически GitHub Actions при каждом пуше в `main`
(`.github/workflows/build.yml`). Все сборки подписаны одним ключом, поэтому
обновления ставятся поверх без потери сохранённых паролей.

## Что умеет

**Поиск (без паролей)**
- Пинг-скан своей подсети и всего `192.168.0.0/16` через ping-сокет Android (как системный `ping`, root не нужен) — тысячи адресов в секунду.
- TCP-проверка портов 80/443/8080/8443/22/23/8291/8728/554/8000 у живых хостов и «слепая» проверка тех, кто молчит на ping (своя подсеть + `.1`/`.254` каждой /24).
- MikroTik MNDP и UPnP/SSDP: модели, имена, MAC.
- Опознание по веб-интерфейсу (Keenetic, MikroTik, TP-Link, Xiaomi, D-Link, Eltex, Huawei, ZTE, ASUS, Tenda, Zyxel, Ubiquiti, OpenWrt, камеры Hikvision/Dahua).
- Процесс привязывается к Wi-Fi/Ethernet сети, поэтому скан работает и когда у Wi-Fi нет интернета.

**Карта**: Интернет → шлюз телефона → роутеры. Для роутеров с паролем связи строятся по их реальному маршруту по умолчанию; пунктир — связь угадана по подсети.

**Автонастройка** (бэкап перед каждым изменением, подтверждение, проверка результата):

| | MikroTik | Keenetic | TP-Link, Xiaomi, прочие |
|---|---|---|---|
| Опрос (адреса, шлюз, DHCP, Wi-Fi, порты, ARP) | ✔ RouterOS API 8728 | ✔ RCI | — |
| Бэкап | ✔ `.backup` на роутере + снимок в телефон | ✔ startup/running-config в телефон | — |
| Смена пароля (с проверкой входа) | ✔ | ✔ | — |
| Каналы Wi-Fi | ✔ | ✔ | — |
| Ширина 20 МГц, DHCP, автосогласование портов | ✔ | сохранение конфигурации | — |
| Карта, эфир, веб-интерфейс внутри приложения | ✔ | ✔ | ✔ |

**Проверки**: несколько DHCP в одной сети, конфликты IP (по ARP роутеров), двойной NAT, совпадение LAN/WAN,
полудуплекс и 10/100 Мбит/с на портах, каналы 2,4 ГГц не на 1/6/11, свои точки на одном канале,
40 МГц в 2,4 ГГц, коллизии 5 ГГц, разная защита у одной сети, открытые сети.

**Журнал**: всё пишется в `app.log` (ротация 3 МБ). «Ещё → Журнал → Отчёт» собирает сводку по устройствам
и весь журнал в один файл; пароли и токены заменяются на `***`. Кнопка «Разведка для журнала» на карточке
неподдерживаемого роутера записывает, как устроена его страница входа — по этому добавляются новые драйверы.

**Безопасность**: пароли шифруются ключом Android Keystore (AES-GCM) и не покидают телефон.

## Для MikroTik

Включи API: `IP → Services → api` (порт 8728) и разреши доступ с подсети телефона.

## Похожие проекты (изучены при разработке)

- [osociety/vernet](https://github.com/osociety/vernet), [osociety/network_tools](https://github.com/osociety/network_tools) — сканер сети на Flutter.
- [VREMSoftwareDevelopment/WiFiAnalyzer](https://github.com/VREMSoftwareDevelopment/WiFiAnalyzer) — анализ каналов Wi-Fi на Android.
- [openwisp/openwisp-controller](https://github.com/openwisp/openwisp-controller), [eduardogsilva/routerfleet](https://github.com/eduardogsilva/routerfleet) — централизованное управление роутерами (серверные, OpenWrt/MikroTik).
- [salatmaster/keenetic-mcp](https://github.com/salatmaster/keenetic-mcp) (заметки по RCI), [malinovsku/ha-keenetic_api](https://github.com/malinovsku/ha-keenetic_api) — Keenetic RCI.
- [ShafiqSadat/RouterOSClient](https://github.com/ShafiqSadat/RouterOSClient), [Eitol/mikrotik_mndp](https://github.com/Eitol/mikrotik_mndp) — MikroTik на Dart.
- [AlexandrErohin/TP-Link-Archer-C6U](https://github.com/AlexandrErohin/TP-Link-Archer-C6U), [dmamontov/hass-miwifi](https://github.com/dmamontov/hass-miwifi) — клиенты TP-Link и Xiaomi (кандидаты для будущих драйверов).

Готового мобильного приложения, которое массово управляет роутерами разных производителей, не нашлось:
сканеры не настраивают, контроллеры работают на сервере и в основном с OpenWrt/MikroTik.
