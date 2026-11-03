"""Доводит сгенерированный `flutter create` Android-проект до нужного вида:
minSdk >= 24, постоянный ключ подписи (чтобы обновления ставились поверх),
и отключённый lint на релизе."""
import pathlib
import re
import sys

app = pathlib.Path("android/app")
kts = app / "build.gradle.kts"
groovy = app / "build.gradle"

if kts.exists():
    s = kts.read_text()
    s = re.sub(r"minSdk\s*=\s*flutter\.minSdkVersion", "minSdk = maxOf(24, flutter.minSdkVersion)", s)
    if 'create("wifihelp")' not in s:
        s = s.replace(
            "    buildTypes {",
            """    signingConfigs {
        create("wifihelp") {
            storeFile = file("wifihelp.jks")
            storePassword = "wifihelp"
            keyAlias = "wifihelp"
            keyPassword = "wifihelp"
        }
    }

    lint {
        checkReleaseBuilds = false
        abortOnError = false
    }

    buildTypes {""",
            1,
        )
    s = s.replace('signingConfigs.getByName("debug")', 'signingConfigs.getByName("wifihelp")')
    kts.write_text(s)
    print(s)
elif groovy.exists():
    s = groovy.read_text()
    s = re.sub(r"minSdk(Version)?\s*=?\s*flutter\.minSdkVersion", "minSdkVersion Math.max(24, flutter.minSdkVersion)", s)
    if "wifihelp {" not in s:
        s = s.replace(
            "    buildTypes {",
            """    signingConfigs {
        wifihelp {
            storeFile file("wifihelp.jks")
            storePassword "wifihelp"
            keyAlias "wifihelp"
            keyPassword "wifihelp"
        }
    }

    lintOptions {
        checkReleaseBuilds false
        abortOnError false
    }

    buildTypes {""",
            1,
        )
    s = s.replace("signingConfigs.debug", "signingConfigs.wifihelp")
    groovy.write_text(s)
    print(s)
else:
    sys.exit("android/app/build.gradle(.kts) не найден")

if "wifihelp" not in (kts.read_text() if kts.exists() else groovy.read_text()):
    sys.exit("Не удалось вставить конфигурацию подписи")
