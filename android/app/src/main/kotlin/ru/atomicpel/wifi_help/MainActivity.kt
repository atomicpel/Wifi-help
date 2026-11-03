package ru.atomicpel.wifi_help

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Base64
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.FileDescriptor
import java.net.Inet4Address
import java.net.InetAddress
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MainActivity : FlutterActivity() {
    private lateinit var channel: MethodChannel
    private val main = Handler(Looper.getMainLooper())
    private val io = Executors.newCachedThreadPool()
    private var pendingPerm: MethodChannel.Result? = null
    private var mcLock: WifiManager.MulticastLock? = null
    private var boundNetwork: Network? = null
    private val keyAlias = "wifihelp_vault"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "wifihelp/native")
        channel.setMethodCallHandler { call, result -> handle(call, result) }
    }

    private fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "filesDir" -> result.success(filesDir.absolutePath)
            "deviceInfo" -> result.success(
                mapOf(
                    "model" to Build.MODEL,
                    "manufacturer" to Build.MANUFACTURER,
                    "sdk" to Build.VERSION.SDK_INT,
                    "release" to Build.VERSION.RELEASE
                )
            )
            "networkInfo" -> background(result) { networkInfo() }
            "ensurePermissions" -> ensurePermissions(result)
            "wifiScan" -> wifiScan(result)
            "pingSweep" -> pingSweepAsync(call, result)
            "arpTable" -> background(result) { readArp() }
            "multicastLock" -> {
                try {
                    setMulticast(call.argument<Boolean>("on") == true)
                    result.success(true)
                } catch (e: Throwable) {
                    result.success(false)
                }
            }
            "encrypt" -> background(result) { encrypt(call.argument<String>("text") ?: "") }
            "decrypt" -> background(result) { decrypt(call.argument<String>("data") ?: "") }
            "openUrl" -> openUrl(call.argument<String>("url") ?: "", result)
            "openWeb" -> openWeb(call, result)
            "shareText" -> shareText(
                call.argument<String>("subject") ?: "",
                call.argument<String>("text") ?: "",
                result
            )
            "saveDownload" -> background(result) {
                saveDownload(call.argument<String>("name") ?: "file.txt", call.argument<String>("text") ?: "")
            }
            else -> result.notImplemented()
        }
    }

    private fun background(result: MethodChannel.Result, block: () -> Any?) {
        io.execute {
            try {
                val v = block()
                main.post { result.success(v) }
            } catch (e: Throwable) {
                main.post { result.error("ERR", e.javaClass.simpleName + ": " + (e.message ?: ""), null) }
            }
        }
    }

    // ---------------------------------------------------------------- network

    @Suppress("DEPRECATION")
    private fun pickNetwork(cm: ConnectivityManager): Network? {
        var wifi: Network? = null
        var eth: Network? = null
        for (n in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(n) ?: continue
            if (eth == null && caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) eth = n
            if (wifi == null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) wifi = n
        }
        return eth ?: wifi ?: cm.activeNetwork
    }

    @Suppress("DEPRECATION")
    @SuppressLint("MissingPermission")
    private fun networkInfo(): Map<String, Any?> {
        val out = HashMap<String, Any?>()
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val net = pickNetwork(cm)
        if (net != null) {
            val caps = cm.getNetworkCapabilities(net)
            val transport = when {
                caps == null -> "unknown"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                else -> "other"
            }
            out["transport"] = transport
            val lp = cm.getLinkProperties(net)
            if (lp != null) {
                out["iface"] = lp.interfaceName
                for (la in lp.linkAddresses) {
                    val a = la.address
                    if (a is Inet4Address) {
                        out["ip"] = a.hostAddress
                        out["prefix"] = la.prefixLength
                    }
                }
                for (r in lp.routes) {
                    val g = r.gateway
                    if (r.isDefaultRoute && g is Inet4Address && !g.isAnyLocalAddress) out["gateway"] = g.hostAddress
                }
                out["dns"] = lp.dnsServers.filterIsInstance<Inet4Address>().map { it.hostAddress ?: "" }
            }
            // Привязываем процесс к локальной сети: иначе при Wi-Fi без интернета
            // Android отправит трафик в мобильную сеть и роутеры будут "недоступны".
            if (transport != "cellular") {
                try {
                    cm.bindProcessToNetwork(net)
                    boundNetwork = net
                    out["bound"] = true
                } catch (e: Throwable) {
                    out["bound"] = false
                    out["bindError"] = e.message
                }
            }
        }
        try {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val wi = wm.connectionInfo
            if (wi != null) {
                var ssid = wi.ssid ?: ""
                if (ssid.length >= 2 && ssid.startsWith("\"") && ssid.endsWith("\"")) ssid = ssid.substring(1, ssid.length - 1)
                if (ssid.isNotEmpty() && ssid != "<unknown ssid>") out["ssid"] = ssid
                val b = wi.bssid
                if (b != null && b != "02:00:00:00:00:00") out["bssid"] = b
                out["freq"] = wi.frequency
                out["linkSpeed"] = wi.linkSpeed
                out["rssi"] = wi.rssi
            }
        } catch (e: Throwable) {
            out["wifiInfoError"] = e.message
        }
        out["locationOn"] = locationOn()
        return out
    }

    private fun locationOn(): Boolean {
        return try {
            val lm = getSystemService(Context.LOCATION_SERVICE) as LocationManager
            if (Build.VERSION.SDK_INT >= 28) {
                lm.isLocationEnabled
            } else {
                lm.isProviderEnabled(LocationManager.GPS_PROVIDER) || lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
            }
        } catch (e: Throwable) {
            false
        }
    }

    // ------------------------------------------------------------ permissions

    private fun neededPerms(): Array<String> {
        val l = mutableListOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
        if (Build.VERSION.SDK_INT >= 33) l.add(Manifest.permission.NEARBY_WIFI_DEVICES)
        return l.toTypedArray()
    }

    private fun ensurePermissions(result: MethodChannel.Result) {
        val miss = neededPerms().filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (miss.isEmpty()) {
            result.success(mapOf("granted" to true, "locationOn" to locationOn()))
            return
        }
        if (pendingPerm != null) {
            result.success(mapOf("granted" to false, "locationOn" to locationOn(), "busy" to true))
            return
        }
        pendingPerm = result
        requestPermissions(miss.toTypedArray(), 4242)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 4242) {
            val r = pendingPerm
            pendingPerm = null
            val fine = checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
            r?.success(mapOf("granted" to fine, "locationOn" to locationOn()))
        }
    }

    // ---------------------------------------------------------------- wi-fi

    @Suppress("DEPRECATION")
    @SuppressLint("MissingPermission")
    private fun wifiScan(result: MethodChannel.Result) {
        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            result.success(mapOf("error" to "no_permission"))
            return
        }
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val done = AtomicBoolean(false)
        var receiver: BroadcastReceiver? = null
        val finish = { fresh: Boolean ->
            if (done.compareAndSet(false, true)) {
                try {
                    receiver?.let { unregisterReceiver(it) }
                } catch (e: Throwable) {
                }
                val list: List<Map<String, Any?>> = try {
                    wm.scanResults.map { sr ->
                        mapOf(
                            "ssid" to (sr.SSID ?: ""),
                            "bssid" to (sr.BSSID ?: ""),
                            "freq" to sr.frequency,
                            "level" to sr.level,
                            "caps" to (sr.capabilities ?: ""),
                            "width" to sr.channelWidth,
                            "center0" to sr.centerFreq0
                        )
                    }
                } catch (e: Throwable) {
                    emptyList()
                }
                result.success(mapOf("results" to list, "fresh" to fresh, "locationOn" to locationOn()))
            }
        }
        receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, i: Intent?) {
                finish(i?.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, true) ?: true)
            }
        }
        val filter = IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            registerReceiver(receiver, filter)
        }
        val started = try {
            wm.startScan()
        } catch (e: Throwable) {
            false
        }
        if (!started) finish(false) else main.postDelayed({ finish(false) }, 12000)
    }

    private fun setMulticast(on: Boolean) {
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        if (on) {
            if (mcLock == null) {
                val l = wm.createMulticastLock("wifihelp")
                l.setReferenceCounted(false)
                l.acquire()
                mcLock = l
            }
        } else {
            try {
                mcLock?.release()
            } catch (e: Throwable) {
            }
            mcLock = null
        }
    }

    // ------------------------------------------------------------ ping sweep

    private fun pingSweepAsync(call: MethodCall, result: MethodChannel.Result) {
        val rawRanges = call.argument<List<Any>>("ranges") ?: emptyList()
        val ranges = rawRanges.map { r ->
            val l = r as List<*>
            Pair((l[0] as Number).toLong(), (l[1] as Number).toLong())
        }
        val pps = (call.argument<Any>("pps") as? Number)?.toInt() ?: 8000
        val waitMs = (call.argument<Any>("waitMs") as? Number)?.toInt() ?: 1500
        val exclude = (call.argument<List<Any>>("exclude") ?: emptyList()).map { (it as Number).toLong() }.toHashSet()
        io.execute {
            val r: Map<String, Any?> = try {
                pingSweep(ranges, pps, waitMs, exclude)
            } catch (e: Throwable) {
                mapOf("error" to (e.javaClass.simpleName + ": " + (e.message ?: "")), "alive" to emptyList<Any>())
            }
            main.post { result.success(r) }
        }
    }

    /**
     * Быстрый ICMP-скан через "ping-сокет" (SOCK_DGRAM + IPPROTO_ICMP) — так же
     * работает системный ping, root не нужен. Отправляем эхо-запросы с заданной
     * скоростью, в полезной нагрузке — адрес цели и время отправки.
     */
    private fun pingSweep(ranges: List<Pair<Long, Long>>, pps: Int, waitMs: Int, exclude: Set<Long>): Map<String, Any?> {
        var total = 0L
        for (p in ranges) total += (p.second - p.first + 1)
        val fd: FileDescriptor = Os.socket(OsConstants.AF_INET, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_ICMP)
        val bn = boundNetwork
        if (bn != null) {
            try {
                bn.bindSocket(fd)
            } catch (e: Throwable) {
            }
        }
        val alive = ConcurrentHashMap<Long, Int>()
        val running = AtomicBoolean(true)
        var errors = 0
        val receiver = Thread {
            val buf = ByteArray(1500)
            val pfd = StructPollfd()
            pfd.fd = fd
            pfd.events = OsConstants.POLLIN.toShort()
            while (running.get()) {
                try {
                    pfd.revents = 0
                    val n = Os.poll(arrayOf(pfd), 100)
                    if (n <= 0) continue
                    val len = Os.read(fd, buf, 0, buf.size)
                    if (len >= 20 && (buf[0].toInt() and 0xFF) == 0) {
                        var ip = 0L
                        for (i in 8 until 12) ip = (ip shl 8) or (buf[i].toLong() and 0xFF)
                        var ts = 0L
                        for (i in 12 until 20) ts = (ts shl 8) or (buf[i].toLong() and 0xFF)
                        val rtt = ((System.nanoTime() - ts) / 1_000_000L).toInt()
                        alive.putIfAbsent(ip, if (rtt < 0) 0 else rtt)
                    }
                } catch (e: ErrnoException) {
                    // ICMP-ошибки (недоступен узел и т.п.) приходят сюда — пропускаем
                } catch (e: Throwable) {
                }
            }
        }
        receiver.start()

        val pkt = ByteArray(20)
        var sent = 0L
        var seq = 0
        val batch = maxOf(1, pps / 100) // пакетов за 10 мс
        var inBatch = 0
        var batchStart = System.nanoTime()
        var lastProgress = 0L
        try {
            for (p in ranges) {
                var ip = p.first
                while (ip <= p.second) {
                    val last = ip and 0xFFL
                    if (last != 0L && last != 255L && !exclude.contains(ip)) {
                        for (i in pkt.indices) pkt[i] = 0
                        pkt[0] = 8
                        seq = (seq + 1) and 0xFFFF
                        pkt[6] = (seq shr 8).toByte()
                        pkt[7] = seq.toByte()
                        for (i in 0 until 4) pkt[8 + i] = ((ip shr (24 - 8 * i)) and 0xFFL).toByte()
                        val ts = System.nanoTime()
                        for (i in 0 until 8) pkt[12 + i] = ((ts shr (56 - 8 * i)) and 0xFFL).toByte()
                        val cs = checksum(pkt)
                        pkt[2] = (cs shr 8).toByte()
                        pkt[3] = cs.toByte()
                        val addr = InetAddress.getByAddress(
                            byteArrayOf(
                                ((ip shr 24) and 0xFFL).toByte(),
                                ((ip shr 16) and 0xFFL).toByte(),
                                ((ip shr 8) and 0xFFL).toByte(),
                                (ip and 0xFFL).toByte()
                            )
                        )
                        var tries = 0
                        while (tries < 3) {
                            try {
                                Os.sendto(fd, pkt, 0, pkt.size, 0, addr, 0)
                                break
                            } catch (e: ErrnoException) {
                                if (e.errno == OsConstants.ENOBUFS || e.errno == OsConstants.EAGAIN) {
                                    Thread.sleep(5)
                                    tries++
                                } else {
                                    errors++
                                    break
                                }
                            }
                        }
                        sent++
                        inBatch++
                        if (inBatch >= batch) {
                            inBatch = 0
                            val elapsed = (System.nanoTime() - batchStart) / 1_000_000L
                            if (elapsed < 10) Thread.sleep(10 - elapsed)
                            batchStart = System.nanoTime()
                        }
                        val now = System.currentTimeMillis()
                        if (now - lastProgress > 250) {
                            lastProgress = now
                            val s = sent
                            val f = alive.size
                            main.post {
                                try {
                                    channel.invokeMethod("pingProgress", mapOf("sent" to s, "total" to total, "found" to f))
                                } catch (e: Throwable) {
                                }
                            }
                        }
                    }
                    ip++
                }
            }
            Thread.sleep(waitMs.toLong())
        } finally {
            running.set(false)
            try {
                receiver.join(500)
            } catch (e: Throwable) {
            }
            try {
                Os.close(fd)
            } catch (e: Throwable) {
            }
        }
        val list = alive.entries.map { mapOf("ip" to longToIp(it.key), "rtt" to it.value) }
        return mapOf("alive" to list, "sent" to sent, "sendErrors" to errors)
    }

    private fun checksum(b: ByteArray): Int {
        var sum = 0
        var i = 0
        while (i < b.size - 1) {
            sum += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (b.size % 2 == 1) sum += (b[b.size - 1].toInt() and 0xFF) shl 8
        while ((sum shr 16) != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    private fun longToIp(v: Long): String =
        "${(v shr 24) and 0xFFL}.${(v shr 16) and 0xFFL}.${(v shr 8) and 0xFFL}.${v and 0xFFL}"

    // ------------------------------------------------------------------ arp

    private fun readArp(): Map<String, Any?> {
        val out = ArrayList<Map<String, String>>()
        var source = "none"
        var error: String? = null
        try {
            File("/proc/net/arp").readLines().drop(1).forEach { line ->
                val p = line.trim().split(Regex("\\s+"))
                if (p.size >= 6 && p[3] != "00:00:00:00:00:00" && p[2] != "0x0") {
                    out.add(mapOf("ip" to p[0], "mac" to p[3], "iface" to p[5]))
                }
            }
            source = "proc"
        } catch (e: Throwable) {
            error = "proc: " + (e.message ?: e.javaClass.simpleName)
        }
        if (out.isEmpty()) {
            try {
                val proc = Runtime.getRuntime().exec(arrayOf("ip", "neigh", "show"))
                proc.inputStream.bufferedReader().readLines().forEach { line ->
                    val p = line.trim().split(Regex("\\s+"))
                    val i = p.indexOf("lladdr")
                    if (i > 0 && i + 1 < p.size && p[0].contains('.')) {
                        val d = p.indexOf("dev")
                        val dev = if (d >= 0 && d + 1 < p.size) p[d + 1] else ""
                        out.add(mapOf("ip" to p[0], "mac" to p[i + 1], "iface" to dev))
                    }
                }
                proc.waitFor()
                if (out.isNotEmpty()) source = "ip-neigh"
            } catch (e: Throwable) {
                error = (error ?: "") + "; ip neigh: " + (e.message ?: e.javaClass.simpleName)
            }
        }
        return mapOf("entries" to out, "source" to source, "error" to error)
    }

    // --------------------------------------------------------------- crypto

    private fun secretKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val existing = ks.getKey(keyAlias, null)
        if (existing is SecretKey) return existing
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(
            KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return kg.generateKey()
    }

    private fun encrypt(text: String): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, secretKey())
        val iv = c.iv
        val ct = c.doFinal(text.toByteArray(Charsets.UTF_8))
        val out = ByteArray(1 + iv.size + ct.size)
        out[0] = iv.size.toByte()
        System.arraycopy(iv, 0, out, 1, iv.size)
        System.arraycopy(ct, 0, out, 1 + iv.size, ct.size)
        return Base64.encodeToString(out, Base64.NO_WRAP)
    }

    private fun decrypt(data: String): String {
        if (data.isEmpty()) return ""
        val raw = Base64.decode(data, Base64.NO_WRAP)
        val ivLen = raw[0].toInt()
        val iv = raw.copyOfRange(1, 1 + ivLen)
        val ct = raw.copyOfRange(1 + ivLen, raw.size)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, iv))
        return String(c.doFinal(ct), Charsets.UTF_8)
    }

    // --------------------------------------------------------------- intents

    private fun openUrl(url: String, result: MethodChannel.Result) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            result.success(true)
        } catch (e: Throwable) {
            result.success(false)
        }
    }

    private fun openWeb(call: MethodCall, result: MethodChannel.Result) {
        try {
            val i = Intent(this, WebActivity::class.java)
            i.putExtra("url", call.argument<String>("url") ?: "about:blank")
            i.putExtra("title", call.argument<String>("title") ?: "Роутер")
            call.argument<String>("user")?.let { i.putExtra("user", it) }
            call.argument<String>("pass")?.let { i.putExtra("pass", it) }
            startActivity(i)
            result.success(true)
        } catch (e: Throwable) {
            result.success(false)
        }
    }

    private fun shareText(subject: String, text: String, result: MethodChannel.Result) {
        try {
            val i = Intent(Intent.ACTION_SEND)
                .setType("text/plain")
                .putExtra(Intent.EXTRA_SUBJECT, subject)
                .putExtra(Intent.EXTRA_TEXT, text)
            startActivity(Intent.createChooser(i, subject))
            result.success(true)
        } catch (e: Throwable) {
            result.success(false)
        }
    }

    private fun saveDownload(name: String, text: String): String {
        val bytes = text.toByteArray(Charsets.UTF_8)
        if (Build.VERSION.SDK_INT >= 29) {
            val values = ContentValues()
            values.put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            values.put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
            values.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/WifiHelp")
            val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw IllegalStateException("MediaStore не дал создать файл")
            val os = contentResolver.openOutputStream(uri) ?: throw IllegalStateException("Не открыть файл на запись")
            os.use { it.write(bytes) }
            return "Загрузки/WifiHelp/$name"
        } else {
            val dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: filesDir
            val f = File(dir, name)
            f.writeBytes(bytes)
            return f.absolutePath
        }
    }
}
