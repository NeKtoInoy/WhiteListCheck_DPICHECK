package ru.netstatus.app

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.net.URL
import java.security.SecureRandom

// ============================================================================
// Дополнительные проверки к глубокой диагностике:
//   1) загрузка ~256 КБ с зарубежных серверов: ловит обрыв после первых
//      килобайт (троттлинг), который не виден по одному TCP/TLS-рукопожатию;
//   2) UDP/QUIC: белые списки обычно убивают UDP целиком;
//   3) подбор SNI: какие домены проходят на ваш зарубежный IP в этой сети;
//   4) журнал замеров и уведомление о смене режима сети.
// ============================================================================

object DpiExtra {
    const val GROUP_DL_FOREIGN = "Загрузка 256 КБ: зарубежные серверы"
    const val GROUP_DL_RU = "Загрузка: российский эталон"
    const val GROUP_UDP = "UDP / QUIC (порт 443)"
    const val GROUP_DNS = "DNS-разрешение"
    const val GROUP_SNI_PREFIX = "Подбор SNI на "

    private const val DL_LIMIT = 262_144L
    private const val DL_DEADLINE_MS = 12_000L

    data class DlTarget(val label: String, val url: String, val range: Boolean)

    val dlForeign = listOf(
        DlTarget("Cloudflare", "https://speed.cloudflare.com/__down?bytes=262144", false),
        DlTarget("OVH (FR)", "https://proof.ovh.net/files/1Mb.dat", true),
        DlTarget("Hetzner (DE)", "https://fsn1-speed.hetzner.com/100MB.bin", true)
    )
    val dlRu = listOf(
        DlTarget("Яндекс", "https://ya.ru/", false)
    )

    // Кандидаты в SNI для Reality: российские домены из белых списков и популярные зарубежные.
    private val sniCandidates = listOf(
        "ya.ru", "yandex.ru", "dzen.ru", "vk.com", "vk.ru", "mail.ru", "ok.ru",
        "avito.ru", "ozon.ru", "wildberries.ru", "gosuslugi.ru", "sberbank.ru",
        "vtb.ru", "tbank.ru", "rutube.ru", "kinopoisk.ru", "2gis.ru", "rzd.ru",
        "max.ru", "t2.ru",
        "amazon.com", "www.microsoft.com", "www.apple.com", "www.google.com",
        "github.com", "www.cloudflare.com", "www.samsung.com", "www.yahoo.com"
    )

    private val trackedModes = setOf("whitelist", "ip_filter", "normal", "tls_dpi", "clean")

    // ---------- Режим по заголовку вердикта ----------

    fun modeOf(title: String): String = when {
        title.startsWith("Похоже на БЕЛЫЕ") -> "whitelist"
        title.startsWith("Похоже на ограничение по IP") -> "ip_filter"
        title.startsWith("Обычный режим") -> "normal"
        title.startsWith("Режется сам TLS") -> "tls_dpi"
        title.startsWith("IP-фильтра") -> "clean"
        title.startsWith("Нет выхода") -> "noexit"
        title.startsWith("Отключите VPN") -> "vpn"
        title.startsWith("Нет сети") -> "nonet"
        else -> "unknown"
    }

    // ---------- Загрузка ----------

    internal fun download(group: String, t: DlTarget): DiagStep {
        val t0 = System.currentTimeMillis()
        var total = 0L
        var conn: HttpURLConnection? = null
        try {
            val c = URL(t.url).openConnection() as HttpURLConnection
            conn = c
            c.connectTimeout = 4000
            c.readTimeout = 5000
            c.instanceFollowRedirects = true
            c.setRequestProperty("Accept-Encoding", "identity")
            c.setRequestProperty(
                "User-Agent",
                "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36"
            )
            if (t.range) c.setRequestProperty("Range", "bytes=0-${DL_LIMIT - 1}")
            val code = c.responseCode
            if (code >= 400) {
                return DiagStep(group, t.label, "DL", "", Outcome.OTHER, System.currentTimeMillis() - t0, "HTTP $code")
            }
            val buf = ByteArray(8192)
            var stalled = false
            try {
                c.inputStream.use { s ->
                    while (total < DL_LIMIT) {
                        if (System.currentTimeMillis() - t0 > DL_DEADLINE_MS) {
                            stalled = true
                            break
                        }
                        val n = s.read(buf)
                        if (n < 0) break
                        total += n
                    }
                }
            } catch (e: SocketTimeoutException) {
                stalled = true
            }
            val ms = System.currentTimeMillis() - t0
            val kb = total / 1024
            if (stalled) {
                return DiagStep(group, t.label, "DL", "", Outcome.TIMEOUT, ms, "получено $kb КБ, затем тишина", total)
            }
            if (total == 0L) {
                return DiagStep(group, t.label, "DL", "", Outcome.OTHER, ms, "пустой ответ", 0L)
            }
            val speed = if (ms > 0) total * 1000 / ms / 1024 else 0L
            val sec = String.format(java.util.Locale.US, "%.1f", ms / 1000.0)
            return DiagStep(group, t.label, "DL", "", Outcome.OK, ms, "получено $kb КБ за $sec с (≈$speed КБ/с)", total)
        } catch (e: Exception) {
            return DiagStep(
                group, t.label, "DL", "", DpiProbe.classify(e),
                System.currentTimeMillis() - t0, DpiProbe.shortErr(e), total
            )
        } finally {
            try { conn?.disconnect() } catch (_: Exception) { }
        }
    }

    // ---------- UDP / QUIC ----------

    // Отправляем «заземлённый» QUIC-пакет с неизвестной версией (≥1200 байт).
    // Сервер по RFC 9000 отвечает Version Negotiation без шифрования, так что
    // сам факт ответа показывает, что UDP/443 до него ходит.
    internal fun quic(group: String, label: String, ip: String): DiagStep {
        val t0 = System.currentTimeMillis()
        return try {
            DatagramSocket().use { s ->
                s.soTimeout = 2500
                val rnd = SecureRandom()
                val pkt = ByteArray(1200)
                pkt[0] = 0xC3.toByte()
                pkt[1] = 0x1a
                pkt[2] = 0x2a
                pkt[3] = 0x3a
                pkt[4] = 0x4a
                pkt[5] = 8
                val dcid = ByteArray(8)
                rnd.nextBytes(dcid)
                System.arraycopy(dcid, 0, pkt, 6, 8)
                pkt[14] = 8
                val scid = ByteArray(8)
                rnd.nextBytes(scid)
                System.arraycopy(scid, 0, pkt, 15, 8)
                s.send(DatagramPacket(pkt, pkt.size, InetAddress.getByName(ip), 443))
                val buf = ByteArray(1500)
                val rp = DatagramPacket(buf, buf.size)
                s.receive(rp)
                DiagStep(group, label, "UDP", "", Outcome.OK, System.currentTimeMillis() - t0,
                    "ответ QUIC получен (${rp.length} байт)")
            }
        } catch (e: SocketTimeoutException) {
            DiagStep(group, label, "UDP", "", Outcome.TIMEOUT, System.currentTimeMillis() - t0, "нет ответа за 2.5 с")
        } catch (e: Exception) {
            DiagStep(group, label, "UDP", "", DpiProbe.classify(e), System.currentTimeMillis() - t0, DpiProbe.shortErr(e))
        }
    }

    internal suspend fun udpAll(): List<DiagStep> = coroutineScope {
        val targets = listOf("Cloudflare" to "1.1.1.1", "Google" to "google.com", "Яндекс" to "ya.ru")
        targets.map { (label, host) ->
            async(Dispatchers.IO) {
                val ip = DpiProbe.resolve(host)
                if (ip == null)
                    DiagStep(GROUP_UDP, label, "DNS", "", Outcome.DNS_FAIL, 0L, "адрес не разрешился")
                else
                    quic(GROUP_UDP, label, ip)
            }
        }.awaitAll()
    }

    // ---------- DNS ----------

    internal suspend fun dnsAll(): List<DiagStep> = coroutineScope {
        val names = listOf("ya.ru", "google.com", "www.instagram.com", "rutracker.org")
        names.map { n ->
            async(Dispatchers.IO) {
                val t0 = System.currentTimeMillis()
                val job = DpiProbe.ioScope.async {
                    try {
                        InetAddress.getAllByName(n).firstOrNull { it is Inet4Address }?.hostAddress
                    } catch (_: Exception) {
                        null
                    }
                }
                val ip = withTimeoutOrNull(4000L) { job.await() }
                val ms = System.currentTimeMillis() - t0
                if (ip == null)
                    DiagStep(GROUP_DNS, n, "DNS", "", Outcome.DNS_FAIL, ms, "не разрешился")
                else
                    DiagStep(GROUP_DNS, n, "DNS", "", Outcome.OK, ms, ip)
            }
        }.awaitAll()
    }

    // Адрес из частных/служебных диапазонов в ответе на публичное имя = подмена DNS.
    private fun isFakeIp(ip: String): Boolean {
        if (ip.startsWith("0.") || ip.startsWith("127.") || ip.startsWith("10.") ||
            ip.startsWith("192.168.") || ip.startsWith("169.254.")
        ) return true
        if (ip.startsWith("172.")) {
            val second = ip.split(".").getOrNull(1)?.toIntOrNull() ?: return false
            return second in 16..31
        }
        return false
    }

    // ---------- Подбор SNI ----------

    internal suspend fun sniPick(own: List<OwnServer>): List<DiagStep> = coroutineScope {
        val sw = own.firstOrNull { it.label.startsWith("SW") }
        val label = sw?.label ?: "1.1.1.1"
        val host = sw?.host ?: "1.1.1.1"
        val port = sw?.port ?: 443
        val group = GROUP_SNI_PREFIX + label
        val ip = DpiProbe.resolve(host)
        if (ip == null) {
            return@coroutineScope listOf(
                DiagStep(group, label, "DNS", "", Outcome.DNS_FAIL, 0L, "адрес не разрешился")
            )
        }
        val tcp = withContext(Dispatchers.IO) { DpiProbe.tcpStep(group, label, ip, port) }
        if (!tcp.outcome.reached()) return@coroutineScope listOf(tcp)
        val sem = Semaphore(8)
        val tls = sniCandidates.map { sni ->
            async(Dispatchers.IO) {
                sem.withPermit { DpiProbe.tlsStep(group, label, ip, port, sni, sni) }
            }
        }.awaitAll()
        listOf(tcp) + tls
    }

    // ---------- Разбор дополнительных проверок ----------

    data class Analysis(val flags: List<String>, val lines: List<String>)

    fun analyze(steps: List<DiagStep>): Analysis {
        val flags = mutableListOf<String>()
        val lines = mutableListOf<String>()

        // Загрузка: информативны только OK / тишина / сброс (HTTP-ошибки и DNS не считаем).
        fun informative(s: DiagStep) =
            s.outcome == Outcome.OK || s.outcome == Outcome.TIMEOUT || s.outcome == Outcome.RESET
        val dlF = steps.filter { it.group == GROUP_DL_FOREIGN && informative(it) }
        val ruOk = steps.any { it.group == GROUP_DL_RU && it.outcome == Outcome.OK }
        if (dlF.isNotEmpty()) {
            val bad = dlF.filter { it.outcome != Outcome.OK }
            if (bad.size * 2 >= dlF.size) {
                val kbs = bad.map { it.value / 1024 }.sorted()
                val med = kbs[kbs.size / 2]
                val head = if (med == 0L) "Загрузки с зарубежных серверов не идут"
                           else "Загрузки с зарубежных серверов обрываются после ~$med КБ"
                val classic = if (med in 8L..40L) " (похоже на известный обрыв после ~16 КБ)" else ""
                val ru = if (ruOk) ", российские сайты грузятся нормально" else ""
                flags += head + classic + ru
                lines += "Загрузка 256 КБ: обрыв у ${bad.size} из ${dlF.size} зарубежных серверов."
            } else {
                lines += "Загрузка 256 КБ с зарубежных серверов проходит" +
                    (if (bad.isEmpty()) " без обрывов." else ", кроме: " + bad.joinToString(", ") { it.target } + ".")
                if (bad.isNotEmpty()) {
                    flags += "Не отвечают отдельные серверы: " + bad.joinToString(", ") { it.target } +
                        " (возможно, блокируется диапазон хостера)"
                }
            }
        }

        // UDP/QUIC.
        val udp = steps.filter { it.group == GROUP_UDP }
        val uF = udp.filter { it.target != "Яндекс" }
        val uR = udp.filter { it.target == "Яндекс" }
        if (uF.isNotEmpty()) {
            val uBad = uF.filter { it.outcome != Outcome.OK }
            if (uF.none { it.outcome == Outcome.OK }) {
                flags += if (uR.any { it.outcome == Outcome.OK })
                    "UDP/QUIC: нет ответа от зарубежных адресов (от российских есть)"
                else
                    "UDP/QUIC: нет ответа ни от зарубежных, ни от российских адресов"
            } else if (uBad.isNotEmpty()) {
                flags += "UDP/QUIC: нет ответа от " + uBad.joinToString(", ") { it.target }
                lines += "UDP/QUIC до зарубежных адресов проходит частично."
            } else {
                lines += "UDP/QUIC до зарубежных адресов проходит."
            }
        }

        // DNS.
        val dns = steps.filter { it.group == GROUP_DNS }
        if (dns.isNotEmpty()) {
            val failed = dns.filter { it.outcome != Outcome.OK }
            val fake = dns.filter { it.outcome == Outcome.OK && isFakeIp(it.detail) }
            if (failed.isNotEmpty()) flags += "DNS не отвечает для: " + failed.joinToString(", ") { it.target }
            if (fake.isNotEmpty()) {
                flags += "DNS подменяет ответ: " + fake.joinToString(", ") { it.target + " → " + it.detail }
            }
            lines += "DNS: " + dns.joinToString("; ") {
                it.target + " " + (if (it.outcome == Outcome.OK) it.detail else "нет ответа")
            }
        }

        // Подбор SNI.
        val sni = steps.filter { it.group.startsWith(GROUP_SNI_PREFIX) && it.stage == "TLS" }
        if (sni.isNotEmpty()) {
            val where = sni.first().target
            val ok = sni.filter { it.outcome.reached() }.map { it.sniKind }
            val silent = sni.filter { it.outcome == Outcome.TIMEOUT }.map { it.sniKind }
            val rst = sni.filter { it.outcome == Outcome.RESET }.map { it.sniKind }
            val other = sni.filter { !it.outcome.reached() && it.outcome != Outcome.TIMEOUT && it.outcome != Outcome.RESET }
                .map { it.sniKind }
            flags += "Подбор SNI на $where: проходят ${ok.size} из ${sni.size}"
            val ruSilent = silent.filter { it.endsWith(".ru") }
            if (ruSilent.size >= 3) {
                flags += "Часть российских SNI молча отбрасывается на зарубежном IP (" +
                    ruSilent.take(5).joinToString(", ") + (if (ruSilent.size > 5) "…" else "") +
                    "): не берите их для Reality"
            }
            lines += "SNI проходят: " + (if (ok.isEmpty()) "ни один" else ok.joinToString(", "))
            if (silent.isNotEmpty()) lines += "SNI режутся молча (тишина): " + silent.joinToString(", ")
            if (rst.isNotEmpty()) lines += "SNI режутся сбросом (RST): " + rst.joinToString(", ")
            if (other.isNotEmpty()) lines += "SNI, другие ошибки: " + other.joinToString(", ")
        }
        return Analysis(flags, lines)
    }

    // ---------- Фоновый запуск + уведомление о смене режима ----------

    suspend fun runBackground(ctx: Context) {
        val net = Scanner.networkType(ctx)
        val op = if (net == "мобильный интернет") Scanner.operatorName(ctx) else ""
        val r = DpiProbe.run(OwnServers.list, net, op, light = true)
        val prev = DiagHistory.lastMode(ctx)
        DiagHistory.record(ctx, r)
        if (prev != null && r.mode != prev && r.mode in trackedModes) {
            notifyMode(ctx, "Режим сети изменился. " + r.modeLine())
        }
    }

    private fun notifyMode(ctx: Context, text: String) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) return
        val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel("netmode", "Режим сети", NotificationManager.IMPORTANCE_DEFAULT)
        )
        val launch = ctx.packageManager.getLaunchIntentForPackage(ctx.packageName)
            ?: Intent(ctx, MainActivity::class.java)
        val pi = PendingIntent.getActivity(ctx, 0, launch, PendingIntent.FLAG_IMMUTABLE)
        val notif = Notification.Builder(ctx, "netmode")
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentTitle("Белый список?")
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        nm.notify(2, notif)
    }
}

// ---------- Журнал замеров ----------

object DiagHistory {
    private const val FILE = "diag_history.jsonl"
    private const val MAX = 1000
    private val tracked = setOf("whitelist", "ip_filter", "normal", "tls_dpi", "clean")

    data class Entry(
        val time: Long,
        val network: String,
        val operator: String,
        val mode: String,
        val title: String
    )

    @Synchronized
    fun record(ctx: Context, r: DiagReport) {
        try {
            val o = JSONObject()
            o.put("t", r.time)
            o.put("net", r.network)
            o.put("op", r.operator)
            o.put("mode", r.mode)
            o.put("title", r.verdictTitle)
            o.put("flags", JSONArray(r.flags))
            val st = JSONArray()
            for (s in r.steps) {
                st.put("${s.target}|${s.stage}|${s.sniKind}|${s.outcome}|${s.ms}")
            }
            o.put("steps", st)
            val f = File(ctx.filesDir, FILE)
            f.appendText(o.toString() + "\n")
            val lines = f.readLines()
            if (lines.size > MAX + 200) {
                f.writeText(lines.takeLast(MAX).joinToString("\n") + "\n")
            }
            if (r.mode in tracked) {
                ctx.getSharedPreferences("netstatus", Context.MODE_PRIVATE)
                    .edit().putString("last_diag_mode", r.mode).apply()
            }
        } catch (_: Exception) { }
    }

    fun lastMode(ctx: Context): String? =
        ctx.getSharedPreferences("netstatus", Context.MODE_PRIVATE).getString("last_diag_mode", null)

    @Synchronized
    fun readAll(ctx: Context): List<Entry> {
        val f = File(ctx.filesDir, FILE)
        if (!f.exists()) return emptyList()
        val out = mutableListOf<Entry>()
        try {
            for (line in f.readLines()) {
                if (line.isBlank()) continue
                try {
                    val o = JSONObject(line)
                    out += Entry(
                        o.optLong("t"), o.optString("net"), o.optString("op"),
                        o.optString("mode"), o.optString("title")
                    )
                } catch (_: Exception) { }
            }
        } catch (_: Exception) { }
        return out
    }

    // Последние замеры одним текстом (по строке JSON на замер) для отправки.
    @Synchronized
    fun exportText(ctx: Context, last: Int = 100): String {
        val f = File(ctx.filesDir, FILE)
        if (!f.exists()) return ""
        return try {
            f.readLines().filter { it.isNotBlank() }.takeLast(last).joinToString("\n")
        } catch (_: Exception) {
            ""
        }
    }
}
