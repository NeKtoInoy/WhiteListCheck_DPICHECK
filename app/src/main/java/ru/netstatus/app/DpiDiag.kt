package ru.netstatus.app

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.*
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

// ============================================================================
// Глубокая диагностика: «белые списки или DPI?»
//
// Обычная проверка приложения отвечает на вопрос «открываются ли сайты».
// Здесь мы смотрим, НА КАКОМ ЭТАПЕ соединение ломается, потому что у разных
// видов блокировки разный «почерк»:
//
//   * Белые списки (фильтр по IP, L3): TCP-соединение до постороннего IP
//     даже не устанавливается — SYN уходит в пустоту, таймаут.
//   * DPI по SNI (L7): TCP устанавливается нормально, а после отправки TLS
//     ClientHello с «плохим» SNI приходит RST либо наступает тишина.
//   * Блок конкретного IP/порта вашего сервера: до сервера не достучаться,
//     при этом остальной интернет доступен.
//
// TLS-рукопожатие делается БЕЗ проверки сертификата и БЕЗ отправки данных:
// нам нужен только факт, дошло ли рукопожатие до сервера. Это диагностика,
// а не защищённое соединение, никаких запросов и секретов тут не передаётся.
// ============================================================================

const val DIAG_SNI_BLOCKED = "www.instagram.com" // заведомо «плохой» SNI
const val DIAG_SNI_WHITE = "ya.ru"                // заведомо «хороший» SNI

enum class Outcome { OK, ALERT, TIMEOUT, RESET, REFUSED, UNREACHABLE, DNS_FAIL, OTHER }

// ALERT = сервер ответил TLS-ошибкой (alert). Значит, пакет до сервера дошёл и
// ответ вернулся, то есть сеть не блокирует. Для диагностики это «успех».
fun Outcome.reached(): Boolean = this == Outcome.OK || this == Outcome.ALERT

data class DiagStep(
    val group: String,   // GROUP_*
    val target: String,  // например «1.1.1.1»
    val stage: String,   // «TCP» или «TLS»
    val sniKind: String, // для TLS: «свой», «плохой», «белый», «сервера»; для TCP пусто
    val outcome: Outcome,
    val ms: Long,
    val detail: String,
    val value: Long = 0L // для загрузки: сколько байт получено
)

data class DiagReport(
    val steps: List<DiagStep>,
    val verdictTitle: String,
    val verdictText: String,
    val network: String,
    val operator: String,
    val time: Long,
    val flags: List<String> = emptyList(),
    val mode: String = ""
)

const val GROUP_FOREIGN = "Зарубежные IP (вне белого списка)"
const val GROUP_WHITE = "Российские IP (эталон из белого списка)"
const val GROUP_OWN = "Ваш сервер"

object DpiProbe {
    private const val CONNECT_MS = 4000
    private const val READ_MS = 5000
    private const val TOTAL_MS = 45_000L

    // Отдельный scope для блокирующих сокетов (по образцу Scanner): зависший
    // поток не должен держать вызывающего.
    internal val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // Нейтральные зарубежные IP с открытым 443 и родным SNI.
    private val foreignRefs = listOf(
        "1.1.1.1" to "one.one.one.one",
        "8.8.8.8" to "dns.google",
        "9.9.9.9" to "dns.quad9.net"
    )

    // Российские эталоны: IP получаем через DNS.
    private val whiteRefs = listOf("ya.ru", "vk.com")

    // Принимаем любой сертификат: нам важно лишь, дошло ли рукопожатие.
    private val trustAll: Array<TrustManager> = arrayOf(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    })

    fun classify(e: Throwable): Outcome {
        val sb = StringBuilder()
        var t: Throwable? = e
        var depth = 0
        while (t != null && depth < 5) {
            sb.append(t.javaClass.simpleName).append(':').append(t.message ?: "").append('|')
            t = t.cause
            depth++
        }
        val s = sb.toString().lowercase()
        return when {
            e is SocketTimeoutException || "timed out" in s || "etimedout" in s -> Outcome.TIMEOUT
            "refused" in s || "econnrefused" in s -> Outcome.REFUSED
            "unreachable" in s || "no route" in s || "enetunreach" in s || "ehostunreach" in s ->
                Outcome.UNREACHABLE
            "unknownhost" in s || "unable to resolve" in s -> Outcome.DNS_FAIL
            // Сервер ответил TLS-alert: значит, до него дошли.
            "alert" in s || "handshake_failure" in s || "unrecognized_name" in s ||
                "protocol_version" in s -> Outcome.ALERT
            "reset" in s || "econnreset" in s || "closed by peer" in s || "broken pipe" in s ||
                "epipe" in s || "unexpected end of stream" in s || "connection closed" in s ||
                "eof" in s -> Outcome.RESET
            else -> Outcome.OTHER
        }
    }

    internal fun shortErr(e: Throwable): String {
        val m = e.message?.take(80)
        return if (m.isNullOrBlank()) e.javaClass.simpleName else "${e.javaClass.simpleName}: $m"
    }

    // DNS с потолком по времени (InetAddress.getByName сам таймаута не имеет).
    internal suspend fun resolve(host: String): String? {
        // Литерал IPv4 разбирать через DNS не нужно.
        if (Regex("""\d{1,3}(\.\d{1,3}){3}""").matches(host)) return host
        val job = ioScope.async {
            try {
                InetAddress.getAllByName(host).firstOrNull { it is Inet4Address }?.hostAddress
            } catch (_: Exception) {
                null
            }
        }
        return withTimeoutOrNull(4000L) { job.await() }
    }

    internal fun tcpStep(group: String, target: String, ip: String, port: Int): DiagStep {
        val t0 = System.currentTimeMillis()
        return try {
            Socket().use { it.connect(InetSocketAddress(ip, port), CONNECT_MS) }
            DiagStep(group, target, "TCP", "", Outcome.OK, System.currentTimeMillis() - t0, "соединение открыто")
        } catch (e: Exception) {
            DiagStep(group, target, "TCP", "", classify(e), System.currentTimeMillis() - t0, shortErr(e))
        }
    }

    internal fun tlsStep(
        group: String, target: String, ip: String, port: Int, sni: String, kind: String
    ): DiagStep {
        val t0 = System.currentTimeMillis()
        var plain: Socket? = null
        return try {
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, trustAll, SecureRandom())
            plain = Socket()
            plain.connect(InetSocketAddress(ip, port), CONNECT_MS)
            plain.soTimeout = READ_MS
            val ssl = ctx.socketFactory.createSocket(plain, sni, port, true) as SSLSocket
            val params = ssl.sslParameters
            params.serverNames = listOf<SNIServerName>(SNIHostName(sni))
            ssl.sslParameters = params
            ssl.soTimeout = READ_MS
            ssl.startHandshake()
            ssl.close()
            DiagStep(group, target, "TLS", kind, Outcome.OK, System.currentTimeMillis() - t0, "рукопожатие прошло")
        } catch (e: Exception) {
            try { plain?.close() } catch (_: Exception) { }
            DiagStep(group, target, "TLS", kind, classify(e), System.currentTimeMillis() - t0, shortErr(e))
        }
    }

    // Одна цель: сначала TCP; если открылся — TLS с набором SNI.
    private suspend fun probeTarget(
        group: String,
        target: String,
        host: String,
        port: Int,
        snis: List<Pair<String, String>> // (SNI, вид)
    ): List<DiagStep> = coroutineScope {
        val ip = resolve(host)
        if (ip == null) {
            return@coroutineScope listOf(
                DiagStep(group, target, "DNS", "", Outcome.DNS_FAIL, 0L, "адрес не разрешился")
            )
        }
        val tcp = withContext(Dispatchers.IO) { tcpStep(group, target, ip, port) }
        if (!tcp.outcome.reached()) return@coroutineScope listOf(tcp)
        val tls = snis.map { (sni, kind) ->
            async(Dispatchers.IO) { tlsStep(group, target, ip, port, sni, kind) }
        }.awaitAll()
        listOf(tcp) + tls
    }

    suspend fun run(own: List<OwnServer>, network: String, operator: String): DiagReport {
        if (network == "VPN" || network == "нет сети") {
            val (t, x) = verdict(emptyList(), network)
            return DiagReport(emptyList(), t, x, network, operator, System.currentTimeMillis(), emptyList(), DpiExtra.modeOf(t))
        }
        val steps: List<DiagStep> = withTimeoutOrNull(TOTAL_MS) {
            coroutineScope {
                val jobs = mutableListOf<Deferred<List<DiagStep>>>()
                for ((ip, name) in foreignRefs) {
                    jobs += async {
                        probeTarget(
                            GROUP_FOREIGN, ip, ip, 443,
                            listOf(name to "свой", DIAG_SNI_BLOCKED to "плохой", DIAG_SNI_WHITE to "белый")
                        )
                    }
                }
                for (h in whiteRefs) {
                    jobs += async {
                        probeTarget(
                            GROUP_WHITE, h, h, 443,
                            listOf(h to "свой", DIAG_SNI_BLOCKED to "плохой")
                        )
                    }
                }
                for (o in own) {
                    jobs += async {
                        val snis = if (o.sni.isNotBlank()) listOf(o.sni to "сервера") else emptyList()
                        probeTarget(GROUP_OWN, o.label, o.host, o.port, snis)
                    }
                }
                for (t in DpiExtra.dlForeign) {
                    jobs += async(Dispatchers.IO) { listOf(DpiExtra.download(DpiExtra.GROUP_DL_FOREIGN, t)) }
                }
                for (t in DpiExtra.dlRu) {
                    jobs += async(Dispatchers.IO) { listOf(DpiExtra.download(DpiExtra.GROUP_DL_RU, t)) }
                }
                jobs += async { DpiExtra.udpAll() }
                jobs += async { DpiExtra.sniPick(own) }
                jobs.awaitAll().flatten()
            }
        } ?: emptyList()
        val (title, text) = verdict(steps, network)
        val analysis = DpiExtra.analyze(steps)
        return DiagReport(steps, title, text, network, operator, System.currentTimeMillis(), analysis.flags, DpiExtra.modeOf(title))
    }

    // ---------- Вердикт ----------

    private fun majority(count: Int, total: Int) = total > 0 && count * 2 >= total

    fun verdict(steps: List<DiagStep>, network: String): Pair<String, String> {
        if (network == "VPN") {
            return "Отключите VPN и повторите" to
                "Пока включён VPN, проверка идёт через туннель и ничего не говорит о сети оператора."
        }
        if (network == "нет сети") {
            return "Нет сети" to "Телефон не подключён к сети. Включите мобильный интернет или Wi-Fi."
        }
        if (steps.isEmpty()) {
            return "Проверка не успела завершиться" to
                "Не получили ни одного результата за отведённое время. Попробуйте ещё раз."
        }

        val foreign = steps.filter { it.group == GROUP_FOREIGN }
        val white = steps.filter { it.group == GROUP_WHITE }
        val own = steps.filter { it.group == GROUP_OWN }

        // TCP-этап: DNS-сбой тоже считаем отдельным «не дошли».
        fun tcp(list: List<DiagStep>) = list.filter { it.stage == "TCP" || it.stage == "DNS" }
        val fTcp = tcp(foreign)
        val wTcp = tcp(white)
        val fOk = majority(fTcp.count { it.outcome.reached() && it.stage == "TCP" }, fTcp.size)
        val wOk = majority(wTcp.count { it.outcome.reached() && it.stage == "TCP" }, wTcp.size)
        val fTimeouts = fTcp.count { it.outcome == Outcome.TIMEOUT }

        val base: Pair<String, String> = when {
            !wOk && !fOk ->
                "Нет выхода наружу" to
                    "Не открывается ни российский эталон, ни зарубежный. Возможна полная потеря связи " +
                    "или проблемы с DNS. Проверьте сигнал и повторите."

            wOk && !fOk ->
                if (majority(fTimeouts, fTcp.size))
                    "Похоже на БЕЛЫЕ СПИСКИ (фильтр по IP)" to
                        "Российские IP доступны, а TCP до нейтральных зарубежных IP не устанавливается " +
                        "(таймаут). Это блокировка на уровне IP-адресов: смена SNI или транспорта не " +
                        "поможет. Нужен вход (RU-сервер) с IP из белого списка."
                else
                    "Похоже на ограничение по IP со сбросом" to
                        "Российские IP доступны, а соединения с зарубежными IP сбрасываются или " +
                        "отклоняются. Это тоже фильтр на уровне IP/маршрутов, а не только DPI по SNI."

            else -> {
                // IP-фильтра не видно, смотрим на TLS.
                val honest = (foreign + white).filter { it.stage == "TLS" && it.sniKind == "свой" }
                val bad = (foreign + white).filter { it.stage == "TLS" && it.sniKind == "плохой" }
                val honestOk = honest.count { it.outcome.reached() }
                val badFail = bad.count { !it.outcome.reached() }
                val badFailKinds = bad.filter { !it.outcome.reached() }.map { it.outcome }
                val white2 = foreign.filter { it.stage == "TLS" && it.sniKind == "белый" }
                when {
                    majority(honestOk, honest.size) && majority(badFail, bad.size) ->
                        "Обычный режим: DPI режет только запрещённые SNI" to
                            "Белых списков по IP нет: TCP до зарубежных адресов открывается, TLS с обычным " +
                            "SNI проходит. Запрещённый SNI (${DIAG_SNI_BLOCKED}) на тот же IP " +
                            (if (badFailKinds.count { it == Outcome.RESET } * 2 >= badFailKinds.size)
                                "получает сброс (RST)" else "обрывается без ответа") +
                            ". Это нормально для России: так работает чёрный список доменов. " +
                            "Он мешает вашему серверу, только если SNI вашего Reality похож на заблокированный." +
                            if (white2.isNotEmpty() && white2.any { it.outcome.reached() })
                                " Российский SNI (${DIAG_SNI_WHITE}) на зарубежном IP проходит: подмена SNI " +
                                "в этой сети не режется."
                            else if (white2.isNotEmpty())
                                " Российский SNI (${DIAG_SNI_WHITE}) на зарубежном IP тоже режется: " +
                                "оператор проверяет связку IP + SNI."
                            else ""

                    !majority(honestOk, honest.size) && honest.isNotEmpty() ->
                        "Режется сам TLS-трафик" to
                            "TCP открывается, но даже обычное TLS-рукопожатие не проходит. Похоже на " +
                            "агрессивный DPI или проблемы на маршруте. Повторите проверку и сравните с Wi-Fi."

                    else ->
                        "IP-фильтра и DPI по SNI не видно" to
                            "На этом уровне ограничений нет: TCP и TLS до эталонных адресов проходят, " +
                            "в том числе с запрещённым SNI. Если ваш сервер не работает, смотрите блок " +
                            "«Ваш сервер» ниже."
                }
            }
        }

        // Добавка про собственные серверы (по одному абзацу на каждый).
        if (own.isEmpty()) return base
        val lines = own.map { it.target }.distinct().mapNotNull { label ->
            val mine = own.filter { it.target == label }
            val ownTcp = mine.firstOrNull { it.stage == "TCP" || it.stage == "DNS" }
            val ownTls = mine.filter { it.stage == "TLS" }
            when {
                ownTcp == null -> null
                ownTcp.stage == "DNS" -> "$label: адрес не разрешился (DNS)."
                !ownTcp.outcome.reached() -> {
                    val kind = when (ownTcp.outcome) {
                        Outcome.TIMEOUT -> "таймаут"
                        Outcome.REFUSED -> "порт закрыт или отклонён"
                        Outcome.RESET -> "сброс соединения"
                        else -> "не открывается"
                    }
                    if (wOk && fOk)
                        "$label: TCP не проходит ($kind), хотя остальной интернет доступен. " +
                            "Похоже, блокируется именно этот IP или порт, либо сервер не отвечает."
                    else
                        "$label: TCP не проходит ($kind). При фильтре по IP это ожидаемо, " +
                            "если адрес не в белом списке."
                }
                ownTls.isNotEmpty() && ownTls.none { it.outcome.reached() } ->
                    "$label: TCP открывается, но TLS-рукопожатие обрывается (" +
                        (if (ownTls.first().outcome == Outcome.RESET) "RST" else "тишина") +
                        "). Похоже, DPI режет соединение к серверу: нужен другой SNI или транспорт XHTTP."
                else ->
                    "$label: TCP и TLS проходят, сеть сервер не режет " +
                        "(это не гарантирует, что VLESS работает, но на этих уровнях блокировки нет)."
            }
        }
        return if (lines.isEmpty()) base else base.first to (base.second + "\n\n" + lines.joinToString("\n"))
    }

    // ---------- Текстовый отчёт ----------

    fun reportText(r: DiagReport): String {
        val sb = StringBuilder()
        val time = java.text.SimpleDateFormat("dd.MM.yyyy HH:mm", java.util.Locale("ru"))
            .format(java.util.Date(r.time))
        sb.append("Глубокая диагностика $time\n")
        val net = if (r.operator.isNotBlank()) "${r.network} · ${r.operator}" else r.network
        sb.append("Сеть: $net\n")
        sb.append("Вердикт: ${r.verdictTitle}\n${r.verdictText}\n")
        if (r.flags.isNotEmpty()) {
            sb.append("\nОсобенности:\n")
            for (f in r.flags) sb.append("  • $f\n")
        }
        sb.append("\n")
        var group = ""
        for (s in r.steps) {
            if (s.group.startsWith(DpiExtra.GROUP_SNI_PREFIX)) continue
            if (s.group != group) {
                group = s.group
                sb.append("[$group]\n")
            }
            val st = if (s.stage == "TLS") "TLS(${s.sniKind})" else s.stage
            sb.append("  ${s.target} $st: ${s.outcome} ${s.ms}мс — ${s.detail}\n")
        }
        val extra = DpiExtra.analyze(r.steps).lines
        if (extra.isNotEmpty()) {
            sb.append("\n[Дополнительно]\n")
            for (l in extra) sb.append("  $l\n")
        }
        return sb.toString()
    }
}

// ---------- Состояние (на уровне процесса, переживает смену экранов) ----------

object DiagHolder {
    var report by mutableStateOf<DiagReport?>(null)
    var running by mutableStateOf(false)
    var expanded by mutableStateOf(false)
}

// Серверы владельца. IP, порт и SNI подставляются при сборке (секреты CI),
// в исходниках репозитория их нет. В отчётах показывается только метка.
data class OwnServer(val label: String, val host: String, val port: Int, val sni: String)

object OwnServers {
    val list: List<OwnServer> = listOf(
        OwnServer("RU-1", BuildConfig.OWN_RU_HOST, BuildConfig.OWN_RU_PORT.toIntOrNull() ?: 443, BuildConfig.OWN_RU_SNI),
        OwnServer("SW-1", BuildConfig.OWN_SW_HOST, BuildConfig.OWN_SW_PORT.toIntOrNull() ?: 443, BuildConfig.OWN_SW_SNI)
    ).filter { it.host.isNotBlank() }
}

// Запуск диагностики. Вызывается автоматически вместе с основной проверкой.
fun startDiag(context: Context, scope: CoroutineScope) {
    if (DiagHolder.running) return
    DiagHolder.running = true
    scope.launch {
        try {
            val net = Scanner.networkType(context)
            val op = if (net == "мобильный интернет") Scanner.operatorName(context) else ""
            val r = DpiProbe.run(OwnServers.list, net, op)
            DiagHolder.report = r
            DiagHistory.record(context, r)
        } finally {
            DiagHolder.running = false
        }
    }
}

// Короткая пометка о режиме сети для главного экрана.
fun DiagReport.modeLine(): String = when {
    verdictTitle.startsWith("Похоже на БЕЛЫЕ") ->
        "Белые списки: открываются российские адреса, зарубежные нет (фильтр по IP)."
    verdictTitle.startsWith("Похоже на ограничение по IP") ->
        "Зарубежные адреса сбрасываются: похоже на фильтр по IP."
    verdictTitle.startsWith("Обычный режим") ->
        "Обычный режим: белых списков нет, DPI режет только запрещённые домены."
    verdictTitle.startsWith("Режется сам TLS") ->
        "DPI: режется даже обычный защищённый трафик."
    verdictTitle.startsWith("IP-фильтра") ->
        "Ограничений по IP и SNI не видно."
    verdictTitle.startsWith("Нет выхода") ->
        "Нет выхода наружу: проверьте сигнал и повторите."
    verdictTitle.startsWith("Отключите VPN") ->
        "Выключите VPN: с ним сеть оператора не проверить."
    else -> verdictTitle
}

// Пометка о режиме сети под главным вердиктом.
@Composable
fun DiagSummary() {
    val r = DiagHolder.report
    val running = DiagHolder.running
    if (r == null && !running) return
    Surface(
        Modifier.fillMaxWidth().padding(top = 8.dp),
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceVariant
    ) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 8.dp)) {
            Text(
                "Режим сети",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                if (running && r == null) "проверяю…" else r!!.modeLine(),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            if (r != null) {
                r.flags.take(4).forEach { f ->
                    Text(
                        "• $f",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 2.dp)
                    )
                }
            }
        }
    }
}

// ---------- Интерфейс ----------

private fun outcomeLabel(o: Outcome): String = when (o) {
    Outcome.OK -> "ок"
    Outcome.ALERT -> "ответил (TLS-alert)"
    Outcome.TIMEOUT -> "таймаут"
    Outcome.RESET -> "сброс (RST)"
    Outcome.REFUSED -> "отклонено"
    Outcome.UNREACHABLE -> "недоступно"
    Outcome.DNS_FAIL -> "DNS"
    Outcome.OTHER -> "ошибка"
}

// Сворачиваемая карточка «Подробнее»: этапы TCP/TLS, пояснение и отправка отчёта.
@Composable
fun DiagCard(scope: CoroutineScope, networkType: String, operator: String) {
    val context = LocalContext.current
    val report = DiagHolder.report
    val running = DiagHolder.running
    val expanded = DiagHolder.expanded

    Surface(
        Modifier.fillMaxWidth().padding(top = 12.dp),
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant
    ) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .tvFocusHighlight()
                    .clickable { DiagHolder.expanded = !DiagHolder.expanded }
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        "Подробнее: что именно проверялось",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        if (running) "проверка…" else if (report == null) "ещё не запускалась" else "этапы TCP и TLS",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Icon(
                    if (expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                    contentDescription = if (expanded) "Свернуть" else "Развернуть",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (expanded) {
                if (running) {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth().padding(top = 10.dp))
                }
                if (report != null && !running) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        report.verdictTitle,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        report.verdictText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(top = 4.dp)
                    )

                    var group = ""
                    report.steps.filter { !it.group.startsWith(DpiExtra.GROUP_SNI_PREFIX) }.forEach { s ->
                        if (s.group != group) {
                            group = s.group
                            Text(
                                group,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(top = 10.dp, bottom = 2.dp)
                            )
                        }
                        Row(
                            Modifier.fillMaxWidth().padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            StatusBadge(s.outcome.reached())
                            Spacer(Modifier.width(8.dp))
                            Text(
                                s.target + " · " +
                                    (if (s.stage == "TLS") "TLS (SNI ${s.sniKind})" else s.stage),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.weight(1f)
                            )
                            Text(
                                if (s.stage == "DL" || s.stage == "UDP") s.detail
                                else outcomeLabel(s.outcome) + if (s.outcome.reached()) " · ${s.ms} мс" else "",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                textAlign = TextAlign.End,
                                modifier = Modifier.padding(start = 8.dp)
                            )
                        }
                    }

                    val extra = DpiExtra.analyze(report.steps).lines
                    if (extra.isNotEmpty()) {
                        Text(
                            "Дополнительно",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 10.dp, bottom = 2.dp)
                        )
                        extra.forEach { l ->
                            Text(
                                l,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.padding(vertical = 1.dp)
                            )
                        }
                    }

                    OutlinedButton(
                        onClick = {
                            val intent = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, DpiProbe.reportText(report))
                            }
                            context.startActivity(Intent.createChooser(intent, "Отправить отчёт"))
                        },
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth().padding(top = 12.dp)
                    ) {
                        Text("Отправить подробный отчёт")
                    }
                }
                val hist = remember(report, expanded) {
                    try { DiagHistory.readAll(context).takeLast(8).reversed() } catch (_: Exception) { emptyList<DiagHistory.Entry>() }
                }
                if (hist.isNotEmpty()) {
                    Text(
                        "История замеров",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 14.dp, bottom = 2.dp)
                    )
                    val fmt = remember { java.text.SimpleDateFormat("dd.MM HH:mm", java.util.Locale("ru")) }
                    hist.forEach { e ->
                        Text(
                            fmt.format(java.util.Date(e.time)) + " · " +
                                (if (e.operator.isNotBlank()) e.operator else e.network) + " · " + e.title,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.padding(vertical = 1.dp)
                        )
                    }
                    OutlinedButton(
                        onClick = {
                            val intent = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, DiagHistory.exportText(context))
                            }
                            context.startActivity(Intent.createChooser(intent, "Выгрузить историю"))
                        },
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth().padding(top = 10.dp)
                    ) {
                        Text("Выгрузить историю замеров")
                    }
                }
                if (report == null && !running) {
                    Text(
                        "Запустится вместе с проверкой. Нужен выключенный VPN.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }
            }
        }
    }
}
