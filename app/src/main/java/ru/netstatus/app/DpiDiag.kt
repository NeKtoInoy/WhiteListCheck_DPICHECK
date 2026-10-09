package ru.netstatus.app

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
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
    val detail: String
)

data class DiagReport(
    val steps: List<DiagStep>,
    val verdictTitle: String,
    val verdictText: String,
    val network: String,
    val operator: String,
    val time: Long
)

const val GROUP_FOREIGN = "Зарубежные IP (вне белого списка)"
const val GROUP_WHITE = "Российские IP (эталон из белого списка)"
const val GROUP_OWN = "Ваш сервер"

object DpiProbe {
    private const val CONNECT_MS = 4000
    private const val READ_MS = 5000
    private const val TOTAL_MS = 30_000L

    // Отдельный scope для блокирующих сокетов (по образцу Scanner): зависший
    // поток не должен держать вызывающего.
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

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

    private fun shortErr(e: Throwable): String {
        val m = e.message?.take(80)
        return if (m.isNullOrBlank()) e.javaClass.simpleName else "${e.javaClass.simpleName}: $m"
    }

    // DNS с потолком по времени (InetAddress.getByName сам таймаута не имеет).
    private suspend fun resolve(host: String): String? {
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

    private fun tcpStep(group: String, target: String, ip: String, port: Int): DiagStep {
        val t0 = System.currentTimeMillis()
        return try {
            Socket().use { it.connect(InetSocketAddress(ip, port), CONNECT_MS) }
            DiagStep(group, target, "TCP", "", Outcome.OK, System.currentTimeMillis() - t0, "соединение открыто")
        } catch (e: Exception) {
            DiagStep(group, target, "TCP", "", classify(e), System.currentTimeMillis() - t0, shortErr(e))
        }
    }

    private fun tlsStep(
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

    suspend fun run(ownHost: String, ownPort: Int, ownSni: String, network: String, operator: String): DiagReport {
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
                if (ownHost.isNotBlank()) {
                    jobs += async {
                        val snis = if (ownSni.isNotBlank()) listOf(ownSni to "сервера") else emptyList()
                        probeTarget(GROUP_OWN, ownHost, ownHost, ownPort, snis)
                    }
                }
                jobs.awaitAll().flatten()
            }
        } ?: emptyList()
        val (title, text) = verdict(steps, network)
        return DiagReport(steps, title, text, network, operator, System.currentTimeMillis())
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
                        "Похоже на DPI (фильтр по SNI)" to
                            "TCP открывается и TLS с обычным SNI проходит, а с запрещённым SNI " +
                            "(${DIAG_SNI_BLOCKED}) на тот же IP " +
                            (if (badFailKinds.count { it == Outcome.RESET } * 2 >= badFailKinds.size)
                                "приходит сброс (RST)" else "наступает тишина (обрыв без ответа)") +
                            ". Помогут: другой SNI для Reality, XHTTP, порт 443." +
                            if (white2.isNotEmpty() && white2.none { it.outcome.reached() })
                                " Подмена SNI на белый домен (${DIAG_SNI_WHITE}) на постороннем IP тоже режется: " +
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

        // Добавка про собственный сервер.
        if (own.isEmpty()) return base
        val ownTcp = own.firstOrNull { it.stage == "TCP" || it.stage == "DNS" }
        val ownTls = own.filter { it.stage == "TLS" }
        val extra = when {
            ownTcp == null -> ""
            ownTcp.stage == "DNS" -> "Ваш сервер: адрес не разрешился (DNS)."
            !ownTcp.outcome.reached() -> {
                val kind = when (ownTcp.outcome) {
                    Outcome.TIMEOUT -> "таймаут"
                    Outcome.REFUSED -> "порт закрыт/отклонён"
                    Outcome.RESET -> "сброс соединения"
                    else -> "не открывается"
                }
                if (wOk && fOk)
                    "Ваш сервер: TCP не проходит ($kind), хотя остальной интернет доступен. " +
                        "Похоже, блокируется именно этот IP или порт (или сервер не отвечает)."
                else
                    "Ваш сервер: TCP не проходит ($kind). При фильтре по IP это ожидаемо, " +
                        "если адрес не в белом списке."
            }
            ownTls.isNotEmpty() && ownTls.none { it.outcome.reached() } ->
                "Ваш сервер: TCP открывается, но TLS-рукопожатие обрывается (" +
                    (if (ownTls.first().outcome == Outcome.RESET) "RST" else "тишина") +
                    "). Похоже, DPI режет соединение к серверу. Попробуйте другой SNI или транспорт XHTTP."
            else ->
                "Ваш сервер: TCP и TLS проходят. На этих уровнях блокировки нет " +
                    "(это не гарантирует, что VLESS работает, но сеть вас не режет)."
        }
        return if (extra.isEmpty()) base else base.first to (base.second + "\n\n" + extra)
    }

    // ---------- Текстовый отчёт ----------

    fun reportText(r: DiagReport): String {
        val sb = StringBuilder()
        val time = java.text.SimpleDateFormat("dd.MM.yyyy HH:mm", java.util.Locale("ru"))
            .format(java.util.Date(r.time))
        sb.append("Глубокая диагностика $time\n")
        val net = if (r.operator.isNotBlank()) "${r.network} · ${r.operator}" else r.network
        sb.append("Сеть: $net\n")
        sb.append("Вердикт: ${r.verdictTitle}\n${r.verdictText}\n\n")
        var group = ""
        for (s in r.steps) {
            if (s.group != group) {
                group = s.group
                sb.append("[$group]\n")
            }
            val st = if (s.stage == "TLS") "TLS(${s.sniKind})" else s.stage
            sb.append("  ${s.target} $st: ${s.outcome} ${s.ms}мс — ${s.detail}\n")
        }
        return sb.toString()
    }
}

// ---------- Состояние (на уровне процесса, переживает смену экранов) ----------

object DiagHolder {
    var report by mutableStateOf<DiagReport?>(null)
    var running by mutableStateOf(false)
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

@Composable
fun DiagCard(scope: CoroutineScope, networkType: String, operator: String) {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("netstatus", Context.MODE_PRIVATE) }
    var host by rememberSaveable { mutableStateOf(prefs.getString("diag_host", "") ?: "") }
    var port by rememberSaveable { mutableStateOf(prefs.getString("diag_port", "443") ?: "443") }
    var sni by rememberSaveable { mutableStateOf(prefs.getString("diag_sni", "") ?: "") }
    val report = DiagHolder.report
    val running = DiagHolder.running

    fun start() {
        val p = port.trim().toIntOrNull()?.takeIf { it in 1..65535 } ?: 443
        prefs.edit()
            .putString("diag_host", host.trim())
            .putString("diag_port", p.toString())
            .putString("diag_sni", sni.trim())
            .apply()
        DiagHolder.running = true
        scope.launch {
            try {
                val net = Scanner.networkType(context)
                val op = if (net == "мобильный интернет") Scanner.operatorName(context) else ""
                val r = DpiProbe.run(host.trim(), p, sni.trim(), net, op)
                DiagHolder.report = r
            } finally {
                DiagHolder.running = false
            }
        }
    }

    Surface(
        Modifier.fillMaxWidth().padding(top = 12.dp),
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant
    ) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 12.dp)) {
            Text(
                "Глубокая диагностика: DPI или белые списки?",
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                "Смотрит, на каком этапе рвётся соединение: TCP до IP (белые списки) или TLS по SNI (DPI). " +
                    "Запускайте без VPN.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp)
            )

            Spacer(Modifier.height(8.dp))
            Text(
                "Ваш сервер (необязательно)",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Row(Modifier.fillMaxWidth().padding(top = 4.dp)) {
                OutlinedTextField(
                    value = host,
                    onValueChange = { host = it },
                    label = { Text("IP или домен") },
                    singleLine = true,
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(8.dp))
                OutlinedTextField(
                    value = port,
                    onValueChange = { port = it.filter { c -> c.isDigit() }.take(5) },
                    label = { Text("Порт") },
                    singleLine = true,
                    modifier = Modifier.width(96.dp)
                )
            }
            OutlinedTextField(
                value = sni,
                onValueChange = { sni = it },
                label = { Text("SNI сервера (например amazon.com)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(top = 6.dp)
            )

            Button(
                onClick = { start() },
                enabled = !running,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth().padding(top = 10.dp).height(48.dp)
            ) {
                Text(
                    if (running) "Диагностика…" else "Запустить диагностику",
                    fontWeight = FontWeight.SemiBold
                )
            }

            if (running) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth().padding(top = 10.dp))
            }

            if (networkType == "VPN" && report == null) {
                Text(
                    "Сейчас включён VPN: результат будет неточным.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }

            if (report != null && !running) {
                Spacer(Modifier.height(12.dp))
                Text(
                    report.verdictTitle,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    report.verdictText,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.padding(top = 4.dp)
                )

                var group = ""
                report.steps.forEach { s ->
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
                            outcomeLabel(s.outcome) + if (s.outcome.reached()) " · ${s.ms} мс" else "",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = TextAlign.End,
                            modifier = Modifier.padding(start = 8.dp)
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
        }
    }
}
