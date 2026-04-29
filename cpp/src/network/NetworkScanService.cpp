#include "network/NetworkScanService.h"

#include "core/AppPaths.h"
#include "core/VendorDbService.h"

#include <QDateTime>
#include <QFileInfo>
#include <QHash>
#include <QHostAddress>
#include <QHostInfo>
#include <QMutex>
#include <QMutexLocker>
#include <QNetworkInterface>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QThreadPool>
#include <QtConcurrent>

#include <algorithm>
#include <array>

#ifdef Q_OS_WIN
#include <QTcpSocket>
#else
#include <arpa/inet.h>
#include <cstdio>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace nt {

namespace {

bool isUsableIpv4(const QHostAddress& address) {
    if (address.protocol() != QAbstractSocket::IPv4Protocol) {
        return false;
    }
    const QString ip = address.toString();
    return !ip.startsWith(QStringLiteral("127."))
        && !ip.startsWith(QStringLiteral("169.254."))
        && !ip.startsWith(QStringLiteral("198.18."));
}

int adapterScore(const AdapterInfo& adapter) {
    int score = 0;
    if (adapter.ip.startsWith(QStringLiteral("192.168."))) score += 50;
    else if (adapter.ip.startsWith(QStringLiteral("10."))) score += 45;
    else if (adapter.ip.startsWith(QStringLiteral("172."))) score += 35;
    if (adapter.prefixLength == 24) score += 12;
    else if (adapter.prefixLength >= 22 && adapter.prefixLength <= 26) score += 8;
    if (!adapter.isVpn) score += 20;
    return score;
}

QString shellQuote(const QString& value) {
    QString escaped = value;
    escaped.replace(QLatin1Char('\''), QStringLiteral("'\\''"));
    return QStringLiteral("'") + escaped + QStringLiteral("'");
}

QString systemCommandPath(const QString& program) {
#ifdef Q_OS_MACOS
    if (program == QStringLiteral("ping")) return QStringLiteral("/sbin/ping");
    if (program == QStringLiteral("arp")) return QStringLiteral("/usr/sbin/arp");
    if (program == QStringLiteral("netstat")) return QStringLiteral("/usr/sbin/netstat");
    if (program == QStringLiteral("fping")) {
        const QString bundled = AppPaths::bundledToolPath(QStringLiteral("fping"));
        if (QFileInfo::exists(bundled)) return bundled;
        if (QFileInfo::exists(QStringLiteral("/usr/bin/fping"))) return QStringLiteral("/usr/bin/fping");
    }
#elif defined(Q_OS_LINUX)
    if (program == QStringLiteral("ping")) {
        if (QFileInfo::exists(QStringLiteral("/usr/bin/ping"))) return QStringLiteral("/usr/bin/ping");
        if (QFileInfo::exists(QStringLiteral("/bin/ping"))) return QStringLiteral("/bin/ping");
    }
    if (program == QStringLiteral("fping")) {
        if (QFileInfo::exists(QStringLiteral("/usr/bin/fping"))) return QStringLiteral("/usr/bin/fping");
        if (QFileInfo::exists(QStringLiteral("/usr/sbin/fping"))) return QStringLiteral("/usr/sbin/fping");
    }
    if (program == QStringLiteral("ip")) {
        if (QFileInfo::exists(QStringLiteral("/usr/sbin/ip"))) return QStringLiteral("/usr/sbin/ip");
        if (QFileInfo::exists(QStringLiteral("/sbin/ip"))) return QStringLiteral("/sbin/ip");
        if (QFileInfo::exists(QStringLiteral("/usr/bin/ip"))) return QStringLiteral("/usr/bin/ip");
    }
    if (program == QStringLiteral("arp")) {
        if (QFileInfo::exists(QStringLiteral("/usr/sbin/arp"))) return QStringLiteral("/usr/sbin/arp");
        if (QFileInfo::exists(QStringLiteral("/sbin/arp"))) return QStringLiteral("/sbin/arp");
    }
#endif
    return program;
}

QString runCommandCapture(const QString& program, const QStringList& args, bool mergeStdErr = false, int* exitStatus = nullptr) {
#ifdef Q_OS_WIN
    QProcess process;
    process.setProcessChannelMode(mergeStdErr ? QProcess::MergedChannels : QProcess::SeparateChannels);
    process.start(systemCommandPath(program), args);
    if (!process.waitForFinished(2500)) {
        process.kill();
        process.waitForFinished(200);
        if (exitStatus != nullptr) {
            *exitStatus = -1;
        }
        return {};
    }
    if (exitStatus != nullptr) {
        *exitStatus = process.exitStatus() == QProcess::NormalExit ? process.exitCode() : -1;
    }
    return QString::fromLocal8Bit(process.readAllStandardOutput());
#else
    QStringList quoted;
    quoted.reserve(args.size() + 1);
    quoted.append(shellQuote(systemCommandPath(program)));
    for (const auto& arg : args) {
        quoted.append(shellQuote(arg));
    }
    QString command = quoted.join(QLatin1Char(' '));
    command += mergeStdErr ? QStringLiteral(" 2>&1") : QStringLiteral(" 2>/dev/null");

    FILE* pipe = ::popen(command.toUtf8().constData(), "r");
    if (pipe == nullptr) {
        if (exitStatus != nullptr) {
            *exitStatus = -1;
        }
        return {};
    }

    std::array<char, 512> buffer {};
    QByteArray output;
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output.append(buffer.data());
    }

    const int status = ::pclose(pipe);
    if (exitStatus != nullptr) {
        if (status == -1) {
            *exitStatus = -1;
        } else if (WIFEXITED(status)) {
            *exitStatus = WEXITSTATUS(status);
        } else {
            *exitStatus = -1;
        }
    }
    return QString::fromLocal8Bit(output);
#endif
}

QString normalizeMacString(QString value) {
    value = value.trimmed().toLower();
    value.replace(QLatin1Char('-'), QLatin1Char(':'));
    if (value.contains(QLatin1Char('.'))) {
        QString hex = value;
        hex.remove(QLatin1Char('.'));
        if (hex.size() != 12) {
            return QStringLiteral("-");
        }
        QStringList parts;
        for (int index = 0; index < hex.size(); index += 2) {
            parts.append(hex.mid(index, 2));
        }
        return parts.join(QLatin1Char(':'));
    }

    const QStringList rawParts = value.split(QLatin1Char(':'), Qt::SkipEmptyParts);
    if (rawParts.size() == 6) {
        QStringList parts;
        parts.reserve(6);
        for (QString part : rawParts) {
            if (part.size() > 2) {
                return QStringLiteral("-");
            }
            parts.append(part.rightJustified(2, QLatin1Char('0')));
        }
        return parts.join(QLatin1Char(':'));
    }

    QString hex = value;
    hex.remove(QRegularExpression(QStringLiteral("[^0-9a-f]")));
    if (hex.size() != 12) {
        return QStringLiteral("-");
    }
    QStringList parts;
    for (int index = 0; index < hex.size(); index += 2) {
        parts.append(hex.mid(index, 2));
    }
    return parts.join(QLatin1Char(':'));
}

QString routeDisplayForHost(const AdapterInfo& adapter, const ScanRecord& row) {
    if (row.onLink) {
        return adapter.id.isEmpty()
            ? QStringLiteral("напрямую")
            : QStringLiteral("напрямую (%1)").arg(adapter.id);
    }
    if (!row.gateway.trimmed().isEmpty() && row.gateway != QStringLiteral("-")) {
        return QStringLiteral("через %1").arg(row.gateway);
    }
    return QStringLiteral("-");
}

bool tryConnectPort(const QString& ip, quint16 port, int timeoutMs) {
#ifdef Q_OS_WIN
    QTcpSocket socket;
    socket.connectToHost(ip, port);
    if (!socket.waitForConnected(timeoutMs)) {
        return false;
    }
    socket.disconnectFromHost();
    socket.waitForDisconnected(50);
    return true;
#else
    const QByteArray ipBytes = ip.toUtf8();
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }

    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    sockaddr_in addr {};
#ifdef __APPLE__
    addr.sin_len = sizeof(addr);
#endif
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, ipBytes.constData(), &addr.sin_addr) != 1) {
        ::close(fd);
        return false;
    }

    int result = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (result == 0) {
        ::close(fd);
        return true;
    }
    if (errno != EINPROGRESS) {
        ::close(fd);
        return false;
    }

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(fd, &writeSet);
    timeval timeout {};
    timeout.tv_sec = timeoutMs / 1000;
    timeout.tv_usec = (timeoutMs % 1000) * 1000;

    result = ::select(fd + 1, nullptr, &writeSet, nullptr, &timeout);
    if (result <= 0) {
        ::close(fd);
        return false;
    }

    int socketError = 0;
    socklen_t errorLength = sizeof(socketError);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &errorLength) != 0) {
        ::close(fd);
        return false;
    }

    ::close(fd);
    return socketError == 0;
#endif
}

QString formatPingDisplay(const QString& value) {
    bool ok = false;
    const double pingMs = value.trimmed().toDouble(&ok);
    if (!ok) {
        return {};
    }
    return QStringLiteral("%1 ms").arg(qMax(1, qRound(pingMs)));
}

}

NetworkScanService::NetworkScanService(VendorDbService* vendorDb, QObject* parent)
    : QObject(parent)
    , m_vendorDb(vendorDb)
    , m_watcher(new QFutureWatcher<nt::ScanRecord>(this)) {
    connect(m_watcher, &QFutureWatcher<nt::ScanRecord>::resultReadyAt, this, [this](int index) {
        const auto record = m_watcher->resultAt(index);
        if (!m_cancelRequested && !record.ip.isEmpty() && record.status != HostStatus::Offline) {
            emit recordReady(record);
        }
    });
    connect(m_watcher, &QFutureWatcher<nt::ScanRecord>::finished, this, [this]() {
        QList<ScanRecord> records;
        const auto future = m_watcher->future();
        const auto postScanMacs = captureArpTable(m_activeAdapter.id);
        m_prefetchedMacs = postScanMacs.isEmpty() ? m_prefetchedMacs : postScanMacs;
        records.reserve(future.resultCount());
        for (int index = 0; index < future.resultCount(); ++index) {
            auto record = future.resultAt(index);
            if (!record.ip.isEmpty() && record.status != HostStatus::Offline) {
                if ((record.mac.isEmpty() || record.mac == QStringLiteral("-"))) {
                    const QString refreshedMac = postScanMacs.value(record.ip, QStringLiteral("-"));
                    if (!refreshedMac.isEmpty() && refreshedMac != QStringLiteral("-")) {
                        record.mac = refreshedMac;
                    }
                }
                record.gateway = record.gateway.trimmed().isEmpty() ? m_cachedGateway : record.gateway;
                record.mask = record.mask.trimmed().isEmpty() ? m_cachedMask : record.mask;
                if (m_vendorDb != nullptr) {
                    record.vendor = m_vendorDb->lookupVendor(record.mac);
                }
                records.append(record);
            }
        }
        const int durationMs = static_cast<int>(QDateTime::currentMSecsSinceEpoch() - m_startedMs);
        emit scanFinished(records, durationMs);
    });
}

NetworkScanService::~NetworkScanService() {
    cancel();
}

QList<AdapterInfo> NetworkScanService::adapters() const {
    QList<AdapterInfo> items;
    const auto interfaces = QNetworkInterface::allInterfaces();
    for (const auto& iface : interfaces) {
        if (!(iface.flags() & QNetworkInterface::IsUp) || !(iface.flags() & QNetworkInterface::IsRunning)) {
            continue;
        }
        for (const auto& entry : iface.addressEntries()) {
            if (!isUsableIpv4(entry.ip())) {
                continue;
            }
            AdapterInfo item;
            item.id = iface.name();
            item.name = iface.humanReadableName().trimmed().isEmpty() ? iface.name() : iface.humanReadableName();
            item.ip = entry.ip().toString();
            item.prefixLength = entry.prefixLength();
            item.network = QHostAddress(entry.ip().toIPv4Address() & entry.netmask().toIPv4Address()).toString()
                + QStringLiteral("/") + QString::number(entry.prefixLength());
            item.isVpn = isVpnName(item.id) || isVpnName(item.name);
            items.append(item);
        }
    }
    return items;
}

RangeSuggestion NetworkScanService::suggestRange() const {
    RangeSuggestion suggestion;
    const auto list = adapters();
    if (list.isEmpty()) {
        suggestion.startIp = QStringLiteral("192.168.1.1");
        suggestion.endIp = QStringLiteral("192.168.1.254");
        suggestion.label = QStringLiteral("Резервный диапазон 192.168.1.0/24");
        return suggestion;
    }

    auto best = std::max_element(list.begin(), list.end(), [](const auto& left, const auto& right) {
        return adapterScore(left) < adapterScore(right);
    });
    const quint32 ip = QHostAddress(best->ip).toIPv4Address();
    const quint32 mask = best->prefixLength <= 0 ? 0xFFFFFF00u : (~0u << (32 - best->prefixLength));
    const quint32 network = ip & mask;
    const quint32 broadcast = network | (~mask);
    if (broadcast <= network + 1) {
        suggestion.startIp = intToIp(ip);
        suggestion.endIp = intToIp(ip);
    } else {
        suggestion.startIp = intToIp(network + 1);
        suggestion.endIp = intToIp(broadcast - 1);
    }
    suggestion.label = QStringLiteral("Автодиапазон от %1 / %2").arg(best->ip, best->network);
    suggestion.adapterId = best->id;
    return suggestion;
}

void NetworkScanService::start(const QString& startIp, const QString& endIp, const QString& adapterId, int maxWorkers) {
    if (isRunning()) {
        return;
    }

    const auto ips = expandRange(startIp, endIp);
    if (ips.isEmpty()) {
        emit scanFailed(QStringLiteral("Неверный диапазон IP."));
        return;
    }

    m_cancelRequested = false;
    m_startedMs = QDateTime::currentMSecsSinceEpoch();
    QThreadPool::globalInstance()->setMaxThreadCount(qBound(8, maxWorkers, 96));
    m_activeAdapter = adapterById(adapterId);
    const auto adapter = m_activeAdapter;
    m_cachedGateway = detectGateway(adapter);
    m_cachedMask = detectMask(adapter);
    m_prefetchedPingDisplay = sweepPingRange(startIp, endIp, adapter);
    m_prefetchedMacs = captureArpTable(adapter.id);
    emit scanStarted();

    auto future = QtConcurrent::mapped(ips, [this, adapter](const QString& ip) {
        if (m_cancelRequested) {
            return ScanRecord{};
        }
        return probeHost(ip, adapter);
    });
    m_watcher->setFuture(future);
}

void NetworkScanService::cancel() {
    m_cancelRequested = true;
}

bool NetworkScanService::isRunning() const {
    return m_watcher->isRunning();
}

AdapterInfo NetworkScanService::adapterById(const QString& adapterId) const {
    const auto list = adapters();
    for (const auto& adapter : list) {
        if (adapter.id == adapterId || adapter.name == adapterId) {
            return adapter;
        }
    }
    return list.isEmpty() ? AdapterInfo{} : list.first();
}

ScanRecord NetworkScanService::probeHost(const QString& ip, const AdapterInfo& adapter) {
    ScanRecord row;
    row.ip = ip;
    row.gateway = m_cachedGateway;
    row.mask = m_cachedMask;
    row.onLink = isOnLink(ip, adapter);
    row.pingDisplay = QStringLiteral("[n/a]");
    row.portsDisplay = QStringLiteral("[n/a]");
    row.webDetect = QStringLiteral("[n/a]");
    row.name = QStringLiteral("-");
    row.vendor = QStringLiteral("unknown vendor");
    row.typeHint = QStringLiteral("[n/a]");
    row.speed = QStringLiteral("[n/a]");

    PingResult ping;
    const auto prefetchedPing = m_prefetchedPingDisplay.constFind(ip);
    if (prefetchedPing != m_prefetchedPingDisplay.constEnd()) {
        ping.success = true;
        ping.display = prefetchedPing.value();
    }
#if !defined(Q_OS_MACOS)
    else if (m_prefetchedPingDisplay.isEmpty()) {
        ping = pingHost(ip, adapter.ip);
    }
#endif
    row.pingDisplay = ping.display.isEmpty() ? QStringLiteral("[n/a]") : ping.display;
    row.mac = m_prefetchedMacs.value(ip, QStringLiteral("-"));

    QStringList openPorts;
    bool portsScanned = false;
    if (ping.success) {
        row.status = HostStatus::Online;
    } else if (row.onLink && !row.mac.isEmpty() && row.mac != QStringLiteral("-")) {
        row.status = HostStatus::Unknown;
    } else {
        openPorts = probeOpenPorts(ip);
        portsScanned = true;
        if (!openPorts.isEmpty() || (!row.mac.isEmpty() && row.mac != QStringLiteral("-"))) {
            row.status = HostStatus::Unknown;
        } else {
            row.status = HostStatus::Offline;
        }
    }

    if (row.status == HostStatus::Offline || m_cancelRequested) {
        return row;
    }

    if (!portsScanned) {
        openPorts = probeOpenPorts(ip);
    }
    if (!openPorts.isEmpty()) {
        row.portsDisplay = openPorts.join(QLatin1Char(','));
        row.port = row.portsDisplay;
    } else {
        row.port = QStringLiteral("-");
    }

    row.vendor = m_vendorDb != nullptr ? m_vendorDb->lookupVendor(row.mac) : QStringLiteral("unknown vendor");
    row.name = routeDisplayForHost(adapter, row);
    row.webDetect = detectWebService(ip, openPorts);
    row.typeHint = QStringLiteral("Хост");
    row.speed = ping.success ? QStringLiteral("icmp") : QStringLiteral("link");
    return row;
}

bool NetworkScanService::isVpnName(const QString& name) {
    static const QRegularExpression vpnRe(QStringLiteral("(tun|tap|wg|utun|tailscale|hamachi|nord|openvpn|vpn|clash|mihomo|wireguard|ppp)"),
                                          QRegularExpression::CaseInsensitiveOption);
    return vpnRe.match(name).hasMatch();
}

QList<QString> NetworkScanService::expandRange(const QString& startIp, const QString& endIp) {
    const quint32 start = ipToInt(startIp);
    const quint32 end = ipToInt(endIp);
    if (start == 0 || end == 0 || end < start) {
        return {};
    }
    QList<QString> result;
    result.reserve(static_cast<int>(end - start + 1));
    for (quint32 value = start; value <= end; ++value) {
        result.append(intToIp(value));
        if (value == 0xFFFFFFFFu) {
            break;
        }
    }
    return result;
}

quint32 NetworkScanService::ipToInt(const QString& ip) {
    const auto address = QHostAddress(ip);
    return address.protocol() == QAbstractSocket::IPv4Protocol ? address.toIPv4Address() : 0u;
}

QString NetworkScanService::intToIp(quint32 value) {
    return QHostAddress(value).toString();
}

NetworkScanService::PingResult NetworkScanService::pingHost(const QString& ip, const QString& sourceIp) {
    PingResult result;
    QStringList args;
    int exitStatus = -1;
#ifdef Q_OS_WIN
    args << QStringLiteral("-n") << QStringLiteral("1") << QStringLiteral("-w") << QStringLiteral("350");
    if (!sourceIp.isEmpty()) {
        args << QStringLiteral("-S") << sourceIp;
    }
    args << ip;
    const QString output = runCommandCapture(QStringLiteral("ping"), args, true, &exitStatus);
#elif defined(Q_OS_MACOS)
    args << QStringLiteral("-c") << QStringLiteral("1") << QStringLiteral("-W") << QStringLiteral("350");
    args << ip;
    const QString output = runCommandCapture(QStringLiteral("ping"), args, true, &exitStatus);
#else
    args << QStringLiteral("-c") << QStringLiteral("1") << QStringLiteral("-W") << QStringLiteral("1");
    if (!sourceIp.isEmpty()) {
        args << QStringLiteral("-I") << sourceIp;
    }
    args << ip;
    const QString output = runCommandCapture(QStringLiteral("ping"), args, true, &exitStatus);
#endif

    static const QRegularExpression timeRe(QStringLiteral("time[=<]([0-9]+(?:\\.[0-9]+)?)\\s*ms"),
                                           QRegularExpression::CaseInsensitiveOption);
    const auto match = timeRe.match(output);
    if (match.hasMatch()) {
        const int pingMs = qMax(1, qRound(match.captured(1).toDouble()));
        result.success = true;
        result.display = QStringLiteral("%1 ms").arg(pingMs);
        return result;
    }

    result.success = (exitStatus == 0);
    if (result.success) {
        result.display = QStringLiteral("ok");
    }
    return result;
}

QHash<QString, QString> NetworkScanService::sweepPingRange(const QString& startIp, const QString& endIp, const AdapterInfo& adapter) {
    QHash<QString, QString> alive;
    QString fping = systemCommandPath(QStringLiteral("fping"));
    if (fping == QStringLiteral("fping")) {
        fping = QStandardPaths::findExecutable(QStringLiteral("fping"));
    }
    if (fping.isEmpty() || !QFileInfo::exists(fping)) {
        return alive;
    }

    QStringList args {
        QStringLiteral("-C"), QStringLiteral("1"),
        QStringLiteral("-r0"),
        QStringLiteral("-t220"),
        QStringLiteral("-i1"),
    };
    if (!adapter.id.trimmed().isEmpty()) {
        args << QStringLiteral("-I") << adapter.id;
    }
    args << QStringLiteral("-g") << startIp << endIp;

    int exitStatus = -1;
    const QString output = runCommandCapture(fping, args, true, &exitStatus);
    Q_UNUSED(exitStatus)

    static const QRegularExpression lineRe(QStringLiteral("^\\s*(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s*:\\s*(.+)$"));
    static const QRegularExpression timeRe(QStringLiteral("([0-9]+(?:\\.[0-9]+)?)\\s*ms"),
                                           QRegularExpression::CaseInsensitiveOption);
    for (const QString& rawLine : output.split(QLatin1Char('\n'))) {
        const auto lineMatch = lineRe.match(rawLine);
        if (!lineMatch.hasMatch()) {
            continue;
        }
        const QString ip = lineMatch.captured(1);
        const QString tail = lineMatch.captured(2).trimmed();
        if (tail.isEmpty()
            || tail == QStringLiteral("-")
            || tail.contains(QStringLiteral("timed out"), Qt::CaseInsensitive)) {
            continue;
        }
        const auto timeMatch = timeRe.match(tail);
        if (timeMatch.hasMatch()) {
            alive.insert(ip, QStringLiteral("%1 ms").arg(qMax(1, qRound(timeMatch.captured(1).toDouble()))));
            continue;
        }
        const QString compactDisplay = formatPingDisplay(tail);
        if (!compactDisplay.isEmpty()) {
            alive.insert(ip, compactDisplay);
        }
    }
    return alive;
}

QStringList NetworkScanService::probeOpenPorts(const QString& ip) {
    static const QList<quint16> ports {22, 80, 443};
    QStringList openPorts;
    for (const auto port : ports) {
        if (tryConnectPort(ip, port, 180)) {
            openPorts.append(QString::number(port));
        }
    }
    return openPorts;
}

QString NetworkScanService::detectWebService(const QString& ip, const QStringList& openPorts) {
    Q_UNUSED(ip)
    if (openPorts.contains(QStringLiteral("80"))) return QStringLiteral("HTTP");
    if (openPorts.contains(QStringLiteral("443"))) return QStringLiteral("HTTPS");
    return QStringLiteral("[n/a]");
}

QString NetworkScanService::lookupMac(const QString& ip) {
    int exitStatus = -1;
#ifdef Q_OS_LINUX
    const QString output = runCommandCapture(QStringLiteral("ip"), {QStringLiteral("neigh"), QStringLiteral("show"), ip}, false, &exitStatus);
#elif defined(Q_OS_MACOS)
    const QString output = runCommandCapture(QStringLiteral("arp"), {QStringLiteral("-n"), ip}, false, &exitStatus);
#else
    const QString output = runCommandCapture(QStringLiteral("arp"), {QStringLiteral("-a"), ip}, false, &exitStatus);
#endif
    if (exitStatus < 0) {
        return QStringLiteral("-");
    }

    static const QRegularExpression macRe(QStringLiteral("([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5}|[0-9a-fA-F]{4}(?:\\.[0-9a-fA-F]{4}){2})"));
    const auto match = macRe.match(output);
    if (!match.hasMatch()) {
        return QStringLiteral("-");
    }

    return normalizeMacString(match.captured(1));
}

QHash<QString, QString> NetworkScanService::captureArpTable(const QString& adapterId) {
    QHash<QString, QString> entries;
    int exitStatus = -1;
#ifdef Q_OS_LINUX
    const QString output = runCommandCapture(QStringLiteral("ip"), {QStringLiteral("neigh"), QStringLiteral("show")}, false, &exitStatus);
    if (exitStatus < 0) {
        return entries;
    }
    static const QRegularExpression lineRe(QStringLiteral("^(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+dev\\s+(\\S+)\\s+lladdr\\s+([0-9a-fA-F:.\\-]+)"),
                                           QRegularExpression::CaseInsensitiveOption);
    for (const QString& rawLine : output.split(QLatin1Char('\n'))) {
        const auto match = lineRe.match(rawLine.trimmed());
        if (!match.hasMatch()) {
            continue;
        }
        const QString ip = match.captured(1);
        const QString netif = match.captured(2);
        if (!adapterId.trimmed().isEmpty() && netif != adapterId) {
            continue;
        }
        entries.insert(ip, normalizeMacString(match.captured(3)));
    }
#elif defined(Q_OS_MACOS)
    const QString output = runCommandCapture(QStringLiteral("arp"), {QStringLiteral("-an")}, false, &exitStatus);
    if (exitStatus < 0) {
        return entries;
    }
    static const QRegularExpression lineRe(QStringLiteral("^\\?\\s+\\((\\d+\\.\\d+\\.\\d+\\.\\d+)\\)\\s+at\\s+([^\\s]+)\\s+on\\s+(\\S+)"),
                                           QRegularExpression::CaseInsensitiveOption);
    for (const QString& rawLine : output.split(QLatin1Char('\n'))) {
        const auto match = lineRe.match(rawLine.trimmed());
        if (!match.hasMatch()) {
            continue;
        }
        const QString ip = match.captured(1);
        const QString macToken = match.captured(2);
        const QString netif = match.captured(3);
        if (!adapterId.trimmed().isEmpty() && netif != adapterId) {
            continue;
        }
        if (macToken.compare(QStringLiteral("(incomplete)"), Qt::CaseInsensitive) == 0) {
            continue;
        }
        entries.insert(ip, normalizeMacString(macToken));
    }
#else
    const QString output = runCommandCapture(QStringLiteral("arp"), {QStringLiteral("-a")}, false, &exitStatus);
    if (exitStatus < 0) {
        return entries;
    }
    static const QRegularExpression lineRe(QStringLiteral("^(?:\\S+\\s+)?(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+([0-9a-fA-F:.\\-]+)"),
                                           QRegularExpression::CaseInsensitiveOption);
    for (const QString& rawLine : output.split(QLatin1Char('\n'))) {
        const auto match = lineRe.match(rawLine.trimmed());
        if (!match.hasMatch()) {
            continue;
        }
        entries.insert(match.captured(1), normalizeMacString(match.captured(2)));
    }
#endif
    return entries;
}

QString NetworkScanService::resolveName(const QString& ip) {
    const auto hostInfo = QHostInfo::fromName(ip);
    return hostInfo.hostName().trimmed().isEmpty() ? QStringLiteral("-") : hostInfo.hostName().trimmed();
}

QString NetworkScanService::detectGateway(const AdapterInfo& adapter) {
#ifdef Q_OS_MACOS
    if (adapter.id.trimmed().isEmpty()) {
        return QStringLiteral("-");
    }

    static QMutex mutex;
    static QHash<QString, QString> cache;
    {
        QMutexLocker locker(&mutex);
        const auto cached = cache.constFind(adapter.id);
        if (cached != cache.constEnd()) {
            return cached.value();
        }
    }

    int exitStatus = -1;
    const QString output = runCommandCapture(QStringLiteral("netstat"), {QStringLiteral("-rn"), QStringLiteral("-f"), QStringLiteral("inet")}, false, &exitStatus);
    if (exitStatus < 0) {
        return QStringLiteral("-");
    }

    QHash<QString, QString> discovered;
    const QStringList lines = output.split(QLatin1Char('\n'));
    for (const QString& rawLine : lines) {
        const QString line = rawLine.simplified();
        if (line.isEmpty()
            || line.startsWith(QStringLiteral("Routing tables"))
            || line.startsWith(QStringLiteral("Internet"))
            || line.startsWith(QStringLiteral("Destination"))) {
            continue;
        }

        const QStringList parts = line.split(QLatin1Char(' '), Qt::SkipEmptyParts);
        if (parts.size() < 4) {
            continue;
        }

        const QString destination = parts.at(0);
        const QString gateway = parts.at(1).trimmed();
        const QString netif = parts.at(3).trimmed();
        if (netif.isEmpty() || gateway.isEmpty() || gateway.startsWith(QStringLiteral("link#"))) {
            continue;
        }

        const bool prefer = destination == QStringLiteral("default");
        if (prefer || !discovered.contains(netif)) {
            discovered.insert(netif, gateway);
        }
    }

    {
        QMutexLocker locker(&mutex);
        for (auto it = discovered.begin(); it != discovered.end(); ++it) {
            cache.insert(it.key(), it.value());
        }
        return cache.value(adapter.id, QStringLiteral("-"));
    }
#else
    Q_UNUSED(adapter)
    return QStringLiteral("-");
#endif
}

QString NetworkScanService::detectMask(const AdapterInfo& adapter) {
    if (adapter.prefixLength <= 0) {
        return QStringLiteral("-");
    }
    quint32 mask = adapter.prefixLength == 32 ? 0xFFFFFFFFu : (~0u << (32 - adapter.prefixLength));
    return QHostAddress(mask).toString();
}

bool NetworkScanService::isOnLink(const QString& ip, const AdapterInfo& adapter) {
    if (adapter.ip.isEmpty() || adapter.prefixLength <= 0 || adapter.prefixLength > 32) {
        return false;
    }

    const quint32 hostIp = ipToInt(ip);
    const quint32 adapterIp = ipToInt(adapter.ip);
    if (hostIp == 0u || adapterIp == 0u) {
        return false;
    }

    const quint32 mask = adapter.prefixLength == 32 ? 0xFFFFFFFFu : (~0u << (32 - adapter.prefixLength));
    return (hostIp & mask) == (adapterIp & mask);
}

}
