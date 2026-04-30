#include "core/VendorDbService.h"

#include "core/AppPaths.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTemporaryFile>
#include <QTimer>

#include <algorithm>
#include <numeric>

namespace nt {

namespace {

constexpr auto kDefaultUrl = "https://www.wireshark.org/download/automated/data/manuf";

QStringList candidateUrls() {
    return {
        QString::fromLatin1(kDefaultUrl),
        QStringLiteral("https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"),
    };
}

QString normalizeVendorLabel(QString shortVendor, QString longVendor) {
    shortVendor = shortVendor.simplified();
    longVendor = longVendor.simplified();

    if (longVendor.isEmpty()) {
        return shortVendor;
    }
    if (shortVendor.isEmpty()) {
        return longVendor;
    }
    if (longVendor.compare(shortVendor, Qt::CaseInsensitive) == 0) {
        return longVendor;
    }
    if (longVendor.startsWith(shortVendor + QLatin1Char(' '), Qt::CaseInsensitive)
        || longVendor.startsWith(shortVendor + QLatin1Char(','), Qt::CaseInsensitive)
        || longVendor.startsWith(shortVendor + QLatin1Char('.'), Qt::CaseInsensitive)) {
        return longVendor;
    }
    return longVendor;
}

} // namespace

VendorDbService::VendorDbService(QObject* parent)
    : QObject(parent) {
    AppPaths::ensureRuntimeTree();
}

bool VendorDbService::ensureReady(bool autoDownload) {
    if (m_loaded) {
        emit statusChanged(m_status, true);
        return true;
    }
    const bool ok = loadFromDisk(autoDownload);
    emit statusChanged(m_status, ok);
    return ok;
}

bool VendorDbService::seedBundledDb() {
    const QString seedPath = AppPaths::vendorSeedPath();
    if (!QFile::exists(seedPath) || QFile::exists(AppPaths::vendorDbPath())) {
        return false;
    }
    QDir().mkpath(AppPaths::dataDir());
    return QFile::copy(seedPath, AppPaths::vendorDbPath());
}

bool VendorDbService::loadFromDisk(bool autoDownload) {
    seedBundledDb();
    QByteArray data;
    QString sourcePath = AppPaths::vendorDbPath();
    QFile file(sourcePath);
    if (file.exists() && file.open(QIODevice::ReadOnly)) {
        data = file.readAll();
        file.close();
    }

    if (data.isEmpty()) {
        sourcePath = AppPaths::vendorSeedPath();
        QFile seedFile(sourcePath);
        if (seedFile.exists() && seedFile.open(QIODevice::ReadOnly)) {
            data = seedFile.readAll();
            seedFile.close();
        }
    }

    if (data.isEmpty() && autoDownload) {
        updateFromNetwork();
        sourcePath = AppPaths::vendorDbPath();
        QFile refreshedFile(sourcePath);
        if (refreshedFile.exists() && refreshedFile.open(QIODevice::ReadOnly)) {
            data = refreshedFile.readAll();
            refreshedFile.close();
        }
    }

    if (data.isEmpty()) {
        m_status = QStringLiteral("База вендоров: недоступна");
        m_loaded = false;
        return false;
    }
    if (!parseManuf(data)) {
        m_status = QStringLiteral("База вендоров: ошибка разбора");
        m_loaded = false;
        return false;
    }

    const int entries = std::accumulate(m_byBits.begin(), m_byBits.end(), 0, [](int sum, const auto& value) {
        return sum + value.size();
    });
    const bool fromBundle = sourcePath == AppPaths::vendorSeedPath();
    m_status = fromBundle
        ? QStringLiteral("База вендоров: bundle (%1 записей)").arg(entries)
        : QStringLiteral("База вендоров: готова (%1 записей)").arg(entries);
    m_loaded = entries > 0;
    return m_loaded;
}

bool VendorDbService::updateFromNetwork(int timeoutMs) {
    QNetworkAccessManager manager;
    bool ok = false;

    for (const auto& urlString : candidateUrls()) {
        QNetworkRequest request{QUrl(urlString)};
        request.setTransferTimeout(timeoutMs);
        request.setRawHeader("User-Agent", QByteArrayLiteral("NetWorkToolsQt/3.0"));

        QEventLoop loop;
        QTimer timer;
        timer.setSingleShot(true);
        QNetworkReply* reply = manager.get(request);
        connect(&timer, &QTimer::timeout, &loop, [&]() {
            if (reply != nullptr) {
                reply->abort();
            }
            loop.quit();
        });
        connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        timer.start(timeoutMs);
        loop.exec();

        const QByteArray data = reply->readAll();
        const auto error = reply->error();
        reply->deleteLater();
        if (error != QNetworkReply::NoError || data.size() < 10000) {
            continue;
        }

        QSaveFile out(AppPaths::vendorDbPath());
        if (!out.open(QIODevice::WriteOnly)) {
            break;
        }
        out.write(data);
        if (!out.commit()) {
            break;
        }
        ok = true;
        break;
    }

    if (!ok) {
        m_status = QStringLiteral("База вендоров: ошибка загрузки");
        emit statusChanged(m_status, false);
        return false;
    }

    const bool ready = loadFromDisk(false);
    emit statusChanged(m_status, ready);
    return ready;
}

QString VendorDbService::normalizeMac(const QString& mac) {
    QString value = mac.trimmed().toLower();
    value.replace(QLatin1Char('-'), QLatin1Char(':'));
    if (value.contains(QLatin1Char('.'))) {
        QString hex = value;
        hex.remove(QLatin1Char('.'));
        if (hex.size() != 12) {
            return QString();
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
                return QString();
            }
            parts.append(part.rightJustified(2, QLatin1Char('0')));
        }
        return parts.join(QLatin1Char(':'));
    }

    QString hex = value;
    hex.remove(QRegularExpression(QStringLiteral("[^0-9a-f]")));
    if (hex.size() != 12) {
        return QString();
    }
    QStringList parts;
    for (int index = 0; index < hex.size(); index += 2) {
        parts.append(hex.mid(index, 2));
    }
    return parts.join(QLatin1Char(':'));
}

bool VendorDbService::parsePrefixToken(const QString& token, quint64& prefixValue, int& bits) {
    QString text = token.trimmed();
    bits = -1;
    const int slashIndex = text.indexOf(QLatin1Char('/'));
    if (slashIndex >= 0) {
        bits = text.mid(slashIndex + 1).toInt();
        text = text.left(slashIndex).trimmed();
    }

    QString hex = text;
    hex.remove(QRegularExpression(QStringLiteral("[^0-9A-Fa-f]")));
    if (hex.isEmpty()) {
        return false;
    }
    const int sourceBits = hex.size() * 4;
    if (bits < 0) {
        bits = sourceBits;
    }
    bool ok = false;
    prefixValue = hex.left(12).toULongLong(&ok, 16);
    if (!ok || bits <= 0 || bits > 48) {
        return false;
    }
    if (sourceBits > bits) {
        prefixValue >>= (sourceBits - bits);
    } else if (sourceBits < bits) {
        prefixValue <<= (bits - sourceBits);
    }
    return true;
}

bool VendorDbService::parseManuf(const QByteArray& data) {
    m_byBits.clear();
    const QList<QByteArray> lines = data.split('\n');
    for (const auto& rawLine : lines) {
        const QString line = QString::fromUtf8(rawLine).section(QLatin1Char('#'), 0, 0).trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) {
            continue;
        }

        QString prefixToken;
        QString shortVendor;
        QString longVendor;

        const QStringList tabParts = line.split(QRegularExpression(QStringLiteral("\\t+")), Qt::SkipEmptyParts);
        if (tabParts.size() >= 2) {
            prefixToken = tabParts.at(0).trimmed();
            shortVendor = tabParts.at(1).trimmed();
            longVendor = tabParts.value(2).trimmed();
        } else {
            const QStringList parts = line.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
            if (parts.size() < 2) {
                continue;
            }
            prefixToken = parts.at(0).trimmed();
            shortVendor = parts.at(1).trimmed();
            longVendor = parts.mid(2).join(QLatin1Char(' ')).trimmed();
        }

        if (prefixToken.isEmpty() || shortVendor.isEmpty()) {
            continue;
        }

        quint64 prefixValue = 0;
        int bits = -1;
        if (!parsePrefixToken(prefixToken, prefixValue, bits)) {
            continue;
        }

        const QString vendor = normalizeVendorLabel(shortVendor, longVendor).trimmed();
        if (vendor.isEmpty()) {
            continue;
        }

        m_byBits[bits].insert(prefixValue, vendor);
    }
    return !m_byBits.isEmpty();
}

QString VendorDbService::lookupVendor(const QString& mac) const {
    const QString normalized = normalizeMac(mac);
    if (normalized.isEmpty() || !m_loaded) {
        return QStringLiteral("unknown vendor");
    }

    QString hex = normalized;
    hex.remove(QLatin1Char(':'));
    bool ok = false;
    const quint64 full = hex.toULongLong(&ok, 16);
    if (!ok) {
        return QStringLiteral("unknown vendor");
    }

    QList<int> bitWidths = m_byBits.keys();
    std::sort(bitWidths.begin(), bitWidths.end(), std::greater<int>());
    for (const int bits : bitWidths) {
        const quint64 masked = bits >= 48 ? full : (full >> (48 - bits));
        const auto map = m_byBits.value(bits);
        const auto it = map.constFind(masked);
        if (it != map.constEnd()) {
            return it.value();
        }
    }

    return QStringLiteral("unknown vendor");
}

QString VendorDbService::statusText() const {
    return m_status;
}

QString VendorDbService::dbPath() const {
    return AppPaths::vendorDbPath();
}

} // namespace nt
