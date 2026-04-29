#include "core/SnapshotService.h"

#include "core/AppPaths.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMap>
#include <QRegularExpression>
#include <QSaveFile>

namespace nt {

namespace {

QString safeText(const QString& text) {
    return text.trimmed().isEmpty() ? QStringLiteral("-") : text.trimmed();
}

QString slugify(const QString& text) {
    QString value = text;
    value.replace(QRegularExpression(QStringLiteral("[^0-9A-Za-zА-Яа-я._-]+")), QStringLiteral("_"));
    value = value.trimmed();
    while (value.startsWith(QLatin1Char('_')) || value.startsWith(QLatin1Char('.')) || value.startsWith(QLatin1Char('-'))) {
        value.remove(0, 1);
    }
    while (value.endsWith(QLatin1Char('_')) || value.endsWith(QLatin1Char('.')) || value.endsWith(QLatin1Char('-'))) {
        value.chop(1);
    }
    return value.isEmpty() ? QStringLiteral("snapshot") : value;
}

QString normalizeStatus(HostStatus status) {
    switch (status) {
    case HostStatus::Online:
        return QStringLiteral("ONLINE");
    case HostStatus::Offline:
        return QStringLiteral("OFFLINE");
    case HostStatus::Unknown:
    default:
        return QStringLiteral("-");
    }
}

QJsonObject rowToJson(const ScanRecord& row) {
    return {
        {QStringLiteral("port"), safeText(row.port)},
        {QStringLiteral("status"), normalizeStatus(row.status)},
        {QStringLiteral("speed"), safeText(row.speed)},
        {QStringLiteral("vlan"), safeText(row.vlan)},
        {QStringLiteral("mac"), safeText(row.mac)},
        {QStringLiteral("ip"), row.ip.trimmed()},
        {QStringLiteral("gateway"), safeText(row.gateway)},
        {QStringLiteral("mask"), safeText(row.mask)},
        {QStringLiteral("vendor"), safeText(row.vendor)},
        {QStringLiteral("type_hint"), safeText(row.typeHint)},
        {QStringLiteral("name"), safeText(row.name)},
        {QStringLiteral("on_link"), row.onLink},
    };
}

HostStatus statusFromString(const QString& value) {
    const QString upper = value.trimmed().toUpper();
    if (upper == QStringLiteral("ONLINE") || upper == QStringLiteral("UP")) {
        return HostStatus::Online;
    }
    if (upper == QStringLiteral("OFFLINE") || upper == QStringLiteral("DOWN")) {
        return HostStatus::Offline;
    }
    return HostStatus::Unknown;
}

ScanRecord rowFromJson(const QJsonObject& object) {
    ScanRecord row;
    row.port = object.value(QStringLiteral("port")).toString();
    row.status = statusFromString(object.value(QStringLiteral("status")).toString());
    row.speed = object.value(QStringLiteral("speed")).toString();
    row.vlan = object.value(QStringLiteral("vlan")).toString();
    row.mac = object.value(QStringLiteral("mac")).toString();
    row.ip = object.value(QStringLiteral("ip")).toString();
    row.gateway = object.value(QStringLiteral("gateway")).toString();
    row.mask = object.value(QStringLiteral("mask")).toString();
    row.vendor = object.value(QStringLiteral("vendor")).toString();
    row.typeHint = object.value(QStringLiteral("type_hint")).toString();
    row.name = object.value(QStringLiteral("name")).toString();
    row.onLink = object.value(QStringLiteral("on_link")).toBool(false);
    return row;
}

QString fieldValue(const ScanRecord& row, const QString& field) {
    if (field == QStringLiteral("status")) return normalizeStatus(row.status);
    if (field == QStringLiteral("mac")) return safeText(row.mac);
    if (field == QStringLiteral("vendor")) return safeText(row.vendor);
    if (field == QStringLiteral("type_hint")) return safeText(row.typeHint);
    if (field == QStringLiteral("name")) return safeText(row.name);
    if (field == QStringLiteral("port")) return safeText(row.port);
    if (field == QStringLiteral("speed")) return safeText(row.speed);
    if (field == QStringLiteral("vlan")) return safeText(row.vlan);
    if (field == QStringLiteral("gateway")) return safeText(row.gateway);
    if (field == QStringLiteral("mask")) return safeText(row.mask);
    if (field == QStringLiteral("on_link")) return row.onLink ? QStringLiteral("да") : QStringLiteral("нет");
    return QStringLiteral("-");
}

QString rowHeadline(const ScanRecord& row) {
    QStringList parts;
    parts.append(safeText(row.mac));
    parts.append(safeText(row.vendor));
    parts.append(safeText(row.port));
    return parts.join(QStringLiteral(" | "));
}

QStringList trackedFields() {
    return {
        QStringLiteral("status"),
        QStringLiteral("mac"),
        QStringLiteral("vendor"),
        QStringLiteral("type_hint"),
        QStringLiteral("name"),
        QStringLiteral("port"),
        QStringLiteral("speed"),
        QStringLiteral("vlan"),
        QStringLiteral("gateway"),
        QStringLiteral("mask"),
        QStringLiteral("on_link"),
    };
}

QMap<QString, ScanRecord> mapByIp(const QList<ScanRecord>& rows) {
    QMap<QString, ScanRecord> mapped;
    for (const auto& row : rows) {
        if (!row.ip.trimmed().isEmpty()) {
            mapped.insert(row.ip.trimmed(), row);
        }
    }
    return mapped;
}

}

SnapshotService::SnapshotService(QObject* parent)
    : QObject(parent) {
    AppPaths::ensureRuntimeTree();
}

QList<SnapshotMeta> SnapshotService::listSnapshots() const {
    QList<SnapshotMeta> items;
    QDir dir(AppPaths::snapshotDir());
    dir.mkpath(QStringLiteral("."));
    const auto entries = dir.entryInfoList({QStringLiteral("*.json")}, QDir::Files, QDir::Time);
    for (const auto& info : entries) {
        QString error;
        SnapshotMeta meta;
        loadSnapshotRows(info.absoluteFilePath(), &meta, &error);
        if (meta.path.isEmpty()) {
            continue;
        }
        items.append(meta);
    }
    return items;
}

bool SnapshotService::saveSnapshot(
    const QString& name,
    const QList<ScanRecord>& rows,
    const QString& startIp,
    const QString& endIp,
    const QString& adapter,
    QString* outPath,
    QString* errorText
) const {
    QDir().mkpath(AppPaths::snapshotDir());
    const QString createdAt = QDateTime::currentDateTime().toString(Qt::ISODate);
    const QString safeName = name.trimmed().isEmpty() ? QStringLiteral("baseline") : name.trimmed();
    const QString id = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss_")) + slugify(safeName).left(48);
    const QString path = AppPaths::snapshotDir() + QLatin1Char('/') + id + QStringLiteral(".json");

    QJsonArray jsonRows;
    for (const auto& row : rows) {
        if (!row.ip.trimmed().isEmpty()) {
            jsonRows.append(rowToJson(row));
        }
    }

    const QJsonObject payload{
        {QStringLiteral("schema"), 1},
        {QStringLiteral("id"), id},
        {QStringLiteral("name"), safeName},
        {QStringLiteral("created_at"), createdAt},
        {QStringLiteral("source"), QStringLiteral("manual")},
        {QStringLiteral("range"), QJsonObject{
            {QStringLiteral("start_ip"), startIp.trimmed()},
            {QStringLiteral("end_ip"), endIp.trimmed()},
            {QStringLiteral("adapter"), adapter.trimmed()},
        }},
        {QStringLiteral("row_count"), jsonRows.size()},
        {QStringLiteral("rows"), jsonRows},
    };

    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        if (errorText != nullptr) {
            *errorText = QStringLiteral("Не удалось записать снимок: %1").arg(path);
        }
        return false;
    }
    file.write(QJsonDocument(payload).toJson(QJsonDocument::Indented));
    if (!file.commit()) {
        if (errorText != nullptr) {
            *errorText = QStringLiteral("Не удалось завершить сохранение снимка: %1").arg(path);
        }
        return false;
    }

    if (outPath != nullptr) {
        *outPath = path;
    }
    return true;
}

QList<ScanRecord> SnapshotService::loadSnapshotRows(const QString& path, SnapshotMeta* outMeta, QString* errorText) const {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (errorText != nullptr) {
            *errorText = QStringLiteral("Не удалось открыть снимок: %1").arg(path);
        }
        return {};
    }

    const auto doc = QJsonDocument::fromJson(file.readAll());
    if (!doc.isObject()) {
        if (errorText != nullptr) {
            *errorText = QStringLiteral("Снимок не является JSON-объектом: %1").arg(path);
        }
        return {};
    }

    const auto object = doc.object();
    const auto range = object.value(QStringLiteral("range")).toObject();
    if (outMeta != nullptr) {
        outMeta->id = object.value(QStringLiteral("id")).toString(QFileInfo(path).baseName());
        outMeta->name = object.value(QStringLiteral("name")).toString(QFileInfo(path).baseName());
        outMeta->createdAt = object.value(QStringLiteral("created_at")).toString();
        outMeta->source = object.value(QStringLiteral("source")).toString(QStringLiteral("manual"));
        outMeta->startIp = range.value(QStringLiteral("start_ip")).toString();
        outMeta->endIp = range.value(QStringLiteral("end_ip")).toString();
        outMeta->adapter = range.value(QStringLiteral("adapter")).toString();
        outMeta->path = path;
        outMeta->rowCount = object.value(QStringLiteral("row_count")).toInt();
    }

    QList<ScanRecord> rows;
    const auto array = object.value(QStringLiteral("rows")).toArray();
    rows.reserve(array.size());
    for (const auto& value : array) {
        if (value.isObject()) {
            rows.append(rowFromJson(value.toObject()));
        }
    }
    return rows;
}

SnapshotDiffSummary SnapshotService::diffRows(const QList<ScanRecord>& referenceRows, const QList<ScanRecord>& currentRows) const {
    const auto reference = mapByIp(referenceRows);
    const auto current = mapByIp(currentRows);

    SnapshotDiffSummary summary;

    for (auto it = current.begin(); it != current.end(); ++it) {
        if (!reference.contains(it.key())) {
            ++summary.added;
            SnapshotDiffEntry entry;
            entry.kind = SnapshotDiffKind::Added;
            entry.ip = it.key();
            entry.beforeValue = QStringLiteral("-");
            entry.afterValue = rowHeadline(it.value());
            entry.details = QStringLiteral("Узел появился в сети");
            summary.entries.append(entry);
        }
    }

    for (auto it = reference.begin(); it != reference.end(); ++it) {
        if (!current.contains(it.key())) {
            ++summary.removed;
            SnapshotDiffEntry entry;
            entry.kind = SnapshotDiffKind::Removed;
            entry.ip = it.key();
            entry.beforeValue = rowHeadline(it.value());
            entry.afterValue = QStringLiteral("-");
            entry.details = QStringLiteral("Узел вышел из сети");
            summary.entries.append(entry);
        }
    }

    for (auto it = reference.begin(); it != reference.end(); ++it) {
        if (!current.contains(it.key())) {
            continue;
        }
        const auto before = it.value();
        const auto after = current.value(it.key());
        QStringList diffs;
        for (const auto& field : trackedFields()) {
            if (fieldValue(before, field) != fieldValue(after, field)) {
                diffs.append(QStringLiteral("%1: %2 -> %3").arg(field, fieldValue(before, field), fieldValue(after, field)));
            }
        }
        if (diffs.isEmpty()) {
            continue;
        }
        ++summary.changed;
        SnapshotDiffEntry entry;
        entry.kind = SnapshotDiffKind::Changed;
        entry.ip = it.key();
        entry.beforeValue = rowHeadline(before);
        entry.afterValue = rowHeadline(after);
        entry.details = diffs.join(QStringLiteral("\n"));
        summary.entries.append(entry);
    }

    summary.total = summary.added + summary.removed + summary.changed;
    std::sort(summary.entries.begin(), summary.entries.end(), [](const auto& left, const auto& right) {
        return QHostAddress(left.ip).toIPv4Address() < QHostAddress(right.ip).toIPv4Address();
    });
    return summary;
}

}
