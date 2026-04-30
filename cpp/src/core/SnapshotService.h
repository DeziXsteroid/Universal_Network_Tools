#pragma once

#include "core/Types.h"

#include <QObject>

namespace nt {

class SnapshotService final : public QObject {
    Q_OBJECT

public:
    explicit SnapshotService(QObject* parent = nullptr);

    QList<SnapshotMeta> listSnapshots() const;
    bool saveSnapshot(
        const QString& name,
        const QList<ScanRecord>& rows,
        const QString& startIp,
        const QString& endIp,
        const QString& adapter,
        QString* outPath,
        QString* errorText
    ) const;
    bool deleteSnapshot(const QString& path, QString* errorText) const;
    QList<ScanRecord> loadSnapshotRows(const QString& path, SnapshotMeta* outMeta, QString* errorText) const;
    SnapshotDiffSummary diffRows(const QList<ScanRecord>& referenceRows, const QList<ScanRecord>& currentRows) const;
};

} // namespace nt
