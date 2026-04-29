#pragma once

#include "core/Types.h"

#include <QStringList>

#include <QFutureWatcher>
#include <QHash>
#include <QObject>

namespace nt {

class VendorDbService;

class NetworkScanService final : public QObject {
    Q_OBJECT

public:
    explicit NetworkScanService(VendorDbService* vendorDb, QObject* parent = nullptr);
    ~NetworkScanService() override;

    QList<AdapterInfo> adapters() const;
    RangeSuggestion suggestRange() const;

    void start(const QString& startIp, const QString& endIp, const QString& adapterId, int maxWorkers);
    void cancel();
    bool isRunning() const;

signals:
    void scanStarted();
    void recordReady(const nt::ScanRecord& record);
    void scanFinished(const QList<nt::ScanRecord>& records, int durationMs);
    void scanFailed(const QString& errorText);

private:
    struct PingResult {
        bool success {false};
        QString display;
    };

    ScanRecord probeHost(const QString& ip, const AdapterInfo& adapter);
    static bool isVpnName(const QString& name);
    static QList<QString> expandRange(const QString& startIp, const QString& endIp);
    static quint32 ipToInt(const QString& ip);
    static QString intToIp(quint32 value);
    static QHash<QString, QString> sweepPingRange(const QString& startIp, const QString& endIp, const AdapterInfo& adapter);
    static QHash<QString, QString> captureArpTable(const QString& adapterId = QString());
    static PingResult pingHost(const QString& ip, const QString& sourceIp);
    static QStringList probeOpenPorts(const QString& ip);
    static QString detectWebService(const QString& ip, const QStringList& openPorts);
    static QString lookupMac(const QString& ip);
    static QString resolveName(const QString& ip);
    static QString detectGateway(const AdapterInfo& adapter);
    static QString detectMask(const AdapterInfo& adapter);
    static bool isOnLink(const QString& ip, const AdapterInfo& adapter);
    AdapterInfo adapterById(const QString& adapterId) const;

    VendorDbService* m_vendorDb {nullptr};
    QFutureWatcher<nt::ScanRecord>* m_watcher {nullptr};
    bool m_cancelRequested {false};
    qint64 m_startedMs {0};
    AdapterInfo m_activeAdapter;
    QString m_cachedGateway;
    QString m_cachedMask;
    QHash<QString, QString> m_prefetchedPingDisplay;
    QHash<QString, QString> m_prefetchedMacs;
};

}
