#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QMetaType>
#include <QNetworkInterface>
#include <QString>

namespace nt {

enum class HostStatus {
    Unknown,
    Online,
    Offline,
};

inline QString hostStatusText(HostStatus status) {
    switch (status) {
    case HostStatus::Online:
        return QStringLiteral("Онлайн");
    case HostStatus::Offline:
        return QStringLiteral("Офлайн");
    case HostStatus::Unknown:
    default:
        return QStringLiteral("-");
    }
}

inline QString hostStatusIndicator(HostStatus status) {
    switch (status) {
    case HostStatus::Online:
        return QStringLiteral("\u25cf Онлайн");
    case HostStatus::Offline:
        return QStringLiteral("\u25cf Офлайн");
    case HostStatus::Unknown:
    default:
        return QStringLiteral("-");
    }
}

struct AdapterInfo {
    QString id;
    QString name;
    QString ip;
    QString network;
    int prefixLength {0};
    bool isVpn {false};
};

struct ScanRecord {
    QString port;
    HostStatus status {HostStatus::Unknown};
    QString pingDisplay;
    QString portsDisplay;
    QString webDetect;
    QString speed;
    QString vlan;
    QString mac;
    QString ip;
    QString gateway;
    QString mask;
    QString vendor;
    QString typeHint;
    QString name;
    bool onLink {false};
};

struct RangeSuggestion {
    QString startIp;
    QString endIp;
    QString label;
    QString adapterId;
};

struct SessionProfile {
    QString name;
    QString host;
    quint16 port {0};
    QString username;
    QString password;
};

struct SnapshotMeta {
    QString id;
    QString name;
    QString createdAt;
    QString source;
    QString startIp;
    QString endIp;
    QString adapter;
    QString path;
    int rowCount {0};
};

enum class SnapshotDiffKind {
    Added,
    Removed,
    Changed,
};

struct SnapshotDiffEntry {
    SnapshotDiffKind kind {SnapshotDiffKind::Changed};
    QString ip;
    QString beforeValue;
    QString afterValue;
    QString details;
};

struct SnapshotDiffSummary {
    int added {0};
    int removed {0};
    int changed {0};
    int total {0};
    QList<SnapshotDiffEntry> entries;
};

struct HttpRequestSpec {
    QString method;
    QString url;
    QJsonObject headers;
    QJsonObject params;
    QByteArray body;
    QString username;
    QString password;
    int timeoutSec {10};
};

struct HttpResponse {
    int statusCode {0};
    QByteArray body;
    QJsonObject headers;
    QString errorText;
    QString method;
    QString url;
    QString reasonPhrase;
};

inline QJsonObject sessionProfileToJson(const SessionProfile& profile) {
    return {
        {QStringLiteral("name"), profile.name},
        {QStringLiteral("host"), profile.host},
        {QStringLiteral("port"), static_cast<int>(profile.port)},
        {QStringLiteral("username"), profile.username},
        {QStringLiteral("password"), profile.password},
    };
}

inline SessionProfile sessionProfileFromJson(const QJsonObject& object, quint16 defaultPort) {
    SessionProfile profile;
    profile.name = object.value(QStringLiteral("name")).toString();
    profile.host = object.value(QStringLiteral("host")).toString(QStringLiteral("127.0.0.1"));
    profile.port = static_cast<quint16>(object.value(QStringLiteral("port")).toInt(defaultPort));
    profile.username = object.value(QStringLiteral("username")).toString();
    profile.password = object.value(QStringLiteral("password")).toString();
    if (profile.port == 0) {
        profile.port = defaultPort;
    }
    return profile;
}

inline QJsonArray sessionProfilesToJson(const QList<SessionProfile>& profiles) {
    QJsonArray array;
    for (const auto& profile : profiles) {
        array.append(sessionProfileToJson(profile));
    }
    return array;
}

inline QList<SessionProfile> sessionProfilesFromJson(const QJsonArray& array, quint16 defaultPort) {
    QList<SessionProfile> profiles;
    for (const auto& value : array) {
        if (!value.isObject()) {
            continue;
        }
        profiles.append(sessionProfileFromJson(value.toObject(), defaultPort));
    }
    return profiles;
}

}

Q_DECLARE_METATYPE(nt::AdapterInfo)
Q_DECLARE_METATYPE(nt::RangeSuggestion)
Q_DECLARE_METATYPE(nt::ScanRecord)
Q_DECLARE_METATYPE(QList<nt::ScanRecord>)
Q_DECLARE_METATYPE(nt::SessionProfile)
Q_DECLARE_METATYPE(QList<nt::SessionProfile>)
Q_DECLARE_METATYPE(nt::SnapshotMeta)
Q_DECLARE_METATYPE(QList<nt::SnapshotMeta>)
Q_DECLARE_METATYPE(nt::SnapshotDiffSummary)
Q_DECLARE_METATYPE(nt::HttpResponse)
