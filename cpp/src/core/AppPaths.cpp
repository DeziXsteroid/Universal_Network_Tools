#include "core/AppPaths.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>

namespace nt {

QString AppPaths::appName() {
    return QStringLiteral("NetWorkTools");
}

QString AppPaths::appDataDir() {
    QString base = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
    if (base.isEmpty()) {
        base = QDir::homePath() + QStringLiteral("/.networktools");
    }
    return QDir(base).filePath(appName());
}

QString AppPaths::dataDir() {
    return appDataDir() + QStringLiteral("/data");
}

QString AppPaths::snapshotDir() {
    return appDataDir() + QStringLiteral("/snapshots");
}

QString AppPaths::vendorDbPath() {
    return dataDir() + QStringLiteral("/manuf");
}

QString AppPaths::vendorSeedPath() {
    const QString appDirCandidate = QCoreApplication::applicationDirPath() + QStringLiteral("/data/manuf");
    if (QFileInfo::exists(appDirCandidate)) {
        return appDirCandidate;
    }
    const QString resourcesCandidate = QCoreApplication::applicationDirPath() + QStringLiteral("/../Resources/data/manuf");
    return resourcesCandidate;
}

QString AppPaths::bundledToolPath(const QString& name) {
    const QString appDirCandidate = QCoreApplication::applicationDirPath() + QStringLiteral("/bin/") + name;
    if (QFileInfo::exists(appDirCandidate)) {
        return appDirCandidate;
    }
    return QCoreApplication::applicationDirPath() + QStringLiteral("/../Resources/bin/") + name;
}

QString AppPaths::settingsPath() {
    return appDataDir() + QStringLiteral("/settings.json");
}

QString AppPaths::logsDir() {
    return appDataDir() + QStringLiteral("/logs");
}

void AppPaths::ensureRuntimeTree() {
    QDir().mkpath(appDataDir());
    QDir().mkpath(dataDir());
    QDir().mkpath(snapshotDir());
    QDir().mkpath(logsDir());
}

} // namespace nt
