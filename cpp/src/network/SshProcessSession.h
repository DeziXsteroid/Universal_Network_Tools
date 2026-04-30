#pragma once

#include "core/Types.h"

#include <QObject>

class QProcess;

namespace nt {

class SshProcessSession final : public QObject {
    Q_OBJECT

public:
    explicit SshProcessSession(QObject* parent = nullptr);

    void open(const SessionProfile& profile);
    void close();
    void sendText(const QString& text);
    void sendBytes(const QByteArray& bytes);
    bool isConnected() const;

signals:
    void outputReady(const QString& text);
    void stateChanged(const QString& text);
    void connectedChanged(bool connected);

private:
    QStringList buildCommand(const SessionProfile& profile, QString* program) const;
    void handleProcessText(const QString& text);

    QProcess* m_process {nullptr};
    SessionProfile m_profile;
    bool m_connected {false};
    bool m_authRejected {false};
};

} // namespace nt
