#pragma once

#include <QObject>

class QUdpSocket;

namespace nt {

class UdpSocketSession final : public QObject {
    Q_OBJECT

public:
    explicit UdpSocketSession(QObject* parent = nullptr);

    bool bind(quint16 localPort, bool reuseAddress, QString* errorText);
    void close();
    void sendDatagram(const QString& host, quint16 port, const QByteArray& bytes, QString* errorText);
    bool isOpen() const;
    quint16 localPort() const;

signals:
    void datagramReceived(const QString& endpoint, const QByteArray& bytes);
    void stateChanged(const QString& text);
    void connectedChanged(bool open);

private:
    QUdpSocket* m_socket {nullptr};
};

}
