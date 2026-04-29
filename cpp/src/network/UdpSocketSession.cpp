#include "network/UdpSocketSession.h"

#include <QHostAddress>
#include <QUdpSocket>

namespace nt {

UdpSocketSession::UdpSocketSession(QObject* parent)
    : QObject(parent)
    , m_socket(new QUdpSocket(this)) {
    connect(m_socket, &QUdpSocket::readyRead, this, [this]() {
        while (m_socket->hasPendingDatagrams()) {
            QHostAddress address;
            quint16 port = 0;
            QByteArray payload;
            payload.resize(static_cast<int>(m_socket->pendingDatagramSize()));
            m_socket->readDatagram(payload.data(), payload.size(), &address, &port);
            emit datagramReceived(QStringLiteral("%1:%2").arg(address.toString()).arg(port), payload);
        }
    });
    connect(m_socket, &QUdpSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
        emit stateChanged(m_socket->errorString());
    });
}

bool UdpSocketSession::bind(quint16 localPort, bool reuseAddress, QString* errorText) {
    close();
    QAbstractSocket::BindMode bindMode = QAbstractSocket::DefaultForPlatform;
    if (reuseAddress) {
        bindMode = QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint;
    }
    if (!m_socket->bind(QHostAddress::AnyIPv4, localPort, bindMode)) {
        if (errorText != nullptr) {
            *errorText = m_socket->errorString();
        }
        emit stateChanged(m_socket->errorString());
        emit connectedChanged(false);
        return false;
    }
    emit stateChanged(QStringLiteral("UDP открыт :%1").arg(m_socket->localPort()));
    emit connectedChanged(true);
    return true;
}

void UdpSocketSession::close() {
    if (m_socket->state() != QAbstractSocket::UnconnectedState) {
        m_socket->close();
        emit stateChanged(QStringLiteral("Закрыто"));
        emit connectedChanged(false);
    }
}

void UdpSocketSession::sendDatagram(const QString& host, quint16 port, const QByteArray& bytes, QString* errorText) {
    if (!isOpen()) {
        if (errorText != nullptr) {
            *errorText = QStringLiteral("UDP-сокет закрыт");
        }
        emit stateChanged(QStringLiteral("UDP-сокет закрыт"));
        return;
    }
    const auto written = m_socket->writeDatagram(bytes, QHostAddress(host), port);
    if (written < 0 && errorText != nullptr) {
        *errorText = m_socket->errorString();
    }
}

bool UdpSocketSession::isOpen() const {
    return m_socket->state() == QAbstractSocket::BoundState;
}

quint16 UdpSocketSession::localPort() const {
    return m_socket->localPort();
}

}
