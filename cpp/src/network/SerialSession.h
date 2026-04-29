#pragma once

#include <QObject>

class QSerialPort;

namespace nt {

class SerialSession final : public QObject {
    Q_OBJECT

public:
    explicit SerialSession(QObject* parent = nullptr);

    bool open(
        const QString& portName,
        qint32 baudRate,
        int dataBits,
        const QString& parityName,
        const QString& stopBitsName,
        const QString& flowControlName,
        QString* errorText
    );
    void close();
    void sendBytes(const QByteArray& bytes, QString* errorText);
    bool isOpen() const;

signals:
    void dataReceived(const QByteArray& bytes);
    void stateChanged(const QString& text);
    void connectedChanged(bool connected);

private:
    QSerialPort* m_port {nullptr};
};

}
