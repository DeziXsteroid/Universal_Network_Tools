#pragma once

#include "core/Types.h"

#include <QHash>
#include <QObject>

class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

namespace nt {

class HttpRequestService final : public QObject {
    Q_OBJECT

public:
    explicit HttpRequestService(QObject* parent = nullptr);
    void send(const HttpRequestSpec& spec);

signals:
    void finished(const nt::HttpResponse& response);

private:
    QNetworkAccessManager* m_manager {nullptr};
};

} // namespace nt
