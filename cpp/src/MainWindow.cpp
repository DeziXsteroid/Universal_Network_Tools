#include "MainWindow.h"

#include "core/AppPaths.h"
#include "core/SettingsService.h"
#include "core/SnapshotService.h"
#include "core/TerminalSanitizer.h"
#include "core/VendorDbService.h"
#include "network/HttpRequestService.h"
#include "network/NetworkScanService.h"
#include "network/SerialSession.h"
#include "network/SshProcessSession.h"
#include "network/TcpClientSession.h"
#include "network/TelnetSession.h"
#include "network/UdpSocketSession.h"

#include <algorithm>
#include <QAction>
#include <QApplication>
#include <QAbstractItemView>
#include <QAbstractSocket>
#include <QBrush>
#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QComboBox>
#include <QClipboard>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFont>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHostAddress>
#include <QHostInfo>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QKeyEvent>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QMenu>
#include <QMenuBar>
#include <QPainter>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadialGradient>
#include <QRegularExpression>
#include <QSpinBox>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStyleFactory>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QSerialPortInfo>
#include <QTabWidget>
#include <QTimer>
#include <QTextCursor>
#include <QTextEdit>
#include <QUrl>
#include <QVariant>
#include <QVBoxLayout>

namespace {

constexpr auto kWindowTitle = "Сканер IP - Network Tools";

QFont fixedFont(double pointSize = 10.5) {
    QFont font;
#ifdef Q_OS_MACOS
    font.setFamily(QStringLiteral("Menlo"));
#elif defined(Q_OS_WIN)
    font.setFamily(QStringLiteral("Consolas"));
#else
    font.setFamily(QStringLiteral("DejaVu Sans Mono"));
#endif
    font.setStyleHint(QFont::Monospace);
    font.setFixedPitch(true);
    font.setPointSizeF(pointSize);
    return font;
}

QColor terminalColorFromCode(int code) {
    switch (code) {
    case 30: return QColor("#0f1318");
    case 31: return QColor("#d85d5d");
    case 32: return QColor("#82c46c");
    case 33: return QColor("#d7bb62");
    case 34: return QColor("#6f9cd8");
    case 35: return QColor("#b184d7");
    case 36: return QColor("#68bfb5");
    case 37: return QColor("#d6dce4");
    case 90: return QColor("#5c6570");
    case 91: return QColor("#f27c7c");
    case 92: return QColor("#9ad988");
    case 93: return QColor("#f0d977");
    case 94: return QColor("#88b2ef");
    case 95: return QColor("#c8a0f3");
    case 96: return QColor("#82d9cf");
    case 97: return QColor("#f5f8fb");
    default: return QColor("#eef2f6");
    }
}

QTextCharFormat defaultTerminalFormat() {
    QTextCharFormat format;
    format.setFont(fixedFont());
    format.setForeground(QColor("#eef2f6"));
    format.setBackground(QColor("#0f1318"));
    format.setFontWeight(QFont::Normal);
    format.setFontUnderline(false);
    return format;
}

void applyTerminalSgr(const QList<int>& codes, QTextCharFormat& format) {
    if (codes.isEmpty()) {
        format = defaultTerminalFormat();
        return;
    }
    for (const int code : codes) {
        if (code == 0) {
            format = defaultTerminalFormat();
        } else if (code == 1) {
            format.setFontWeight(QFont::Bold);
        } else if (code == 22) {
            format.setFontWeight(QFont::Normal);
        } else if (code == 4) {
            format.setFontUnderline(true);
        } else if (code == 24) {
            format.setFontUnderline(false);
        } else if (code == 39) {
            format.setForeground(defaultTerminalFormat().foreground());
        } else if (code == 49) {
            format.setBackground(defaultTerminalFormat().background());
        } else if ((code >= 30 && code <= 37) || (code >= 90 && code <= 97)) {
            format.setForeground(terminalColorFromCode(code));
        } else if ((code >= 40 && code <= 47) || (code >= 100 && code <= 107)) {
            const int fgCode = code >= 100 ? code - 10 : code - 10;
            format.setBackground(terminalColorFromCode(fgCode));
        }
    }
}

void appendConsole(QPlainTextEdit* box, const QString& text) {
    if (box == nullptr || text.isEmpty()) {
        return;
    }
    QTextCursor cursor = box->textCursor();
    cursor.movePosition(QTextCursor::End);
    cursor.insertText(text);
    if (!text.endsWith(QLatin1Char('\n'))) {
        cursor.insertText(QStringLiteral("\n"));
    }
    box->setTextCursor(cursor);
    box->ensureCursorVisible();
}

quint32 ipToInt(const QString& ip) {
    const auto address = QHostAddress(ip);
    return address.protocol() == QAbstractSocket::IPv4Protocol ? address.toIPv4Address() : 0u;
}

int insertionRowForIp(QTableWidget* table, const QString& ip) {
    if (table == nullptr) {
        return 0;
    }
    const quint32 target = ipToInt(ip);
    for (int row = 0; row < table->rowCount(); ++row) {
        const auto* item = table->item(row, 0);
        if (item == nullptr) {
            return row;
        }
        if (ipToInt(item->text()) > target) {
            return row;
        }
    }
    return table->rowCount();
}

QPair<QString, QString> rangeFromIpAndPrefix(const QString& ip, int prefixLength) {
    if (prefixLength <= 0 || prefixLength > 32) {
        return {ip, ip};
    }

    const quint32 value = ipToInt(ip);
    if (value == 0u) {
        return {ip, ip};
    }

    const quint32 mask = prefixLength == 32 ? 0xFFFFFFFFu : (~0u << (32 - prefixLength));
    const quint32 network = value & mask;
    const quint32 broadcast = network | (~mask);
    if (broadcast <= network + 1u) {
        return {QHostAddress(value).toString(), QHostAddress(value).toString()};
    }
    return {QHostAddress(network + 1u).toString(), QHostAddress(broadcast - 1u).toString()};
}

QIcon statusOrb(nt::HostStatus status) {
    QColor outer("#c93d27");
    QColor center("#ff947f");
    if (status == nt::HostStatus::Online) {
        outer = QColor("#2f9728");
        center = QColor("#93ef70");
    } else if (status == nt::HostStatus::Unknown) {
        outer = QColor("#1f42af");
        center = QColor("#7ca5ff");
    }

    QPixmap pixmap(26, 26);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setPen(QPen(QColor(0, 0, 0, 120), 1.1));
    QRadialGradient gradient(10, 9, 12, 8, 7);
    gradient.setColorAt(0.0, QColor("#ffffff"));
    gradient.setColorAt(0.18, center);
    gradient.setColorAt(1.0, outer);
    painter.setBrush(gradient);
    painter.drawEllipse(2, 2, 21, 21);
    return QIcon(pixmap);
}

QString fallbackCell(const QString& value, const QString& fallback) {
    return value.trimmed().isEmpty() || value == QStringLiteral("-") ? fallback : value;
}

class SettingsDialog final : public QDialog {
public:
    SettingsDialog(nt::SettingsService* settings, nt::VendorDbService* vendorDb, QWidget* parent = nullptr)
        : QDialog(parent)
        , m_settings(settings)
        , m_vendorDb(vendorDb) {
        setWindowTitle(QStringLiteral("Настройки"));
        setModal(true);
        resize(560, 280);

        auto* root = new QVBoxLayout(this);
        auto* form = new QFormLayout();

        m_workersSpin = new QSpinBox(this);
        m_workersSpin->setRange(8, 96);
        m_workersSpin->setValue(settings->scanWorkers());
        form->addRow(QStringLiteral("Потоки сканирования"), m_workersSpin);

        m_scanOnStartupCheck = new QCheckBox(QStringLiteral("Включить"), this);
        m_scanOnStartupCheck->setChecked(settings->value(QStringLiteral("scan_on_startup"), true).toBool(true));
        form->addRow(QStringLiteral("Автоскан при запуске"), m_scanOnStartupCheck);

        m_themeCombo = new QComboBox(this);
        m_themeCombo->addItem(QStringLiteral("Темная"), QStringLiteral("dark"));
        m_themeCombo->addItem(QStringLiteral("Светлая"), QStringLiteral("light"));
        m_themeCombo->setCurrentIndex(qMax(0, m_themeCombo->findData(settings->theme())));
        form->addRow(QStringLiteral("Тема"), m_themeCombo);

        m_languageCombo = new QComboBox(this);
        m_languageCombo->addItem(QStringLiteral("Русский"), QStringLiteral("ru"));
        m_languageCombo->addItem(QStringLiteral("English"), QStringLiteral("en"));
        m_languageCombo->setCurrentIndex(qMax(0, m_languageCombo->findData(settings->language())));
        form->addRow(QStringLiteral("Язык"), m_languageCombo);

        m_vendorStatus = new QLabel(vendorDb->statusText(), this);
        m_vendorStatus->setWordWrap(true);
        m_vendorStatus->setTextInteractionFlags(Qt::TextSelectableByMouse);
        form->addRow(QStringLiteral("База вендоров"), m_vendorStatus);

        auto* pathLabel = new QLabel(vendorDb->dbPath(), this);
        pathLabel->setWordWrap(true);
        pathLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        form->addRow(QStringLiteral("Путь к базе"), pathLabel);

        root->addLayout(form);

        auto* actions = new QHBoxLayout();
        auto* updateButton = new QPushButton(QStringLiteral("Обновить базу"), this);
        auto* openFolderButton = new QPushButton(QStringLiteral("Открыть папку данных"), this);
        actions->addWidget(updateButton);
        actions->addWidget(openFolderButton);
        actions->addStretch(1);
        root->addLayout(actions);

        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        root->addWidget(buttons);

        connect(updateButton, &QPushButton::clicked, this, [this]() {
            m_vendorStatus->setText(QStringLiteral("Обновление..."));
            const bool ok = m_vendorDb->updateFromNetwork();
            m_vendorStatus->setText(m_vendorDb->statusText());
            if (!ok) {
                QMessageBox::warning(this, QStringLiteral("База вендоров"), QStringLiteral("Не удалось обновить базу вендоров."));
            }
        });
        connect(openFolderButton, &QPushButton::clicked, this, []() {
            QDesktopServices::openUrl(QUrl::fromLocalFile(nt::AppPaths::appDataDir()));
        });
        connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
            m_settings->setValue(QStringLiteral("scan_workers"), m_workersSpin->value());
            m_settings->setValue(QStringLiteral("scan_on_startup"), m_scanOnStartupCheck->isChecked());
            m_settings->setValue(QStringLiteral("theme"), m_themeCombo->currentData().toString());
            m_settings->setValue(QStringLiteral("language"), m_languageCombo->currentData().toString());
            m_settings->save();
            accept();
        });
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
        connect(vendorDb, &nt::VendorDbService::statusChanged, this, [this](const QString& status, bool) {
            m_vendorStatus->setText(status);
        });
    }

private:
    nt::SettingsService* m_settings {nullptr};
    nt::VendorDbService* m_vendorDb {nullptr};
    QSpinBox* m_workersSpin {nullptr};
    QCheckBox* m_scanOnStartupCheck {nullptr};
    QComboBox* m_themeCombo {nullptr};
    QComboBox* m_languageCombo {nullptr};
    QLabel* m_vendorStatus {nullptr};
};

}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_settings(new nt::SettingsService(this))
    , m_vendorDb(new nt::VendorDbService(this))
    , m_snapshots(new nt::SnapshotService(this))
    , m_scanner(new nt::NetworkScanService(m_vendorDb, this))
    , m_http(new nt::HttpRequestService(this))
    , m_serialSession(new nt::SerialSession(this))
    , m_sshSession(new nt::SshProcessSession(this))
    , m_tcpSession(new nt::TcpClientSession(this))
    , m_telnetSession(new nt::TelnetSession(this))
    , m_udpSession(new nt::UdpSocketSession(this)) {
    m_sshTerminalFormat = defaultTerminalFormat();
    m_telnetTerminalFormat = defaultTerminalFormat();
    m_settings->load();
    m_vendorDb->ensureReady(false);
    m_scanAutoScanTimer = new QTimer(this);
    m_scanAutoScanTimer->setSingleShot(false);
    m_scanAutoScanTimer->setInterval(qMax(5, m_settings->value(QStringLiteral("auto_scan_interval_sec"), 30).toInt(30)) * 1000);

    qRegisterMetaType<nt::ScanRecord>("nt::ScanRecord");
    qRegisterMetaType<QList<nt::ScanRecord>>("QList<nt::ScanRecord>");
    qRegisterMetaType<nt::HttpResponse>("nt::HttpResponse");

    applyDarkPalette();
    applyStyleSheet();
    buildUi();

    setWindowTitle(QString::fromUtf8(kWindowTitle));
    resize(m_settings->initialWindowSize());
    setMinimumSize(860, 455);
    statusBar()->hide();
    updateScanFooter(QStringLiteral("Готово"));

    connect(m_scanAutoScanTimer, &QTimer::timeout, this, [this]() {
        if (m_scanAutoScanCheck != nullptr && m_scanAutoScanCheck->isChecked() && !m_scanner->isRunning()) {
            startScan();
        }
    });
    const bool autoScanEnabled = m_settings->value(QStringLiteral("auto_scan_enabled"), false).toBool(false);
    const bool scanOnStartup = m_settings->value(QStringLiteral("scan_on_startup"), true).toBool(true);
    if (autoScanEnabled || scanOnStartup) {
        QTimer::singleShot(250, this, [this]() {
            if (!m_scanner->isRunning()) {
                startScan();
            }
        });
    }

    connect(m_scanner, &nt::NetworkScanService::scanStarted, this, [this]() {
        if (m_scanStartButton != nullptr) {
            m_scanStartButton->setText(QStringLiteral("■ Стоп"));
            m_scanStartButton->setEnabled(true);
        }
        if (m_scanStopButton != nullptr) {
            m_scanStopButton->setEnabled(true);
        }
        updateScanFooter(QStringLiteral("Сканирование..."));
    });
    connect(m_scanner, &nt::NetworkScanService::recordReady, this, &MainWindow::appendScanRecord);
    connect(m_scanner, &nt::NetworkScanService::scanFinished, this, &MainWindow::finalizeScan);
    connect(m_scanner, &nt::NetworkScanService::scanFailed, this, [this](const QString& errorText) {
        QMessageBox::warning(this, QStringLiteral("Сканер IP"), errorText);
        if (m_scanStartButton != nullptr) {
            m_scanStartButton->setEnabled(true);
            m_scanStartButton->setText(QStringLiteral("▶ Старт"));
        }
        if (m_scanStopButton != nullptr) {
            m_scanStopButton->setEnabled(false);
        }
        if (m_scanFooterThreadsLabel != nullptr) {
            m_scanFooterThreadsLabel->setText(QStringLiteral("Потоки: 0"));
        }
        updateScanFooter(QStringLiteral("Готово"));
    });

    connect(m_http, &nt::HttpRequestService::finished, this, [this](const nt::HttpResponse& response) {
        QString text;
        if (!response.errorText.isEmpty()) {
            text = response.errorText;
        } else {
            text = QStringLiteral("HTTP %1\n\n").arg(response.statusCode);
            const auto parsed = QJsonDocument::fromJson(response.body);
            if (!parsed.isNull()) {
                text += QString::fromUtf8(parsed.toJson(QJsonDocument::Indented));
            } else {
                text += QString::fromUtf8(response.body);
            }
        }
        m_requestResponseEdit->setPlainText(text);
    });

    connect(m_serialSession, &nt::SerialSession::dataReceived, this, [this](const QByteArray& bytes) {
        appendTrafficEntry(
            m_serialWidgets.outputBox,
            QColor("#66a8ff"),
            QStringLiteral("RX"),
            displayBytes(bytes, m_serialWidgets.hexCheck != nullptr && m_serialWidgets.hexCheck->isChecked())
        );
    });
    connect(m_serialSession, &nt::SerialSession::stateChanged, this, [this](const QString& text) {
        statusBar()->showMessage(text, 3000);
    });
    connect(m_serialSession, &nt::SerialSession::connectedChanged, this, [this](bool connected) {
        if (m_serialWidgets.connectButton != nullptr) {
            m_serialWidgets.connectButton->setText(connected ? QStringLiteral("Отключить") : QStringLiteral("Подключить"));
        }
    });

    connect(m_tcpSession, &nt::TcpClientSession::dataReceived, this, [this](const QByteArray& bytes) {
        appendTrafficEntry(
            m_tcpWidgets.outputBox,
            QColor("#66a8ff"),
            QStringLiteral("RX"),
            displayBytes(bytes, m_tcpWidgets.hexCheck != nullptr && m_tcpWidgets.hexCheck->isChecked())
        );
    });
    connect(m_tcpSession, &nt::TcpClientSession::stateChanged, this, [this](const QString& text) {
        statusBar()->showMessage(text, 3000);
    });
    connect(m_tcpSession, &nt::TcpClientSession::connectedChanged, this, [this](bool connected) {
        if (m_tcpWidgets.connectButton != nullptr) {
            m_tcpWidgets.connectButton->setText(connected ? QStringLiteral("Отключить") : QStringLiteral("Подключить"));
        }
    });

    connect(m_udpSession, &nt::UdpSocketSession::datagramReceived, this, [this](const QString& endpoint, const QByteArray& bytes) {
        appendTrafficEntry(
            m_udpWidgets.outputBox,
            QColor("#66a8ff"),
            QStringLiteral("RX"),
            displayBytes(bytes, m_udpWidgets.hexCheck != nullptr && m_udpWidgets.hexCheck->isChecked()),
            endpoint
        );
    });
    connect(m_udpSession, &nt::UdpSocketSession::stateChanged, this, [this](const QString& text) {
        statusBar()->showMessage(text, 3000);
    });
    connect(m_udpSession, &nt::UdpSocketSession::connectedChanged, this, [this](bool open) {
        if (m_udpWidgets.connectButton != nullptr) {
            m_udpWidgets.connectButton->setText(open ? QStringLiteral("Закрыть") : QStringLiteral("Открыть"));
        }
    });

    connect(m_sshSession, &nt::SshProcessSession::outputReady, this, [this](const QString& text) {
        appendSessionTerminalOutput(m_sshWidgets.outputBox, text);
    });
    connect(m_sshSession, &nt::SshProcessSession::stateChanged, this, [this](const QString& text) {
        if (m_sshWidgets.statusLabel != nullptr) {
            m_sshWidgets.statusLabel->setText(text);
        }
    });
    connect(m_sshSession, &nt::SshProcessSession::connectedChanged, this, [this](bool connected) {
        if (m_sshWidgets.connectButton != nullptr) {
            m_sshWidgets.connectButton->setText(connected ? QStringLiteral("Отключить") : QStringLiteral("Подключить"));
        }
    });

    connect(m_telnetSession, &nt::TelnetSession::outputReady, this, [this](const QString& text) {
        appendSessionTerminalOutput(m_telnetWidgets.outputBox, text);
    });
    connect(m_telnetSession, &nt::TelnetSession::stateChanged, this, [this](const QString& text) {
        if (m_telnetWidgets.statusLabel != nullptr) {
            m_telnetWidgets.statusLabel->setText(text);
        }
    });
    connect(m_telnetSession, &nt::TelnetSession::connectedChanged, this, [this](bool connected) {
        if (m_telnetWidgets.connectButton != nullptr) {
            m_telnetWidgets.connectButton->setText(connected ? QStringLiteral("Отключить") : QStringLiteral("Подключить"));
        }
    });
}

MainWindow::~MainWindow() = default;

void MainWindow::closeEvent(QCloseEvent* event) {
    m_settings->setSection(QStringLiteral("window"), QJsonObject{
        {QStringLiteral("width"), width()},
        {QStringLiteral("height"), height()},
    });
    m_settings->save();
    m_scanner->cancel();
    m_sshSession->close();
    m_telnetSession->close();
    QMainWindow::closeEvent(event);
}

bool MainWindow::eventFilter(QObject* object, QEvent* event) {
    const bool isSessionTerminal = object == m_sshWidgets.outputBox || object == m_telnetWidgets.outputBox;
    if (!isSessionTerminal) {
        return QMainWindow::eventFilter(object, event);
    }
    auto* box = qobject_cast<QTextEdit*>(object);
    if (box == nullptr) {
        return QMainWindow::eventFilter(object, event);
    }
    if (event->type() == QEvent::MouseButtonPress || event->type() == QEvent::MouseButtonDblClick) {
        removeSessionDraft(box);
        renderSessionDraft(box);
        return QMainWindow::eventFilter(object, event);
    }
    if (event->type() != QEvent::KeyPress) {
        return QMainWindow::eventFilter(object, event);
    }
    auto* keyEvent = static_cast<QKeyEvent*>(event);
    QString* draft = sessionDraftForBox(box);
    int* draftCursor = sessionDraftCursorForBox(box);
    if (draft == nullptr || draftCursor == nullptr) {
        return true;
    }

    if (keyEvent->matches(QKeySequence::Paste)) {
        const QString text = QApplication::clipboard()->text();
        if (!text.isEmpty()) {
            removeSessionDraft(box);
            draft->insert(*draftCursor, text);
            *draftCursor += text.size();
            renderSessionDraft(box);
        }
        return true;
    }
    if (keyEvent->matches(QKeySequence::Copy) && box->textCursor().hasSelection()) {
        return QMainWindow::eventFilter(object, event);
    }
    if (keyEvent->matches(QKeySequence::SelectAll)) {
        return QMainWindow::eventFilter(object, event);
    }

    const Qt::KeyboardModifiers modifiers = keyEvent->modifiers();
    removeSessionDraft(box);
    switch (keyEvent->key()) {
    case Qt::Key_Return:
    case Qt::Key_Enter:
        if (modifiers & Qt::ShiftModifier) {
            draft->insert(*draftCursor, QLatin1Char('\n'));
            ++(*draftCursor);
            renderSessionDraft(box);
            return true;
        }
        if (!draft->isEmpty()) {
            sendSessionTerminalBytes(box, draft->toUtf8());
        }
        sendSessionTerminalBytes(box, object == m_telnetWidgets.outputBox ? QByteArrayLiteral("\r\n") : QByteArrayLiteral("\n"));
        draft->clear();
        *draftCursor = 0;
        return true;
    case Qt::Key_Backspace:
        if (*draftCursor > 0) {
            draft->remove(*draftCursor - 1, 1);
            --(*draftCursor);
        } else if (draft->isEmpty()) {
            sendSessionTerminalBytes(box, QByteArray(1, '\x7f'));
        }
        renderSessionDraft(box);
        return true;
    case Qt::Key_Delete:
        if (*draftCursor < draft->size()) {
            draft->remove(*draftCursor, 1);
        } else if (draft->isEmpty()) {
            sendSessionTerminalBytes(box, QByteArrayLiteral("\x1b[3~"));
        }
        renderSessionDraft(box);
        return true;
    case Qt::Key_Left:
        if (*draftCursor > 0) {
            --(*draftCursor);
        }
        renderSessionDraft(box);
        return true;
    case Qt::Key_Right:
        if (*draftCursor < draft->size()) {
            ++(*draftCursor);
        }
        renderSessionDraft(box);
        return true;
    case Qt::Key_Up:
        if (draft->isEmpty()) {
            sendSessionTerminalBytes(box, QByteArrayLiteral("\x1b[A"));
        }
        renderSessionDraft(box);
        return true;
    case Qt::Key_Down:
        if (draft->isEmpty()) {
            sendSessionTerminalBytes(box, QByteArrayLiteral("\x1b[B"));
        }
        renderSessionDraft(box);
        return true;
    case Qt::Key_Home:
        *draftCursor = 0;
        renderSessionDraft(box);
        return true;
    case Qt::Key_End:
        *draftCursor = draft->size();
        renderSessionDraft(box);
        return true;
    case Qt::Key_PageUp:
    case Qt::Key_PageDown:
        renderSessionDraft(box);
        return QMainWindow::eventFilter(object, event);
    case Qt::Key_Tab:
        draft->insert(*draftCursor, QLatin1Char('\t'));
        ++(*draftCursor);
        renderSessionDraft(box);
        return true;
    case Qt::Key_Escape:
        if (draft->isEmpty()) {
            sendSessionTerminalBytes(box, QByteArray(1, '\x1b'));
        }
        renderSessionDraft(box);
        return true;
    default:
        break;
    }

    if (modifiers == Qt::ControlModifier && keyEvent->key() == Qt::Key_C) {
        if (box->textCursor().hasSelection()) {
            renderSessionDraft(box);
            return QMainWindow::eventFilter(object, event);
        }
        draft->clear();
        *draftCursor = 0;
        sendSessionTerminalBytes(box, QByteArray(1, '\x03'));
        return true;
    }
    if (modifiers == Qt::ControlModifier && keyEvent->key() >= Qt::Key_A && keyEvent->key() <= Qt::Key_Z) {
        const char controlByte = static_cast<char>(keyEvent->key() - Qt::Key_A + 1);
        sendSessionTerminalBytes(box, QByteArray(1, controlByte));
        renderSessionDraft(box);
        return true;
    }

    const QString text = keyEvent->text();
    if (!text.isEmpty() && !(modifiers & Qt::MetaModifier)) {
        draft->insert(*draftCursor, text);
        *draftCursor += text.size();
        renderSessionDraft(box);
        return true;
    }
    renderSessionDraft(box);
    return QMainWindow::eventFilter(object, event);
}

void MainWindow::applyDarkPalette() {
    qApp->setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    QPalette palette;
    if (m_settings->theme() == QStringLiteral("light")) {
        palette.setColor(QPalette::Window, QColor("#eceff3"));
        palette.setColor(QPalette::WindowText, QColor("#1f2730"));
        palette.setColor(QPalette::Base, QColor("#ffffff"));
        palette.setColor(QPalette::AlternateBase, QColor("#f4f6f9"));
        palette.setColor(QPalette::Button, QColor("#dde3ea"));
        palette.setColor(QPalette::ButtonText, QColor("#1f2730"));
        palette.setColor(QPalette::Text, QColor("#1f2730"));
        palette.setColor(QPalette::Highlight, QColor("#c8d7e8"));
        palette.setColor(QPalette::HighlightedText, QColor("#111111"));
        palette.setColor(QPalette::Light, QColor("#f6f8fb"));
        palette.setColor(QPalette::Midlight, QColor("#d8dde5"));
        palette.setColor(QPalette::Mid, QColor("#cbd3dc"));
        palette.setColor(QPalette::Dark, QColor("#a5b0bc"));
        palette.setColor(QPalette::Shadow, QColor("#8f99a6"));
    } else {
        palette.setColor(QPalette::Window, QColor("#15191f"));
        palette.setColor(QPalette::WindowText, QColor("#e7ecf2"));
        palette.setColor(QPalette::Base, QColor("#0f1318"));
        palette.setColor(QPalette::AlternateBase, QColor("#171d24"));
        palette.setColor(QPalette::Button, QColor("#242b35"));
        palette.setColor(QPalette::ButtonText, QColor("#eef2f6"));
        palette.setColor(QPalette::Text, QColor("#eef2f6"));
        palette.setColor(QPalette::Highlight, QColor("#39444f"));
        palette.setColor(QPalette::HighlightedText, QColor("#ffffff"));
        palette.setColor(QPalette::Light, QColor("#3d4653"));
        palette.setColor(QPalette::Midlight, QColor("#2b323c"));
        palette.setColor(QPalette::Mid, QColor("#2b323c"));
        palette.setColor(QPalette::Dark, QColor("#0d1014"));
        palette.setColor(QPalette::Shadow, QColor("#090b0d"));
    }
    qApp->setPalette(palette);
}

void MainWindow::applyStyleSheet() {
    if (m_settings->theme() == QStringLiteral("light")) {
        setStyleSheet(QStringLiteral(R"(
        QMainWindow { background:#eceff3; }
        QMenuBar { background:#dde3ea; color:#1f2730; border-bottom:1px solid #b9c3ce; spacing:4px; font-size:11px; }
        QMenuBar::item { background:transparent; color:#1f2730; padding:3px 6px; margin:1px; }
        QMenuBar::item:selected { background:#cfd8e1; }
        QMenu { background:#f8f9fb; color:#1f2730; border:1px solid #b9c3ce; font-size:11px; }
        QMenu::item:selected { background:#dce5ee; }
        QFrame#toolbarPanel, QFrame#workPane, QFrame#sessionPane { background:#f7f9fb; border:1px solid #c8d0d9; }
        QLabel { color:#24303a; font-size:11px; }
        QLabel#titleLabel { font-size:14pt; font-weight:700; color:#1d2730; }
        QLabel#sectionLabel { font-size:10pt; font-weight:700; color:#1d2730; }
        QLabel#statusHint { color:#596676; }
        QListWidget, QTableWidget, QPlainTextEdit, QTextEdit, QLineEdit, QComboBox, QSpinBox, QTabWidget::pane {
            background:#ffffff; color:#1f2730; border:1px solid #bcc7d2; selection-background-color:#d3dfec; selection-color:#111111;
        }
        QLineEdit, QComboBox, QSpinBox { min-height:20px; max-height:20px; padding:1px 5px; font-size:11px; }
        QListWidget::item { padding:4px 6px; }
        QListWidget::item:selected { background:#d3dfec; }
        QHeaderView::section { background:#e6ebf1; color:#1f2730; border:0; border-right:1px solid #ccd4dd; border-bottom:1px solid #ccd4dd; padding:3px 5px; font-weight:400; font-size:11px; }
        QPushButton { background:#dde3ea; color:#1f2730; border:1px solid #aab4c0; padding:2px 8px; min-height:22px; max-height:22px; font-size:11px; font-weight:500; }
        QPushButton:hover { background:#d1d9e2; }
        QPushButton:pressed { background:#c2ccd8; padding-top:3px; padding-left:9px; }
        QPushButton:disabled { color:#7c8895; background:#edf1f5; border:1px solid #c6ced7; }
        QGroupBox { font-weight:700; color:#1f2730; border:1px solid #c8d0d9; margin-top:10px; padding-top:10px; background:#f7f9fb; }
        QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; }
        QStatusBar { background:#f7f9fb; color:#24303a; border-top:1px solid #c8d0d9; }
        QLabel#statusCell { background:#eef2f6; color:#24303a; border:1px solid #c8d0d9; padding:3px 7px; font-size:11px; }
        QPushButton#scanStartButton { font-size:11px; min-width:132px; max-width:132px; min-height:20px; max-height:20px; padding:0px 8px; font-weight:600; background:#dde3ea; border:1px solid #aab4c0; }
        QCheckBox { color:#24303a; font-size:11px; spacing:4px; }
        QPushButton#miniIconButton { min-width:26px; max-width:26px; padding:2px; font-size:10pt; }
    )"));
        return;
    }
    setStyleSheet(QStringLiteral(R"(
        QMainWindow { background:#15191f; }
        QMenuBar {
            background:#101419;
            color:#eef2f6;
            border-bottom:1px solid #2a313b;
            spacing:4px;
            font-size:11px;
        }
        QMenuBar::item {
            background:transparent;
            color:#eef2f6;
            padding:3px 6px;
            margin:1px;
        }
        QMenuBar::item:selected { background:#252c34; }
        QMenu {
            background:#171d24;
            color:#eef2f6;
            border:1px solid #36414d;
            font-size:11px;
        }
        QMenu::item:selected { background:#252c34; }
        QFrame#toolbarPanel, QFrame#workPane, QFrame#sessionPane {
            background:#171c22;
            border:1px solid #313944;
        }
        QLabel { color:#e7ecf2; font-size:11px; }
        QLabel#titleLabel { font-size:14pt; font-weight:700; color:#eef2f6; }
        QLabel#sectionLabel { font-size:10pt; font-weight:700; color:#eef2f6; }
        QLabel#statusHint { color:#9ca8b5; }
        QListWidget, QTableWidget, QPlainTextEdit, QTextEdit, QLineEdit, QComboBox, QSpinBox, QTabWidget::pane {
            background:#0f1318;
            color:#eef2f6;
            border:1px solid #394451;
            selection-background-color:#39444f;
            selection-color:#ffffff;
        }
        QLineEdit, QComboBox, QSpinBox {
            min-height:20px;
            max-height:20px;
            padding:1px 5px;
            font-size:11px;
        }
        QListWidget::item { padding:4px 6px; }
        QListWidget::item:selected { background:#39444f; }
        QHeaderView::section {
            background:#1a2129;
            color:#eef2f6;
            border:0;
            border-right:1px solid #2c3642;
            border-bottom:1px solid #2c3642;
            padding:3px 5px;
            font-weight:400;
            font-size:11px;
        }
        QPushButton {
            background:#242c36;
            color:#eef2f6;
            border:1px solid #455262;
            padding:2px 8px;
            min-height:22px;
            max-height:22px;
            font-size:11px;
            font-weight:500;
        }
        QPushButton:hover { background:#2c3743; }
        QPushButton:pressed {
            background:#1d242d;
            padding-top:3px;
            padding-left:9px;
        }
        QPushButton:disabled {
            color:#798290;
            background:#1c222a;
            border:1px solid #2f3741;
        }
        QGroupBox {
            font-weight:700;
            color:#eef2f6;
            border:1px solid #313944;
            margin-top:10px;
            padding-top:10px;
            background:#171c22;
        }
        QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; }
        QStatusBar { background:#171c22; color:#e7ecf2; border-top:1px solid #313944; }
        QLabel#statusCell {
            background:#11161b;
            color:#eef2f6;
            border:1px solid #313944;
            padding:3px 7px;
            font-size:11px;
        }
        QPushButton#scanStartButton {
            font-size:11px;
            min-width:132px;
            max-width:132px;
            min-height:20px;
            max-height:20px;
            padding:0px 8px;
            font-weight:600;
            background:#242c36;
            border:1px solid #455262;
        }
        QCheckBox {
            color:#e7ecf2;
            font-size:11px;
            spacing:4px;
        }
        QPushButton#miniIconButton {
            min-width:26px;
            max-width:26px;
            padding:2px;
            font-size:10pt;
        }
    )"));
}

bool MainWindow::isLightTheme() const {
    return m_settings->theme() == QStringLiteral("light");
}

void MainWindow::refreshScanTableColors() {
    if (m_scanTable == nullptr) {
        return;
    }
    const QColor defaultBackground = isLightTheme() ? QColor("#ffffff") : QColor("#0f1318");
    const QColor defaultForeground = isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6");
    const QColor gatewayBackground = isLightTheme() ? QColor("#efe2b6") : QColor("#3a301d");
    const QColor gatewayForeground = isLightTheme() ? QColor("#4c3812") : QColor("#f2d38a");

    for (int row = 0; row < m_scanTable->rowCount(); ++row) {
        const auto* ipItem = m_scanTable->item(row, 0);
        const auto* gatewayItem = m_scanTable->item(row, 4);
        const bool isGatewayHost = ipItem != nullptr
            && gatewayItem != nullptr
            && !gatewayItem->text().trimmed().isEmpty()
            && gatewayItem->text() != QStringLiteral("-")
            && ipItem->text() == gatewayItem->text();
        for (int col = 0; col < m_scanTable->columnCount(); ++col) {
            auto* item = m_scanTable->item(row, col);
            if (item == nullptr) {
                continue;
            }
            item->setBackground(QBrush(isGatewayHost ? gatewayBackground : defaultBackground));
            item->setForeground(QBrush(isGatewayHost ? gatewayForeground : defaultForeground));
            QFont font = item->font();
            font.setBold(isGatewayHost);
            item->setFont(font);
        }
    }
    m_scanTable->viewport()->update();
}

QWidget* MainWindow::createHeader() {
    auto* frame = new QFrame(this);
    frame->setObjectName(QStringLiteral("appHeader"));
    auto* layout = new QHBoxLayout(frame);
    layout->setContentsMargins(10, 8, 10, 8);
    layout->setSpacing(8);

    auto* title = new QLabel(QString::fromUtf8(kWindowTitle), frame);
    title->setObjectName(QStringLiteral("titleLabel"));
    layout->addWidget(title);
    layout->addStretch(1);

    auto* settingsButton = new QPushButton(QStringLiteral("Настройки"), frame);
    settingsButton->setMinimumWidth(96);
    connect(settingsButton, &QPushButton::clicked, this, &MainWindow::openSettingsDialog);
    layout->addWidget(settingsButton);
    return frame;
}

QWidget* MainWindow::createSidebar() {
    auto* frame = new QFrame(this);
    frame->setObjectName(QStringLiteral("navPanel"));
    frame->setMinimumWidth(180);
    frame->setMaximumWidth(230);

    auto* layout = new QVBoxLayout(frame);
    layout->setContentsMargins(10, 10, 10, 10);
    layout->setSpacing(8);

    auto* title = new QLabel(QStringLiteral("Разделы"), frame);
    title->setObjectName(QStringLiteral("sectionLabel"));
    layout->addWidget(title);

    m_navList = new QListWidget(frame);
    m_navList->addItems({
        QStringLiteral("Сканер IP"),
        QStringLiteral("HTTP / REQ"),
        QStringLiteral("Serial"),
        QStringLiteral("TCP"),
        QStringLiteral("UDP"),
        QStringLiteral("SSH"),
        QStringLiteral("Telnet"),
    });
    connect(m_navList, &QListWidget::currentRowChanged, this, &MainWindow::syncCurrentPage);
    layout->addWidget(m_navList, 1);
    return frame;
}

QWidget* MainWindow::createScanPage() {
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(3, 3, 3, 3);
    root->setSpacing(3);

    auto* toolbar = new QFrame(page);
    toolbar->setObjectName(QStringLiteral("toolbarPanel"));
    auto* toolbarLayout = new QVBoxLayout(toolbar);
    toolbarLayout->setContentsMargins(5, 5, 5, 5);
    toolbarLayout->setSpacing(4);

    auto* rangeRow = new QHBoxLayout();
    rangeRow->setSpacing(5);
    rangeRow->addWidget(new QLabel(QStringLiteral("Диапазон IP:"), toolbar));
    m_scanStartIp = new QLineEdit(toolbar);
    m_scanStartIp->setFixedWidth(132);
    rangeRow->addWidget(m_scanStartIp);
    rangeRow->addWidget(new QLabel(QStringLiteral("до"), toolbar));
    m_scanEndIp = new QLineEdit(toolbar);
    m_scanEndIp->setFixedWidth(132);
    rangeRow->addWidget(m_scanEndIp);
    rangeRow->addWidget(new QLabel(QStringLiteral("Адаптер:"), toolbar));
    m_scanAdapterCombo = new QComboBox(toolbar);
    m_scanAdapterCombo->setFixedWidth(180);
    rangeRow->addWidget(m_scanAdapterCombo);
    rangeRow->addStretch(1);
    toolbarLayout->addLayout(rangeRow);

    auto* optionsRow = new QHBoxLayout();
    optionsRow->setSpacing(5);
    optionsRow->addWidget(new QLabel(QStringLiteral("Авто IP:"), toolbar));
    m_scanAutoIpCheck = new QCheckBox(QStringLiteral("вкл"), toolbar);
    m_scanAutoIpCheck->setChecked(true);
    optionsRow->addWidget(m_scanAutoIpCheck);
    m_scanAutoScanCheck = new QCheckBox(QStringLiteral("авто скан"), toolbar);
    m_scanAutoScanCheck->setChecked(m_settings->value(QStringLiteral("auto_scan_enabled"), false).toBool(false));
    optionsRow->addWidget(m_scanAutoScanCheck);
    optionsRow->addSpacing(12);
    optionsRow->addWidget(new QLabel(QStringLiteral("Маска:"), toolbar));
    m_scanPrefixCombo = new QComboBox(toolbar);
    m_scanPrefixCombo->addItems({QStringLiteral("/24"), QStringLiteral("/23"), QStringLiteral("/22"), QStringLiteral("/16"), QStringLiteral("/32")});
    m_scanPrefixCombo->setCurrentText(QStringLiteral("/24"));
    m_scanPrefixCombo->setFixedWidth(70);
    optionsRow->addWidget(m_scanPrefixCombo);
    m_scanStartButton = new QPushButton(QStringLiteral("▶ Старт"), toolbar);
    m_scanStartButton->setObjectName(QStringLiteral("scanStartButton"));
    m_scanStartButton->setFixedWidth(132);
    optionsRow->addWidget(m_scanStartButton);
    optionsRow->addStretch(1);
    toolbarLayout->addLayout(optionsRow);

    m_scanOnlineLabel = new QLabel(QStringLiteral("Онлайн: 0"), toolbar);
    m_scanOnlineLabel->hide();
    m_scanStopButton = new QPushButton(page);
    m_scanStopButton->hide();

    connect(m_scanStartButton, &QPushButton::clicked, this, [this]() {
        if (m_scanner->isRunning()) {
            stopScan();
        } else {
            startScan();
        }
    });
    connect(m_scanStopButton, &QPushButton::clicked, this, &MainWindow::stopScan);
    connect(m_scanStartIp, &QLineEdit::returnPressed, this, &MainWindow::startScan);
    connect(m_scanEndIp, &QLineEdit::returnPressed, this, &MainWindow::startScan);
    connect(m_scanAdapterCombo, &QComboBox::currentIndexChanged, this, [this](int) {
        if (m_scanAutoIpCheck == nullptr || m_scanAutoIpCheck->isChecked()) {
            applyRangeFromCurrentAdapter();
        }
    });
    connect(m_scanPrefixCombo, &QComboBox::currentIndexChanged, this, [this](int) {
        if (m_scanAutoIpCheck == nullptr || m_scanAutoIpCheck->isChecked()) {
            applyRangeFromCurrentAdapter();
        }
    });
    connect(m_scanAutoIpCheck, &QCheckBox::toggled, this, [this](bool checked) {
        if (checked) {
            applyRangeFromCurrentAdapter();
            updateScanFooter(QStringLiteral("Авто IP включен"));
        } else {
            updateScanFooter(QStringLiteral("Авто IP выключен"));
        }
    });
    connect(m_scanAutoScanCheck, &QCheckBox::toggled, this, [this](bool checked) {
        m_settings->setValue(QStringLiteral("auto_scan_enabled"), checked);
        m_settings->save();
        if (checked) {
            m_scanAutoScanTimer->start();
            updateScanFooter(QStringLiteral("Авто скан включен"));
            if (!m_scanner->isRunning()) {
                startScan();
            }
        } else {
            m_scanAutoScanTimer->stop();
            updateScanFooter(QStringLiteral("Авто скан выключен"));
        }
    });

    root->addWidget(toolbar, 0);

    auto* tableFrame = new QFrame(page);
    tableFrame->setObjectName(QStringLiteral("workPane"));
    auto* tableLayout = new QVBoxLayout(tableFrame);
    tableLayout->setContentsMargins(0, 0, 0, 0);

    m_scanTable = new QTableWidget(0, 6, tableFrame);
    m_scanTable->setHorizontalHeaderLabels({
        QStringLiteral("IP"),
        QStringLiteral("Пинг"),
        QStringLiteral("MAC"),
        QStringLiteral("Вендор"),
        QStringLiteral("Шлюз IP"),
        QStringLiteral("Откр. порт"),
    });
    m_scanTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_scanTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_scanTable->setAlternatingRowColors(false);
    m_scanTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_scanTable->verticalHeader()->setVisible(false);
    m_scanTable->verticalHeader()->setDefaultSectionSize(23);
    m_scanTable->horizontalHeader()->setFixedHeight(23);
    m_scanTable->horizontalHeader()->setStretchLastSection(false);
    m_scanTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_scanTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Fixed);
    m_scanTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Fixed);
    m_scanTable->setShowGrid(true);
    m_scanTable->setColumnWidth(0, 165);
    m_scanTable->setColumnWidth(1, 72);
    m_scanTable->setColumnWidth(2, 128);
    m_scanTable->setColumnWidth(4, 132);
    m_scanTable->setColumnWidth(5, 110);
    tableLayout->addWidget(m_scanTable, 1);
    root->addWidget(tableFrame, 1);

    auto* footer = new QFrame(page);
    footer->setObjectName(QStringLiteral("toolbarPanel"));
    auto* footerLayout = new QHBoxLayout(footer);
    footerLayout->setContentsMargins(0, 0, 0, 0);
    footerLayout->setSpacing(1);
    m_scanFooterStateLabel = new QLabel(QStringLiteral("Готово"), footer);
    m_scanFooterThreadsLabel = new QLabel(QStringLiteral("Потоки: 0"), footer);
    m_scanFooterStateLabel->setObjectName(QStringLiteral("statusCell"));
    m_scanFooterThreadsLabel->setObjectName(QStringLiteral("statusCell"));
    m_scanFooterStateLabel->setMinimumWidth(320);
    m_scanFooterThreadsLabel->setMinimumWidth(120);
    footerLayout->addWidget(m_scanFooterStateLabel, 1);
    footerLayout->addWidget(m_scanFooterThreadsLabel);
    root->addWidget(footer, 0);

    reloadAdapters();
    applySuggestedRange();
    if (m_scanAutoScanCheck != nullptr && m_scanAutoScanCheck->isChecked()) {
        m_scanAutoScanTimer->start();
    }
    return page;
}

QWidget* MainWindow::createRequestPage() {
    auto* page = new QWidget(this);
    auto* root = new QHBoxLayout(page);
    root->setContentsMargins(8, 8, 8, 8);
    root->setSpacing(8);

    m_requestResponseEdit = new QPlainTextEdit(page);
    m_requestResponseEdit->setReadOnly(true);
    m_requestResponseEdit->setFont(fixedFont());
    root->addWidget(m_requestResponseEdit, 3);

    auto* controls = new QGroupBox(QStringLiteral("Запрос"), page);
    auto* controlsLayout = new QVBoxLayout(controls);

    auto* form = new QGridLayout();
    m_requestMethodCombo = new QComboBox(controls);
    m_requestMethodCombo->addItems({QStringLiteral("GET"), QStringLiteral("POST"), QStringLiteral("PUT"), QStringLiteral("PATCH"), QStringLiteral("DELETE")});
    m_requestUrlEdit = new QLineEdit(controls);
    m_requestUserEdit = new QLineEdit(controls);
    m_requestPassEdit = new QLineEdit(controls);
    m_requestPassEdit->setEchoMode(QLineEdit::Password);
    m_requestTimeoutSpin = new QSpinBox(controls);
    m_requestTimeoutSpin->setRange(1, 120);
    m_requestTimeoutSpin->setValue(10);

    form->addWidget(new QLabel(QStringLiteral("Метод"), controls), 0, 0);
    form->addWidget(m_requestMethodCombo, 0, 1);
    form->addWidget(new QLabel(QStringLiteral("URL"), controls), 1, 0);
    form->addWidget(m_requestUrlEdit, 1, 1);
    form->addWidget(new QLabel(QStringLiteral("Логин"), controls), 2, 0);
    form->addWidget(m_requestUserEdit, 2, 1);
    form->addWidget(new QLabel(QStringLiteral("Пароль"), controls), 3, 0);
    form->addWidget(m_requestPassEdit, 3, 1);
    form->addWidget(new QLabel(QStringLiteral("Таймаут"), controls), 4, 0);
    form->addWidget(m_requestTimeoutSpin, 4, 1);
    controlsLayout->addLayout(form);

    auto* tabs = new QTabWidget(controls);
    m_requestHeadersEdit = new QPlainTextEdit(QStringLiteral("{\n  \"Accept\": \"application/json\"\n}"), tabs);
    m_requestParamsEdit = new QPlainTextEdit(QStringLiteral("{}"), tabs);
    m_requestBodyEdit = new QPlainTextEdit(QStringLiteral("{}"), tabs);
    m_requestHeadersEdit->setFont(fixedFont());
    m_requestParamsEdit->setFont(fixedFont());
    m_requestBodyEdit->setFont(fixedFont());
    tabs->addTab(m_requestHeadersEdit, QStringLiteral("Заголовки"));
    tabs->addTab(m_requestParamsEdit, QStringLiteral("Параметры"));
    tabs->addTab(m_requestBodyEdit, QStringLiteral("Тело"));
    controlsLayout->addWidget(tabs, 1);

    auto* sendButton = new QPushButton(QStringLiteral("Отправить запрос"), controls);
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::sendHttpRequest);
    controlsLayout->addWidget(sendButton);
    root->addWidget(controls, 2);
    return page;
}

QWidget* MainWindow::createSerialPage() {
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(6, 6, 6, 6);
    root->setSpacing(6);

    auto* top = new QFrame(page);
    top->setObjectName(QStringLiteral("toolbarPanel"));
    auto* topLayout = new QGridLayout(top);
    topLayout->setContentsMargins(8, 8, 8, 8);
    topLayout->setHorizontalSpacing(6);
    topLayout->setVerticalSpacing(6);

    m_serialWidgets.portCombo = new QComboBox(top);
    m_serialWidgets.baudCombo = new QComboBox(top);
    m_serialWidgets.baudCombo->addItems({QStringLiteral("1200"), QStringLiteral("2400"), QStringLiteral("4800"), QStringLiteral("9600"), QStringLiteral("19200"), QStringLiteral("38400"), QStringLiteral("57600"), QStringLiteral("115200")});
    m_serialWidgets.baudCombo->setCurrentText(QStringLiteral("9600"));
    m_serialWidgets.bitsCombo = new QComboBox(top);
    m_serialWidgets.bitsCombo->addItems({QStringLiteral("8"), QStringLiteral("7")});
    m_serialWidgets.parityCombo = new QComboBox(top);
    m_serialWidgets.parityCombo->addItems({QStringLiteral("Нет"), QStringLiteral("Чет"), QStringLiteral("Нечет")});
    m_serialWidgets.stopBitsCombo = new QComboBox(top);
    m_serialWidgets.stopBitsCombo->addItems({QStringLiteral("1"), QStringLiteral("1.5"), QStringLiteral("2")});
    m_serialWidgets.flowControlCombo = new QComboBox(top);
    m_serialWidgets.flowControlCombo->addItems({QStringLiteral("Нет"), QStringLiteral("RTS/CTS"), QStringLiteral("XON/XOFF")});
    m_serialWidgets.hexCheck = new QCheckBox(QStringLiteral("HEX"), top);
    m_serialWidgets.eolCombo = new QComboBox(top);
    m_serialWidgets.eolCombo->addItems({QStringLiteral("Нет"), QStringLiteral("CR"), QStringLiteral("LF"), QStringLiteral("CRLF")});
    m_serialWidgets.connectButton = new QPushButton(QStringLiteral("Подключить"), top);
    auto* refreshButton = new QPushButton(QStringLiteral("Обновить"), top);

    topLayout->addWidget(new QLabel(QStringLiteral("Порт"), top), 0, 0);
    topLayout->addWidget(m_serialWidgets.portCombo, 0, 1);
    topLayout->addWidget(new QLabel(QStringLiteral("Скорость"), top), 0, 2);
    topLayout->addWidget(m_serialWidgets.baudCombo, 0, 3);
    topLayout->addWidget(new QLabel(QStringLiteral("Биты"), top), 0, 4);
    topLayout->addWidget(m_serialWidgets.bitsCombo, 0, 5);
    topLayout->addWidget(new QLabel(QStringLiteral("Четность"), top), 0, 6);
    topLayout->addWidget(m_serialWidgets.parityCombo, 0, 7);
    topLayout->addWidget(new QLabel(QStringLiteral("Стоп-биты"), top), 1, 0);
    topLayout->addWidget(m_serialWidgets.stopBitsCombo, 1, 1);
    topLayout->addWidget(new QLabel(QStringLiteral("Flow"), top), 1, 2);
    topLayout->addWidget(m_serialWidgets.flowControlCombo, 1, 3);
    topLayout->addWidget(new QLabel(QStringLiteral("Окончание"), top), 1, 4);
    topLayout->addWidget(m_serialWidgets.eolCombo, 1, 5);
    topLayout->addWidget(m_serialWidgets.hexCheck, 1, 6);
    topLayout->addWidget(refreshButton, 1, 7);
    topLayout->addWidget(m_serialWidgets.connectButton, 1, 8);
    root->addWidget(top);

    m_serialWidgets.outputBox = new QTextEdit(page);
    m_serialWidgets.outputBox->setReadOnly(true);
    m_serialWidgets.outputBox->setFont(fixedFont());
    m_serialWidgets.outputBox->setLineWrapMode(QTextEdit::NoWrap);
    root->addWidget(m_serialWidgets.outputBox, 1);

    auto* sendBox = new QFrame(page);
    sendBox->setObjectName(QStringLiteral("workPane"));
    auto* sendLayout = new QGridLayout(sendBox);
    sendLayout->setContentsMargins(8, 8, 8, 8);
    sendLayout->setHorizontalSpacing(6);
    sendLayout->setVerticalSpacing(6);
    m_serialWidgets.inputEdit = new QLineEdit(sendBox);
    m_serialWidgets.inputEdit->setPlaceholderText(QStringLiteral("Данные"));
    auto* sendButton = new QPushButton(QStringLiteral("Отправить"), sendBox);
    sendLayout->addWidget(new QLabel(QStringLiteral("Ввод"), sendBox), 0, 0);
    sendLayout->addWidget(m_serialWidgets.inputEdit, 0, 1);
    sendLayout->addWidget(sendButton, 0, 2);
    for (int i = 0; i < 3; ++i) {
        auto* quickEdit = new QLineEdit(sendBox);
        quickEdit->setPlaceholderText(QStringLiteral("Команда %1").arg(i + 1));
        auto* quickButton = new QPushButton(QStringLiteral("▶ %1").arg(i + 1), sendBox);
        m_serialWidgets.quickEdits.append(quickEdit);
        sendLayout->addWidget(new QLabel(QStringLiteral("Cmd %1").arg(i + 1), sendBox), i + 1, 0);
        sendLayout->addWidget(quickEdit, i + 1, 1);
        sendLayout->addWidget(quickButton, i + 1, 2);
        connect(quickEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("serial"), m_serialWidgets); });
        connect(quickButton, &QPushButton::clicked, this, [this, i]() { sendQuickCommand(QStringLiteral("serial"), m_serialWidgets, i); });
    }
    root->addWidget(sendBox);

    connect(refreshButton, &QPushButton::clicked, this, &MainWindow::refreshSerialPorts);
    connect(m_serialWidgets.connectButton, &QPushButton::clicked, this, &MainWindow::toggleSerial);
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::sendSerialPayload);
    connect(m_serialWidgets.inputEdit, &QLineEdit::returnPressed, this, &MainWindow::sendSerialPayload);
    connect(m_serialWidgets.inputEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("serial"), m_serialWidgets); });
    connect(m_serialWidgets.eolCombo, &QComboBox::currentTextChanged, this, [this]() { saveQuickCommands(QStringLiteral("serial"), m_serialWidgets); });

    refreshSerialPorts();
    {
        const auto section = m_settings->section(QStringLiteral("serial"));
        m_serialWidgets.baudCombo->setCurrentText(section.value(QStringLiteral("baud")).toString(QStringLiteral("9600")));
        m_serialWidgets.bitsCombo->setCurrentText(section.value(QStringLiteral("data_bits")).toString(QStringLiteral("8")));
        m_serialWidgets.parityCombo->setCurrentText(section.value(QStringLiteral("parity")).toString(QStringLiteral("Нет")));
        m_serialWidgets.stopBitsCombo->setCurrentText(section.value(QStringLiteral("stop_bits")).toString(QStringLiteral("1")));
        m_serialWidgets.flowControlCombo->setCurrentText(section.value(QStringLiteral("flow_control")).toString(QStringLiteral("Нет")));
        m_serialWidgets.eolCombo->setCurrentText(section.value(QStringLiteral("eol")).toString(QStringLiteral("Нет")));
    }
    loadQuickCommands(QStringLiteral("serial"), m_serialWidgets);
    return page;
}

QWidget* MainWindow::createTcpPage() {
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(6, 6, 6, 6);
    root->setSpacing(6);

    auto* top = new QFrame(page);
    top->setObjectName(QStringLiteral("toolbarPanel"));
    auto* topLayout = new QGridLayout(top);
    topLayout->setContentsMargins(8, 8, 8, 8);
    topLayout->setHorizontalSpacing(6);
    topLayout->setVerticalSpacing(6);

    m_tcpWidgets.hostEdit = new QLineEdit(QStringLiteral("127.0.0.1"), top);
    m_tcpWidgets.portSpin = new QSpinBox(top);
    m_tcpWidgets.portSpin->setRange(1, 65535);
    m_tcpWidgets.portSpin->setValue(23);
    m_tcpWidgets.localPortSpin = new QSpinBox(top);
    m_tcpWidgets.localPortSpin->setRange(0, 65535);
    m_tcpWidgets.localPortSpin->setValue(0);
    m_tcpWidgets.hexCheck = new QCheckBox(QStringLiteral("HEX"), top);
    m_tcpWidgets.eolCombo = new QComboBox(top);
    m_tcpWidgets.eolCombo->addItems({QStringLiteral("Нет"), QStringLiteral("CR"), QStringLiteral("LF"), QStringLiteral("CRLF")});
    m_tcpWidgets.noDelayCheck = new QCheckBox(QStringLiteral("NoDelay"), top);
    m_tcpWidgets.noDelayCheck->setChecked(true);
    m_tcpWidgets.keepAliveCheck = new QCheckBox(QStringLiteral("KeepAlive"), top);
    m_tcpWidgets.connectButton = new QPushButton(QStringLiteral("Подключить"), top);

    topLayout->addWidget(new QLabel(QStringLiteral("Хост"), top), 0, 0);
    topLayout->addWidget(m_tcpWidgets.hostEdit, 0, 1);
    topLayout->addWidget(new QLabel(QStringLiteral("Удаленный порт"), top), 0, 2);
    topLayout->addWidget(m_tcpWidgets.portSpin, 0, 3);
    topLayout->addWidget(new QLabel(QStringLiteral("Локальный порт"), top), 0, 4);
    topLayout->addWidget(m_tcpWidgets.localPortSpin, 0, 5);
    topLayout->addWidget(m_tcpWidgets.noDelayCheck, 1, 0);
    topLayout->addWidget(m_tcpWidgets.keepAliveCheck, 1, 1);
    topLayout->addWidget(new QLabel(QStringLiteral("Окончание"), top), 1, 2);
    topLayout->addWidget(m_tcpWidgets.eolCombo, 1, 3);
    topLayout->addWidget(m_tcpWidgets.hexCheck, 1, 4);
    topLayout->addWidget(m_tcpWidgets.connectButton, 1, 5);
    root->addWidget(top);

    m_tcpWidgets.outputBox = new QTextEdit(page);
    m_tcpWidgets.outputBox->setReadOnly(true);
    m_tcpWidgets.outputBox->setFont(fixedFont());
    m_tcpWidgets.outputBox->setLineWrapMode(QTextEdit::NoWrap);
    root->addWidget(m_tcpWidgets.outputBox, 1);

    auto* sendBox = new QFrame(page);
    sendBox->setObjectName(QStringLiteral("workPane"));
    auto* sendLayout = new QGridLayout(sendBox);
    sendLayout->setContentsMargins(8, 8, 8, 8);
    sendLayout->setHorizontalSpacing(6);
    sendLayout->setVerticalSpacing(6);
    m_tcpWidgets.inputEdit = new QLineEdit(sendBox);
    m_tcpWidgets.inputEdit->setPlaceholderText(QStringLiteral("Данные"));
    auto* sendButton = new QPushButton(QStringLiteral("Отправить"), sendBox);
    sendLayout->addWidget(new QLabel(QStringLiteral("Ввод"), sendBox), 0, 0);
    sendLayout->addWidget(m_tcpWidgets.inputEdit, 0, 1);
    sendLayout->addWidget(sendButton, 0, 2);
    for (int i = 0; i < 3; ++i) {
        auto* quickEdit = new QLineEdit(sendBox);
        quickEdit->setPlaceholderText(QStringLiteral("Команда %1").arg(i + 1));
        auto* quickButton = new QPushButton(QStringLiteral("▶ %1").arg(i + 1), sendBox);
        m_tcpWidgets.quickEdits.append(quickEdit);
        sendLayout->addWidget(new QLabel(QStringLiteral("Cmd %1").arg(i + 1), sendBox), i + 1, 0);
        sendLayout->addWidget(quickEdit, i + 1, 1);
        sendLayout->addWidget(quickButton, i + 1, 2);
        connect(quickEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("tcp"), m_tcpWidgets); });
        connect(quickButton, &QPushButton::clicked, this, [this, i]() { sendQuickCommand(QStringLiteral("tcp"), m_tcpWidgets, i); });
    }
    root->addWidget(sendBox);

    connect(m_tcpWidgets.connectButton, &QPushButton::clicked, this, &MainWindow::toggleTcp);
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::sendTcpPayload);
    connect(m_tcpWidgets.inputEdit, &QLineEdit::returnPressed, this, &MainWindow::sendTcpPayload);
    connect(m_tcpWidgets.inputEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("tcp"), m_tcpWidgets); });
    connect(m_tcpWidgets.eolCombo, &QComboBox::currentTextChanged, this, [this]() { saveQuickCommands(QStringLiteral("tcp"), m_tcpWidgets); });
    {
        const auto section = m_settings->section(QStringLiteral("tcp"));
        m_tcpWidgets.hostEdit->setText(section.value(QStringLiteral("host")).toString(QStringLiteral("127.0.0.1")));
        m_tcpWidgets.portSpin->setValue(section.value(QStringLiteral("port")).toInt(23));
        m_tcpWidgets.localPortSpin->setValue(section.value(QStringLiteral("local_port")).toInt(0));
        m_tcpWidgets.noDelayCheck->setChecked(section.value(QStringLiteral("no_delay")).toBool(true));
        m_tcpWidgets.keepAliveCheck->setChecked(section.value(QStringLiteral("keep_alive")).toBool(false));
        m_tcpWidgets.eolCombo->setCurrentText(section.value(QStringLiteral("eol")).toString(QStringLiteral("Нет")));
    }
    loadQuickCommands(QStringLiteral("tcp"), m_tcpWidgets);
    return page;
}

QWidget* MainWindow::createUdpPage() {
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(6, 6, 6, 6);
    root->setSpacing(6);

    auto* top = new QFrame(page);
    top->setObjectName(QStringLiteral("toolbarPanel"));
    auto* topLayout = new QGridLayout(top);
    topLayout->setContentsMargins(8, 8, 8, 8);
    topLayout->setHorizontalSpacing(6);
    topLayout->setVerticalSpacing(6);

    m_udpWidgets.hostEdit = new QLineEdit(QStringLiteral("127.0.0.1"), top);
    m_udpWidgets.remotePortSpin = new QSpinBox(top);
    m_udpWidgets.remotePortSpin->setRange(1, 65535);
    m_udpWidgets.remotePortSpin->setValue(52381);
    m_udpWidgets.localPortSpin = new QSpinBox(top);
    m_udpWidgets.localPortSpin->setRange(0, 65535);
    m_udpWidgets.localPortSpin->setValue(0);
    m_udpWidgets.hexCheck = new QCheckBox(QStringLiteral("HEX"), top);
    m_udpWidgets.eolCombo = new QComboBox(top);
    m_udpWidgets.eolCombo->addItems({QStringLiteral("Нет"), QStringLiteral("CR"), QStringLiteral("LF"), QStringLiteral("CRLF")});
    m_udpWidgets.reuseAddressCheck = new QCheckBox(QStringLiteral("Reuse"), top);
    m_udpWidgets.reuseAddressCheck->setChecked(true);
    m_udpWidgets.connectButton = new QPushButton(QStringLiteral("Открыть"), top);

    topLayout->addWidget(new QLabel(QStringLiteral("Удаленный хост"), top), 0, 0);
    topLayout->addWidget(m_udpWidgets.hostEdit, 0, 1);
    topLayout->addWidget(new QLabel(QStringLiteral("Удаленный порт"), top), 0, 2);
    topLayout->addWidget(m_udpWidgets.remotePortSpin, 0, 3);
    topLayout->addWidget(new QLabel(QStringLiteral("Локальный порт"), top), 0, 4);
    topLayout->addWidget(m_udpWidgets.localPortSpin, 0, 5);
    topLayout->addWidget(m_udpWidgets.reuseAddressCheck, 1, 0);
    topLayout->addWidget(new QLabel(QStringLiteral("Окончание"), top), 1, 1);
    topLayout->addWidget(m_udpWidgets.eolCombo, 1, 2);
    topLayout->addWidget(m_udpWidgets.hexCheck, 1, 3);
    topLayout->addWidget(m_udpWidgets.connectButton, 1, 5);
    root->addWidget(top);

    m_udpWidgets.outputBox = new QTextEdit(page);
    m_udpWidgets.outputBox->setReadOnly(true);
    m_udpWidgets.outputBox->setFont(fixedFont());
    m_udpWidgets.outputBox->setLineWrapMode(QTextEdit::NoWrap);
    root->addWidget(m_udpWidgets.outputBox, 1);

    auto* sendBox = new QFrame(page);
    sendBox->setObjectName(QStringLiteral("workPane"));
    auto* sendLayout = new QGridLayout(sendBox);
    sendLayout->setContentsMargins(8, 8, 8, 8);
    sendLayout->setHorizontalSpacing(6);
    sendLayout->setVerticalSpacing(6);
    m_udpWidgets.inputEdit = new QLineEdit(sendBox);
    m_udpWidgets.inputEdit->setPlaceholderText(QStringLiteral("Данные"));
    auto* sendButton = new QPushButton(QStringLiteral("Отправить"), sendBox);
    sendLayout->addWidget(new QLabel(QStringLiteral("Ввод"), sendBox), 0, 0);
    sendLayout->addWidget(m_udpWidgets.inputEdit, 0, 1);
    sendLayout->addWidget(sendButton, 0, 2);
    for (int i = 0; i < 3; ++i) {
        auto* quickEdit = new QLineEdit(sendBox);
        quickEdit->setPlaceholderText(QStringLiteral("Команда %1").arg(i + 1));
        auto* quickButton = new QPushButton(QStringLiteral("▶ %1").arg(i + 1), sendBox);
        m_udpWidgets.quickEdits.append(quickEdit);
        sendLayout->addWidget(new QLabel(QStringLiteral("Cmd %1").arg(i + 1), sendBox), i + 1, 0);
        sendLayout->addWidget(quickEdit, i + 1, 1);
        sendLayout->addWidget(quickButton, i + 1, 2);
        connect(quickEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("udp"), m_udpWidgets); });
        connect(quickButton, &QPushButton::clicked, this, [this, i]() { sendQuickCommand(QStringLiteral("udp"), m_udpWidgets, i); });
    }
    root->addWidget(sendBox);

    connect(m_udpWidgets.connectButton, &QPushButton::clicked, this, &MainWindow::toggleUdp);
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::sendUdpPayload);
    connect(m_udpWidgets.inputEdit, &QLineEdit::returnPressed, this, &MainWindow::sendUdpPayload);
    connect(m_udpWidgets.inputEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("udp"), m_udpWidgets); });
    connect(m_udpWidgets.eolCombo, &QComboBox::currentTextChanged, this, [this]() { saveQuickCommands(QStringLiteral("udp"), m_udpWidgets); });
    {
        const auto section = m_settings->section(QStringLiteral("udp"));
        m_udpWidgets.hostEdit->setText(section.value(QStringLiteral("host")).toString(QStringLiteral("127.0.0.1")));
        m_udpWidgets.remotePortSpin->setValue(section.value(QStringLiteral("remote_port")).toInt(52381));
        m_udpWidgets.localPortSpin->setValue(section.value(QStringLiteral("local_port")).toInt(0));
        m_udpWidgets.reuseAddressCheck->setChecked(section.value(QStringLiteral("reuse_address")).toBool(true));
        m_udpWidgets.eolCombo->setCurrentText(section.value(QStringLiteral("eol")).toString(QStringLiteral("Нет")));
    }
    loadQuickCommands(QStringLiteral("udp"), m_udpWidgets);
    return page;
}

QWidget* MainWindow::createSessionPage(const QString& kind, SessionWidgets& widgets, quint16 defaultPort) {
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(6, 6, 6, 6);

    auto* splitter = new QSplitter(Qt::Horizontal, page);
    splitter->setHandleWidth(1);
    root->addWidget(splitter, 1);

    auto* left = new QFrame(splitter);
    left->setObjectName(QStringLiteral("sessionPane"));
    left->setMinimumWidth(240);
    auto* leftLayout = new QVBoxLayout(left);
    leftLayout->setContentsMargins(8, 8, 8, 8);

    auto* profilesBox = new QGroupBox(kind + QStringLiteral(" профили"), left);
    auto* profilesLayout = new QVBoxLayout(profilesBox);
    widgets.profiles = new QListWidget(profilesBox);
    profilesLayout->addWidget(widgets.profiles, 1);
    auto* profileButtons = new QHBoxLayout();
    auto* newButton = new QPushButton(QStringLiteral("Новый"), profilesBox);
    auto* deleteButton = new QPushButton(QStringLiteral("Удалить"), profilesBox);
    profileButtons->addWidget(newButton);
    profileButtons->addWidget(deleteButton);
    profilesLayout->addLayout(profileButtons);
    leftLayout->addWidget(profilesBox, 1);

    auto* right = new QFrame(splitter);
    right->setObjectName(QStringLiteral("sessionPane"));
    auto* rightLayout = new QVBoxLayout(right);
    rightLayout->setContentsMargins(8, 8, 8, 8);

    auto* workspaceBox = new QGroupBox(kind + QStringLiteral(" рабочая область"), right);
    auto* grid = new QGridLayout(workspaceBox);
    widgets.nameEdit = new QLineEdit(workspaceBox);
    widgets.hostEdit = new QLineEdit(workspaceBox);
    widgets.portSpin = new QSpinBox(workspaceBox);
    widgets.portSpin->setRange(1, 65535);
    widgets.portSpin->setValue(defaultPort);
    widgets.userEdit = new QLineEdit(workspaceBox);
    widgets.passEdit = new QLineEdit(workspaceBox);
    widgets.passEdit->setEchoMode(QLineEdit::Password);
    widgets.connectButton = new QPushButton(QStringLiteral("Подключить"), workspaceBox);
    widgets.saveButton = new QPushButton(QStringLiteral("Сохранить профиль"), workspaceBox);

    grid->addWidget(new QLabel(QStringLiteral("Имя"), workspaceBox), 0, 0);
    grid->addWidget(widgets.nameEdit, 0, 1);
    grid->addWidget(new QLabel(QStringLiteral("Хост"), workspaceBox), 0, 2);
    grid->addWidget(widgets.hostEdit, 0, 3);
    grid->addWidget(new QLabel(QStringLiteral("Порт"), workspaceBox), 0, 4);
    grid->addWidget(widgets.portSpin, 0, 5);
    grid->addWidget(new QLabel(QStringLiteral("Логин"), workspaceBox), 1, 0);
    grid->addWidget(widgets.userEdit, 1, 1);
    grid->addWidget(new QLabel(QStringLiteral("Пароль"), workspaceBox), 1, 2);
    grid->addWidget(widgets.passEdit, 1, 3);
    grid->addWidget(widgets.saveButton, 1, 4);
    grid->addWidget(widgets.connectButton, 1, 5);
    rightLayout->addWidget(workspaceBox);

    widgets.statusLabel = new QLabel(QStringLiteral("Отключено"), right);
    widgets.statusLabel->setObjectName(QStringLiteral("statusHint"));
    rightLayout->addWidget(widgets.statusLabel);

    widgets.outputBox = new QTextEdit(right);
    widgets.outputBox->setReadOnly(true);
    widgets.outputBox->setFont(fixedFont());
    widgets.outputBox->setLineWrapMode(QTextEdit::NoWrap);
    widgets.outputBox->setFocusPolicy(Qt::StrongFocus);
    widgets.outputBox->setUndoRedoEnabled(false);
    widgets.outputBox->installEventFilter(this);
    rightLayout->addWidget(widgets.outputBox, 1);

    splitter->addWidget(left);
    splitter->addWidget(right);
    splitter->setStretchFactor(0, 0);
    splitter->setStretchFactor(1, 1);
    splitter->setSizes({260, 980});

    connect(newButton, &QPushButton::clicked, this, [this, &widgets, defaultPort]() { newSessionProfile(widgets, defaultPort); });
    connect(deleteButton, &QPushButton::clicked, this, [this, kind, &widgets, defaultPort]() { deleteSessionProfile(kind.toLower(), widgets, defaultPort); });
    connect(widgets.saveButton, &QPushButton::clicked, this, [this, kind, &widgets, defaultPort]() { saveSessionProfile(kind.toLower(), widgets, defaultPort); });
    connect(widgets.profiles, &QListWidget::itemSelectionChanged, this, [this, &widgets, defaultPort]() {
        const auto* item = widgets.profiles->currentItem();
        if (item == nullptr) {
            return;
        }
        const auto profile = item->data(Qt::UserRole).value<nt::SessionProfile>();
        applySessionProfile(profile, widgets);
        Q_UNUSED(defaultPort)
    });

    loadSessionProfiles(kind.toLower(), widgets, defaultPort);
    return page;
}

QWidget* MainWindow::createPlaceholderPage(const QString& title, const QString& text) {
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(12, 12, 12, 12);

    auto* box = new QFrame(page);
    box->setObjectName(QStringLiteral("workPane"));
    auto* boxLayout = new QVBoxLayout(box);
    auto* titleLabel = new QLabel(title, box);
    titleLabel->setObjectName(QStringLiteral("sectionLabel"));
    auto* textLabel = new QLabel(text, box);
    textLabel->setWordWrap(true);
    textLabel->setObjectName(QStringLiteral("statusHint"));
    boxLayout->addWidget(titleLabel);
    boxLayout->addWidget(textLabel);
    boxLayout->addStretch(1);
    root->addWidget(box, 1);
    return page;
}

void MainWindow::configureMenuBar() {
    auto* mainMenu = menuBar();
    mainMenu->setNativeMenuBar(false);
    mainMenu->clear();

    auto* scanMenu = mainMenu->addMenu(QStringLiteral("Сканирование"));
    scanMenu->addAction(QStringLiteral("Старт"), this, [this]() {
        syncCurrentPage(0);
        startScan();
    });
    scanMenu->addAction(QStringLiteral("Стоп"), this, &MainWindow::stopScan);
    scanMenu->addSeparator();
    scanMenu->addAction(QStringLiteral("Сохранить снимок"), this, &MainWindow::saveSnapshot);
    scanMenu->addAction(QStringLiteral("Сравнить с базой"), this, &MainWindow::compareSnapshot);
    scanMenu->addSeparator();
    scanMenu->addAction(QStringLiteral("Автодиапазон"), this, &MainWindow::applySuggestedRange);

    auto* goToMenu = mainMenu->addMenu(QStringLiteral("Функции"));
    const QList<QPair<QString, int>> pages {
        {QStringLiteral("Сканер IP"), 0},
        {QStringLiteral("HTTP / REQ"), 1},
        {QStringLiteral("Serial"), 2},
        {QStringLiteral("TCP"), 3},
        {QStringLiteral("UDP"), 4},
        {QStringLiteral("SSH"), 5},
        {QStringLiteral("Telnet"), 6},
    };
    for (const auto& item : pages) {
        goToMenu->addAction(item.first, this, [this, index = item.second]() { syncCurrentPage(index); });
    }

    auto* commandsMenu = mainMenu->addMenu(QStringLiteral("Команды"));
    commandsMenu->addAction(QStringLiteral("Обновить диапазон"), this, &MainWindow::resolveHostnameRange);
    commandsMenu->addAction(QStringLiteral("Обновить адаптеры"), this, &MainWindow::reloadAdapters);

    auto* favoritesMenu = mainMenu->addMenu(QStringLiteral("Избранное"));
    auto* emptyFavorites = favoritesMenu->addAction(QStringLiteral("Пока пусто"));
    emptyFavorites->setEnabled(false);

    mainMenu->addAction(QStringLiteral("Настройки"), this, &MainWindow::openSettingsDialog);

    auto* helpMenu = mainMenu->addMenu(QStringLiteral("Справка"));
    helpMenu->addAction(QStringLiteral("Руководство"), this, [this]() {
        QMessageBox::information(
            this,
            QStringLiteral("Руководство"),
            QStringLiteral(
                "Network Tools\n\n"
                "Назначение:\n"
                "Промышленная настольная утилита для IP-сканирования, HTTP-запросов, Serial, TCP, UDP, SSH и Telnet.\n\n"
                "Транспортные модули:\n"
                "Serial, TCP и UDP поддерживают как текстовый обмен, так и произвольные бинарные/HEX-последовательности, включая команды уровня VISCA и аналогичные протоколы управления.\n\n"
                "Безопасность и эксплуатация:\n"
                "Используйте только доверенные сетевые сегменты и подтвержденные учетные данные. Перед запуском в продуктивной среде проверьте сетевые политики, адреса, порты и сценарии автосканирования.\n\n"
                "Журналы обмена:\n"
                "Зеленая стрелка обозначает исходящую команду, синяя стрелка — входящий ответ. При включенном HEX данные отображаются в шестнадцатеричном виде как для передачи, так и для приема."
            )
        );
    });
    helpMenu->addAction(QStringLiteral("О программе"), this, [this]() {
        QMessageBox::information(
            this,
            QStringLiteral("О программе"),
            QStringLiteral("Network Tools\nNative C++/Qt desktop utility for network diagnostics and transport control.")
        );
    });
}

void MainWindow::buildUi() {
    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    configureMenuBar();

    m_pages = new QStackedWidget(central);
    m_pages->addWidget(createScanPage());
    m_pages->addWidget(createRequestPage());
    m_pages->addWidget(createSerialPage());
    m_pages->addWidget(createTcpPage());
    m_pages->addWidget(createUdpPage());
    m_pages->addWidget(createSessionPage(QStringLiteral("SSH"), m_sshWidgets, 22));
    m_pages->addWidget(createSessionPage(QStringLiteral("Telnet"), m_telnetWidgets, 23));
    root->addWidget(m_pages, 1);
    setCentralWidget(central);
    syncCurrentPage(0);

    connect(m_sshWidgets.connectButton, &QPushButton::clicked, this, [this]() {
        if (m_sshSession->isConnected()) {
            m_sshSession->close();
            return;
        }
        m_sshWidgets.outputBox->clear();
        m_sshSession->open(currentSessionProfile(m_sshWidgets, 22));
    });
    connect(m_telnetWidgets.connectButton, &QPushButton::clicked, this, [this]() {
        if (m_telnetSession->isConnected()) {
            m_telnetSession->close();
            return;
        }
        m_telnetWidgets.outputBox->clear();
        m_telnetSession->open(currentSessionProfile(m_telnetWidgets, 23));
    });
}

void MainWindow::syncCurrentPage(int row) {
    if (m_pages == nullptr || row < 0 || row >= m_pages->count()) {
        return;
    }
    m_pages->setCurrentIndex(row);
}

void MainWindow::openSettingsDialog() {
    const QString previousTheme = m_settings->theme();
    const QString previousLanguage = m_settings->language();
    SettingsDialog dialog(m_settings, m_vendorDb, this);
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }
    if (previousTheme != m_settings->theme()) {
        applyDarkPalette();
        applyStyleSheet();
        refreshScanTableColors();
    }
    if (previousLanguage != m_settings->language()) {
        QMessageBox::information(
            this,
            QStringLiteral("Настройки"),
            QStringLiteral("Язык интерфейса сохранен. Для полной локализации перезапустите приложение.")
        );
    }
}

void MainWindow::reloadAdapters() {
    const auto list = m_scanner->adapters();
    const auto previous = m_scanAdapterCombo->currentData().toString();
    m_scanAdapterCombo->clear();
    for (const auto& adapter : list) {
        const auto range = rangeFromIpAndPrefix(adapter.ip, adapter.prefixLength);
        const QString label = QStringLiteral("%1 | %2").arg(adapter.name, adapter.network);
        m_scanAdapterCombo->addItem(label, adapter.id);
        m_scanAdapterCombo->setItemData(m_scanAdapterCombo->count() - 1, range.first, Qt::UserRole + 1);
        m_scanAdapterCombo->setItemData(m_scanAdapterCombo->count() - 1, range.second, Qt::UserRole + 2);
    }
    const int previousIndex = m_scanAdapterCombo->findData(previous);
    if (previousIndex >= 0) {
        m_scanAdapterCombo->setCurrentIndex(previousIndex);
    }
}

void MainWindow::applySuggestedRange() {
    const auto suggestion = m_scanner->suggestRange();
    const int index = m_scanAdapterCombo->findData(suggestion.adapterId);
    if (index >= 0) {
        m_scanAdapterCombo->setCurrentIndex(index);
    }
    if (m_scanAutoIpCheck != nullptr) {
        m_scanAutoIpCheck->setChecked(true);
    }
    if (m_scanAdapterCombo != nullptr && m_scanAdapterCombo->currentIndex() >= 0) {
        applyRangeFromCurrentAdapter();
    } else {
        m_scanStartIp->setText(suggestion.startIp);
        m_scanEndIp->setText(suggestion.endIp);
    }
    updateScanFooter(suggestion.label);
}

void MainWindow::applyRangeFromCurrentAdapter() {
    if (m_scanAdapterCombo == nullptr || m_scanAdapterCombo->currentIndex() < 0) {
        return;
    }
    nt::AdapterInfo adapter;
    const QString adapterId = m_scanAdapterCombo->currentData().toString();
    for (const auto& item : m_scanner->adapters()) {
        if (item.id == adapterId || item.name == adapterId) {
            adapter = item;
            break;
        }
    }
    if (adapter.ip.isEmpty()) {
        return;
    }
    bool ok = false;
    const QString prefixText = m_scanPrefixCombo != nullptr ? m_scanPrefixCombo->currentText() : QStringLiteral("/24");
    const int prefix = prefixText.mid(1).toInt(&ok);
    const auto range = rangeFromIpAndPrefix(adapter.ip, ok ? prefix : qMax(1, adapter.prefixLength));
    if (!range.first.isEmpty()) {
        m_scanStartIp->setText(range.first);
    }
    if (!range.second.isEmpty()) {
        m_scanEndIp->setText(range.second);
    }
}

void MainWindow::resolveHostnameRange() {
    applyRangeFromCurrentAdapter();
    updateScanFooter(QStringLiteral("Диапазон обновлен по адаптеру"));
}

void MainWindow::startScan() {
    syncCurrentPage(0);
    if (m_scanAutoIpCheck != nullptr && m_scanAutoIpCheck->isChecked()) {
        applyRangeFromCurrentAdapter();
    }
    clearScanTable();
    m_scanRows.clear();
    if (m_scanOnlineLabel != nullptr) {
        m_scanOnlineLabel->setText(QStringLiteral("Онлайн: 0"));
    }
    m_vendorDb->ensureReady(true);
    updateScanFooter(QStringLiteral("Сканирование..."));
    if (m_scanFooterThreadsLabel != nullptr) {
        m_scanFooterThreadsLabel->setText(QStringLiteral("Потоки: %1").arg(m_settings->scanWorkers()));
    }
    m_scanner->start(
        m_scanStartIp->text().trimmed(),
        m_scanEndIp->text().trimmed(),
        m_scanAdapterCombo->currentData().toString(),
        m_settings->scanWorkers()
    );
}

void MainWindow::stopScan() {
    m_scanner->cancel();
    if (m_scanStartButton != nullptr) {
        m_scanStartButton->setEnabled(true);
        m_scanStartButton->setText(QStringLiteral("▶ Старт"));
    }
    if (m_scanStopButton != nullptr) {
        m_scanStopButton->setEnabled(false);
    }
    if (m_scanFooterThreadsLabel != nullptr) {
        m_scanFooterThreadsLabel->setText(QStringLiteral("Потоки: 0"));
    }
    updateScanFooter(m_scanAutoScanCheck != nullptr && m_scanAutoScanCheck->isChecked()
        ? QStringLiteral("Остановка сканирования... Авто скан активен")
        : QStringLiteral("Остановка сканирования..."));
}

void MainWindow::saveSnapshot() {
    if (m_scanRows.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("Снимки"), QStringLiteral("Пока нет результатов сканирования для сохранения."));
        return;
    }
    bool ok = false;
    const QString name = QInputDialog::getText(this, QStringLiteral("Сохранить снимок"), QStringLiteral("Название снимка"), QLineEdit::Normal, QStringLiteral("baseline"), &ok);
    if (!ok) {
        return;
    }
    QString path;
    QString error;
    if (!m_snapshots->saveSnapshot(name, m_scanRows, m_scanStartIp->text(), m_scanEndIp->text(), m_scanAdapterCombo->currentText(), &path, &error)) {
        QMessageBox::warning(this, QStringLiteral("Снимки"), error);
        return;
    }
    updateScanFooter(QStringLiteral("Снимок сохранен: %1").arg(path));
}

void MainWindow::compareSnapshot() {
    const auto snapshots = m_snapshots->listSnapshots();
    if (snapshots.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("Сравнение с базой"), QStringLiteral("Сохраненных снимков пока нет."));
        return;
    }

    QStringList options;
    for (const auto& item : snapshots) {
        options.append(QStringLiteral("%1 | %2 | хостов: %3").arg(item.name, item.createdAt.left(19), QString::number(item.rowCount)));
    }

    bool ok = false;
    const QString choice = QInputDialog::getItem(this, QStringLiteral("Сравнение с базой"), QStringLiteral("Сохраненные снимки"), options, 0, false, &ok);
    if (!ok || choice.isEmpty()) {
        return;
    }
    const int index = options.indexOf(choice);
    if (index < 0 || index >= snapshots.size()) {
        return;
    }

    nt::SnapshotMeta meta;
    QString error;
    const auto rows = m_snapshots->loadSnapshotRows(snapshots.at(index).path, &meta, &error);
    if (!error.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Сравнение с базой"), error);
        return;
    }

    const auto summary = m_snapshots->diffRows(rows, m_scanRows);
    QMessageBox::information(
        this,
        QStringLiteral("Сравнение с базой"),
        QStringLiteral("База: %1\nСохранено: %2\nХостов: %3\nНовых: %4\nИсчезло: %5\nИзменено: %6")
            .arg(meta.name, meta.createdAt.left(19))
            .arg(meta.rowCount)
            .arg(summary.added)
            .arg(summary.removed)
            .arg(summary.changed)
    );
}

void MainWindow::clearScanTable() {
    m_scanTable->setRowCount(0);
    for (auto it = m_hostLabels.begin(); it != m_hostLabels.end(); ++it) {
        it.value()->setText(QStringLiteral("-"));
    }
}

int MainWindow::findRowByIp(QTableWidget* table, const QString& ip) {
    for (int row = 0; row < table->rowCount(); ++row) {
        const auto* item = table->item(row, 0);
        if (item != nullptr && item->text() == ip) {
            return row;
        }
    }
    return -1;
}

void MainWindow::appendScanRecord(const nt::ScanRecord& record) {
    if (record.ip.isEmpty()) {
        return;
    }

    int rowIndex = findRowByIp(m_scanTable, record.ip);
    if (rowIndex < 0) {
        rowIndex = insertionRowForIp(m_scanTable, record.ip);
        m_scanTable->insertRow(rowIndex);
    }

    const QList<QString> values = {
        record.ip,
        fallbackCell(record.pingDisplay, QStringLiteral("[n/a]")),
        fallbackCell(record.mac, QStringLiteral("-")),
        fallbackCell(record.vendor, QStringLiteral("unknown vendor")),
        fallbackCell(record.gateway, QStringLiteral("-")),
        fallbackCell(record.port, QStringLiteral("-")),
    };
    const QString gatewayValue = fallbackCell(record.gateway, QStringLiteral("-"));
    const bool isGatewayHost = gatewayValue != QStringLiteral("-") && record.ip == gatewayValue;
    const QColor defaultBackground = isLightTheme() ? QColor("#ffffff") : QColor("#0f1318");
    const QColor defaultForeground = isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6");
    const QColor gatewayBackground = isLightTheme() ? QColor("#efe2b6") : QColor("#3a301d");
    const QColor gatewayForeground = isLightTheme() ? QColor("#4c3812") : QColor("#f2d38a");

    for (int col = 0; col < values.size(); ++col) {
        auto* item = m_scanTable->item(rowIndex, col);
        if (item == nullptr) {
            item = new QTableWidgetItem();
            m_scanTable->setItem(rowIndex, col, item);
        }
        item->setText(values.at(col));
        item->setBackground(QBrush(isGatewayHost ? gatewayBackground : defaultBackground));
        item->setForeground(QBrush(isGatewayHost ? gatewayForeground : defaultForeground));
        QFont font = item->font();
        font.setBold(isGatewayHost);
        item->setFont(font);
        if (col == 0) {
            item->setIcon(statusOrb(record.status));
            item->setToolTip(
                QStringLiteral("Статус: %1\nMAC: %2\nВендор: %3\nШлюз IP: %4\nОткрытые порты: %5\nМаршрут: %6\nМаска: %7%8")
                    .arg(nt::hostStatusText(record.status))
                    .arg(fallbackCell(record.mac, QStringLiteral("-")))
                    .arg(fallbackCell(record.vendor, QStringLiteral("unknown vendor")))
                    .arg(fallbackCell(record.gateway, QStringLiteral("-")))
                    .arg(fallbackCell(record.port, QStringLiteral("-")))
                    .arg(fallbackCell(record.name, QStringLiteral("-")))
                    .arg(fallbackCell(record.mask, QStringLiteral("-")))
                    .arg(isGatewayHost ? QStringLiteral("\nУзел является шлюзом сети.") : QString())
            );
        }
    }

    bool updated = false;
    for (auto& existing : m_scanRows) {
        if (existing.ip == record.ip) {
            existing = record;
            updated = true;
            break;
        }
    }
    if (!updated) {
        m_scanRows.append(record);
    }

    updateScanSummary();
}

void MainWindow::finalizeScan(const QList<nt::ScanRecord>& records, int durationMs) {
    QList<nt::ScanRecord> sortedRecords = records;
    std::sort(sortedRecords.begin(), sortedRecords.end(), [](const nt::ScanRecord& left, const nt::ScanRecord& right) {
        return ipToInt(left.ip) < ipToInt(right.ip);
    });
    if (m_scanTable != nullptr) {
        m_scanTable->setUpdatesEnabled(false);
        m_scanTable->setRowCount(0);
    }
    m_scanRows.clear();
    for (const auto& record : sortedRecords) {
        appendScanRecord(record);
    }
    if (m_scanTable != nullptr) {
        m_scanTable->setUpdatesEnabled(true);
        m_scanTable->viewport()->update();
    }
    if (m_scanStartButton != nullptr) {
        m_scanStartButton->setEnabled(true);
        m_scanStartButton->setText(QStringLiteral("▶ Старт"));
    }
    if (m_scanStopButton != nullptr) {
        m_scanStopButton->setEnabled(false);
    }
    if (m_scanFooterThreadsLabel != nullptr) {
        m_scanFooterThreadsLabel->setText(QStringLiteral("Потоки: 0"));
    }
    updateScanSummary();
    updateSelectedHostPanel();
    updateScanFooter(QStringLiteral("Готово | Завершено за %1 c").arg(durationMs / 1000.0, 0, 'f', 2));
}

void MainWindow::updateScanSummary() {
    int online = 0;
    int offline = 0;
    int detected = 0;
    int macCount = 0;
    for (const auto& row : m_scanRows) {
        if (row.status == nt::HostStatus::Online) {
            ++online;
            ++detected;
        } else if (row.status == nt::HostStatus::Unknown) {
            ++detected;
        } else if (row.status == nt::HostStatus::Offline) {
            ++offline;
        }
        if (!row.mac.trimmed().isEmpty() && row.mac != QStringLiteral("-")) {
            ++macCount;
        }
    }
    if (m_scanOnlineLabel != nullptr) {
        m_scanOnlineLabel->setText(QStringLiteral("Онлайн: %1").arg(online));
    }
    if (m_scanFooterStateLabel != nullptr && !m_scanner->isRunning()) {
        m_scanFooterStateLabel->setText(
            QStringLiteral("Готово | Активных: %1 | Онлайн: %2 | MAC: %3")
                .arg(m_scanRows.size())
                .arg(online)
                .arg(macCount)
        );
    }
}

void MainWindow::updateScanFooter(const QString& stateText) {
    if (m_scanFooterStateLabel != nullptr && !stateText.isEmpty()) {
        m_scanFooterStateLabel->setText(stateText);
    }
}

void MainWindow::updateSelectedHostPanel() {
    if (m_hostLabels.isEmpty()) {
        return;
    }
    const int row = m_scanTable->currentRow();
    if (row < 0) {
        return;
    }
    const auto* ipItem = m_scanTable->item(row, 0);
    if (ipItem == nullptr) {
        return;
    }
    const QString selectedIp = ipItem->text();
    auto it = std::find_if(m_scanRows.begin(), m_scanRows.end(), [&](const auto& record) {
        return record.ip == selectedIp;
    });
    if (it == m_scanRows.end()) {
        return;
    }
    const auto& item = *it;
    m_hostLabels.value(QStringLiteral("ip"))->setText(item.ip);
    m_hostLabels.value(QStringLiteral("status"))->setText(nt::hostStatusIndicator(item.status));
    m_hostLabels.value(QStringLiteral("mac"))->setText(item.mac.isEmpty() ? QStringLiteral("-") : item.mac);
    m_hostLabels.value(QStringLiteral("vendor"))->setText(item.vendor.isEmpty() ? QStringLiteral("-") : item.vendor);
    m_hostLabels.value(QStringLiteral("type"))->setText(item.typeHint.isEmpty() ? QStringLiteral("-") : item.typeHint);
    m_hostLabels.value(QStringLiteral("name"))->setText(item.name.isEmpty() ? QStringLiteral("-") : item.name);
    m_hostLabels.value(QStringLiteral("gateway"))->setText(item.gateway.isEmpty() ? QStringLiteral("-") : item.gateway);
    m_hostLabels.value(QStringLiteral("mask"))->setText(item.mask.isEmpty() ? QStringLiteral("-") : item.mask);
}

void MainWindow::sendHttpRequest() {
    if (m_requestUrlEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("HTTP / REQ"), QStringLiteral("Поле URL пустое."));
        return;
    }

    auto parseObject = [this](QPlainTextEdit* edit, const QString& title, bool allowEmpty = true) -> QJsonObject {
        QJsonParseError error;
        const QByteArray data = edit->toPlainText().trimmed().toUtf8();
        if (data.isEmpty() && allowEmpty) {
            return {};
        }
        const auto document = QJsonDocument::fromJson(data, &error);
        if (error.error != QJsonParseError::NoError || !document.isObject()) {
            QMessageBox::warning(this, QStringLiteral("HTTP / REQ"), title + QStringLiteral(" должны быть JSON-объектом."));
            return {};
        }
        return document.object();
    };

    nt::HttpRequestSpec spec;
    spec.method = m_requestMethodCombo->currentText();
    spec.url = m_requestUrlEdit->text().trimmed();
    spec.headers = parseObject(m_requestHeadersEdit, QStringLiteral("Заголовки"));
    spec.params = parseObject(m_requestParamsEdit, QStringLiteral("Параметры"));
    spec.body = m_requestBodyEdit->toPlainText().toUtf8();
    spec.username = m_requestUserEdit->text().trimmed();
    spec.password = m_requestPassEdit->text();
    spec.timeoutSec = m_requestTimeoutSpin->value();

    m_requestResponseEdit->setPlainText(QStringLiteral("Отправка..."));
    m_http->send(spec);
}

void MainWindow::refreshSerialPorts() {
    const QString current = m_serialWidgets.portCombo != nullptr ? m_serialWidgets.portCombo->currentData().toString() : QString();
    const QString preferred = current.isEmpty()
        ? m_settings->section(QStringLiteral("serial")).value(QStringLiteral("port_name")).toString()
        : current;
    if (m_serialWidgets.portCombo == nullptr) {
        return;
    }
    m_serialWidgets.portCombo->clear();
    const auto ports = QSerialPortInfo::availablePorts();
    if (ports.isEmpty()) {
        m_serialWidgets.portCombo->addItem(QStringLiteral("(портов нет)"), QString());
        return;
    }
    for (const auto& port : ports) {
        const QString label = QStringLiteral("%1 - %2").arg(port.portName(), port.description().trimmed().isEmpty() ? port.portName() : port.description());
        m_serialWidgets.portCombo->addItem(label, port.portName());
    }
    const int index = m_serialWidgets.portCombo->findData(preferred);
    m_serialWidgets.portCombo->setCurrentIndex(index >= 0 ? index : 0);
}

void MainWindow::toggleSerial() {
    if (m_serialSession->isOpen()) {
        m_serialSession->close();
        return;
    }
    const QString portName = m_serialWidgets.portCombo->currentData().toString();
    if (portName.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Serial"), QStringLiteral("Порт не выбран."));
        return;
    }
    QString error;
    const bool ok = m_serialSession->open(
        portName,
        m_serialWidgets.baudCombo->currentText().toInt(),
        m_serialWidgets.bitsCombo->currentText().toInt(),
        m_serialWidgets.parityCombo->currentText(),
        m_serialWidgets.stopBitsCombo->currentText(),
        m_serialWidgets.flowControlCombo->currentText(),
        &error
    );
    if (!ok) {
        QMessageBox::critical(this, QStringLiteral("Serial"), error);
        return;
    }
    auto section = m_settings->section(QStringLiteral("serial"));
    section.insert(QStringLiteral("port_name"), portName);
    section.insert(QStringLiteral("baud"), m_serialWidgets.baudCombo->currentText());
    section.insert(QStringLiteral("data_bits"), m_serialWidgets.bitsCombo->currentText());
    section.insert(QStringLiteral("parity"), m_serialWidgets.parityCombo->currentText());
    section.insert(QStringLiteral("stop_bits"), m_serialWidgets.stopBitsCombo->currentText());
    section.insert(QStringLiteral("flow_control"), m_serialWidgets.flowControlCombo->currentText());
    m_settings->setSection(QStringLiteral("serial"), section);
    m_settings->save();
    appendTrafficEntry(m_serialWidgets.outputBox, QColor("#b0bac5"), QStringLiteral("INFO"), QStringLiteral("Подключено %1 @ %2").arg(portName, m_serialWidgets.baudCombo->currentText()));
}

void MainWindow::toggleTcp() {
    if (m_tcpSession->isConnected()) {
        m_tcpSession->close();
        return;
    }
    const QString host = m_tcpWidgets.hostEdit->text().trimmed();
    if (host.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("TCP"), QStringLiteral("Поле хоста пустое."));
        return;
    }
    m_tcpWidgets.outputBox->clear();
    QString error;
    if (!m_tcpSession->open(
            host,
            static_cast<quint16>(m_tcpWidgets.portSpin->value()),
            static_cast<quint16>(m_tcpWidgets.localPortSpin->value()),
            m_tcpWidgets.noDelayCheck->isChecked(),
            m_tcpWidgets.keepAliveCheck->isChecked(),
            &error)) {
        QMessageBox::critical(this, QStringLiteral("TCP"), error);
        return;
    }
    auto section = m_settings->section(QStringLiteral("tcp"));
    section.insert(QStringLiteral("host"), host);
    section.insert(QStringLiteral("port"), m_tcpWidgets.portSpin->value());
    section.insert(QStringLiteral("local_port"), m_tcpWidgets.localPortSpin->value());
    section.insert(QStringLiteral("no_delay"), m_tcpWidgets.noDelayCheck->isChecked());
    section.insert(QStringLiteral("keep_alive"), m_tcpWidgets.keepAliveCheck->isChecked());
    m_settings->setSection(QStringLiteral("tcp"), section);
    m_settings->save();
}

void MainWindow::toggleUdp() {
    if (m_udpSession->isOpen()) {
        m_udpSession->close();
        return;
    }
    QString error;
    if (!m_udpSession->bind(static_cast<quint16>(m_udpWidgets.localPortSpin->value()), m_udpWidgets.reuseAddressCheck->isChecked(), &error)) {
        QMessageBox::critical(this, QStringLiteral("UDP"), error);
        return;
    }
    auto section = m_settings->section(QStringLiteral("udp"));
    section.insert(QStringLiteral("host"), m_udpWidgets.hostEdit->text().trimmed());
    section.insert(QStringLiteral("remote_port"), m_udpWidgets.remotePortSpin->value());
    section.insert(QStringLiteral("local_port"), m_udpWidgets.localPortSpin->value());
    section.insert(QStringLiteral("reuse_address"), m_udpWidgets.reuseAddressCheck->isChecked());
    m_settings->setSection(QStringLiteral("udp"), section);
    m_settings->save();
    appendTrafficEntry(m_udpWidgets.outputBox, QColor("#b0bac5"), QStringLiteral("INFO"), QStringLiteral("Открыт UDP :%1").arg(m_udpSession->localPort()));
}

QByteArray MainWindow::payloadFromText(const QString& text, bool hexEnabled) {
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        return {};
    }
    if (trimmed.contains(QStringLiteral("\\x"))) {
        QByteArray payload;
        const auto matches = QRegularExpression(QStringLiteral("\\\\x([0-9a-fA-F]{2})")).globalMatch(trimmed);
        auto it = matches;
        while (it.hasNext()) {
            const auto match = it.next();
            bool ok = false;
            const auto value = match.captured(1).toUInt(&ok, 16);
            if (ok) {
                payload.append(static_cast<char>(value));
            }
        }
        if (!payload.isEmpty()) {
            return payload;
        }
    }
    if (hexEnabled) {
        QByteArray payload;
        const auto parts = trimmed.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        bool allHex = !parts.isEmpty();
        for (const auto& part : parts) {
            bool ok = false;
            const auto value = part.toUInt(&ok, 16);
            if (!ok || part.size() > 2) {
                allHex = false;
                break;
            }
            payload.append(static_cast<char>(value));
        }
        if (allHex) {
            return payload;
        }
    }
    return trimmed.toUtf8();
}

QString MainWindow::displayBytes(const QByteArray& bytes, bool hexEnabled) {
    if (hexEnabled) {
        return QString::fromUtf8(bytes.toHex(' '));
    }
    return nt::TerminalSanitizer::sanitize(bytes);
}

QByteArray MainWindow::applyLineEnding(QByteArray payload, const QString& eolName, bool hexEnabled) {
    if (hexEnabled) {
        return payload;
    }
    if (eolName == QStringLiteral("CR")) {
        payload.append('\r');
    } else if (eolName == QStringLiteral("LF")) {
        payload.append('\n');
    } else if (eolName == QStringLiteral("CRLF")) {
        payload.append("\r\n");
    }
    return payload;
}

void MainWindow::appendTrafficEntry(QTextEdit* box, const QColor& arrowColor, const QString& direction, const QString& payload, const QString& endpoint) {
    if (box == nullptr || payload.isEmpty()) {
        return;
    }
    QTextCursor cursor(box->document());
    cursor.movePosition(QTextCursor::End);

    QTextCharFormat arrowFormat;
    arrowFormat.setForeground(arrowColor);
    arrowFormat.setFont(fixedFont());
    arrowFormat.setFontWeight(QFont::Bold);

    QTextCharFormat textFormat;
    textFormat.setForeground(QColor("#eef2f6"));
    textFormat.setFont(fixedFont());

    QTextCharFormat metaFormat = textFormat;
    metaFormat.setForeground(QColor("#a7b2be"));

    cursor.insertText(QStringLiteral("➜ "), arrowFormat);
    cursor.insertText(direction, arrowFormat);
    if (!endpoint.isEmpty()) {
        cursor.insertText(QStringLiteral(" [%1]").arg(endpoint), metaFormat);
    }
    cursor.insertText(QStringLiteral("\n"), textFormat);
    cursor.insertText(payload, textFormat);
    cursor.insertText(QStringLiteral("\n\n"), textFormat);
    box->setTextCursor(cursor);
    box->ensureCursorVisible();
}

void MainWindow::loadQuickCommands(const QString& key, StreamWidgets& widgets) {
    const auto section = m_settings->section(key);
    const auto commands = section.value(QStringLiteral("quick_commands")).toArray();
    for (int i = 0; i < widgets.quickEdits.size(); ++i) {
        widgets.quickEdits[i]->setText(i < commands.size() ? commands.at(i).toString() : QString());
    }
    if (widgets.inputEdit != nullptr) {
        widgets.inputEdit->setText(section.value(QStringLiteral("draft")).toString());
    }
    if (widgets.eolCombo != nullptr) {
        widgets.eolCombo->setCurrentText(section.value(QStringLiteral("eol")).toString(QStringLiteral("Нет")));
    }
}

void MainWindow::saveQuickCommands(const QString& key, const StreamWidgets& widgets) {
    auto section = m_settings->section(key);
    QJsonArray commands;
    for (auto* edit : widgets.quickEdits) {
        commands.append(edit == nullptr ? QString() : edit->text());
    }
    section.insert(QStringLiteral("quick_commands"), commands);
    if (widgets.inputEdit != nullptr) {
        section.insert(QStringLiteral("draft"), widgets.inputEdit->text());
    }
    if (widgets.eolCombo != nullptr) {
        section.insert(QStringLiteral("eol"), widgets.eolCombo->currentText());
    }
    m_settings->setSection(key, section);
    m_settings->save();
}

void MainWindow::sendQuickCommand(const QString& key, StreamWidgets& widgets, int index) {
    if (index < 0 || index >= widgets.quickEdits.size() || widgets.inputEdit == nullptr) {
        return;
    }
    widgets.inputEdit->setText(widgets.quickEdits[index]->text());
    saveQuickCommands(key, widgets);
    if (key == QStringLiteral("serial")) {
        sendSerialPayload();
    } else if (key == QStringLiteral("tcp")) {
        sendTcpPayload();
    } else if (key == QStringLiteral("udp")) {
        sendUdpPayload();
    }
}

void MainWindow::sendSerialPayload() {
    QByteArray payload = payloadFromText(m_serialWidgets.inputEdit->text(), m_serialWidgets.hexCheck->isChecked());
    if (payload.isEmpty()) {
        return;
    }
    payload = applyLineEnding(payload, m_serialWidgets.eolCombo->currentText(), m_serialWidgets.hexCheck->isChecked());
    QString error;
    m_serialSession->sendBytes(payload, &error);
    if (!error.isEmpty()) {
        appendTrafficEntry(m_serialWidgets.outputBox, QColor("#d85d5d"), QStringLiteral("ERR"), error);
        return;
    }
    appendTrafficEntry(m_serialWidgets.outputBox, QColor("#7fda72"), QStringLiteral("TX"), displayBytes(payload, m_serialWidgets.hexCheck->isChecked()));
}

void MainWindow::sendTcpPayload() {
    QByteArray payload = payloadFromText(m_tcpWidgets.inputEdit->text(), m_tcpWidgets.hexCheck->isChecked());
    if (payload.isEmpty()) {
        return;
    }
    if (!m_tcpSession->isConnected()) {
        appendTrafficEntry(m_tcpWidgets.outputBox, QColor("#d85d5d"), QStringLiteral("ERR"), QStringLiteral("TCP не подключен"));
        return;
    }
    payload = applyLineEnding(payload, m_tcpWidgets.eolCombo->currentText(), m_tcpWidgets.hexCheck->isChecked());
    m_tcpSession->sendBytes(payload);
    appendTrafficEntry(m_tcpWidgets.outputBox, QColor("#7fda72"), QStringLiteral("TX"), displayBytes(payload, m_tcpWidgets.hexCheck->isChecked()));
}

void MainWindow::sendUdpPayload() {
    QByteArray payload = payloadFromText(m_udpWidgets.inputEdit->text(), m_udpWidgets.hexCheck->isChecked());
    if (payload.isEmpty()) {
        return;
    }
    payload = applyLineEnding(payload, m_udpWidgets.eolCombo->currentText(), m_udpWidgets.hexCheck->isChecked());
    QString error;
    m_udpSession->sendDatagram(
        m_udpWidgets.hostEdit->text().trimmed(),
        static_cast<quint16>(m_udpWidgets.remotePortSpin->value()),
        payload,
        &error
    );
    if (!error.isEmpty()) {
        appendTrafficEntry(m_udpWidgets.outputBox, QColor("#d85d5d"), QStringLiteral("ERR"), error);
        return;
    }
    appendTrafficEntry(
        m_udpWidgets.outputBox,
        QColor("#7fda72"),
        QStringLiteral("TX"),
        displayBytes(payload, m_udpWidgets.hexCheck->isChecked()),
        QStringLiteral("%1:%2").arg(m_udpWidgets.hostEdit->text().trimmed()).arg(m_udpWidgets.remotePortSpin->value())
    );
}

void MainWindow::sendSessionTerminalBytes(QTextEdit* box, const QByteArray& bytes) {
    if (bytes.isEmpty()) {
        return;
    }
    if (box == m_sshWidgets.outputBox) {
        m_sshSession->sendBytes(bytes);
        return;
    }
    if (box == m_telnetWidgets.outputBox) {
        QByteArray payload = bytes;
        payload.replace("\r\n", "\n");
        payload.replace('\r', '\n');
        payload.replace("\n", "\r\n");
        m_telnetSession->sendBytes(payload);
    }
}

void MainWindow::appendSessionTerminalOutput(QTextEdit* box, const QString& text) {
    if (box == nullptr || text.isEmpty()) {
        return;
    }
    QTextCharFormat* format = sessionTerminalFormatForBox(box);
    if (format == nullptr) {
        return;
    }
    removeSessionDraft(box);
    QTextCursor cursor = box->textCursor();
    cursor.movePosition(QTextCursor::End);
    QString chunk;
    const auto flushChunk = [&]() {
        if (!chunk.isEmpty()) {
            cursor.insertText(chunk, *format);
            chunk.clear();
        }
    };
    for (int i = 0; i < text.size(); ++i) {
        const QChar ch = text.at(i);
        if (ch == QChar::fromLatin1('\x1b')) {
            flushChunk();
            if (i + 1 >= text.size()) {
                break;
            }
            const QChar next = text.at(i + 1);
            if (next == QLatin1Char(']')) {
                int j = i + 2;
                while (j < text.size()) {
                    if (text.at(j) == QChar::fromLatin1('\x07')) {
                        break;
                    }
                    if (text.at(j) == QChar::fromLatin1('\x1b') && j + 1 < text.size() && text.at(j + 1) == QLatin1Char('\\')) {
                        ++j;
                        break;
                    }
                    ++j;
                }
                i = j;
                continue;
            }
            if (next != QLatin1Char('[')) {
                continue;
            }
            int j = i + 2;
            while (j < text.size()) {
                const QChar final = text.at(j);
                if (final.unicode() >= '@' && final.unicode() <= '~') {
                    break;
                }
                ++j;
            }
            if (j >= text.size()) {
                break;
            }
            const QString params = text.mid(i + 2, j - (i + 2));
            const QChar final = text.at(j);
            if (final == QLatin1Char('m')) {
                QList<int> codes;
                const auto parts = params.split(QLatin1Char(';'));
                for (const auto& part : parts) {
                    bool ok = false;
                    const int value = part.isEmpty() ? 0 : part.toInt(&ok);
                    codes.append(ok || part.isEmpty() ? value : 0);
                }
                applyTerminalSgr(codes, *format);
            } else if (final == QLatin1Char('J')) {
                const int mode = params.isEmpty() ? 0 : params.toInt();
                if (mode == 2 || mode == 3) {
                    box->clear();
                    cursor = box->textCursor();
                    *format = defaultTerminalFormat();
                }
            } else if (final == QLatin1Char('K')) {
                cursor.movePosition(QTextCursor::EndOfBlock, QTextCursor::KeepAnchor);
                cursor.removeSelectedText();
            }
            i = j;
            continue;
        }
        if (ch == QChar::fromLatin1('\r')) {
            flushChunk();
            cursor.movePosition(QTextCursor::End);
            cursor.movePosition(QTextCursor::StartOfBlock, QTextCursor::KeepAnchor);
            cursor.removeSelectedText();
            continue;
        }
        if (ch == QChar::fromLatin1('\b')) {
            flushChunk();
            cursor.deletePreviousChar();
            continue;
        }
        if (ch == QLatin1Char('\n')) {
            flushChunk();
            cursor.insertText(QStringLiteral("\n"), *format);
            continue;
        }
        if (ch == QLatin1Char('\t')) {
            chunk.append(QStringLiteral("    "));
            continue;
        }
        if (ch.unicode() < 0x20) {
            continue;
        }
        chunk.append(ch);
    }
    flushChunk();
    box->setTextCursor(cursor);
    renderSessionDraft(box);
    box->ensureCursorVisible();
}

void MainWindow::renderSessionDraft(QTextEdit* box) {
    QString* draft = sessionDraftForBox(box);
    int* draftCursor = sessionDraftCursorForBox(box);
    QTextCharFormat* format = sessionTerminalFormatForBox(box);
    if (box == nullptr || draft == nullptr || draftCursor == nullptr || format == nullptr) {
        return;
    }
    QTextCursor cursor = box->textCursor();
    cursor.movePosition(QTextCursor::End);
    cursor.insertText(*draft, *format);
    const int endPosition = cursor.position();
    cursor.setPosition(endPosition - (draft->size() - *draftCursor));
    box->setTextCursor(cursor);
    box->ensureCursorVisible();
}

void MainWindow::removeSessionDraft(QTextEdit* box) {
    QString* draft = sessionDraftForBox(box);
    if (box == nullptr || draft == nullptr || draft->isEmpty()) {
        return;
    }
    QTextCursor cursor = box->textCursor();
    cursor.movePosition(QTextCursor::End);
    cursor.setPosition(cursor.position() - draft->size(), QTextCursor::KeepAnchor);
    cursor.removeSelectedText();
    box->setTextCursor(cursor);
}

QString* MainWindow::sessionDraftForBox(QTextEdit* box) {
    if (box == m_sshWidgets.outputBox) {
        return &m_sshDraft;
    }
    if (box == m_telnetWidgets.outputBox) {
        return &m_telnetDraft;
    }
    return nullptr;
}

int* MainWindow::sessionDraftCursorForBox(QTextEdit* box) {
    if (box == m_sshWidgets.outputBox) {
        return &m_sshDraftCursor;
    }
    if (box == m_telnetWidgets.outputBox) {
        return &m_telnetDraftCursor;
    }
    return nullptr;
}

QTextCharFormat* MainWindow::sessionTerminalFormatForBox(QTextEdit* box) {
    if (box == m_sshWidgets.outputBox) {
        return &m_sshTerminalFormat;
    }
    if (box == m_telnetWidgets.outputBox) {
        return &m_telnetTerminalFormat;
    }
    return nullptr;
}

void MainWindow::loadSessionProfiles(const QString& kind, SessionWidgets& widgets, quint16 defaultPort) {
    widgets.profiles->clear();
    const auto profiles = m_settings->sessionProfiles(kind, defaultPort);
    for (const auto& profile : profiles) {
        const QString subtitle = profile.username.trimmed().isEmpty()
            ? QStringLiteral("%1:%2").arg(profile.host).arg(profile.port)
            : QStringLiteral("%1@%2:%3").arg(profile.username, profile.host).arg(profile.port);
        auto* item = new QListWidgetItem(QStringLiteral("%1\n%2").arg(profile.name, subtitle));
        item->setData(Qt::UserRole, QVariant::fromValue(profile));
        widgets.profiles->addItem(item);
    }
    if (widgets.profiles->count() > 0) {
        widgets.profiles->setCurrentRow(0);
    } else {
        newSessionProfile(widgets, defaultPort);
    }
}

void MainWindow::applySessionProfile(const nt::SessionProfile& profile, SessionWidgets& widgets) {
    widgets.nameEdit->setText(profile.name);
    widgets.hostEdit->setText(profile.host);
    widgets.portSpin->setValue(profile.port);
    widgets.userEdit->setText(profile.username);
    widgets.passEdit->setText(profile.password);
}

nt::SessionProfile MainWindow::currentSessionProfile(const SessionWidgets& widgets, quint16 defaultPort) const {
    nt::SessionProfile profile;
    profile.name = widgets.nameEdit->text().trimmed();
    profile.host = widgets.hostEdit->text().trimmed();
    profile.port = static_cast<quint16>(widgets.portSpin->value());
    profile.username = widgets.userEdit->text().trimmed();
    profile.password = widgets.passEdit->text();
    if (profile.port == 0) {
        profile.port = defaultPort;
    }
    if (profile.name.isEmpty()) {
        profile.name = QStringLiteral("%1:%2").arg(profile.host, QString::number(profile.port));
    }
    return profile;
}

void MainWindow::saveSessionProfile(const QString& kind, SessionWidgets& widgets, quint16 defaultPort) {
    const auto profile = currentSessionProfile(widgets, defaultPort);
    if (profile.host.isEmpty()) {
        QMessageBox::warning(this, kind.toUpper(), QStringLiteral("Поле хоста пустое."));
        return;
    }

    QList<nt::SessionProfile> profiles = m_settings->sessionProfiles(kind, defaultPort);
    profiles.erase(std::remove_if(profiles.begin(), profiles.end(), [&](const auto& item) {
        return item.name == profile.name;
    }), profiles.end());
    profiles.prepend(profile);
    while (profiles.size() > 80) {
        profiles.removeLast();
    }

    m_settings->storeSessionProfiles(kind, profiles, profile);
    m_settings->save();
    loadSessionProfiles(kind, widgets, defaultPort);
}

void MainWindow::deleteSessionProfile(const QString& kind, SessionWidgets& widgets, quint16 defaultPort) {
    const auto* item = widgets.profiles->currentItem();
    if (item == nullptr) {
        return;
    }
    const auto current = item->data(Qt::UserRole).value<nt::SessionProfile>();
    QList<nt::SessionProfile> profiles = m_settings->sessionProfiles(kind, defaultPort);
    profiles.erase(std::remove_if(profiles.begin(), profiles.end(), [&](const auto& profile) {
        return profile.name == current.name;
    }), profiles.end());
    m_settings->storeSessionProfiles(kind, profiles, currentSessionProfile(widgets, defaultPort));
    m_settings->save();
    loadSessionProfiles(kind, widgets, defaultPort);
}

void MainWindow::newSessionProfile(SessionWidgets& widgets, quint16 defaultPort) {
    widgets.nameEdit->clear();
    widgets.hostEdit->setText(QStringLiteral("127.0.0.1"));
    widgets.portSpin->setValue(defaultPort);
    widgets.userEdit->clear();
    widgets.passEdit->clear();
}
