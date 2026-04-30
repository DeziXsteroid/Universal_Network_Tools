#include "core/TerminalSanitizer.h"

#include <QRegularExpression>

namespace nt {

QString TerminalSanitizer::sanitize(const QByteArray& data) {
    QString text = QString::fromUtf8(data);
    if (text.isEmpty()) {
        text = QString::fromLocal8Bit(data);
    }
    return sanitizeText(text);
}

QString TerminalSanitizer::sanitizeText(const QString& input) {
    QString text = input;
    text.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
    text.replace(QStringLiteral("\r"), QStringLiteral("\n"));

    static const QRegularExpression oscRe(QStringLiteral("\x1B\\][^\x07\x1B]*(?:\x07|\x1B\\\\)"));
    static const QRegularExpression csiRe(QStringLiteral("\x1B\\[[0-?]*[ -/]*[@-~]"));
    static const QRegularExpression controlRe(QStringLiteral("[\\x00-\\x08\\x0B-\\x1A\\x1C-\\x1F]"));

    text.remove(oscRe);
    text.remove(csiRe);
    text.remove(controlRe);
    return text;
}

QString TerminalSanitizer::sanitizeTerminal(const QByteArray& data) {
    QString text = QString::fromUtf8(data);
    if (text.isEmpty()) {
        text = QString::fromLocal8Bit(data);
    }
    return sanitizeTerminalText(text);
}

QString TerminalSanitizer::sanitizeTerminalText(const QString& input) {
    QString text = input;
    text.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));

    static const QRegularExpression oscRe(QStringLiteral("\x1B\\][^\x07\x1B]*(?:\x07|\x1B\\\\)"));
    text.remove(oscRe);
    QString filtered;
    filtered.reserve(text.size());
    for (const QChar ch : text) {
        const ushort u = ch.unicode();
        if (u >= 0x20 || u == '\b' || u == '\t' || u == '\n' || u == '\r' || u == 0x1B) {
            filtered.append(ch);
        }
    }
    return filtered;
}

} // namespace nt
