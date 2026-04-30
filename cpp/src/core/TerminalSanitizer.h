#pragma once

#include <QByteArray>
#include <QString>

namespace nt {

class TerminalSanitizer {
public:
    static QString sanitize(const QByteArray& data);
    static QString sanitizeText(const QString& text);
    static QString sanitizeTerminal(const QByteArray& data);
    static QString sanitizeTerminalText(const QString& text);
};

} // namespace nt
