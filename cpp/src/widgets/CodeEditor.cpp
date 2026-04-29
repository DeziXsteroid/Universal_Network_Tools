#include "widgets/CodeEditor.h"

#include <QPainter>
#include <QRegularExpression>
#include <QSyntaxHighlighter>
#include <QTextBlock>

namespace {

class JsonSyntaxHighlighter final : public QSyntaxHighlighter {
public:
    explicit JsonSyntaxHighlighter(QTextDocument* document)
        : QSyntaxHighlighter(document) {
        m_keyFormat.setForeground(QColor("#66b7ff"));
        m_keyFormat.setFontWeight(QFont::Bold);
        m_stringFormat.setForeground(QColor("#9ddf7a"));
        m_numberFormat.setForeground(QColor("#f3c969"));
        m_boolFormat.setForeground(QColor("#e49cff"));
        m_nullFormat.setForeground(QColor("#d98080"));
        m_braceFormat.setForeground(QColor("#d6dde6"));
    }

protected:
    void highlightBlock(const QString& text) override {
        highlightRule(text, QRegularExpression(QStringLiteral("\"(?:\\\\.|[^\"\\\\])*\"(?=\\s*:)")), m_keyFormat);
        highlightRule(text, QRegularExpression(QStringLiteral("(?<!:)\\s*\"(?:\\\\.|[^\"\\\\])*\"")), m_stringFormat);
        highlightRule(text, QRegularExpression(QStringLiteral("\\b-?(?:0|[1-9]\\d*)(?:\\.\\d+)?(?:[eE][+-]?\\d+)?\\b")), m_numberFormat);
        highlightRule(text, QRegularExpression(QStringLiteral("\\b(?:true|false)\\b")), m_boolFormat);
        highlightRule(text, QRegularExpression(QStringLiteral("\\bnull\\b")), m_nullFormat);
        highlightRule(text, QRegularExpression(QStringLiteral("[\\{\\}\\[\\],:]")), m_braceFormat);
    }

private:
    void highlightRule(const QString& text, const QRegularExpression& expression, const QTextCharFormat& format) {
        auto matchIterator = expression.globalMatch(text);
        while (matchIterator.hasNext()) {
            const auto match = matchIterator.next();
            const int start = match.capturedStart();
            const int length = match.capturedLength();
            if (start >= 0 && length > 0) {
                setFormat(start, length, format);
            }
        }
    }

    QTextCharFormat m_keyFormat;
    QTextCharFormat m_stringFormat;
    QTextCharFormat m_numberFormat;
    QTextCharFormat m_boolFormat;
    QTextCharFormat m_nullFormat;
    QTextCharFormat m_braceFormat;
};

class LineNumberArea final : public QWidget {
public:
    explicit LineNumberArea(CodeEditor* editor)
        : QWidget(editor)
        , m_editor(editor) {
    }

    QSize sizeHint() const override {
        return QSize(m_editor->lineNumberAreaWidth(), 0);
    }

protected:
    void paintEvent(QPaintEvent* event) override {
        m_editor->lineNumberAreaPaintEvent(event);
    }

private:
    CodeEditor* m_editor {nullptr};
};

} 

CodeEditor::CodeEditor(QWidget* parent)
    : QPlainTextEdit(parent)
    , m_lineNumberArea(new LineNumberArea(this))
    , m_highlighter(new JsonSyntaxHighlighter(document())) {
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
    font.setPointSizeF(10.5);
    setFont(font);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    setTabStopDistance(fontMetrics().horizontalAdvance(QLatin1Char(' ')) * 4);
    updateLineNumberAreaWidth();
    highlightCurrentLine();
    connect(this, &QPlainTextEdit::blockCountChanged, this, [this]() { updateLineNumberAreaWidth(); });
    connect(this, &QPlainTextEdit::updateRequest, this, [this](const QRect& rect, int dy) { updateLineNumberArea(rect, dy); });
    connect(this, &QPlainTextEdit::cursorPositionChanged, this, [this]() { highlightCurrentLine(); });
}

int CodeEditor::lineNumberAreaWidth() const {
    int digits = 1;
    int max = qMax(1, blockCount());
    while (max >= 10) {
        max /= 10;
        ++digits;
    }
    return 12 + fontMetrics().horizontalAdvance(QLatin1Char('9')) * digits;
}

void CodeEditor::setJsonMode(bool enabled) {
    if (m_highlighter == nullptr) {
        return;
    }
    m_highlighter->setDocument(enabled ? document() : nullptr);
}

void CodeEditor::resizeEvent(QResizeEvent* event) {
    QPlainTextEdit::resizeEvent(event);
    const QRect rect = contentsRect();
    m_lineNumberArea->setGeometry(QRect(rect.left(), rect.top(), lineNumberAreaWidth(), rect.height()));
}

void CodeEditor::lineNumberAreaPaintEvent(QPaintEvent* event) {
    QPainter painter(m_lineNumberArea);
    painter.fillRect(event->rect(), QColor("#11161b"));

    QTextBlock block = firstVisibleBlock();
    int blockNumber = block.blockNumber();
    int top = qRound(blockBoundingGeometry(block).translated(contentOffset()).top());
    int bottom = top + qRound(blockBoundingRect(block).height());

    painter.setPen(QColor("#7d8793"));
    while (block.isValid() && top <= event->rect().bottom()) {
        if (block.isVisible() && bottom >= event->rect().top()) {
            painter.drawText(0, top, m_lineNumberArea->width() - 6, fontMetrics().height(), Qt::AlignRight, QString::number(blockNumber + 1));
        }
        block = block.next();
        top = bottom;
        bottom = top + qRound(blockBoundingRect(block).height());
        ++blockNumber;
    }
}

void CodeEditor::updateLineNumberAreaWidth() {
    setViewportMargins(lineNumberAreaWidth(), 0, 0, 0);
}

void CodeEditor::updateLineNumberArea(const QRect& rect, int dy) {
    if (dy != 0) {
        m_lineNumberArea->scroll(0, dy);
    } else {
        m_lineNumberArea->update(0, rect.y(), m_lineNumberArea->width(), rect.height());
    }
    if (rect.contains(viewport()->rect())) {
        updateLineNumberAreaWidth();
    }
}

void CodeEditor::highlightCurrentLine() {
    QList<QTextEdit::ExtraSelection> selections;
    if (!isReadOnly()) {
        QTextEdit::ExtraSelection selection;
        selection.format.setBackground(QColor(255, 255, 255, 12));
        selection.format.setProperty(QTextFormat::FullWidthSelection, true);
        selection.cursor = textCursor();
        selection.cursor.clearSelection();
        selections.append(selection);
    }
    setExtraSelections(selections);
}
