// The window icon, which Qt Quick has no QML property for.
//
// QGuiApplication::setWindowIcon puts the mark on every window the
// application opens (a QWindow with no icon of its own uses the
// application's), which is what the title bar and the task manager show.
#include <QtCore/QString>
#include <QtGui/QGuiApplication>
#include <QtGui/QIcon>

extern "C" void bm_set_window_icon(const char *path)
{
    if (!path)
        return;
    const QIcon icon(QString::fromUtf8(path));
    if (icon.isNull())
        return;
    QGuiApplication::setWindowIcon(icon);
}
