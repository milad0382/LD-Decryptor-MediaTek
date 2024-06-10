#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
     bool imeiEncDec(QByteArray *, bool);
     QByteArray hash1;

private slots:
     void on_BT_READ_clicked();
     void on_BT_WRITE_clicked();

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
