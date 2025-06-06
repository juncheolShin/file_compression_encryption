#pragma once
#include <cstddef>          // size_t / qsizetype
#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT
        Q_DISABLE_COPY(MainWindow)

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private slots:
    void browseInput();
    void browseOutput();
    void startProcess();
    void updateProgress(qsizetype done, qsizetype total);   // ก็ qsizetype
    void appendLog(const QString& message);
    void onPwToggle(bool checked);
private:
    Ui::MainWindow* ui;
};
