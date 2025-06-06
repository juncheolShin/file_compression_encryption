#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "hufcrypt_core.h"
#include <QFileDialog>
#include <QtConcurrent/QtConcurrent>  
#include <QTime>
#include <QTextCursor>


MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
   
    connect(ui->btnBrowseIn, &QPushButton::clicked, this, &MainWindow::browseInput);
    connect(ui->btnBrowseOut, &QPushButton::clicked, this, &MainWindow::browseOutput);
    connect(ui->btnStart, &QPushButton::clicked, this, &MainWindow::startProcess);
    connect(ui->btnPwToggle, &QPushButton::toggled, this, &MainWindow::onPwToggle);

    ui->btnPwToggle->setCheckable(true);
    ui->btnPwToggle->setToolTip("Show Password");
    ui->lePassword->setEchoMode(QLineEdit::Password);
    ui->btnPwToggle->setCursor(Qt::PointingHandCursor);
}

MainWindow::~MainWindow() { delete ui; }

void MainWindow::appendLog(const QString& message) { //로그 출력
    ui->logBox->append("[" + QTime::currentTime().toString("hh:mm:ss") + "] " + message);
    ui->logBox->moveCursor(QTextCursor::End);
}

void MainWindow::browseInput() { // 입력 파일 선택
    QString f = QFileDialog::getOpenFileName(this, "Select Source File");
    if (!f.isEmpty()) ui->leInput->setText(f);
}
void MainWindow::browseOutput() { // 출력 파일 선택
    QString f = QFileDialog::getSaveFileName(this, "Select Target File");
    if (!f.isEmpty()) ui->leOutput->setText(f);
}

void MainWindow::onPwToggle(bool checked){ //비밀번호 보이기/숨기기
    if (checked) {
        ui->lePassword->setEchoMode(QLineEdit::Normal);
        ui->btnPwToggle->setToolTip("Hide Password");
    }
    else {
        ui->lePassword->setEchoMode(QLineEdit::Password);
        ui->btnPwToggle->setToolTip("Show Password");
    }
}

void MainWindow::startProcess() { // 압축 과정 실행
    ui->progress->setValue(0);
    ui->logBox->clear();
    bool enc = ui->rbEncrypt->isChecked();
    QString in = ui->leInput->text();
    QString out = ui->leOutput->text();
    QString pw = ui->lePassword->text();
    auto* emitter = new hufcrypt::logEmitter(this);

    connect(emitter, &hufcrypt::logEmitter::logMessage, this, &MainWindow::appendLog);

    QtConcurrent::run([=] {
        appendLog("Starting Process...");
        bool ok = hufcrypt::process(
            enc,
            in.toStdString(),
            out.toStdString(),
            pw.toStdString(),
            [=](size_t d, size_t t) {
                QMetaObject::invokeMethod(this, [=] { updateProgress(d, t); },
                    Qt::QueuedConnection);
            },
            emitter
        );
        QMetaObject::invokeMethod(this, [=] {
            ui->logBox->append(ok ? "Done" : "Failed");
            }, Qt::QueuedConnection);
        });
    ui->leInput->clear();
    ui->leOutput->clear();
    ui->lePassword->clear();
}

void MainWindow::updateProgress(qsizetype done, qsizetype total) { // 진행도 업데이트
    int pct = int(done * 100 / total);
    ui->progress->setValue(pct);
}

