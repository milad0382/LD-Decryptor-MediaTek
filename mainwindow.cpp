#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <Misc.h>
#include <QtDebug>
#include <QCryptographicHash>
#include <QFile>
#include <QtCore>
# include <QFileDialog>
#include <QString>
#include <memory.h>
#include <QComboBox>
#include <QDebug>
#include <QByteArray>
using core::Checksum;
using core::Conversion;
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}
MainWindow::~MainWindow()
{
    delete ui;
}
bool MainWindow::imeiEncDec(QByteArray *data, bool dec)
{
    QByteArray raw = *data;
    QByteArray key;
    // keys mtk
   {
     if(ui->combo_algo->currentText() == "Mediatek General MT67x")
      key = QByteArray::fromHex("3f06bd14d45fa985dd027410f0214d22");
      else
      key = QByteArray::fromHex("db0eec7b716d8998b6b54c964126e272");
   }
        if (dec)
        {
            core::Crypto::cryptAES_CFB128_Data(&raw, key, 0);
             *data = core::Crypto::cryptMtkNv(raw.mid(0, 10).toUpper());
        }
        else
        {
            QByteArray swap = core::Checksum::swapMtkNv(raw);
            QByteArray md5 = QCryptographicHash::hash(swap, QCryptographicHash::Md5);
            QByteArray csum;
            for (int i = 0; i < 8; i++)
            {
                char numb = md5.at(i) ^ md5.at(i+8);
                csum.push_back(numb);
            }
            *data = swap;
            data->push_back(csum);
            data->append(0x20-data->length(), '\x00');
            core::Crypto::cryptAES_CFB128_Data(data, key);
        }
    return true;
}

void MainWindow::on_BT_READ_clicked()
{
   QFile file(QFileDialog::getOpenFileName(NULL, tr("open a file")));
    if(!file.open(QIODevice::ReadOnly)) return;
    QByteArray nvlid = file.readAll();
    QString nvdataImei1, nvdataImei2,
    nvramImei1, nvramImei2,ldbfull,stdr;
          if (!nvlid.isEmpty())
            {
          QByteArray data = nvlid.mid(0x40);
          hash1 = data;
          for(int i=0; i < hash1.size();i++){
  QByteArray rwq = data.mid(i,16);
  i = i+16;
  QByteArray ldb = data.toBase64();
  if (imeiEncDec(&ldb, 1))
  ldbfull = ldb;
  if (imeiEncDec(&rwq, 1))
   i = i-1;
 stdr.append("\n"+rwq+"");
 }
  ui->textBrowser->setText(stdr);
 }else{
       ui->textBrowser->setText("Data is Empty!");
 }
 }
void MainWindow::on_BT_WRITE_clicked()
{

}

