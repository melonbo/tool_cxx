#include "widget.h"
#include "ui_widget.h"
#include <QDesktopWidget>
#include <QDebug>

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    init();
    dataParse();
}

Widget::~Widget()
{
    delete ui;
}

void Widget::init()
{
    int window_width = 1400;
    this->setFixedWidth(window_width);
    ui->textEdit->setFixedWidth(window_width-10-10);
    ui->tableWidget->setFixedWidth(window_width-10-10);
    ui->tableWidget->move(ui->textEdit->x(), ui->textEdit->y()+ui->textEdit->height()+10);
}

void Widget::dataParse()
{
    QString data_input_string = ui->textEdit->toPlainText();
    int row_count = data_input_string.size()/40 + 1;
    int column_count = 20;

    ui->tableWidget->setRowCount(row_count);
    ui->tableWidget->setColumnCount(column_count);

    int data_pos = 0;
    for(int i=0; i<row_count; i++)
    {
        QTableWidgetItem* item_row_head = new QTableWidgetItem();
        item_row_head->setText(QString::number(i*20));
        ui->tableWidget->setVerticalHeaderItem(i, item_row_head);

        for(int j=0; j<column_count; j++)
        {
            QTableWidgetItem *item = new QTableWidgetItem(data_input_string.mid(data_pos, 2));
            item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(i, j, item);
            data_pos += 2;
        }
    }
}

void Widget::paintEvent(QPaintEvent *event)
{
    QHeaderView* header = ui->tableWidget->horizontalHeader();  // 获取水平表头
    int height = header->height();  // 获取列头高度
    qDebug() << "Column header height: " << height;

    QHeaderView* header2 = ui->tableWidget->verticalHeader();  // 获取垂直表头
    int width = header2->width();  // 获取行头宽度
    qDebug() << "Row header width: " << width;

    ui->tableWidget->setFixedHeight(46*(ui->tableWidget->rowCount()+1));
    int num = ui->textEdit->height() + 10 + ui->tableWidget->height();
    this->setFixedHeight(num);
    this->move(QApplication::desktop()->screen()->rect().center() - this->rect().center());
}

void Widget::on_textEdit_textChanged()
{
    dataParse();
}
