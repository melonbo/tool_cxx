#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();
    void init();
    void dataParse();

protected:
    void paintEvent(QPaintEvent *event);

private slots:
    void on_textEdit_textChanged();

private:
    Ui::Widget *ui;
};

#endif // WIDGET_H
