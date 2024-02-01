TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
QMAKE_CXXFLAGS += -std=c++11 -fpermissive -O0
QMAKE_CXXFLAGS += -pthread

contains(QT_ARCH, "arm"){
DEFINES += ARCH_ARM
INCLUDEPATH += /home/sad/res/lib_gb28181/a9/lib_pcap/
LIBS += -L/home/sad/res/lib_gb28181/a9/lib_pcap/pcap -lpcap
}else{
INCLUDEPATH += /home/sad/res/lib_gb28181/x86/lib_pcap/
LIBS += -L/home/sad/res/lib_gb28181/x86/lib_pcap/pcap -lpcap
}

SOURCES += main.cpp
