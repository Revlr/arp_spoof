TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -pthread -lpcap

SOURCES += \
        main.cpp \
    arp.cpp \
    pkt.cpp

HEADERS += \
    arp.h \
    pkt.h
