TEMPLATE = app
TARGET = phoenixcoin-qt
VERSION = 0.7.0
INCLUDEPATH += src src/json src/qt
DEFINES += QT_GUI BOOST_THREAD_USE_LIB BOOST_SPIRIT_THREADSAFE
CONFIG += no_include_pwd
CONFIG += thread
QMAKE_CFLAGS += -DNEOSCRYPT_SHA256 -DNEOSCRYPT_ASM -DNEOSCRYPT_OPT
QT += core gui network

greaterThan(QT_MAJOR_VERSION, 4): {
    QT += widgets
    message("Building with the Qt v5 support$$escape_expand(\\n)")
} else {
    message("Building with the Qt v4 support$$escape_expand(\\n)")
}


# Dependency library locations can be customized with:
#    BOOST_INCLUDE_PATH, BOOST_LIB_PATH, BDB_INCLUDE_PATH,
#    BDB_LIB_PATH, OPENSSL_INCLUDE_PATH and OPENSSL_LIB_PATH respectively
win32:BOOST_LIB_SUFFIX=-mgw49-mt-x64-1_81
win32:BOOST_INCLUDE_PATH="/home/Administrator/boost-1.81"
win32:BOOST_LIB_PATH="/home/Administrator/boost-1.81/stage/lib"
win32:BDB_INCLUDE_PATH="/home/Administrator/db-5.3.28/build_unix"
win32:BDB_LIB_PATH="/home/Administrator/db-5.3.28/build_unix"
win32:OPENSSL_INCLUDE_PATH="/home/Administrator/openssl-1.0.2u/include"
win32:OPENSSL_LIB_PATH="/home/Administrator/openssl-1.0.2u"
# Directory with the headers "include" should be renamed or copied to "miniupnpc"
win32:MINIUPNPC_INCLUDE_PATH="/home/Administrator/miniupnpc-2.3.0"
win32:MINIUPNPC_LIB_PATH="/home/Administrator/miniupnpc-2.3.0"

macx:BOOST_LIB_SUFFIX=-mt-x64

OBJECTS_DIR = build
MOC_DIR = build
UI_DIR = build

# use: qmake RELEASE_I386=1
contains(RELEASE_I386, 1) {
    # Mac: optimised 32-bit x86
    macx:QMAKE_CFLAGS += -arch i386 -fomit-frame-pointer -msse2 -mdynamic-no-pic -I/usr/local/i386/include
    macx:QMAKE_CXXFLAGS += -arch i386 -fomit-frame-pointer -msse2 -mdynamic-no-pic -I/usr/local/i386/include
    macx:QMAKE_LFLAGS += -arch i386 -L/usr/local/i386/lib
    # Mac: 10.5+ (GCC 4.2.1) compatibility; Qt with Cocoa is broken on 10.4
    macx:QMAKE_CFLAGS += -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk
    macx:QMAKE_CXXFLAGS += -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk
    macx:QMAKE_OBJECTIVE_CFLAGS += -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk
    macx:QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.5
    # Windows: optimised 32-bit x86
    win32:QMAKE_CFLAGS += -march=i686 -fomit-frame-pointer
    win32:QMAKE_CXXFLAGS += -march=i686 -fomit-frame-pointer
}

# use: qmake RELEASE_AMD64=1
contains(RELEASE_AMD64, 1) {
    # Mac: optimised 64-bit x86
    macx:QMAKE_CFLAGS += -DNEOSCRYPT_MOVQ_FIX -arch x86_64 -fomit-frame-pointer -mdynamic-no-pic -I/usr/local/amd64/include
    macx:QMAKE_CXXFLAGS += -arch x86_64 -fomit-frame-pointer -mdynamic-no-pic -I/usr/local/amd64/include
    macx:QMAKE_LFLAGS += -arch x86_64 -L/usr/local/amd64/lib
    # Mac: 10.5+ (GCC 4.2.1) compatibility
    macx:QMAKE_CFLAGS += -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk
    macx:QMAKE_CXXFLAGS += -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk
    macx:QMAKE_OBJECTIVE_CFLAGS += -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk
    macx:QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.5
}

# strip symbols
!macx:QMAKE_LFLAGS += -Wl,-s
macx:QMAKE_LFLAGS += -dead_strip

win32 {
    DEFINES += WINDOWS

    # disable debug builds
    CONFIG -= debug_and_release debug_and_release_target

    # enable ASLR and DEP via GCC linker flags
    QMAKE_LFLAGS *= -Wl,--dynamicbase -Wl,--nxcompat

    # large address aware linker flag may break MinGW64
    #QMAKE_LFLAGS *= -Wl,--large-address-aware

    # default to static linking
    QMAKE_LFLAGS *= -static -static-libgcc -static-libstdc++ -pthread
}

# use: qmake "USE_QRCODE=1"
# libqrencode (http://fukuchi.org/works/qrencode/index.en.html) must be installed for support
contains(USE_QRCODE, 1) {
    message("Building with the QR code support$$escape_expand(\\n)")
    DEFINES += USE_QRCODE
    LIBS += -lqrencode
}

# use: qmake "USE_UPNP=1" ( enabled by default; default)
#  or: qmake "USE_UPNP=0" (disabled by default)
#  or: qmake "USE_UPNP=-" (not supported)
# miniupnpc (http://miniupnp.free.fr/files/) must be installed for support
contains(USE_UPNP, -) {
    message("Building without UPnP support$$escape_expand(\\n)")
} else {
    message("Building with the UPnP support$$escape_expand(\\n)")
    count(USE_UPNP, 0) {
        USE_UPNP=1
    }
    DEFINES += USE_UPNP=$$USE_UPNP
    INCLUDEPATH += $$MINIUPNPC_INCLUDE_PATH
    LIBS += $$join(MINIUPNPC_LIB_PATH,,-L,) -lminiupnpc
# Remove MINIUPNP_STATICLIB if linking against a shared library
    win32:DEFINES += MINIUPNP_STATICLIB
    win32:LIBS += -liphlpapi
}

# use: qmake "USE_DBUS=1"
contains(USE_DBUS, 1) {
    message("Building with the D-Bus support$$escape_expand(\\n)")
    DEFINES += USE_DBUS
    QT += dbus
}

# use: qmake "USE_IPV6=1" (compiled and enabled by default)
#  or: qmake "USE_IPV6=0" (compiled and disabled by default)
#  or: qmake "USE_IPV6=-" (not compiled)
contains(USE_IPV6, -) {
    message("Building without IPv6 support$$escape_expand(\\n)")
} else {
    message("Building with the IPv6 support$$escape_expand(\\n)")
    count(USE_IPV6, 0) {
        USE_IPV6=1
    }
    DEFINES += USE_IPV6=$$USE_IPV6
}

contains(NEED_QT_PLUGINS, 1) {
    DEFINES += NEED_QT_PLUGINS
    QTPLUGIN += qcncodecs qjpcodecs qtwcodecs qkrcodecs qtaccessiblewidgets
}


# regenerate src/build.h
!win32|contains(USE_BUILD_INFO, 1) {
    genbuild.depends = FORCE
    genbuild.commands = cd $$PWD; /bin/sh share/genbuild.sh $$OUT_PWD/build/build.h
    genbuild.target = $$OUT_PWD/build/build.h
    PRE_TARGETDEPS += $$OUT_PWD/build/build.h
    QMAKE_EXTRA_TARGETS += genbuild
    DEFINES += HAVE_BUILD_INFO
}

QMAKE_CXXFLAGS_WARN_ON = -fdiagnostics-show-option -Wall -Wextra -Wformat -Wformat-security \
    -Wno-unused-parameter

# Input
DEPENDPATH += src src/json src/qt
HEADERS += src/qt/gui.h \
    src/qt/transactiontablemodel.h \
    src/qt/addresstablemodel.h \
    src/qt/optionsdialog.h \
    src/qt/sendcoinsdialog.h \
    src/qt/addressbookpage.h \
    src/qt/signverifymessagedialog.h \
    src/qt/aboutdialog.h \
    src/qt/editaddressdialog.h \
    src/qt/addressvalidator.h \
    src/alert.h \
    src/addrman.h \
    src/base58.h \
    src/bignum.h \
    src/checkpoints.h \
    src/compat.h \
    src/sync.h \
    src/util.h \
    src/uint256.h \
    src/serialize.h \
    src/strlcpy.h \
    src/main.h \
    src/net.h \
    src/key.h \
    src/db.h \
    src/walletdb.h \
    src/script.h \
    src/init.h \
    src/irc.h \
    src/mruset.h \
    src/json/json_spirit_writer_template.h \
    src/json/json_spirit_writer.h \
    src/json/json_spirit_value.h \
    src/json/json_spirit_utils.h \
    src/json/json_spirit_stream_reader.h \
    src/json/json_spirit_reader_template.h \
    src/json/json_spirit_reader.h \
    src/json/json_spirit_error_position.h \
    src/json/json_spirit.h \
    src/qt/clientmodel.h \
    src/qt/guiutil.h \
    src/qt/transactionrecord.h \
    src/qt/guiconstants.h \
    src/qt/optionsmodel.h \
    src/qt/monitoreddatamapper.h \
    src/qt/trafficgraphwidget.h \
    src/qt/transactiondesc.h \
    src/qt/transactiondescdialog.h \
    src/qt/amountfield.h \
    src/wallet.h \
    src/keystore.h \
    src/qt/transactionfilterproxy.h \
    src/qt/transactionview.h \
    src/qt/walletmodel.h \
    src/rpcmain.h \
    src/qt/overviewpage.h \
    src/qt/csvmodelwriter.h \
    src/crypter.h \
    src/qt/sendcoinsentry.h \
    src/qt/qvalidatedlineedit.h \
    src/qt/coinunits.h \
    src/qt/walletstyles.h \
    src/qt/qvaluecombobox.h \
    src/qt/askpassphrasedialog.h \
    src/protocol.h \
    src/qt/notificator.h \
    src/qt/qtipcserver.h \
    src/allocators.h \
    src/ui_interface.h \
    src/qt/rpcconsole.h \
    src/qt/blockexplorer.h \
    src/version.h \
    src/netbase.h \
    src/clientversion.h \
    src/neoscrypt.h \
    src/ecies/ecies.h \
    src/ntp.h \
    src/qt/walletmodeltransaction.h \
    src/qt/coincontrol.h

SOURCES += src/qt/phoenixcoin.cpp \
    src/qt/gui.cpp \
    src/qt/transactiontablemodel.cpp \
    src/qt/addresstablemodel.cpp \
    src/qt/optionsdialog.cpp \
    src/qt/sendcoinsdialog.cpp \
    src/qt/addressbookpage.cpp \
    src/qt/signverifymessagedialog.cpp \
    src/qt/aboutdialog.cpp \
    src/qt/editaddressdialog.cpp \
    src/qt/addressvalidator.cpp \
    src/alert.cpp \
    src/version.cpp \
    src/sync.cpp \
    src/util.cpp \
    src/netbase.cpp \
    src/key.cpp \
    src/script.cpp \
    src/main.cpp \
    src/init.cpp \
    src/net.cpp \
    src/irc.cpp \
    src/checkpoints.cpp \
    src/addrman.cpp \
    src/db.cpp \
    src/walletdb.cpp \
    src/qt/clientmodel.cpp \
    src/qt/guiutil.cpp \
    src/qt/transactionrecord.cpp \
    src/qt/optionsmodel.cpp \
    src/qt/monitoreddatamapper.cpp \
    src/qt/trafficgraphwidget.cpp \
    src/qt/transactiondesc.cpp \
    src/qt/transactiondescdialog.cpp \
    src/qt/strings.cpp \
    src/qt/amountfield.cpp \
    src/wallet.cpp \
    src/keystore.cpp \
    src/qt/transactionfilterproxy.cpp \
    src/qt/transactionview.cpp \
    src/qt/walletmodel.cpp \
    src/rpcmain.cpp \
    src/rpccrypto.cpp \
    src/rpcdump.cpp \
    src/rpcnet.cpp \
    src/rpcmining.cpp \
    src/rpcwallet.cpp \
    src/rpcblockchain.cpp \
    src/rpcrawtransaction.cpp \
    src/qt/overviewpage.cpp \
    src/qt/csvmodelwriter.cpp \
    src/crypter.cpp \
    src/qt/sendcoinsentry.cpp \
    src/qt/qvalidatedlineedit.cpp \
    src/qt/coinunits.cpp \
    src/qt/walletstyles.cpp \
    src/qt/qvaluecombobox.cpp \
    src/qt/askpassphrasedialog.cpp \
    src/protocol.cpp \
    src/qt/notificator.cpp \
    src/qt/qtipcserver.cpp \
    src/qt/rpcconsole.cpp \
    src/qt/blockexplorer.cpp \
    src/noui.cpp \
    src/neoscrypt.c \
    src/neoscrypt_asm.S \
    src/ecies/secure.cpp \
    src/ecies/ecies.cpp \
    src/ntp.cpp \
    src/qt/walletmodeltransaction.cpp \
    src/qt/coincontrol.cpp

RESOURCES += \
    src/qt/phoenixcoin.qrc

FORMS += \
    src/qt/forms/sendcoinsdialog.ui \
    src/qt/forms/addressbookpage.ui \
    src/qt/forms/signverifymessagedialog.ui \
    src/qt/forms/aboutdialog.ui \
    src/qt/forms/editaddressdialog.ui \
    src/qt/forms/transactiondescdialog.ui \
    src/qt/forms/overviewpage.ui \
    src/qt/forms/sendcoinsentry.ui \
    src/qt/forms/askpassphrasedialog.ui \
    src/qt/forms/rpcconsole.ui \
    src/qt/forms/blockexplorer.ui \
    src/qt/forms/optionsdialog.ui \
    src/qt/forms/coincontrol.ui

contains(USE_QRCODE, 1) {
HEADERS += src/qt/qrcodedialog.h
SOURCES += src/qt/qrcodedialog.cpp
FORMS += src/qt/forms/qrcodedialog.ui
}

CODECFORTR = UTF-8

# for lrelease/lupdate
# also add new translations to src/qt/phoenixcoin.qrc under translations/
TRANSLATIONS = $$files(src/qt/locale/phoenixcoin_*.ts)

isEmpty(QMAKE_LRELEASE) {
    win32:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]\\lrelease.exe
    else:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease
}
isEmpty(QM_DIR):QM_DIR = $$PWD/src/qt/locale
# automatically build translations, so they can be included in resource file
TSQM.name = lrelease ${QMAKE_FILE_IN}
TSQM.input = TRANSLATIONS
TSQM.output = $$QM_DIR/${QMAKE_FILE_BASE}.qm
TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN} -qm ${QMAKE_FILE_OUT}
TSQM.CONFIG = no_link
QMAKE_EXTRA_COMPILERS += TSQM

# "Other files" to show in Qt Creator
OTHER_FILES += \
    doc/*.rst doc/*.txt doc/README README.md res/phoenixcoin-qt.rc

win32:RC_FILE = src/qt/res/phoenixcoin-qt.rc

win32:!contains(MINGW_THREAD_BUGFIX, 0) {
    # At least qmake's win32-g++-cross profile is missing the -lmingwthrd
    # thread-safety flag. GCC has -mthreads to enable this, but it doesn't
    # work with static linking. -lmingwthrd must come BEFORE -lmingw, so
    # it is prepended to QMAKE_LIBS_QT_ENTRY.
    # It can be turned off with MINGW_THREAD_BUGFIX=0, just in case it causes
    # any problems on some untested qmake profile now or in the future.
    DEFINES += _MT
    QMAKE_LIBS_QT_ENTRY = -lmingwthrd $$QMAKE_LIBS_QT_ENTRY
}

!win32:!macx {
    DEFINES += LINUX
    LIBS += -lrt
}

macx:HEADERS += src/qt/macdockiconhandler.h src/qt/macnotificationhandler.h
macx:OBJECTIVE_SOURCES += src/qt/macdockiconhandler.mm src/qt/macnotificationhandler.mm
macx:LIBS += -framework Foundation -framework ApplicationServices -framework AppKit
macx:DEFINES += MAC_OSX MSG_NOSIGNAL=0
macx:ICON = src/qt/res/icons/phoenixcoin.icns
macx:TARGET = "Phoenixcoin-Qt"
macx:QMAKE_CFLAGS_THREAD += -pthread
macx:QMAKE_LFLAGS_THREAD += -pthread
macx:QMAKE_CXXFLAGS_THREAD += -pthread

# Set libraries and includes at end, to use platform-defined defaults if not overridden
INCLUDEPATH += $$BOOST_INCLUDE_PATH $$BDB_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH $$QRENCODE_INCLUDE_PATH
LIBS += $$join(BOOST_LIB_PATH,,-L,) $$join(BDB_LIB_PATH,,-L,) $$join(OPENSSL_LIB_PATH,,-L,) $$join(QRENCODE_LIB_PATH,,-L,)
LIBS += -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX -lsecp256k1
# -lgdi32 has to happen after -lcrypto (see  #681)
win32:LIBS += -lws2_32 -lmswsock -lshlwapi -lole32 -loleaut32 -luuid -lgdi32
LIBS += -lboost_filesystem$$BOOST_LIB_SUFFIX -lboost_program_options$$BOOST_LIB_SUFFIX -lboost_thread$$BOOST_LIB_SUFFIX
system($$QMAKE_LRELEASE -silent $$_PRO_FILE_)
