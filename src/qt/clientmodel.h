#ifndef CLIENTMODEL_H
#define CLIENTMODEL_H

#include <QObject>

class OptionsModel;
class AddressTableModel;
class TransactionTableModel;
class CWallet;

QT_BEGIN_NAMESPACE
class QDateTime;
class QTimer;
QT_END_NAMESPACE

/** Model for Bitcoin network client. */
class ClientModel : public QObject
{
    Q_OBJECT

public:
    explicit ClientModel(OptionsModel *optionsModel, QObject *parent = 0);
    ~ClientModel();

#ifdef MINER
    enum MiningType
    {
        SoloMining,
        PoolMining
    };
#endif

    OptionsModel *getOptionsModel();

    int getNumConnections() const;
    int getNumBlocks() const;
    int getNumBlocksAtStartup();

#ifdef MINER
    MiningType getMiningType() const;
    int getMiningThreads() const;
    bool getMiningStarted() const;

    bool getMiningDebug() const;
    void setMiningDebug(bool debug);
    int getMiningScanTime() const;
    void setMiningScanTime(int scantime);
    QString getMiningServer() const;
    void setMiningServer(QString server);
    QString getMiningPort() const;
    void setMiningPort(QString port);
    QString getMiningUsername() const;
    void setMiningUsername(QString username);
    QString getMiningPassword() const;
    void setMiningPassword(QString password);
#endif

    int getHashrate() const;
    double GetDifficulty() const;

    QDateTime getLastBlockDate() const;

    //! Return true if client connected to testnet
    bool isTestNet() const;
    //! Return true if core is doing initial block download
    bool inInitialBlockDownload() const;
    //! Return conservative estimate of total number of blocks, or 0 if unknown
    int getNumBlocksOfPeers() const;
    //! Return warnings to be displayed in status bar
    QString getStatusBarWarnings() const;

#ifdef MINER
    void setMining(MiningType type, bool mining, int threads, int hashrate);
#endif

    QString formatFullVersion() const;
    QString formatBuildDate() const;
    QString clientName() const;
    QString formatClientStartupTime() const;

private:
    OptionsModel *optionsModel;

    int cachedNumBlocks;
    int cachedNumBlocksOfPeers;
    int cachedHashrate;

#ifdef MINER
    MiningType miningType;
    int miningThreads;
    bool miningStarted;
    bool miningDebug;
    int miningScanTime;
    QString miningServer;
    QString miningPort;
    QString miningUsername;
    QString miningPassword;
#endif

    int numBlocksAtStartup;

    QTimer *pollTimer;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

signals:
    void numConnectionsChanged(int count);
    void numBlocksChanged(int count, int countOfPeers);
#ifdef MINER
    void miningChanged(bool mining, int count);
#endif

    //! Asynchronous error notification
    void error(const QString &title, const QString &message, bool modal);

public slots:
    void updateTimer();
    void updateNumConnections(int numConnections);
    void updateAlert(const QString &hash, int status);
};

#endif // CLIENTMODEL_H
