// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <string>

#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include "base58.h"
#include "wallet.h"
#include "rpcmain.h"

using namespace json_spirit;
using namespace std;

extern CWallet *pwalletMain;

class CTxDump {
public:
    CBlockIndex *pindex;
    int64 nValue;
    bool fSpent;
    CWalletTx *ptx;
    int nOut;
    CTxDump(CWalletTx *ptx = NULL, int nOut = -1) {
        pindex = NULL;
        nValue = 0;
        fSpent = false;
        this->ptx = ptx;
        this->nOut = nOut;
    }
};


Value importprivkey(const Array &params, bool fHelp) {

    if(fHelp || (params.size() < 1) || (params.size() > 3)) {
        string msg = "importprivkey <key> [label] [rescan]\n"
          "Adds a private <key> to the wallet in the format of RPC dumpprivkey.\n"
          "[label] specifies an in-wallet text label, empty by default.\n" 
          "[rescan] allows to rescan the block chain, true by default.";
        throw(runtime_error(msg));
    }

    string strSecret = params[0].get_str();
    string strLabel = "";
    if(params.size() > 1)
      strLabel = params[1].get_str();

    bool fRescan = true;
    if(params.size() > 2)
      fRescan = params[2].get_bool();

    CCoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, true);
    CKeyID vchAddress = key.GetPubKey().GetID();
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(vchAddress, strLabel);

        if (!pwalletMain->AddKey(key))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        pwalletMain->UpdateTimeFirstKey();

        if(fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return(Value::null);
}


Value importaddress(const Array &params, bool fHelp) {

    if(fHelp || (params.size() < 1) || (params.size() > 3)) {
        string msg = "importaddress <address> [label] [rescan]\n"
          "Adds a watch only (unspendable) P2PKH <address> to the wallet.\n"
          "Pubkey hash or script in hex may be specified instead of the <address>.\n"
          "[label] specifies an in-wallet text label, empty by default.\n" 
          "[rescan] allows to rescan the block chain, true by default.";
        throw(runtime_error(msg));
    }

    string strLabel = "";
    if(params.size() > 1)
      strLabel = params[1].get_str();

    bool fRescan = false;
    if(params.size() > 2)
      fRescan = params[2].get_bool();

    CScript script;
    CCoinAddress addr;

    if(IsHex(params[0].get_str())) {
        std::vector<uchar> vchScriptPubKey(ParseHex(params[0].get_str()));
        std::string strTemp;
        if(vchScriptPubKey.size() == 20) {
            /* 20-byte pubkey hash assumed;
             * <pubKeyHash> = RIPEMD160(SHA256(pubKey))
             * Example using OpenSSL:
             * echo -n <pubKey> | xxd -r -p | openssl dgst -sha256 -binary | openssl dgst -rmd160
             * Convert to 25-byte script:
             * OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG */
            strTemp = std::string(vchScriptPubKey.begin(), vchScriptPubKey.end());
            const uchar begin[] = { 0x76, 0xA9, 0x14 };
            const uchar end[] = { 0x88, 0xAC };
            vchScriptPubKey.insert(vchScriptPubKey.begin(), begin, begin + 3);
            vchScriptPubKey.insert(vchScriptPubKey.end(), end, end + 2);
        } else if(vchScriptPubKey.size() == 25) {
            /* Copy the public key hash */
            strTemp = params[0].get_str().substr(6, 40);
        } else {
            throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid pubkey hash or script"));
        }
        script = CScript(vchScriptPubKey.begin(), vchScriptPubKey.end());
        /* Insert the Base58 prefix */
        char prefix[2];
        if(fTestNet) prefix[0] = PUBKEY_ADDRESS_TEST_PREFIX;
        else prefix[0] = PUBKEY_ADDRESS_PREFIX;
        prefix[1] = 0x00;
        strTemp.insert(0, prefix);
        /* Convert and encode */
        std::vector<uchar> vchTemp(ParseHex(strTemp));
        addr = CCoinAddress(EncodeBase58Check(vchTemp));
    } else {
        CKeyID keyID;
        addr = CCoinAddress(params[0].get_str());
        if(!addr.GetKeyID(keyID))
          throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address"));
        script = GetScriptForPubKeyHash(keyID);
    }

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if(::IsMine(*pwalletMain, script) == MINE_SPENDABLE)
          throw(JSONRPCError(RPC_WALLET_ERROR, "The private key is already in the wallet"));

        if(pwalletMain->HaveWatchOnly(script))
          throw(JSONRPCError(RPC_WALLET_ERROR, "The address is being watched already"));

        pwalletMain->MarkDirty();

        if(addr.IsValid())
          pwalletMain->SetAddressBookName(addr.Get(), strLabel);

        if(!pwalletMain->AddWatchOnly(script))
          throw(JSONRPCError(RPC_WALLET_ERROR, "Failed to add the address to the wallet"));

        if(fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }

    }

    return(Value::null);
}


Value importpubkey(const Array &params, bool fHelp) {

    if(fHelp || (params.size() < 1) || (params.size() > 3)) {
        string msg =  "importpubkey <key> [label] [rescan]\n"
          "Adds a watch only (unspendable) public <key> in hex to the wallet.\n"
          "[label] specifies an in-wallet text label, empty by default.\n" 
          "[rescan] allows to rescan the block chain, true by default.";
        throw(runtime_error(msg));
    }

    string strLabel = "";
    if(params.size() > 1)
      strLabel = params[1].get_str();

    bool fRescan = false;
    if(params.size() > 2)
      fRescan = params[2].get_bool();

    CScript script;
    CCoinAddress addr(params[0].get_str());

    if(!IsHex(params[0].get_str()))
      throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Hex string expected for public key"));

    CPubKey pubKey(std::vector<uchar> (ParseHex(params[0].get_str())));
    if(!pubKey.IsValid())
      throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key"));

    CKeyID keyID = pubKey.GetID();
    addr = CCoinAddress(keyID);
    script = GetScriptForPubKeyHash(keyID);

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if(::IsMine(*pwalletMain, script) == MINE_SPENDABLE)
          throw(JSONRPCError(RPC_WALLET_ERROR, "The private key is already in the wallet"));

        if(pwalletMain->HaveWatchOnly(script))
          throw(JSONRPCError(RPC_WALLET_ERROR, "The public key is being watched already"));

        pwalletMain->MarkDirty();

        if(addr.IsValid())
          pwalletMain->SetAddressBookName(addr.Get(), strLabel);

        if(!pwalletMain->AddWatchOnly(script))
          throw(JSONRPCError(RPC_WALLET_ERROR, "Failed to add the public key to the wallet"));

        if(fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }

    }

    return(Value::null);
}


Value importwallet(const Array &params, bool fHelp) {

    if(fHelp || (params.size() != 1)) {
        string msg = "importwallet <file>\n"
          "Imports key pairs from a <file> generated by RPC dumpwallet.\n"
          "The file name may be specified with a directory path.";
        throw(runtime_error(msg));
    }

    EnsureWalletIsUnlocked();

    boost::filesystem::ifstream file;
    boost::filesystem::path pathImportFile = params[0].get_str().c_str();
#if (BOOST_VERSION >= 105000)
    if(!pathImportFile.is_absolute()) pathImportFile = GetDataDir(true) / pathImportFile;
#else
    if(!pathImportFile.is_complete()) pathImportFile = GetDataDir(true) / pathImportFile;
#endif
    if(!boost::filesystem::exists(pathImportFile))
      throw(JSONRPCError(RPC_INVALID_PARAMETER, "The file with wallet keys doesn't exist"));
    file.open(pathImportFile, std::ios_base::in);
    if(!file.good())
      throw(JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open the file with wallet keys"));
    file.close();

    if(!ImportWallet(pwalletMain, pathImportFile.string().c_str()))
      throw(JSONRPCError(RPC_WALLET_ERROR, "Failed while importing keys to the wallet"));

    return(Value::null);
}


Value dumpprivkey(const Array &params, bool fHelp) {

    if(fHelp || (params.size() != 1)) {
        string msg = "dumpprivkey <address>\n"
          "Reveals the private key corresponding to an <address>.";
        throw(runtime_error(msg));
    }

    string strAddress = params[0].get_str();
    CCoinAddress address;
    if(!address.SetString(strAddress))
      throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Phoenixcoin address"));
    CKeyID keyID;
    if(!address.GetKeyID(keyID))
      throw(JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key"));
    CSecret vchSecret;
    bool fCompressed;
    if(!pwalletMain->GetSecret(keyID, vchSecret, fCompressed)) {
        throw(JSONRPCError(RPC_WALLET_ERROR,
          "Private key for address " + strAddress + " is not known"));
    }
    return(CCoinSecret(vchSecret, fCompressed).ToString());
}


Value dumpwallet(const Array &params, bool fHelp) {

    if(fHelp || (params.size() != 1)) {
        string msg = "dumpwallet <file>\n"
          "Dumps key pairs to a <file> in a human readable format.\n"
          "The file name may be specified with a directory path.";
        throw(runtime_error(msg));
    }

    EnsureWalletIsUnlocked();

    boost::filesystem::ofstream file;
    boost::filesystem::path pathDumpFile = params[0].get_str().c_str();
#if (BOOST_VERSION >= 105000)
    if(!pathDumpFile.is_absolute()) pathDumpFile = GetDataDir(true) / pathDumpFile;
#else
    if(!pathDumpFile.is_complete()) pathDumpFile = GetDataDir(true) / pathDumpFile;
#endif
    if(boost::filesystem::exists(pathDumpFile))
      throw(JSONRPCError(RPC_INVALID_PARAMETER, "The file for wallet keys exists already"));
    file.open(pathDumpFile, std::ios_base::out);
    if(!file.good())
      throw(JSONRPCError(RPC_INVALID_PARAMETER, "Cannot create the file for wallet keys"));
    file.close();

    if(!ExportWallet(pwalletMain, pathDumpFile.string().c_str()))
      throw(JSONRPCError(RPC_WALLET_ERROR, "Failed while exporting keys from the wallet"));

    return(Value::null);
}
