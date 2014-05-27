// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2012 Litecoin Developers
// Copyright (c) 2013-2014 Phoenixcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php

#ifndef __cplusplus
# error This header can only be compiled as C++.
#endif

#ifndef __INCLUDED_PROTOCOL_H__
#define __INCLUDED_PROTOCOL_H__

#include "serialize.h"
#include "netbase.h"
#include "util.h"
#include <string>


extern bool fTestNet;
static inline unsigned short GetDefaultPort(const bool testnet = fTestNet)
{
    return testnet ? 19555 : 9555;
}


extern uchar pchMessageStart[4];
extern uchar pchMessageStartNew[4];


/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader {
    public:
        CMessageHeader(bool fMagic=true);
        CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn, bool fMagic=true);

        std::string GetCommand() const;
        bool IsValid(bool fMagic=true) const;

        IMPLEMENT_SERIALIZE
            (
             READWRITE(FLATDATA(pchMessageStart));
             READWRITE(FLATDATA(pchCommand));
             READWRITE(nMessageSize);
             READWRITE(nChecksum);
            )

    // TODO: make private (improves encapsulation)
    public:
        enum {
            MESSAGE_START_SIZE = 4,
            COMMAND_SIZE = 12,
            MESSAGE_SIZE_SIZE = 4,
            CHECKSUM_SIZE = 4,

            MESSAGE_SIZE_OFFSET = MESSAGE_START_SIZE + COMMAND_SIZE,
            CHECKSUM_OFFSET = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE
        };
        char pchMessageStart[MESSAGE_START_SIZE];
        char pchCommand[COMMAND_SIZE];
        unsigned int nMessageSize;
        unsigned int nChecksum;
};


/** nServices flags */
enum
{
    NODE_NETWORK = (1 << 0),
};

/** A CService with information about it as peer */
class CAddress : public CService
{
    public:
        CAddress();
        explicit CAddress(CService ipIn, uint64 nServicesIn=NODE_NETWORK);

        void Init();

        IMPLEMENT_SERIALIZE
            (
             CAddress* pthis = const_cast<CAddress*>(this);
             CService* pip = (CService*)pthis;
             if (fRead)
                 pthis->Init();
             if (nType & SER_DISK)
                 READWRITE(nVersion);
             if (nType & SER_DISK)
                 READWRITE(nTime);
             READWRITE(nServices);
             READWRITE(*pip);
            )

        void print() const;

    // TODO: make private (improves encapsulation)
    public:
        uint64 nServices;

        // disk and network only
        unsigned int nTime;

        // memory only
        int64 nLastTry;
};

/** inv message data */
class CInv
{
    public:
        CInv();
        CInv(int typeIn, const uint256& hashIn);
        CInv(const std::string& strType, const uint256& hashIn);

        IMPLEMENT_SERIALIZE
        (
            READWRITE(type);
            READWRITE(hash);
        )

        friend bool operator<(const CInv& a, const CInv& b);

        bool IsKnownType() const;
        const char* GetCommand() const;
        std::string ToString() const;
        void print() const;

    // TODO: make private (improves encapsulation)
    public:
        int type;
        uint256 hash;
};

#endif // __INCLUDED_PROTOCOL_H__
