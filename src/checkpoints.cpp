// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2012 Litecoin Developers
// Copyright (c) 2013-2014 Phoenixcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "main.h"
#include "uint256.h"

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        (      1, uint256("0x006e800301bbd850d7ba67ad9295c3a940f5fc8f5581e3484967bd33c4c8b965"))
        (  20000, uint256("0x2f6c3ff7712dabfe1ed98ed6da35086755f951836da673a0b090c07fdb6c2282"))
        (  46500, uint256("0x0796b9aa0a653861906905c53e1ed80d358053ab27bf874961b96e7f0f472c77"))
        (  69444, uint256("0xc2f9a11d803f7d23f34a2b18f3ecc56fa16b1d728016c51edc727699045429b5"))
        (  74100, uint256("0xe415dbad75289e4a6a1761a395f9fa9c6b8774bed35854d396b73c99344abc1b"))
        (  88000, uint256("0x79d21a2f760e9d3b50d5e1502224c2c76cb4e5bdb3e616adee0f55de2a6a2ce5"))
        ( 100000, uint256("0xe6f6b91c942fb9f3bc522e6fc6435c1b77aed48806e99bb942acbc3f809e09e7"))
        ( 120000, uint256("0x473302adced6282eeb5adebac298664a86c2fbb7a5583c4567534eba4678ddf2"))
        ( 140000, uint256("0xf5e095edc4718a3c957c6c56b64490f491e07ce44d1648e1f38fb050c91d7dd4"))
        ( 154000, uint256("0x1ee82ed7f55ad95e649df3051188fdb31a7620c995cd616fede0f37b5848337c"))
        ( 180000, uint256("0xb23684c957a35aaa7522f45f5088a3271855e373b39a62b688fc87bae2cccae8"))
        ( 200000, uint256("0xe8bbfa06d1ea5fea06491403094b3d86bc11fbc0e3845add62d0c46dc8b95627"))
        ( 225000, uint256("0xe20d9893262980dff322f94fa89eac747b57bc739f3fef0e6d439628c20db9d3"))
        ( 266666, uint256("0x60f3f4e37cf17adc8a5c59e78a50715158149136b23fcaf557bc40c06471f6c2"))
        ( 331333, uint256("0x1a0226a5cbc4b5698ac9b61dcacf1ce9019ea47752ea52ca2a694591a70f1687"))
        ( 380000, uint256("0xd7e9cd0f405b8341ecea242d43079b3a5ff30b7f2f9c0c1f370b615c005fe5df"))
        ;

    bool CheckBlock(int nHeight, const uint256& hash)
    {
        if (fTestNet) return true; // Testnet has no checkpoints

        MapCheckpoints::const_iterator i = mapCheckpoints.find(nHeight);
        if (i == mapCheckpoints.end()) return true;
        return hash == i->second;
    }

    int GetTotalBlocksEstimate()
    {
        if (fTestNet) return 0; // Testnet has no checkpoints

        return mapCheckpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        if (fTestNet) return 0; // Testnet has no checkpoints

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, mapCheckpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return 0;
    }

    uint256 GetLatestHardenedCheckpoint()
    {
        const MapCheckpoints& checkpoints = mapCheckpoints;
        return (checkpoints.rbegin()->second);
    }
}
