// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef KEY_H
#define KEY_H

#include "allocators.h"
#include "serialize.h"
#include "util.h"

// secp160k1
// const unsigned int PRIVATE_KEY_SIZE = 192;
// const unsigned int PUBLIC_KEY_SIZE  = 41;
// const unsigned int SIGNATURE_SIZE   = 48;
//
// secp192k1
// const unsigned int PRIVATE_KEY_SIZE = 222;
// const unsigned int PUBLIC_KEY_SIZE  = 49;
// const unsigned int SIGNATURE_SIZE   = 57;
//
// secp224k1
// const unsigned int PRIVATE_KEY_SIZE = 250;
// const unsigned int PUBLIC_KEY_SIZE  = 57;
// const unsigned int SIGNATURE_SIZE   = 66;
//
// secp256k1:
// const unsigned int PRIVATE_KEY_SIZE = 279;
// const unsigned int PUBLIC_KEY_SIZE  = 65;
// const unsigned int SIGNATURE_SIZE   = 72;
//
// see www.keylength.com
// script supports up to 75 for single byte push

/* ---------- Errors ---------- */

class key_error : public std::runtime_error {
   public:
    explicit key_error(const std::string &str) : std::runtime_error(str) {}
};

/* ---------- Key identifiers ---------- */

class CKeyID : public uint160 {
   public:
    CKeyID() : uint160(0) {}
    CKeyID(const uint160 &in) : uint160(in) {}
};

class CScriptID : public uint160 {
   public:
    CScriptID() : uint160(0) {}
    CScriptID(const uint160 &in) : uint160(in) {}
};

/* ---------- Public key ---------- */

class CPubKey {
   private:
    EVP_PKEY *pkey;
    std::vector<unsigned char> vchPubKey;
    friend class CKey;

   public:
    EVP_PKEY *GetEVPPubKey() const;
    CPubKey() {}
    CPubKey(const std::vector<unsigned char> &vchPubKeyIn)
        : vchPubKey(vchPubKeyIn) {}
    friend bool operator==(const CPubKey &a, const CPubKey &b) {
        return a.vchPubKey == b.vchPubKey;
    }
    friend bool operator!=(const CPubKey &a, const CPubKey &b) {
        return a.vchPubKey != b.vchPubKey;
    }
    friend bool operator<(const CPubKey &a, const CPubKey &b) {
        return a.vchPubKey < b.vchPubKey;
    }

    IMPLEMENT_SERIALIZE(READWRITE(vchPubKey);)

    CKeyID GetID() const { return CKeyID(Hash160(vchPubKey)); }

    uint256 GetHash() const { return Hash(vchPubKey.begin(), vchPubKey.end()); }

    bool IsValid() const {
        return vchPubKey.size() == 33 || vchPubKey.size() == 65;
    }

    bool IsCompressed() const { return vchPubKey.size() == 33; }

    std::vector<unsigned char> Raw() const { return vchPubKey; }

    void EncryptData(const std::vector<unsigned char> &plaintext,
                     std::vector<unsigned char> &out);
};

/* ---------- Private key types ---------- */

// Serialized private key
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;

// Raw 32-byte secret
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CSecret;

/* ---------- Private key ---------- */

class CKey {
   private:
    CSecret vchSecret;
    CPubKey vchPubKey;

   protected:
    EVP_PKEY *pkey;
    bool fSet;
    bool fCompressedPubKey;

    void SetCompressedPubKey();

   public:
    EVP_PKEY *GetEVPPrivKey() const;
    CKey() : pkey(nullptr), fSet(false), fCompressedPubKey(false) {}
    ~CKey() {
        if (!vchSecret.empty()) {
            OPENSSL_cleanse(vchSecret.data(), vchSecret.size());
        }
        if (pkey) {
            EVP_PKEY_free(pkey);
            pkey = nullptr;
        }
    }

    void Reset() {
        if (pkey) EVP_PKEY_free(pkey);
        pkey = nullptr;
        fCompressedPubKey = false;
        fSet = false;
    }
    bool IsNull() const;
    bool IsCompressed() const;
    void MakeNewKey(bool fCompressed);
    bool SetPrivKey(const CPrivKey &vchPrivKey);
    bool SetSecret(const CSecret &vchSecret, bool fCompressed = false);
    CSecret GetSecret(bool &fCompressed) const;
    CPrivKey GetPrivKey() const;
    bool SetPubKey(const CPubKey &vchPubKeyIn);
    CPubKey GetPubKey() const;
    bool Sign(const uint256 hash, std::vector<unsigned char> &vchSig) const;
    bool SignCompact(const uint256 &hash,
                     std::vector<unsigned char> &vchSig) const;
    bool SetCompactSignature(const uint256 &hash,
                             const std::vector<unsigned char> &vchSig);
    bool Verify(const uint256 hash,
                const std::vector<unsigned char> &vchSig) const;
    bool VerifyCompact(const uint256 &hash,
                       const std::vector<unsigned char> &vchSig) const;
    bool IsValid() const;

    void DecryptData(const std::vector<unsigned char> &enc,
                     std::vector<unsigned char> &out);
};

#endif /* KEY_H */
