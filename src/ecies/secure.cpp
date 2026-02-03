// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "ecies.h"

constexpr size_t ECIES_PUBKEY_LEN = 65;
constexpr size_t ECIES_NONCE_LEN = 12;
constexpr size_t ECIES_TAG_LEN = 16;

struct ecies_view {
    const unsigned char* eph_pub;
    const unsigned char* nonce;
    const unsigned char* ciphertext;
    const unsigned char* tag;
    size_t ciphertext_len;
};

inline bool ecies_parse(const ByteVector& v, ecies_view& out) {
    if (v.size() < ECIES_PUBKEY_LEN + ECIES_NONCE_LEN + ECIES_TAG_LEN)
        return false;

    const unsigned char* p = v.data();

    out.eph_pub = p;
    p += ECIES_PUBKEY_LEN;

    out.nonce = p;
    p += ECIES_NONCE_LEN;

    out.ciphertext_len =
        v.size() - ECIES_PUBKEY_LEN - ECIES_NONCE_LEN - ECIES_TAG_LEN;

    out.ciphertext = p;
    out.tag = p + out.ciphertext_len;

    return true;
}
