// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef ECIES_H
#define ECIES_H

#pragma once

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "This ECIES implementation requires OpenSSL 3.5+"
#endif

#include <cstddef>
#include <vector>

using ByteVector = std::vector<unsigned char>;

struct ecies_ctx_t {
    EVP_PKEY* recipient_pub;   // for encrypt
    EVP_PKEY* recipient_priv;  // for decrypt
};

/* Low-level ECIES */
bool ECIES_Encrypt(EVP_PKEY* recipient_pub, const ByteVector& plaintext,
                   ByteVector& out);

bool ECIES_Decrypt(EVP_PKEY* recipient_priv, const ByteVector& enc,
                   ByteVector& out);

/* High-level wrappers */
ByteVector ecies_encrypt(const ecies_ctx_t* ctx, const unsigned char* data,
                         size_t length, char* error, size_t error_len);

ByteVector ecies_decrypt(const ecies_ctx_t* ctx, const ByteVector& cryptex,
                         char* error, size_t error_len);

#endif /* ECIES_H */
