// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <vector>

#include "ecies.h"

using ByteVector = std::vector<unsigned char>;

static constexpr uint8_t ECIES_VERSION = 0x01;
static constexpr size_t PUBKEY_LEN = 65;  // uncompressed secp256k1
static constexpr size_t NONCE_LEN = 12;   // GCM
static constexpr size_t TAG_LEN = 16;
static constexpr size_t KEY_LEN = 32;

/* ------------------------------------------------ */
/* RAII helpers                                     */
/* ------------------------------------------------ */

struct Pkey {
    EVP_PKEY* p = nullptr;
    ~Pkey() {
        if (p) EVP_PKEY_free(p);
    }
};

struct PkeyCtx {
    EVP_PKEY_CTX* p = nullptr;
    explicit PkeyCtx(EVP_PKEY_CTX* x = nullptr) : p(x) {}
    ~PkeyCtx() {
        if (p) EVP_PKEY_CTX_free(p);
    }
    operator EVP_PKEY_CTX*() const { return p; }
};

struct CipherCtx {
    EVP_CIPHER_CTX* p = EVP_CIPHER_CTX_new();
    ~CipherCtx() {
        if (p) EVP_CIPHER_CTX_free(p);
    }
    operator EVP_CIPHER_CTX*() const { return p; }
};

/* ------------------------------------------------ */
/* Helpers                                          */
/* ------------------------------------------------ */

static bool generate_ec_key(Pkey& out) {
    PkeyCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx) return false;

    if (EVP_PKEY_keygen_init(ctx) != 1) return false;

    OSSL_PARAM params[] = {OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                  (char*)"secp256k1", 0),
                           OSSL_PARAM_END};

    return EVP_PKEY_CTX_set_params(ctx, params) == 1 &&
           EVP_PKEY_keygen(ctx, &out.p) == 1;
}

static bool import_pubkey(const unsigned char* buf, size_t len, Pkey& out) {
    if (len != PUBKEY_LEN) return false;

    PkeyCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx) return false;

    if (EVP_PKEY_fromdata_init(ctx) != 1) return false;

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"secp256k1",
                               0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)buf, len),
        OSSL_PARAM_END};

    if (EVP_PKEY_fromdata(ctx, &out.p, EVP_PKEY_PUBLIC_KEY, params) != 1)
        return false;

    PkeyCtx vctx(EVP_PKEY_CTX_new(out.p, nullptr));
    return vctx && EVP_PKEY_public_check(vctx) == 1;
}

static bool ecdh(EVP_PKEY* priv, EVP_PKEY* pub,
                 std::array<unsigned char, 32>& out) {
    size_t len = out.size();
    PkeyCtx ctx(EVP_PKEY_CTX_new(priv, nullptr));
    return ctx && EVP_PKEY_derive_init(ctx) == 1 &&
           EVP_PKEY_derive_set_peer(ctx, pub) == 1 &&
           EVP_PKEY_derive(ctx, out.data(), &len) == 1 && len == out.size();
}

static bool hkdf_sha256(const unsigned char* ikm, size_t ikm_len,
                        const unsigned char* salt, size_t salt_len,
                        const char* info, std::array<unsigned char, 32>& out) {
    size_t len = out.size();
    PkeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    return ctx && EVP_PKEY_derive_init(ctx) == 1 &&
           EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
           EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) == 1 &&
           EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, ikm_len) == 1 &&
           EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char*)info,
                                       std::strlen(info)) == 1 &&
           EVP_PKEY_derive(ctx, out.data(), &len) == 1 && len == out.size();
}

/* ------------------------------------------------ */
/* ECIES Encrypt                                    */
/* ------------------------------------------------ */

bool ECIES_Encrypt(EVP_PKEY* recipient_pub, const ByteVector& plaintext,
                   ByteVector& out) {
    if (!recipient_pub || plaintext.empty()) return false;

    Pkey eph;
    if (!generate_ec_key(eph)) return false;

    std::array<unsigned char, 32> shared;
    if (!ecdh(eph.p, recipient_pub, shared)) return false;

    std::array<unsigned char, PUBKEY_LEN> eph_pub{};
    size_t eph_len = eph_pub.size();
    if (EVP_PKEY_get_octet_string_param(eph.p, OSSL_PKEY_PARAM_PUB_KEY,
                                        eph_pub.data(), eph_pub.size(),
                                        &eph_len) != 1 ||
        eph_len != PUBKEY_LEN)
        return false;

    std::array<unsigned char, KEY_LEN> key;
    if (!hkdf_sha256(shared.data(), shared.size(), eph_pub.data(),
                     eph_pub.size(), "ecies-v1-encrypt", key))
        return false;

    std::array<unsigned char, NONCE_LEN> nonce;
    if (RAND_bytes(nonce.data(), nonce.size()) != 1) return false;

    CipherCtx cctx;
    if (!cctx) return false;

    std::vector<unsigned char> ciphertext(plaintext.size());
    int len = 0, ct_len = 0;

    EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr);
    EVP_EncryptInit_ex(cctx, nullptr, nullptr, key.data(), nonce.data());

    EVP_EncryptUpdate(cctx, nullptr, &len, &ECIES_VERSION, 1);
    EVP_EncryptUpdate(cctx, nullptr, &len, eph_pub.data(), eph_pub.size());
    EVP_EncryptUpdate(cctx, nullptr, &len, nonce.data(), nonce.size());

    EVP_EncryptUpdate(cctx, ciphertext.data(), &len, plaintext.data(),
                      plaintext.size());
    ct_len = len;

    if (EVP_EncryptFinal_ex(cctx, ciphertext.data() + ct_len, &len) != 1)
        return false;
    ct_len += len;

    std::array<unsigned char, TAG_LEN> tag;
    EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data());

    out.clear();
    out.reserve(1 + PUBKEY_LEN + NONCE_LEN + ct_len + TAG_LEN);

    out.push_back(ECIES_VERSION);
    out.insert(out.end(), eph_pub.begin(), eph_pub.end());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.begin() + ct_len);
    out.insert(out.end(), tag.begin(), tag.end());

    OPENSSL_cleanse(shared.data(), shared.size());
    OPENSSL_cleanse(key.data(), key.size());
    return true;
}

/* ------------------------------------------------ */
/* ECIES Decrypt                                    */
/* ------------------------------------------------ */

bool ECIES_Decrypt(EVP_PKEY* recipient_priv, const ByteVector& enc,
                   ByteVector& out) {
    if (!recipient_priv || enc.size() < 1 + PUBKEY_LEN + NONCE_LEN + TAG_LEN)
        return false;

    const unsigned char* p = enc.data();
    if (*p++ != ECIES_VERSION) return false;

    const unsigned char* eph_pub = p;
    p += PUBKEY_LEN;
    const unsigned char* nonce = p;
    p += NONCE_LEN;

    size_t ct_len = enc.size() - 1 - PUBKEY_LEN - NONCE_LEN - TAG_LEN;
    const unsigned char* ct = p;
    const unsigned char* tag = p + ct_len;

    Pkey eph;
    if (!import_pubkey(eph_pub, PUBKEY_LEN, eph)) return false;

    std::array<unsigned char, 32> shared;
    if (!ecdh(recipient_priv, eph.p, shared)) return false;

    std::array<unsigned char, KEY_LEN> key;
    if (!hkdf_sha256(shared.data(), shared.size(), eph_pub, PUBKEY_LEN,
                     "ecies-v1-encrypt", key))
        return false;

    CipherCtx cctx;
    if (!cctx) return false;

    out.resize(ct_len);
    int len = 0;

    EVP_DecryptInit_ex(cctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr);
    EVP_DecryptInit_ex(cctx, nullptr, nullptr, key.data(), nonce);

    EVP_DecryptUpdate(cctx, nullptr, &len, &ECIES_VERSION, 1);
    EVP_DecryptUpdate(cctx, nullptr, &len, eph_pub, PUBKEY_LEN);
    EVP_DecryptUpdate(cctx, nullptr, &len, nonce, NONCE_LEN);

    EVP_DecryptUpdate(cctx, out.data(), &len, ct, ct_len);
    EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag);

    bool ok = EVP_DecryptFinal_ex(cctx, out.data() + len, &len) == 1;

    OPENSSL_cleanse(shared.data(), shared.size());
    OPENSSL_cleanse(key.data(), key.size());
    return ok;
}

/* ------------------------------------------------ */
/* High-level wrappers                              */
/* ------------------------------------------------ */

static void set_error(char* err, size_t len, const char* msg) {
    if (err && len) std::snprintf(err, len, "%s", msg);
}

ByteVector ecies_encrypt(const ecies_ctx_t* ctx, const unsigned char* data,
                         size_t length, char* error, size_t error_len) {
    if (!ctx || !ctx->recipient_pub || !data || length == 0) {
        set_error(error, error_len, "Invalid arguments");
        return {};
    }

    ByteVector plaintext(data, data + length);
    ByteVector encrypted;

    if (!ECIES_Encrypt(ctx->recipient_pub, plaintext, encrypted)) {
        set_error(error, error_len, "ECIES encryption failed");
        return {};
    }

    return encrypted;
}

ByteVector ecies_decrypt(const ecies_ctx_t* ctx, const ByteVector& cryptex,
                         char* error, size_t error_len) {
    if (!ctx || !ctx->recipient_priv || cryptex.empty()) {
        set_error(error, error_len, "Invalid arguments");
        return {};
    }

    ByteVector decrypted;
    if (!ECIES_Decrypt(ctx->recipient_priv, cryptex, decrypted)) {
        set_error(error, error_len, "ECIES decryption failed");
        return {};
    }

    return decrypted;
}
