// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

// Project
#include "key.h"
#include "ecies/ecies.h"

// C / C++
#include <vector>
#include <cstring>
#include <cstdio>
#include <stdexcept>

// OpenSSL (core + 3.x APIs)
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

// libsecp256k1
#include <secp256k1.h>
#include <secp256k1_recovery.h>

/* ----------  Global secp256k1 context ---------- */
static secp256k1_context* g_secp256k1_verify_ctx = [] {
    auto* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx)
        throw std::runtime_error("Failed to create secp256k1 verify context");
    return ctx;
}();

static thread_local secp256k1_context* g_secp256k1_sign_ctx = [] {
    auto* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx)
        throw std::runtime_error("Failed to create secp256k1 sign context");

    unsigned char seed[32];
    if (RAND_bytes(seed, sizeof(seed)) != 1)
        throw std::runtime_error("RAND_bytes failed");

    if (!secp256k1_context_randomize(ctx, seed))
        throw std::runtime_error("Failed to randomize secp256k1 sign context");

    return ctx;
}();

/* ---------- Forward declarations ---------- */

static CPubKey SerializePubKey(const secp256k1_pubkey& pub) {
    unsigned char out[33];
    size_t len = 33;

    secp256k1_ec_pubkey_serialize(g_secp256k1_sign_ctx, out, &len, &pub,
                                  SECP256K1_EC_COMPRESSED);

    return CPubKey(std::vector<unsigned char>(out, out + len));
}

/* ----------  Compressed -> uncompressed helper (for OpenSSL) ---------- */
static bool DecompressPubKey(const unsigned char* comp, unsigned char out[65]) {
    secp256k1_pubkey pub;

    if (!secp256k1_ec_pubkey_parse(g_secp256k1_verify_ctx, &pub, comp, 33))
        return false;

    size_t len = 65;
    secp256k1_ec_pubkey_serialize(g_secp256k1_verify_ctx, out, &len, &pub,
                                  SECP256K1_EC_UNCOMPRESSED);

    return true;
}

/* ----------  Build EVP_PKEY from raw secret ---------- */
static EVP_PKEY* MakePKeyFromSecret(const unsigned char* secret,
                                    size_t secret_len,
                                    const unsigned char* pubkey,
                                    size_t pubkey_len) {
    if (!secret || secret_len != 32) return nullptr;

    unsigned char uncompressed[65];

    if (pubkey_len == 33) {
        if (!DecompressPubKey(pubkey, uncompressed)) return nullptr;
        pubkey = uncompressed;
        pubkey_len = 65;
    } else if (pubkey_len == 65) {
        if (pubkey[0] != 0x04) return nullptr;
    } else {
        return nullptr;
    }

    static OSSL_LIB_CTX* libctx = [] {
        OSSL_LIB_CTX* c = OSSL_LIB_CTX_new();
        if (!OSSL_PROVIDER_load(c, "default"))
            throw std::runtime_error("default provider load failed");
        return c;
    }();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", nullptr);
    if (!ctx) return nullptr;

    EVP_PKEY* pkey = nullptr;

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    BIGNUM* bn = BN_bin2bn(secret, 32, nullptr);
    if (!bn) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    unsigned char bn_buf[32];
    BN_bn2binpad(bn, bn_buf, sizeof(bn_buf));
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"secp256k1",
                               0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, bn_buf, sizeof(bn_buf)),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)pubkey, 65),
        OSSL_PARAM_END};

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        ERR_print_errors_fp(stderr);
        BN_clear_free(bn);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    BN_clear_free(bn);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* ----------  Recover pubkey from sig ---------- */
CPubKey RecoverPubKey(const uint256& hash, const unsigned char sig64[64],
                      int recid, bool compressed) {
    secp256k1_ecdsa_recoverable_signature rsig;
    secp256k1_pubkey pub;

    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            g_secp256k1_verify_ctx, &rsig, sig64, recid))
        return CPubKey();

    if (!secp256k1_ecdsa_recover(g_secp256k1_verify_ctx, &pub, &rsig,
                                 reinterpret_cast<const unsigned char*>(&hash)))
        return CPubKey();

    return SerializePubKey(pub);
}

/* ----------  CKey methods ---------- */

void CKey::SetCompressedPubKey() { fCompressedPubKey = true; }

bool CKey::IsNull() const { return !fSet; }
bool CKey::IsCompressed() const { return fCompressedPubKey; }

void CKey::MakeNewKey(bool fCompressed) {
    Reset();

    CSecret secret(32);
    do {
        if (RAND_bytes(secret.data(), 32) != 1)
            throw key_error("RAND_bytes failed");
    } while (!secp256k1_ec_seckey_verify(g_secp256k1_sign_ctx, secret.data()));

    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(g_secp256k1_sign_ctx, &pub, secret.data()))
        throw key_error("Failed to create public key");

    CPubKey pubkey = SerializePubKey(pub);
    EVP_PKEY* tmp = MakePKeyFromSecret(
        secret.data(), secret.size(), pubkey.Raw().data(), pubkey.Raw().size());
    if (!tmp) throw key_error("EVP_PKEY creation failed");

    pkey = tmp;
    vchSecret = secret;
    vchPubKey = pubkey;
    fCompressedPubKey = fCompressed;
    fSet = true;
}

bool CKey::SetPrivKey(const CPrivKey& vchPrivKey) {
    Reset();

    if (vchPrivKey.size() == 32) {
        CSecret secret(vchPrivKey.begin(), vchPrivKey.end());
        return SetSecret(secret, true);
    }

    const unsigned char* p = vchPrivKey.data();
    EVP_PKEY* tmp = d2i_AutoPrivateKey(nullptr, &p, vchPrivKey.size());
    if (!tmp) return false;

    EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(tmp, nullptr);
    bool ok = vctx && EVP_PKEY_check(vctx) == 1;
    EVP_PKEY_CTX_free(vctx);
    if (!ok) {
        EVP_PKEY_free(tmp);
        return false;
    }

    BIGNUM* bn = nullptr;
    if (!EVP_PKEY_get_bn_param(tmp, OSSL_PKEY_PARAM_PRIV_KEY, &bn)) {
        EVP_PKEY_free(tmp);
        return false;
    }

    CSecret secret(32, 0);
    BN_bn2binpad(bn, secret.data(), 32);
    BN_clear_free(bn);

    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(g_secp256k1_sign_ctx, &pub,
                                    secret.data())) {
        EVP_PKEY_free(tmp);
        return false;
    }

    CPubKey pubkey = SerializePubKey(pub);

    pkey = tmp;
    vchSecret = secret;
    vchPubKey = pubkey;
    fCompressedPubKey = true;
    fSet = true;
    return true;
}

bool CKey::SetSecret(const CSecret& secret, bool fCompressed) {
    Reset();

    if (secret.size() != 32) return false;
    if (!secp256k1_ec_seckey_verify(g_secp256k1_sign_ctx, secret.data()))
        return false;

    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(g_secp256k1_sign_ctx, &pub, secret.data()))
        return false;

    CPubKey pubkey = SerializePubKey(pub);
    EVP_PKEY* tmp = MakePKeyFromSecret(
        secret.data(), secret.size(), pubkey.Raw().data(), pubkey.Raw().size());
    if (!tmp) return false;

    pkey = tmp;
    vchSecret = secret;
    vchPubKey = pubkey;
    fCompressedPubKey = fCompressed;
    fSet = true;
    return true;
}

CSecret CKey::GetSecret(bool& fCompressed) const {
    if (!fSet) throw key_error("CKey::GetSecret(): key not set");
    fCompressed = fCompressedPubKey;
    return vchSecret;
}

CPrivKey CKey::GetPrivKey() const {
    if (!fSet) throw key_error("CKey::GetPrivKey(): key not set");
    return CPrivKey(vchSecret.begin(), vchSecret.end());
}

bool CKey::SetPubKey(const CPubKey& vchPubKeyIn) {
    Reset();

    const std::vector<unsigned char>& pubkey = vchPubKeyIn.vchPubKey;
    const unsigned char* pub = pubkey.data();
    size_t pub_len = pubkey.size();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx) return false;

    EVP_PKEY* tmp = nullptr;

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"secp256k1",
                               0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)pub, pub_len),
        OSSL_PARAM_END};

    if (EVP_PKEY_fromdata(ctx, &tmp, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);

    EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(tmp, nullptr);
    if (!vctx || EVP_PKEY_public_check(vctx) != 1) {
        EVP_PKEY_CTX_free(vctx);
        EVP_PKEY_free(tmp);
        return false;
    }
    EVP_PKEY_CTX_free(vctx);

    pkey = tmp;
    fSet = true;
    vchPubKey = vchPubKeyIn;
    fCompressedPubKey = (pub_len == 33 && (pub[0] == 0x02 || pub[0] == 0x03));

    return true;
}

CPubKey CKey::GetPubKey() const {
    return vchPubKey;
}

/* ---------- Signing ---------- */

bool CKey::Sign(uint256 hash, std::vector<unsigned char>& sig) const {
    if (!fSet) return false;

    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_sign(g_secp256k1_sign_ctx, &signature, hash.begin(),
                              vchSecret.data(), nullptr, nullptr))
        return false;

    secp256k1_ecdsa_signature sig_norm;
    secp256k1_ecdsa_signature_normalize(g_secp256k1_sign_ctx, &sig_norm,
                                        &signature);
    signature = sig_norm;

    unsigned char der[72];
    size_t derlen = sizeof(der);
    secp256k1_ecdsa_signature_serialize_der(g_secp256k1_sign_ctx, der, &derlen,
                                            &signature);
    sig.assign(der, der + derlen);
    return true;
}

bool CKey::SignCompact(const uint256& hash,
                       std::vector<unsigned char>& vchSig) const {
    unsigned char privkey[32];
    std::memcpy(privkey, vchSecret.data(), 32);
    vchSig.clear();
    vchSig.resize(65);

    unsigned char hashData[32];
    std::memcpy(hashData, hash.begin(), 32);
    secp256k1_ecdsa_recoverable_signature sig;

    int signResult = secp256k1_ecdsa_sign_recoverable(
        g_secp256k1_sign_ctx, &sig, hashData, privkey,
        secp256k1_nonce_function_rfc6979, nullptr);

    if (signResult != 1) {
        printf("Signing failed with code: %d\n", signResult);
        return false;
    }

    int recid = 0;
    unsigned char sig64[64];

    secp256k1_ecdsa_recoverable_signature_serialize_compact(
        g_secp256k1_sign_ctx, sig64, &recid, &sig);

    vchSig[0] = 27 + recid + (fCompressedPubKey ? 4 : 0);
    std::memcpy(&vchSig[1], sig64, 64);

    return true;
}

/* ---------- Verification ---------- */

bool CKey::SetCompactSignature(const uint256& hash,
                               const std::vector<unsigned char>& vchSig) {
    if (vchSig.size() != 65) return false;

    int header = vchSig[0];
    if (header < 27 || header > 34) return false;

    int recid = (header - 27) & 3;

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            g_secp256k1_verify_ctx, &sig, &vchSig[1], recid))
        return false;

    unsigned char hashData[32];
    std::memcpy(hashData, hash.begin(), 32);

    secp256k1_pubkey pubkey;
    if (!secp256k1_ecdsa_recover(g_secp256k1_verify_ctx, &pubkey, &sig,
                                 hashData))
        return false;

    unsigned char pubkey_out[33];
    size_t pubkey_out_len = 33;
    secp256k1_ec_pubkey_serialize(g_secp256k1_verify_ctx, pubkey_out,
                                  &pubkey_out_len, &pubkey,
                                  SECP256K1_EC_COMPRESSED);
    std::vector<unsigned char> vchPubKey(pubkey_out,
                                         pubkey_out + pubkey_out_len);
    SetPubKey(CPubKey(vchPubKey));

    fCompressedPubKey = true;
    fSet = true;
    return true;
}

bool CKey::Verify(uint256 hash, const std::vector<unsigned char>& sig) const {
    secp256k1_pubkey pub;
    std::vector<unsigned char> pk = vchPubKey.Raw();
    if (!secp256k1_ec_pubkey_parse(g_secp256k1_verify_ctx, &pub, pk.data(),
                                   pk.size()))
        return false;

    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_signature_parse_der(g_secp256k1_verify_ctx, &signature,
                                             sig.data(), sig.size()))
        return false;

    secp256k1_ecdsa_signature sig_norm;
    secp256k1_ecdsa_signature_normalize(g_secp256k1_verify_ctx, &sig_norm,
                                        &signature);
    signature = sig_norm;

    return secp256k1_ecdsa_verify(g_secp256k1_verify_ctx, &signature,
                                  hash.begin(), &pub);
}

bool CKey::VerifyCompact(const uint256& hash,
                         const std::vector<unsigned char>& vchSig) const {
    CKey recovered;
    if (!recovered.SetCompactSignature(hash, vchSig)) return false;

    const auto& a = recovered.GetPubKey().Raw();
    const auto& b = GetPubKey().Raw();
    return a.size() == b.size() &&
           CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

bool CKey::IsValid() const {
    if (!fSet || !pkey) return false;

    bool fCompr;
    CSecret secret = GetSecret(fCompr);
    CKey key2;
    if (!key2.SetSecret(secret, fCompr)) return false;

    return GetPubKey() == key2.GetPubKey();
}

/* ---------- EncryptData DecryptData ---------- */

static constexpr size_t NONCE_LEN = 12;
static constexpr size_t TAG_LEN = 16;
static constexpr size_t PUBKEY_LEN = 33;

EVP_PKEY* CPubKey::GetEVPPubKey() const {
    if (!IsValid()) return nullptr;

    EVP_PKEY* tmp = nullptr;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx) return nullptr;

    EVP_PKEY_fromdata_init(ctx);

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"secp256k1",
                               0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                (void*)vchPubKey.data(), vchPubKey.size()),
        OSSL_PARAM_END};

    if (EVP_PKEY_fromdata(ctx, &tmp, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return tmp;
}

EVP_PKEY* CKey::GetEVPPrivKey() const {
    if (!pkey) return nullptr;
    EVP_PKEY_up_ref(pkey);
    return pkey;
}

static bool ECDH_Derive(EVP_PKEY* privkey, EVP_PKEY* pubkey,
                        unsigned char out[32]) {
    if (!privkey || !pubkey) return false;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, nullptr);
    if (!ctx) return false;

    unsigned char raw[64];
    size_t rawlen = sizeof(raw);

    bool ok = EVP_PKEY_derive_init(ctx) == 1 &&
              EVP_PKEY_derive_set_peer(ctx, pubkey) == 1 &&
              EVP_PKEY_derive(ctx, raw, &rawlen) == 1;

    if (ok) {
        SHA256(raw, rawlen, out);
    }

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static bool HKDF_SHA256(const unsigned char* secret, size_t secret_len,
                        unsigned char* out, size_t out_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) return false;

    if (EVP_PKEY_derive_init(ctx) != 1) goto err;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1) goto err;

    /* No salt is allowed — DO NOT test return value */
    EVP_PKEY_CTX_set1_hkdf_salt(ctx, nullptr, 0);

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, secret_len) != 1) goto err;
    static const unsigned char info[] = "secp256k1-ecies-aes256gcm-v1";

    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info) - 1) != 1) goto err;

    if (EVP_PKEY_derive(ctx, out, &out_len) != 1) goto err;

    EVP_PKEY_CTX_free(ctx);
    return true;

err:
    EVP_PKEY_CTX_free(ctx);
    return false;
}

void CPubKey::EncryptData(const std::vector<unsigned char>& plaintext,
                          std::vector<unsigned char>& out) {
    if (plaintext.empty()) throw key_error("Empty plaintext");

    // 1. Ephemeral key
    CKey eph;
    eph.MakeNewKey(true);

    unsigned char shared[32];

    EVP_PKEY* priv = eph.GetEVPPrivKey();
    EVP_PKEY* pub = this->GetEVPPubKey();

    if (!ECDH_Derive(priv, pub, shared)) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        throw key_error("ECDH failed");
    }

    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);

    // 2. Derive AEAD key
    unsigned char aead_key[32];
    if (!HKDF_SHA256(shared, sizeof(shared), aead_key, sizeof(aead_key)))
        throw key_error("HKDF failed");

    // 3. Nonce
    unsigned char nonce[NONCE_LEN];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        throw key_error("RAND_bytes failed");

    // Ephemeral pubkey (for AAD and serialization)
    const CPubKey& eph_pub = eph.GetPubKey();
    const std::vector<unsigned char>& eph_raw = eph_pub.Raw();

    // 4. Encrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw key_error("Cipher ctx alloc failed");

    std::vector<unsigned char> ciphertext(plaintext.size());
    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, aead_key, nonce);

    static const unsigned char aad[] = "AES-256-GCM|secp256k1|HKDF-SHA256|v1";

    EVP_EncryptUpdate(ctx, nullptr, &len, aad, sizeof(aad) - 1);
    EVP_EncryptUpdate(ctx, nullptr, &len, eph_raw.data(), eph_raw.size());

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(),
                      plaintext.size());
    int ct_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ct_len += len;

    unsigned char tag[TAG_LEN];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    // 5. Serialize output
    out.clear();
    out.reserve(PUBKEY_LEN + NONCE_LEN + ct_len + TAG_LEN);

    out.insert(out.end(), eph_raw.begin(), eph_raw.end());
    out.insert(out.end(), nonce, nonce + NONCE_LEN);
    out.insert(out.end(), ciphertext.begin(), ciphertext.begin() + ct_len);
    out.insert(out.end(), tag, tag + TAG_LEN);

    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(aead_key, sizeof(aead_key));
}

void CKey::DecryptData(const std::vector<unsigned char>& enc,
                       std::vector<unsigned char>& out) {
    if (enc.size() < PUBKEY_LEN + NONCE_LEN + TAG_LEN)
        throw key_error("Ciphertext too short");

    const unsigned char* p = enc.data();

    // 1. Parse ephemeral pubkey
    CPubKey eph_pub(std::vector<unsigned char>(p, p + PUBKEY_LEN));
    if (!eph_pub.IsValid()) throw key_error("Invalid ephemeral pubkey");
    p += PUBKEY_LEN;

    const unsigned char* nonce = p;
    p += NONCE_LEN;

    size_t ct_len = enc.size() - PUBKEY_LEN - NONCE_LEN - TAG_LEN;
    const unsigned char* ciphertext = p;
    const unsigned char* tag = p + ct_len;

    // 2. ECDH
    unsigned char shared[32];

    EVP_PKEY* priv = this->GetEVPPrivKey();
    EVP_PKEY* pub = eph_pub.GetEVPPubKey();

    if (!ECDH_Derive(priv, pub, shared)) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        throw key_error("ECDH failed");
    }

    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);

    // 3. Derive key
    unsigned char aead_key[32];
    if (!HKDF_SHA256(shared, sizeof(shared), aead_key, sizeof(aead_key)))
        throw key_error("HKDF failed");

    // 4. Decrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw key_error("Cipher ctx alloc failed");

    out.resize(ct_len);
    int len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, aead_key, nonce);

    static const unsigned char aad[] = "AES-256-GCM|secp256k1|HKDF-SHA256|v1";

    EVP_DecryptUpdate(ctx, nullptr, &len, aad, sizeof(aad) - 1);
    EVP_DecryptUpdate(ctx, nullptr, &len, enc.data(), PUBKEY_LEN);

    EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext, ct_len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag);

    if (EVP_DecryptFinal_ex(ctx, out.data() + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw key_error("Authentication failed");
    }

    EVP_CIPHER_CTX_free(ctx);

    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(aead_key, sizeof(aead_key));
}
