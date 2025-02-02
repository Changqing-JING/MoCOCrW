/*
 * #%L
 * %%
 * Copyright (C) 2022 BMW Car IT GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
#pragma once

#include "openssl_wrap.h"

namespace mococrw
{
class ECCSpec;
class RSASpec;

// Needed for old deprecated API
struct HsmKeyParams
{
    bool cka_extractable = false;
    bool cka_sensitive = true;
};

/**
 * This class currently contains PKCS#11 attributes which are changeable on key creation.
 * In the future also parameters for other keystorage interfaces can be added.
 */
class HsmKeyParameters
{
public:
    class Builder;

    bool isExtractable() const { return _extractable; }

private:
    bool _extractable;

    /* Default is that the key cannot be extracted and is marked as sensitive.
     * Check https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
     * for more details.
     */
    HsmKeyParameters() : _extractable(false) {}
};

class HsmKeyParameters::Builder
{
public:
    Builder() {}
    Builder &setExtractable(bool extractable)
    {
        params_._extractable = extractable;
        return *this;
    }

    HsmKeyParameters build() { return params_; }

private:
    HsmKeyParameters params_;
};

/**
 * The highest-level abstract class of a Hardware Security Module (HSM).
 *
 * All HSM implementations should inherit this class either directly or
 * indirectly.
 */
class HSM
{
public:
    virtual ~HSM() = default;

    // Many of protected functions provided by the HSM class are seen
    // as internal, not to be used by the User of MoCOCrW but specific
    // friends:
    friend class AsymmetricPublicKey;
    friend class AsymmetricKeypair;

protected:
    /**
     *  Loads public key from HSM.
     *
     * @param keyLabel String based description of an object on the token. It
     * can be used in combination with keyID to identify an object.
     * @param keyID Vector of raw bytes that identifies a key on the token
     * @note keyID must not be empty
     */
    virtual openssl::SSL_EVP_PKEY_Ptr loadPublicKey(const std::string &keyLabel,
                                                    const std::vector<uint8_t> &keyID) const = 0;
    virtual openssl::SSL_EVP_PKEY_Ptr loadPublicKey(const std::vector<uint8_t> &keyID) const = 0;

    /**
     * Loads private key from HSM.
     *
     * @param keyLabel String based description of an object on the token. It
     * can be used in combination with keyID to identify an object.
     * @param keyID Vector of raw bytes that identifies a key on the token
     * @note keyID must not be empty
     */
    virtual openssl::SSL_EVP_PKEY_Ptr loadPrivateKey(const std::string &keyLabel,
                                                     const std::vector<uint8_t> &keyID) const = 0;
    virtual openssl::SSL_EVP_PKEY_Ptr loadPrivateKey(const std::vector<uint8_t> &keyID) const = 0;

    /**
     * @brief Generate a RSA key pair on the HSM
     *
     * @param spec The RSA specification @ref RSASpec
     * @param keyLabel String based description of an object on the token. It
     * can be used in combination with keyID to identify an object.
     * @param keyID Vector of raw bytes that identifies a key on the token
     * @note keyID must not be empty
     */
    virtual openssl::SSL_EVP_PKEY_Ptr generateKey(const RSASpec &spec,
                                                  const std::string &keyLabel,
                                                  const std::vector<uint8_t> &keyID) = 0;

    /**
     * @brief Generate a ECC key pair on the HSM
     *
     * @param spec The ECC specification @ref ECCSpec
     * @param keyLabel String based description of an object on the token. It
     * can be used in combination with keyID to identify an object.
     * @param keyID Vector of raw bytes that identifies a key on the token
     * @note keyID must not be empty
     */
    virtual openssl::SSL_EVP_PKEY_Ptr generateKey(const ECCSpec &spec,
                                                  const std::string &keyLabel,
                                                  const std::vector<uint8_t> &keyID) = 0;

    /**
     * @brief Generate a RSA key pair on the HSM
     *
     * @param spec The RSA specification @ref RSASpec
     * @param keyLabel String based description of an object on the token. It
     * can be used in combination with keyID to identify an object.
     * @param keyID Vector of raw bytes that identifies a key on the token
     * @param params Struct to set key generation attributes
     * @note keyID must not be empty
     */
    virtual openssl::SSL_EVP_PKEY_Ptr generateKey(const RSASpec &spec,
                                                  const std::string &keyLabel,
                                                  const std::vector<uint8_t> &keyID,
                                                  const HsmKeyParameters &params) = 0;

    /**
     * @brief Generate a ECC key pair on the HSM
     *
     * @param spec The ECC specification @ref ECCSpec
     * @param keyLabel String based description of an object on the token. It
     * can be used in combination with keyID to identify an object.
     * @param keyID Vector of raw bytes that identifies a key on the token
     * @param params Struct to set key generation attributes
     * @note keyID must not be empty
     */
    virtual openssl::SSL_EVP_PKEY_Ptr generateKey(const ECCSpec &spec,
                                                  const std::string &keyLabel,
                                                  const std::vector<uint8_t> &keyID,
                                                  const HsmKeyParameters &params) = 0;
};

/**
 * Hsm handling that leverages OpenSSL's ENGINE_* API interface.
 */
class HsmEngine : public HSM
{
public:
    /**
     * @brief Constructor for an object that can manage keys on HSM using OpenSSL Engine
     * @note Each HsmEngine object is associated with a specific token and a pin to login to that
     * token.
     * @warning Using the HsmEngine object is not thread safe.
     * @warning PIN value is not safely cleaned from memory. Make sure you clean it. Check
     * out utility::stringCleanse()
     * @param id unique identifier for an OpenSSL engine
     * @param modulePath path to HSM module i.e. softhsm
     * @param tokenLabel label of the token where keys are managed
     * @param pin pin to the mentioned token
     */
    HsmEngine(const std::string &id,
              const std::string &modulePath,
              const std::string &tokenLabel,
              const std::string &pin);
    virtual ~HsmEngine();

protected:
    /** Pointer to OpenSSL ENGINE. */
    openssl::SSL_ENGINE_Ptr _engine;
    /** Engine ID. */
    const std::string _id;
    /** Path to Module. */
    const std::string _modulePath;
    /** Token label used to uniquely identify a token on which objects reside */
    const std::string _tokenLabel;
    /** Token PIN */
    std::string _pin;

    openssl::SSL_EVP_PKEY_Ptr loadPublicKey(const std::string &keyLabel,
                                            const std::vector<uint8_t> &keyID) const override;

    openssl::SSL_EVP_PKEY_Ptr loadPublicKey(const std::vector<uint8_t> &keyID) const override;

    openssl::SSL_EVP_PKEY_Ptr loadPrivateKey(const std::string &keyLabel,
                                             const std::vector<uint8_t> &keyID) const override;

    openssl::SSL_EVP_PKEY_Ptr loadPrivateKey(const std::vector<uint8_t> &keyID) const override;

    openssl::SSL_EVP_PKEY_Ptr generateKey(const RSASpec &spec,
                                          const std::string &keyLabel,
                                          const std::vector<uint8_t> &keyID) override;

    openssl::SSL_EVP_PKEY_Ptr generateKey(const ECCSpec &spec,
                                          const std::string &keyLabel,
                                          const std::vector<uint8_t> &keyID) override;

    openssl::SSL_EVP_PKEY_Ptr generateKey(const RSASpec &spec,
                                          const std::string &keyLabel,
                                          const std::vector<uint8_t> &keyID,
                                          const HsmKeyParameters &params) override;

    openssl::SSL_EVP_PKEY_Ptr generateKey(const ECCSpec &spec,
                                          const std::string &keyLabel,
                                          const std::vector<uint8_t> &keyID,
                                          const HsmKeyParameters &params) override;

private:
    /**
     * @brief Construct a PKCS11 URI according to RFC 7512
     */
    std::string _constructPkcs11URI(const std::string &keyLabel,
                                    const std::vector<uint8_t> &keyId) const;

    std::string _constructPkcs11URI(const std::vector<uint8_t> &keyId) const;
};

}  // namespace mococrw
