/*
 * #%L
 * %%
 * Copyright (C) 2024 BMW Car IT GmbH
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

#include <vector>
#include "key.h"
#include "mococrw/x509.h"
#include "openssl_wrap.h"

namespace mococrw
{
class Pkcs12Container
{
public:
    class Builder;
    class BuilderWithLegacyDefaults;

    /**
     * The destructor
     */
    ~Pkcs12Container() { utility::stringCleanse(_pwd); }

    /**
     *  The move constructor
     * @param other The object to move
     */
    Pkcs12Container(Pkcs12Container &&other) = default;

    /**
     * Create a PKCS#12 Container from DER
     *
     * Caller is responsible for cleansing pwd.
     */
    static Pkcs12Container fromDer(const std::vector<uint8_t> &derData, const std::string &pwd);

    /**
     * Create PKCS#12 container from DER File
     *
     * Caller is responsible for cleansing pwd.
     */
    static Pkcs12Container fromDerFile(const std::string &filename, const std::string &pwd);

    /**
     * Retreive private key from PKCS#12 container
     * @throw MoCOCrWException when private key is not available.
     */
    AsymmetricPrivateKey getPrivateKey();

    /**
     * Retreive certificate from PKCS#12 container
     * @throw MoCOCrWException when certificate is not available.
     */
    X509Certificate getCertificate();

    /**
     * Retreive vector of additional certificates from PKCS12 Container.
     * The vector is empty if there are no additional certificates.
     */
    std::vector<X509Certificate> getAdditionalCertificates();

    /**
     * Return a DER representation of this PKCS#12 container.
     */
    std::vector<uint8_t> toDer() const;

    /**
     * Write DER representation of this PKCS#12 container to file.
     */
    void toDerFile(const std::string &filename) const;

    /**
     * Get the internal OpenSSL PKCS#12 instance.
     */
    const PKCS12 *internal() const { return _pkcs12.get(); }
    PKCS12 *internal() { return _pkcs12.get(); }

private:
    /**
     * Create a PKCS#12 container from an existing OpenSSL container.
     * @param ptr a unique pointer to the existing OpenSSL PKCS#12 container.
     */
    Pkcs12Container(std::string pwd, openssl::SSL_PKCS12_Ptr &&ptr)
            : _pwd(std::move(pwd)), _pkcs12(std::move(ptr))
    {
    }

    std::string _pwd;
    openssl::SSL_PKCS12_Ptr _pkcs12;
};

class Pkcs12Container::Builder
{
public:
    /* According to OpenSSL documentation:
     * The parameters nid_key, nid_cert, iter, mac_iter and keytype
     * can all be set to zero and sensible defaults will be used.
     */

    /**
     * Instantiate a Builder object to construct a PKCS#12 container.
     *
     * @param pwd The passphrase of the container.
     * @param pkey The private key to include in the container.
     * @param cert The corresponding certificate of private key.
     */
    Builder(const std::string &pwd, const AsymmetricPrivateKey &pkey, const X509Certificate &cert)
            : _pwd(pwd)
            , _pkey(pkey)
            , _cert(cert)
            , _nidKey(0)
            , _nidCert(0)
            , _iter(0)
            , _macIter(0)
            , _macSaltlen(PKCS12_SALT_LEN)
            , _macDigestType(openssl::DigestTypes::NONE)
            , _keyType(0)
    {
    }

    /**
     * Includes an additional certificate for the PKCS#12 container.
     *
     * @param additionalCert The additional certificate to include.
     */
    Builder &includeAdditionalCert(const X509Certificate &additionalCert)
    {
        _additionalCerts.push_back(additionalCert);
        return *this;
    }

    /**
     * Sets a friendly name for the PKCS#12 container.
     *
     * @param additionalCert The additional certificate to include.
     */
    Builder &setName(const std::string &name)
    {
        _name = name;
        return *this;
    }

    /**
     * Sets the encryption algorithm to use for the key.
     * Set to 0 to use default encryption algorithm and set to -1 to not use encryption at all.
     *
     * @param nidKey The ID of the encryption algorithm
     */
    Builder &setNidKey(int nidKey)
    {
        _nidKey = nidKey;
        return *this;
    }

    /**
     * Sets the encryption algorithm to use for the certificate.
     * Set to 0 to use default encryption algorithm and set to -1 to not use encryption at all.
     *
     * @param nidCert The ID of the encryption algorithm
     */
    Builder &setNidCert(int nidCert)
    {
        _nidCert = nidCert;
        return *this;
    }

    /**
     * Sets the encryption algorithm iteration count to use.
     * Set to 0 to use default count set by OpenSSL.
     *
     * @param iter The iteration count
     */
    Builder &setIter(int iter)
    {
        _iter = iter;
        return *this;
    }

    /**
     * Sets the MAC iteration count to use.
     * Set to 0 to use default count set by OpenSSL.
     *
     * @param macIter The MAC iteration count
     */
    Builder &setMacIter(int macIter)
    {
        _macIter = macIter;
        return *this;
    }

    /**
     * Sets the MAC Salt length to use.
     *
     * @param macSaltlen The MAC salt length
     */
    Builder &setMacSaltLength(int macSaltlen)
    {
        _macSaltlen = macSaltlen;
        return *this;
    }

    /**
     * Sets the MAC message digest function to use.
     *
     * @param macDigestType The MAC message digest type
     */
    Builder &setMacIter(openssl::DigestTypes macDigestType)
    {
        _macDigestType = macDigestType;
        return *this;
    }

    /**
     * Returns the type of key.
     *
     * @param keytype
     * @return Builder&
     */
    Builder &setKeyType(int keyType)
    {
        _keyType = keyType;
        return *this;
    }

    /**
     * Builds a PKCS#12 container based on the parameters passed to this Builder.
     *
     * @return The PKCS#12 container constructed.
     */
    Pkcs12Container build();

protected:
    std::string _pwd;
    std::string _name;
    AsymmetricPrivateKey _pkey;
    X509Certificate _cert;
    std::vector<X509Certificate> _additionalCerts;
    int _nidKey;
    int _nidCert;
    int _iter;
    int _macIter;
    int _macSaltlen;
    openssl::DigestTypes _macDigestType;
    int _keyType;
};

class Pkcs12Container::BuilderWithLegacyDefaults : public Pkcs12Container::Builder
{
public:
    BuilderWithLegacyDefaults(const std::string &pwd,
                              const AsymmetricPrivateKey &pkey,
                              const X509Certificate &cert)
            : Pkcs12Container::Builder(pwd, pkey, cert)
    {
        // Initialise with Legacy defaults:
        _nidKey = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
        _nidCert = NID_pbe_WithSHA1And40BitRC2_CBC;
        _iter = PKCS12_DEFAULT_ITER;
        _macIter = 1;
        _macDigestType = openssl::DigestTypes::SHA1;
        _keyType = 0;
    }
};

}  // namespace mococrw