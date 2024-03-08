/*
 * #%L
 * %%
 * Copyright (C) 2018 BMW Car IT GmbH
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

#include <chrono>
#include <climits>
#include <map>
#include <memory>
#include <type_traits>
#include <set>

#include "openssl_wrap.h"

#include "asn1time.h"
#include "error.h"
#include "extension.h"

namespace mococrw
{
/**
 * This class contains additional information that is used when a certificate is signed.
 * An example would be the duration until the certificate expires.
 */
class CertificateSigningParameters
{
public:
    /// A builder class for signing parameters.
    class Builder;

    /**
     * @return the duration how long a signed certificate should be valid, from the starting point.
     */
    Asn1Time::Seconds certificateValidity() const { return _certificateValidity; }

    /**
     * @return an Asn1Time from when a signed certificate should be valid.
     *         Defaults to 1 second before now.
     */
    Asn1Time notBeforeAsn1() const
    {
        if (_notBefore.is_initialized()) {
            return _notBefore.get();
        }  // Default start time is now (minus one second)
        return Asn1Time::now() - std::chrono::seconds(1);
    }

    /**
     * @return the digest type used for signing certificates.
     */
    openssl::DigestTypes digestType() const { return _digestType; }

    const std::map<openssl::X509Extension_NID, std::shared_ptr<ExtensionBase> > &extensionMap()
            const
    {
        return _extensions;
    }

    /**
     * @param nid the NID which the extension that is looked for has
     * @return the extension with the given NID
     * @throw MoCOCrWException if no such extension is present.
     */
    std::shared_ptr<ExtensionBase> extension(openssl::X509Extension_NID nid) const
    {
        auto extension = _extensions.find(nid);

        if (extension == _extensions.end()) {
            throw MoCOCrWException("Extension type was not added to CertificateSigningParameters");
        }
        return extension->second;
    }

    /**
     * Returns the vector of custom extensions
    */
    std::vector<openssl::SSL_X509_EXTENSION_SharedPtr> getCustomExtensions() const
    {
        return _customExtensions;
    }

    /**
     * Checks whether the extension nid already exists in the current signing parameters
    */
    bool containsCustomExtensionWithNid(int nid) const
    {
        return _usedCustomExtensionNids.find(nid) != _usedCustomExtensionNids.end();
    }

    /**
     * @return the extension with the requested extension type, if present.
     * @throw MoCOCrWException if no such extension is present.
     */
    template <class T>
    inline std::shared_ptr<T> extension() const
    {
        static_assert(std::is_base_of<ExtensionBase, T>::value,
                      "Extension is not derived from ExtensionBase");
        return std::dynamic_pointer_cast<T>(extension(T::NID));
    }

private:
    auto _makeTuple() const
    {
        return std::tie(_certificateValidity, _notBefore, _digestType, _extensions);
    }

public:
    bool operator==(const CertificateSigningParameters &other) const
    {
        return _makeTuple() == other._makeTuple();
    }

    bool operator!=(const CertificateSigningParameters &other) const { return !operator==(other); }

private:
    boost::optional<Asn1Time> _notBefore;
    Asn1Time::Seconds _certificateValidity;
    openssl::DigestTypes _digestType;
    // There is no more than one extension of the same type, so every extension type
    // is unique in the extension map.
    std::map<openssl::X509Extension_NID, std::shared_ptr<ExtensionBase> > _extensions;
    std::vector<openssl::SSL_X509_EXTENSION_SharedPtr> _customExtensions;
    std::set<int> _usedCustomExtensionNids;
};

class CertificateSigningParameters::Builder
{
public:
    template <class T>
    Builder &certificateValidity(T &&validity)
    {
        _sp._certificateValidity = std::forward<T>(validity);
        return *this;
    }

    template <class T>
    Builder &notBeforeAsn1(T &&notBefore)
    {
        _sp._notBefore = std::forward<T>(notBefore);
        return *this;
    }

    template <class T>
    Builder &digestType(T &&type)
    {
        _sp._digestType = std::forward<T>(type);
        return *this;
    }

    template <class T>
    Builder &addExtension(T extension)
    {
        static_assert(std::is_base_of<ExtensionBase, T>::value,
                      "Extension is not derived from ExtensionBase");

        auto nid = extension.getNid();
        _sp._extensions[nid] = std::make_shared<T>(std::move(extension));
        return *this;
    }

    Builder &addExtension(std::shared_ptr<ExtensionBase> extension)
    {
        auto nid = extension->getNid();
        _sp._extensions[nid] = std::move(extension);
        return *this;
    }

    /**
     * Add a custom X509 extension by specifying its OID, criticality and ASN.1 data
     * This method does not validate the ASN1 data for the custom extension!
     *
     * @param oid The numeric object id for the new extension
     * @param critical A certificate-using system (eg. a CA) that does not recognize a critical
     * extension will decline the certificate
     * @param asn1EncodedBytes The data for the custom extension
     * @throws MoCOCrWException when data is to large or extension with same OID was already added
     * @warning This method is unsafe! The provided ASN1 data will not be checked for correctness by
     * MoCOCrW, you have to do this yourself!
     */
    Builder &addCustomExtensionUnsafe(const std::string &oid,
                                      const bool critical,
                                      const std::vector<uint8_t> &asn1EncodedBytes)
    {
        auto asn1OctetString = openssl::createASN1OctetStringUnsafe(asn1EncodedBytes);

        int nid = NID_undef;
        try {
            nid = openssl::_OBJ_create(oid);
        } catch (const openssl::OpenSSLException) {
            // If the oid has already been used to create an object, openssl will not be able to
            // create a new one with the same oid. But the same oid might be used for different
            // certificates, so we need to get the nid of the already existing openssl object.
            nid = openssl::_OBJ_txt2nid(oid); 
        }

        if (_sp.containsCustomExtensionWithNid(nid)) {
            throw MoCOCrWException(
                "An extension with this nid was already added to these signing parameters. "
                "A X509 certificate must not have two extensions with the same identifier!");
        }

        _sp._customExtensions.emplace_back(
                openssl::_X509_EXTENSION_create_by_NID(nid, critical, asn1OctetString.get()));

        _sp._usedCustomExtensionNids.insert(nid);

        return *this;
    }

    inline CertificateSigningParameters build() { return _sp; }

private:
    CertificateSigningParameters _sp;
};

}  // namespace mococrw
