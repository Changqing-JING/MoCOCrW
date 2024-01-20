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

#include "mococrw/pkcs12.h"
#include "mococrw/bio.h"
#include "mococrw/error.h"
#include "mococrw/key.h"
#include "mococrw/openssl_wrap.h"
#include "mococrw/stack_utils.h"
#include "mococrw/util.h"
#include "mococrw/x509.h"
using namespace std::string_literals;

namespace mococrw
{
using namespace openssl;

Pkcs12Container Pkcs12Container::Builder::build()
{
    auto stackAdditionalCerts =
            utility::buildStackFromContainer<SSL_STACK_X509_Ptr>(_additionalCerts);
    auto pkcs12 = _PKCS12_create(_pwd,
                                 _name,
                                 _pkey.internal(),
                                 _cert.internal(),
                                 stackAdditionalCerts.get(),
                                 _nidKey,
                                 _nidCert,
                                 _iter,
                                 _macIter,
                                 _keyType);

    return Pkcs12Container{_pwd, std::move(pkcs12)};
}

Pkcs12Container Pkcs12Container::fromDer(const std::vector<uint8_t> &derData,
                                         const std::string &pwd)
{
    BioObject bio{BioObject::Types::MEM};
    bio.write(derData);
    return Pkcs12Container{pwd, _d2i_PKCS12_bio(bio.internal())};
}

Pkcs12Container Pkcs12Container::fromDerFile(const std::string &filename, const std::string &pwd)
{
    FileBio bio{filename, FileBio::FileMode::READ, FileBio::FileType::BINARY};
    auto pkcs12 = _d2i_PKCS12_bio(bio.internal());
    return Pkcs12Container(pwd, std::move(pkcs12));
}

AsymmetricPrivateKey Pkcs12Container::getPrivateKey()
{
    return AsymmetricPrivateKey{_parsePrivateKeyFromPkcs12(_pkcs12.get(), _pwd)};
}

X509Certificate Pkcs12Container::getCertificate()
{
    return X509Certificate{_parseCertificateFromPkcs12(_pkcs12.get(), _pwd)};
}

std::vector<X509Certificate> Pkcs12Container::getAdditionalCertificates()
{
    auto stackAdditionalCerts = _parseAdditionalCertsFromPkcs12(_pkcs12.get(), _pwd);
    return utility::buildContainerFromStackAndMoveOwnership<STACK_OF(X509),
                                                            SSL_STACK_OWNER_X509_Ptr,
                                                            std::vector<X509Certificate>,
                                                            SSL_X509_Ptr>(stackAdditionalCerts);
}

std::vector<uint8_t> Pkcs12Container::toDer() const
{
    BioObject bio{BioObject::Types::MEM};
    _i2d_PKCS12_bio(bio.internal(), const_cast<PKCS12 *>(internal()));
    return bio.flushToVector();
}

void Pkcs12Container::toDerFile(const std::string &filename) const
{
    FileBio bio{filename, FileBio::FileMode::WRITE, FileBio::FileType::BINARY};
    _i2d_PKCS12_bio(bio.internal(), const_cast<PKCS12 *>(internal()));
}

}  // namespace mococrw