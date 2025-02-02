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
#include "mococrw/csr.h"
#include "mococrw/bio.h"
#include "mococrw/error.h"
#include "mococrw/key.h"

namespace mococrw
{
using namespace openssl;

CertificateSigningRequest::CertificateSigningRequest(const DistinguishedName &dn,
                                                     const AsymmetricKeypair &keypair,
                                                     const openssl::DigestTypes digestFunction)
        : CertificateSigningRequest(
                  dn,
                  keypair,
                  CertificateSigningParameters::Builder{}.digestType(digestFunction).build())
{
}

CertificateSigningRequest::CertificateSigningRequest(const DistinguishedName &dn,
                                                     const AsymmetricKeypair &keypair)
        : CertificateSigningRequest{dn, keypair, DigestTypes::SHA512}
{
}

CertificateSigningRequest::CertificateSigningRequest(const DistinguishedName &dn,
                                                     const AsymmetricKeypair &keypair,
                                                     const CertificateSigningParameters &csp)
        : _req{openssl::_X509_REQ_new()}
{
    /* setup x509 version number */
    _X509_REQ_set_version(_req.get(), 0L);

    auto subject = _X509_NAME_new();
    dn.populateX509Name(subject);
    _X509_REQ_set_subject_name(_req.get(), subject.get());

    _X509_REQ_set_pubkey(_req.get(), const_cast<EVP_PKEY *>(keypair.internal()));

    auto customExtensions = csp.getCustomExtensions();
    auto extStack = openssl::createManagedOpenSSLObject<SSL_STACK_X509_Extension_Ptr>();
    for (const auto &ext : customExtensions) {
        openssl::addObjectToStack(extStack.get(), ext.get());
    }

    // We have to store the extension pointers in an vector outside of the for loop, because
    // addObjectToStack does not copy the extension. Otherwise openssl would use freed memory when
    // adding the extension stack to the csr outside of the for loop.
    std::vector<SSL_X509_EXTENSION_Ptr> baseExtensions;
    for (auto &it : csp.extensionMap()) {
        auto builtExtension = it.second.get()->buildExtension(nullptr);
        openssl::addObjectToStack(extStack.get(), builtExtension.get());
        baseExtensions.emplace_back(std::move(builtExtension));
    }

    _X509_REQ_add_extensions(internal(), extStack.get());

    auto mctx = _EVP_MD_CTX_create();

    auto digestType = csp.digestType();
    if (keypair.getType() == AsymmetricKey::KeyTypes::ECC_ED) {
        digestType = DigestTypes::NONE;
    }
    _EVP_DigestSignInit(mctx.get(), digestType, const_cast<EVP_PKEY *>(keypair.internal()));

    _X509_REQ_sign_ctx(_req.get(), mctx.get());
}

AsymmetricPublicKey CertificateSigningRequest::getPublicKey() const
{
    auto pubkey = _X509_REQ_get_public_key(_req.get());
    return AsymmetricPublicKey(std::move(pubkey));
}

void CertificateSigningRequest::verify() const
{
    auto pubkey = _X509_REQ_get_public_key(_req.get());

    try {
        _X509_REQ_verify(_req.get(), pubkey.get());
    } catch (const OpenSSLException &error) {
        throw MoCOCrWException(error.what());
    }
}

std::string CertificateSigningRequest::toPem() const { return toPEM(); }

std::string CertificateSigningRequest::toPEM() const
{
    BioObject bio{BioObject::Types::MEM};
    _PEM_write_bio_X509_REQ(bio.internal(), _req.get());
    return bio.flushToString();
}

std::vector<uint8_t> CertificateSigningRequest::toDER() const
{
    BioObject bio{BioObject::Types::MEM};
    _i2d_X509_REQ_bio(bio.internal(), _req.get());
    return bio.flushToVector();
}

DistinguishedName CertificateSigningRequest::getSubjectName() const
{
    auto internalSubjectName = _X509_REQ_get_subject_name(_req.get());
    return DistinguishedName::fromX509Name(internalSubjectName);
}

CertificateSigningRequest CertificateSigningRequest::fromPEM(const std::string &pem)
{
    BioObject bio{BioObject::Types::MEM};
    bio.write(pem);
    return CertificateSigningRequest{_PEM_read_bio_X509_REQ(bio.internal())};
}

CertificateSigningRequest CertificateSigningRequest::fromPEMFile(const std::string &filename)
{
    FileBio bio{filename, FileBio::FileMode::READ, FileBio::FileType::TEXT};
    return CertificateSigningRequest{_PEM_read_bio_X509_REQ(bio.internal())};
}

CertificateSigningRequest CertificateSigningRequest::fromDER(const std::vector<uint8_t> &derData)
{
    BioObject bio{BioObject::Types::MEM};
    bio.write(derData);
    return CertificateSigningRequest{_d2i_X509_REQ_bio(bio.internal())};
}

CertificateSigningRequest CertificateSigningRequest::fromDERFile(const std::string &filename)
{
    FileBio bio{filename, FileBio::FileMode::READ, FileBio::FileType::BINARY};
    return CertificateSigningRequest{_d2i_X509_REQ_bio(bio.internal())};
}

CertificateSigningRequest::CertificateSigningRequest(SSL_X509_REQ_Ptr req) : _req{std::move(req)} {}

}  // namespace mococrw
