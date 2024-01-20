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
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "pkcs12.cpp"

using namespace mococrw;
using namespace mococrw::openssl;

using namespace std::string_literals;

class Pkcs12Test : public ::testing::Test
{
public:
    void SetUp() override;

protected:
    static const std::string _password;
    static const std::string _pKeyPemString;

    std::unique_ptr<AsymmetricPrivateKey> _privateKey;
    std::unique_ptr<X509Certificate> _certificate;
    std::unique_ptr<X509Certificate> _root1;
};

void Pkcs12Test::SetUp()
{
    _privateKey = std::make_unique<AsymmetricPrivateKey>(
            AsymmetricPrivateKey::readPrivateKeyFromPEM(_pKeyPemString, ""));
    _certificate =
            std::make_unique<X509Certificate>(X509Certificate::fromPEMFile("pkcs12_test.pem"));
    _root1 = std::make_unique<X509Certificate>(X509Certificate::fromPEMFile("root1.pem"));
}

const std::string Pkcs12Test::_password("test_password");

const std::string Pkcs12Test::_pKeyPemString{R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP3aui7h2ZtI3rGdU+ot6IjfEh675A2KWw5PHNHBF83yoAoGCCqGSM49
AwEHoUQDQgAEBa1GchDoC8YD39wtsQ2GBTSfmtTtz+/TROAwFTlLeUfEsE//Y7eZ
t0+S8PTDc7qgCtNsnicbjRClTsJvujxA9A==
-----END EC PRIVATE KEY-----)"};

TEST_F(Pkcs12Test, testPkcs12Builder)
{
    auto pkcs12 = Pkcs12Container::Builder(_password, *_privateKey, *_certificate)
                          .includeAdditionalCert(*_root1)
                          .build();

    ASSERT_EQ(pkcs12.getPrivateKey().privateKeyToPem(""), _privateKey->privateKeyToPem(""));
    ASSERT_EQ(pkcs12.getCertificate().toPEM(), _certificate->toPEM());
    auto additionalCerts = pkcs12.getAdditionalCertificates();
    ASSERT_EQ(additionalCerts.size(), 1);
    ASSERT_EQ(additionalCerts[0].toPEM(), _root1->toPEM());
}

TEST_F(Pkcs12Test, testPkcs12Der)
{
    using ::testing::NotNull;
    ASSERT_NO_THROW({
        auto bytes = utility::bytesFromFile<uint8_t>("pkcs12_test.p12");
        auto pkcs12 = Pkcs12Container::fromDer(bytes, _password);
        ASSERT_THAT(pkcs12.internal(), NotNull());
        auto der = pkcs12.toDer();
        ASSERT_EQ(bytes, der);
    });
}
