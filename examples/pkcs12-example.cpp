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
#include <iostream>

#include <mococrw/pkcs12.h>

using namespace mococrw;

int main()
{
    const std::string privKeyPem = R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP3aui7h2ZtI3rGdU+ot6IjfEh675A2KWw5PHNHBF83yoAoGCCqGSM49
AwEHoUQDQgAEBa1GchDoC8YD39wtsQ2GBTSfmtTtz+/TROAwFTlLeUfEsE//Y7eZ
t0+S8PTDc7qgCtNsnicbjRClTsJvujxA9A==
-----END EC PRIVATE KEY-----
)";

    // Read Private Key and its certificate:
    auto pkey = AsymmetricPrivateKey::readPrivateKeyFromPEM(privKeyPem, "");
    auto cert = X509Certificate::fromPEMFile("pkcs12_test.pem");

    // Print fingerprint of Certificate before PKCS12 container creation:
    auto certDigest = cert.getDigest(openssl::DigestTypes::SHA512);
    std::cout << "Finger-Print: " << utility::toHex(certDigest) << std ::endl;

    auto certPubkeyDigest = cert.getPublicKeyDigest(openssl::DigestTypes::SHA512);
    std::cout << "Certificate Public Key Finger-Print: " << utility::toHex(certPubkeyDigest)
              << std ::endl;

    // Create container and translate it to DER format:
    auto password = std::string("hello");
    auto name = std::string("name");
    std::vector<uint8_t> pkcs12Der;

    std::cout << "Testing PKCS#12 container generation" << std::endl;
    try {
        auto pkcs12 =
                Pkcs12Container::Builder(password, pkey, cert)
                        .includeAdditionalCert(X509Certificate::fromPEMFile("root3.pem"))
                        .includeAdditionalCert(X509Certificate::fromPEMFile("root3.int1.pem"))
                        .includeAdditionalCert(X509Certificate::fromPEMFile("root3.int1.int11.pem"))
                        .build();
        pkcs12Der = pkcs12.toDer();

        // Also save PKCS#12 Container to p12 file:
        pkcs12.toDerFile("pkcs12_example.p12");
    } catch (const openssl::OpenSSLException &e) {
        std::cerr << "Failed to generate PKCS#12 container. OpenSSL error: " << e.what()
                  << std::endl;
        exit(EXIT_FAILURE);
    }

    // Get PKCS#12 container for DER and unpack it:
    auto derivedPkcs12 = Pkcs12Container::fromDer(pkcs12Der, password);
    try {
        auto unpackedPrivKey = derivedPkcs12.getPrivateKey();
        auto unpackedCert = derivedPkcs12.getCertificate();
        auto unpackedAdditionalCerts = derivedPkcs12.getAdditionalCertificates();

        // Print number of additional Certificates in container:
        std::cout << "Number of Additional Certificates: " << unpackedAdditionalCerts.size()
                  << std::endl;

        // Print finger-print of Certificate:
        auto certDigest2 = unpackedCert.getDigest(openssl::DigestTypes::SHA512);
        std::cout << "Finger-Print: " << utility::toHex(certDigest2) << std::endl;

    } catch (const openssl::OpenSSLException &e) {
        std::cerr << "Failed to unpack PKCS#12 container. OpenSSL error: " << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}