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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include "mococrw/error.h"
#include "mococrw/openssl_wrap.h"
#include "openssl_lib_mock.h"

using namespace ::mococrw::openssl;
using namespace ::std::string_literals;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::Mock;
using ::testing::Return;
using ::testing::SetArgPointee;

/**
 * Test the openssl wrapper.
 *
 * These tests are to determine that the openssl-wrapper,
 * declared and defined in openssl_wrap.h and openssl_wrap.cpp
 * behaves as intended and calls the underlying openssl library
 * correctly.
 *
 */
class OpenSSLWrapperTest : public ::testing::Test
{
public:
    void SetUp() override;
    void TearDown() override;

protected:
    std::string _defaultErrorMessage{"bla bla err msg"};
    std::string _defaultErrorLibrary{"bla bla err lib"};
    std::string _defaultErrorReason{"bla bla err reason"};

    const unsigned long _defaultErrorCode = 1L;
    OpenSSLLibMock &_mock() const { return OpenSSLLibMockManager::getMockInterface(); }
};

namespace testutils
{
EVP_PKEY_CTX *somePkeyCtxPtr()
{
    /* Reserve some memory and cast a pointer to that ; pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<EVP_PKEY_CTX *>(&dummyBuf);
}

EVP_PKEY *somePkeyPtr()
{
    /* Reserve some memory and cast a pointer to that ; pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<EVP_PKEY *>(&dummyBuf);
}

ENGINE *someEnginePtr()
{
    /* Reserve some memory and cast a pointer to that ; pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<ENGINE *>(&dummyBuf);
}

STACK_OF(X509) * someX509StackPtr()
{
    /* Reserve some memory and cast a pointer to that ; pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<STACK_OF(X509) *>(&dummyBuf);
}

X509 *someX509Ptr()
{
    /* Reserve some memory and cast a pointer to that ; pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<X509 *>(&dummyBuf);
}

PKCS12 *somePkcs12Ptr()
{
    /* Reserve some memory and cast a pointer to that ; pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<PKCS12 *>(&dummyBuf);
}
}  // namespace testutils

void OpenSSLWrapperTest::SetUp()
{
    /*
     * We instrument the mock, so that error-handling code
     * will always have well-defined behavior.
     */
    OpenSSLLibMockManager::resetMock();
    ON_CALL(_mock(), SSL_ERR_get_error()).WillByDefault(Return(_defaultErrorCode));
    ON_CALL(_mock(), SSL_ERR_error_string(_, nullptr))
            .WillByDefault(Return(const_cast<char *>(_defaultErrorMessage.c_str())));
    ON_CALL(_mock(), SSL_ERR_lib_error_string(_))
            .WillByDefault(Return(const_cast<char *>(_defaultErrorLibrary.c_str())));
    ON_CALL(_mock(), SSL_ERR_reason_error_string(_))
            .WillByDefault(Return(const_cast<char *>(_defaultErrorReason.c_str())));

    // TODO: Get rid of the uninteresting calls by default here somehow...
}

void OpenSSLWrapperTest::TearDown() { OpenSSLLibMockManager::destroy(); }

/*
 * Test that EVP_PKEY instances are
 * allocated correctly and that the custom deleter
 * will use the correct free function.
 */
TEST_F(OpenSSLWrapperTest, keyMemoryManagement)
{
    EXPECT_CALL(_mock(), SSL_EVP_PKEY_new())
            .WillOnce(Return(nullptr)); /* first invocation will throw because allocation "fails"*/

    EXPECT_CALL(_mock(), SSL_ERR_get_error()).WillOnce(Return(_defaultErrorCode));
    EXPECT_CALL(_mock(), SSL_ERR_error_string(_defaultErrorCode, nullptr));
    EXPECT_CALL(_mock(), SSL_ERR_lib_error_string(_defaultErrorCode));
    EXPECT_CALL(_mock(), SSL_ERR_reason_error_string(_defaultErrorCode));

    EXPECT_THROW(_EVP_PKEY_new(), OpenSSLException);
}

/*
 * Test that the EVP_PKEY_CTX instances
 * are created correctly and that the deleter will
 * use the correct free function.
 *
 */
TEST_F(OpenSSLWrapperTest, keyContextMemoryManagement)
{
    EXPECT_CALL(_mock(), SSL_EVP_PKEY_CTX_new_id(_, nullptr))
            .WillOnce(Return(nullptr)) /* first invocation will throw because allocation "fails" */
            .WillRepeatedly(
                    Return(::testutils::somePkeyCtxPtr())); /* subsequent invocation will succeed */

    /* Since we wrap in a unique_ptr, expect a call to the "free" function */
    EXPECT_CALL(_mock(), SSL_EVP_PKEY_CTX_free(::testutils::somePkeyCtxPtr()));

    EXPECT_CALL(_mock(), SSL_ERR_get_error()).WillOnce(Return(_defaultErrorCode));
    EXPECT_CALL(_mock(), SSL_ERR_error_string(_defaultErrorCode, nullptr));
    EXPECT_CALL(_mock(), SSL_ERR_lib_error_string(_defaultErrorCode));
    EXPECT_CALL(_mock(), SSL_ERR_reason_error_string(_defaultErrorCode));

    EXPECT_THROW(_EVP_PKEY_CTX_new_id(0), OpenSSLException);
    auto key = _EVP_PKEY_CTX_new_id(0);
}

/**
 * Test that keygen-init throws if the underlying openssl function
 * returns an error.
 *
 */
TEST_F(OpenSSLWrapperTest, initThrowsOnError)
{
    // return 0, indicating an error in openssl
    EXPECT_CALL(_mock(), SSL_EVP_PKEY_keygen_init(_)).WillOnce(Return(0));
    ASSERT_THROW(_EVP_PKEY_keygen_init(::testutils::somePkeyCtxPtr()), OpenSSLException);
}

/*
 * Test that key generation uses OpenSSL as expected, setting up all
 * the unique pointers and setting the correct pointers in out-arguments.
 */
TEST_F(OpenSSLWrapperTest, keyGenTest)
{
    // these calls will happen, but we have no particular interest in them
    EXPECT_CALL(_mock(), SSL_EVP_PKEY_CTX_new_id(_, nullptr))
            .WillOnce(Return(::testutils::somePkeyCtxPtr()));
    EXPECT_CALL(_mock(), SSL_EVP_PKEY_keygen_init(_)).WillOnce(Return(1));

    // the keygen call is what we are interested in mostly
    EXPECT_CALL(_mock(), SSL_EVP_PKEY_keygen(_, _)).WillOnce(Return(-1));

    auto ctx = _EVP_PKEY_CTX_new_id(EVP_PKEY_RSA);
    ASSERT_NO_THROW(_EVP_PKEY_keygen_init(ctx.get()));

    // First time this should throw (mock returns value != 1)
    ASSERT_THROW(_EVP_PKEY_keygen(ctx.get()), OpenSSLException);
}

/**
 * Test adding elements to the X509_NAME structure
 *
 * Test the the conversion of enums and std::vector to
 * the values expected by the C API. Also test that
 * the amgic constant which we do not expose through our
 * C++ wrapper API (the last two arguments to the vanilla
 * OpneSSL function) are handeled correctly.
 *
 */
TEST_F(OpenSSLWrapperTest, testAddEntryByNID)
{
    X509_NAME *name = nullptr;
    constexpr int bufsize = 47;
    std::vector<unsigned char> buffer(bufsize);
    EXPECT_CALL(_mock(),
                SSL_X509_NAME_add_entry_by_NID(name,
                                               static_cast<int>(ASN1_NID::CommonName),
                                               static_cast<int>(ASN1_Name_Entry_Type::ASCIIString),
                                               buffer.data(),
                                               buffer.size(),
                                               -1,
                                               0))
            .WillOnce(Return(1));

    _X509_NAME_add_entry_by_NID(
            name, ASN1_NID::CommonName, ASN1_Name_Entry_Type::ASCIIString, buffer);
}

/*
 * Define a custom matcher that checks, given a std::string
 * whether its argument, interpreted as char*, holds the
 * identical (as in strcmp) string.
 */
MATCHER_P(IsSameCString, expectedString, "Expect same C-string")
{
    return 0 == std::strncmp(expectedString.c_str(),
                             reinterpret_cast<char *>(arg),
                             expectedString.size());
}

TEST_F(OpenSSLWrapperTest, testThatWritingPrivateKeyHandlesArgumentsCorrectly)
{
    BIO *bio = nullptr;
    EVP_PKEY *pkey = nullptr;
    EVP_CIPHER *cipher = nullptr;
    const auto pwd = "some password"s;
    EXPECT_CALL(_mock(),
                SSL_PEM_write_bio_PKCS8PrivateKey(
                        bio,
                        pkey,
                        cipher,
                        IsSameCString(pwd) /* make sure that we get the correct password */,
                        pwd.size(),
                        nullptr,
                        nullptr))
            .WillOnce(Return(1));
    _PEM_write_bio_PKCS8PrivateKey(bio, pkey, cipher, pwd);
}

TEST_F(OpenSSLWrapperTest, testThatX509ParsingThrowsOnNullptr)
{
    BIO *bio = nullptr;
    EXPECT_CALL(_mock(), SSL_PEM_read_bio_X509(bio, nullptr, nullptr, nullptr))
            .WillOnce(Return(nullptr));
    EXPECT_THROW(_PEM_read_bio_X509(bio), OpenSSLException);
}

TEST_F(OpenSSLWrapperTest, testX509Digest)
{
    X509 *cert = nullptr;
    EXPECT_CALL(_mock(), SSL_X509_digest(cert, lib::OpenSSLLib::SSL_EVP_sha512(), _, _))
            .WillOnce(Return(1));
    EXPECT_NO_THROW(_X509_digest(cert, DigestTypes::SHA512));
}

TEST_F(OpenSSLWrapperTest, testX509PubKeyDigest)
{
    X509 *cert = nullptr;
    EXPECT_CALL(_mock(), SSL_X509_pubkey_digest(cert, lib::OpenSSLLib::SSL_EVP_sha512(), _, _))
            .WillOnce(Return(1));
    EXPECT_NO_THROW(_X509_pubkey_digest(cert, DigestTypes::SHA512));
}

TEST_F(OpenSSLWrapperTest, testEngineById)
{
    std::string id = "engine_id";
    EXPECT_CALL(_mock(), SSL_ENGINE_by_id(id.c_str()))
            .WillOnce(Return(::testutils::someEnginePtr()));
    EXPECT_NO_THROW(_ENGINE_by_id(id));
}

TEST_F(OpenSSLWrapperTest, testEngineByIdThrowsException)
{
    std::string id = "engine_id";
    EXPECT_CALL(_mock(), SSL_ENGINE_by_id(id.c_str())).WillOnce(Return(nullptr));
    EXPECT_THROW(_ENGINE_by_id(id), OpenSSLException);
}

TEST_F(OpenSSLWrapperTest, testEngineInit)
{
    auto engine = ::testutils::someEnginePtr();
    EXPECT_CALL(_mock(), SSL_ENGINE_init(engine)).WillOnce(Return(1));
    EXPECT_NO_THROW(_ENGINE_init(engine));
}

TEST_F(OpenSSLWrapperTest, testEngineInitThrowsException)
{
    auto engine = ::testutils::someEnginePtr();
    EXPECT_CALL(_mock(), SSL_ENGINE_init(engine)).WillOnce(Return(0));
    EXPECT_THROW(_ENGINE_init(engine), OpenSSLException);
}

TEST_F(OpenSSLWrapperTest, testEngineCtrlCmdString)
{
    auto engine = ::testutils::someEnginePtr();
    std::string cmd = "command";
    std::string cmdArg = "command_arg";

    EXPECT_CALL(_mock(),
                SSL_ENGINE_ctrl_cmd_string(engine, cmd.c_str(), cmdArg.c_str(), 0 /*non-optional*/))
            .WillOnce(Return(1));
    EXPECT_NO_THROW(_ENGINE_ctrl_cmd_string(engine, cmd, cmdArg));
}

TEST_F(OpenSSLWrapperTest, testEngineCtrlCmdStringThrowsException)
{
    auto engine = ::testutils::someEnginePtr();
    std::string cmd = "command";
    std::string cmdArg = "command_arg";

    EXPECT_CALL(_mock(),
                SSL_ENGINE_ctrl_cmd_string(engine, cmd.c_str(), cmdArg.c_str(), 0 /*non-optional*/))
            .WillOnce(Return(0));
    EXPECT_THROW(_ENGINE_ctrl_cmd_string(engine, cmd, cmdArg), OpenSSLException);
}

TEST_F(OpenSSLWrapperTest, testEngineLoadPublicKey)
{
    auto engine = ::testutils::someEnginePtr();
    std::string keyId = "keyid";

    EXPECT_CALL(_mock(), SSL_ENGINE_load_public_key(engine, keyId.c_str(), nullptr, nullptr))
            .WillOnce(Return(::testutils::somePkeyPtr()));
    EXPECT_NO_THROW(_ENGINE_load_public_key(engine, keyId));
}

TEST_F(OpenSSLWrapperTest, testEngineLoadPublicKeyThrowsException)
{
    auto engine = ::testutils::someEnginePtr();
    std::string keyId = "keyid";

    EXPECT_CALL(_mock(), SSL_ENGINE_load_public_key(engine, keyId.c_str(), nullptr, nullptr))
            .WillOnce(Return(nullptr));
    EXPECT_THROW(_ENGINE_load_public_key(engine, keyId), OpenSSLException);
}

TEST_F(OpenSSLWrapperTest, testEngineLoadPrivateKey)
{
    auto engine = ::testutils::someEnginePtr();
    std::string keyId = "keyid";

    EXPECT_CALL(_mock(), SSL_ENGINE_load_private_key(engine, keyId.c_str(), nullptr, nullptr))
            .WillOnce(Return(::testutils::somePkeyPtr()));
    EXPECT_NO_THROW(_ENGINE_load_private_key(engine, keyId));
}

TEST_F(OpenSSLWrapperTest, testEngineLoadPrivateKeyThrowsException)
{
    auto engine = ::testutils::someEnginePtr();
    std::string keyId = "keyid";

    EXPECT_CALL(_mock(), SSL_ENGINE_load_private_key(engine, keyId.c_str(), nullptr, nullptr))
            .WillOnce(Return(nullptr));
    EXPECT_THROW(_ENGINE_load_private_key(engine, keyId), OpenSSLException);
}

TEST_F(OpenSSLWrapperTest, testEngineFinish)
{
    auto engine = ::testutils::someEnginePtr();
    EXPECT_CALL(_mock(), SSL_ENGINE_finish(engine)).WillOnce(Return(1));
    EXPECT_NO_THROW(_ENGINE_finish(engine));
}

TEST_F(OpenSSLWrapperTest, testEngineFinishThrowsException)
{
    auto engine = ::testutils::someEnginePtr();
    EXPECT_CALL(_mock(), SSL_ENGINE_finish(engine)).WillOnce(Return(0));
    EXPECT_THROW(_ENGINE_finish(engine), OpenSSLException);
}

TEST_F(OpenSSLWrapperTest, testEngineCtrlCmd)
{
    auto engine = ::testutils::someEnginePtr();
    std::string cmd = "command";
    void *randomVoidPointer = (void *)0x424244;
    EXPECT_CALL(_mock(),
                SSL_ENGINE_ctrl_cmd(
                        engine, cmd.c_str(), 0 /*non-optional*/, randomVoidPointer, nullptr, 1))
            .WillOnce(Return(1));
    EXPECT_NO_THROW(_ENGINE_ctrl_cmd(engine, cmd, randomVoidPointer));
}

TEST_F(OpenSSLWrapperTest, testEngineCtrlCmdThrowsException)
{
    auto engine = ::testutils::someEnginePtr();
    std::string cmd = "command";
    void *randomVoidPointer = (void *)0x424244;
    EXPECT_CALL(_mock(),
                SSL_ENGINE_ctrl_cmd(
                        engine, cmd.c_str(), 0 /*non-optional*/, randomVoidPointer, nullptr, 1))
            .WillOnce(Return(0));
    EXPECT_THROW(_ENGINE_ctrl_cmd(engine, cmd, randomVoidPointer), OpenSSLException);
}

TEST_F(OpenSSLWrapperTest, testECP256Nid2Nist)
{
    int c = int(ellipticCurveNid::PRIME_256v1);
    EXPECT_CALL(_mock(), SSL_EC_curve_nid2nist(c)).WillOnce(Return("P-256"));
    EXPECT_NO_THROW(_EC_curve_nid2nist(int(ellipticCurveNid::PRIME_256v1)));
}

TEST_F(OpenSSLWrapperTest, testECSantaClausNid2Nist)
{
    int bogusCurve = 25120000;
    EXPECT_CALL(_mock(), SSL_EC_curve_nid2nist(bogusCurve)).WillOnce(Return(nullptr));
    EXPECT_THROW(_EC_curve_nid2nist(bogusCurve), OpenSSLException);
}

/**
 * null-initialized OpenSSL data structure OSSL_PARAM. This is for now used
 * only here for tests. One should use OSSL_PARAM_* functions from OpenSSL.
 */
class _OSSL_PARAM : public OSSL_PARAM
{
public:
    _OSSL_PARAM() = default;
    explicit _OSSL_PARAM(const char *key, void *data, size_t data_size) noexcept : OSSL_PARAM()
    {
        this->key = key;
        this->data = data;
        this->data_size = data_size;
    }
};

TEST_F(OpenSSLWrapperTest, testGetOSSLParamFromDigestType)
{
    _OSSL_PARAM osslParam(OSSL_MAC_PARAM_DIGEST,
                          const_cast<char *>(OSSL_DIGEST_NAME_SHA2_512),
                          strlen(OSSL_DIGEST_NAME_SHA2_512));
    EXPECT_CALL(_mock(), SSL_OSSL_PARAM_construct_utf8_string(_, _, 0)).WillOnce(Return(osslParam));
    _OSSL_PARAM emptyOsslParam;
    EXPECT_CALL(_mock(), SSL_OSSL_PARAM_construct_end()).WillOnce(Return(emptyOsslParam));
    EXPECT_NO_THROW(_getOSSLParamFromDigestType(DigestTypes::SHA512));
}

TEST_F(OpenSSLWrapperTest, testGetOSSLParamFromCmacCipherType)
{
    _OSSL_PARAM osslParam(
            OSSL_MAC_PARAM_CIPHER, const_cast<char *>("aes-128-cbc"), strlen("aes-128-cbc"));
    EXPECT_CALL(_mock(), SSL_OSSL_PARAM_construct_utf8_string(_, _, 0)).WillOnce(Return(osslParam));
    _OSSL_PARAM emptyOsslParam;
    EXPECT_CALL(_mock(), SSL_OSSL_PARAM_construct_end()).WillOnce(Return(emptyOsslParam));
    EXPECT_NO_THROW(_getOSSLParamFromCmacCipherType(CmacCipherTypes::AES_CBC_128));
}

TEST_F(OpenSSLWrapperTest, testPkcs12Creation)
{
    auto pwd = std::string("password");
    auto name = std::string("name");
    X509 *cert = nullptr;
    STACK_OF(X509) *ca = nullptr;
    EXPECT_CALL(
            _mock(),
            SSL_PKCS12_create(
                    pwd.c_str(), name.c_str(), ::testutils::somePkeyPtr(), cert, ca, 0, 0, 0, 0, 0))
            .WillOnce(Return(::testutils::somePkcs12Ptr()));
    EXPECT_NO_THROW(_PKCS12_create(pwd, name, ::testutils::somePkeyPtr(), cert, ca, 0, 0, 0, 0, 0));
}

TEST_F(OpenSSLWrapperTest, testPkcs12MacSetup)
{
    auto pwd = std::string("password");
    auto saltLength = 40;
    auto iter = 1;
    EXPECT_CALL(_mock(),
                SSL_PKCS12_set_mac(::testutils::somePkcs12Ptr(),
                                   pwd.c_str(),
                                   -1,
                                   nullptr,
                                   saltLength,
                                   iter,
                                   nullptr))
            .WillOnce(Return(1));
    EXPECT_NO_THROW(_PKCS12_set_mac(
            ::testutils::somePkcs12Ptr(), pwd, saltLength, iter, DigestTypes::NONE));
}

TEST_F(OpenSSLWrapperTest, testPkcs12PrivateKeyParsing)
{
    auto pwd = std::string("password");
    auto pkey = ::testutils::somePkeyPtr();

    EXPECT_CALL(_mock(), SSL_PKCS12_parse(::testutils::somePkcs12Ptr(), pwd.c_str(), _, _, nullptr))
            .WillOnce(DoAll(SetArgPointee<2>(pkey), Return(1)));
    EXPECT_NO_THROW(_parsePrivateKeyFromPkcs12(::testutils::somePkcs12Ptr(), pwd));
}

TEST_F(OpenSSLWrapperTest, testPkcs12CertParsing)
{
    auto pwd = std::string("password");
    auto cert = ::testutils::someX509Ptr();

    EXPECT_CALL(_mock(), SSL_PKCS12_parse(::testutils::somePkcs12Ptr(), pwd.c_str(), _, _, nullptr))
            .WillOnce(DoAll(SetArgPointee<3>(cert), Return(1)));
    EXPECT_NO_THROW(_parseCertificateFromPkcs12(::testutils::somePkcs12Ptr(), pwd));
}

TEST_F(OpenSSLWrapperTest, testPkcs12AdditionalCertParsing)
{
    auto pwd = std::string("password");
    auto stack = ::testutils::someX509StackPtr();

    EXPECT_CALL(_mock(), SSL_sk_X509_new_null()).WillOnce(Return(stack));
    EXPECT_CALL(_mock(), SSL_PKCS12_parse(::testutils::somePkcs12Ptr(), pwd.c_str(), _, _, _))
            .WillOnce(DoAll(SetArgPointee<4>(stack), Return(1)));
    EXPECT_NO_THROW(_parseAdditionalCertsFromPkcs12(::testutils::somePkcs12Ptr(), pwd));
}

TEST_F(OpenSSLWrapperTest, testPkcs12ToBio)
{
    BIO *bp = nullptr;
    EXPECT_CALL(_mock(), SSL_i2d_PKCS12_bio(bp, ::testutils::somePkcs12Ptr())).WillOnce(Return(0));
    EXPECT_NO_THROW(_i2d_PKCS12_bio(bp, ::testutils::somePkcs12Ptr()));
}

TEST_F(OpenSSLWrapperTest, testBioToPkcs12)
{
    BIO *bp = nullptr;
    EXPECT_CALL(_mock(), SSL_d2i_PKCS12_bio(bp, nullptr))
            .WillOnce(Return(::testutils::somePkcs12Ptr()));
    EXPECT_NO_THROW(_d2i_PKCS12_bio(bp));
}
