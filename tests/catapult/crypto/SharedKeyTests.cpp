/**
*** Copyright (c) 2016-present,
*** Jaguar0625, gimre, BloodyRookie, Tech Bureau, Corp. All rights reserved.
***
*** This file is part of Catapult.
***
*** Catapult is free software: you can redistribute it and/or modify
*** it under the terms of the GNU Lesser General Public License as published by
*** the Free Software Foundation, either version 3 of the License, or
*** (at your option) any later version.
***
*** Catapult is distributed in the hope that it will be useful,
*** but WITHOUT ANY WARRANTY; without even the implied warranty of
*** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*** GNU Lesser General Public License for more details.
***
*** You should have received a copy of the GNU Lesser General Public License
*** along with Catapult. If not, see <http://www.gnu.org/licenses/>.
**/

#include "catapult/crypto/SharedKey.h"
#include "catapult/crypto/KeyUtils.h"
#include "catapult/utils/HexParser.h"
#include "tests/test/nodeps/KeyTestUtils.h"
#include "tests/TestHarness.h"

namespace catapult { namespace crypto {

#define TEST_CLASS SharedKeyTests

	// region HKDF Sha256

	TEST(TEST_CLASS, Hkdf_Hmac_Sha256_Test_Vector_A) {
		// Arrange:
		auto salt = test::HexStringToVector("000102030405060708090A0B0C");
		auto sharedSecret = test::HexStringToVector("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
		auto label = test::HexStringToVector("F0F1F2F3F4F5F6F7F8F9");
		auto expected = std::string("3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865");

		// Act:
		std::vector<uint8_t> output(expected.size() / 2);
		Hkdf_Hmac_Sha256(sharedSecret, salt, output, label);

		// Assert:
		EXPECT_EQ(expected, test::ToHexString(output));
	}

	// endregion

	// region Kdf Hmac_Sha256

	// data from botan: https://github.com/randombit/botan/blob/master/src/tests/data/kdf/sp800_56a.vec
	// SP800-56A(HMAC(SHA-256))
	TEST(TEST_CLASS, Kdf_Hmac_Sha256_Test_Vector_A) {
		// Arrange:
		auto salt = test::HexStringToVector("C767F6D57C1F68860197E6634B7D82C4");
		auto sharedSecret = test::HexStringToVector("713E56305A7BD670FEA95F9E4E3D8B638DED29A3A674D5B64574A3CB996DEEFF");
		auto label = test::HexStringToVector("40FA7C528A99EF7ADB4EF0737BD224DBD4398249B620C63F94343E829E6F7FD0");
		auto expected = std::string("61D0E910F5275ABAAE6CD15897981A070FD90832C53416D60E5F390563B3DA235A");

		// Act:
		std::vector<uint8_t> output(expected.size() / 2);
		KdfSp800_56C_Hmac_Sha256(sharedSecret, salt, output, label);

		// Assert:
		EXPECT_EQ(expected, test::ToHexString(output));
	}

	TEST(TEST_CLASS, Kdf_Hmac_Sha256_Test_Vector_B) {
		// Arrange:
		auto salt = test::HexStringToVector("C767F6D57C1F68860197E6634B7D82C4");
		auto sharedSecret = test::HexStringToVector("E938C5A86E992A2D88C1DF74E356ED81D48D9E5835DB5E301EACB58E7B31501570E2B8656EDD0B7A");
		auto label = test::HexStringToVector("48409EBDA7AA6E2F3897B1A24167CF2FBE7ED3E8AAF9B0F8ECAF55835DB4792A");
		auto expected = std::string("5F572EA878EEAF814539073745828186091ECD5058B2C5D8494859E18FDB990F6DAB");

		// Act:
		std::vector<uint8_t> output(expected.size() / 2);
		KdfSp800_56C_Hmac_Sha256(sharedSecret, salt, output, label);

		// Assert:
		EXPECT_EQ(expected, test::ToHexString(output));
	}

	TEST(TEST_CLASS, Kdf_Hmac_Sha256_Test_Vector_C) {
		// Arrange:
		auto salt = test::HexStringToVector("");
		auto sharedSecret = test::HexStringToVector("A8863B7EB7CADD66C616DFEA7C646F0F507A37819F615A7229E80EC38C524971E1961211F024A976");
		auto label = test::HexStringToVector("69F4C64716B4ED6ACA174C34E95AC10A1E9B710FE46A49FD44978101CB172BA6");
		auto expected = std::string("6B9BDC2303195C79F2D831B19BDFB1E6074632C81F77247854155A3D595B4EEF");

		// Act:
		std::vector<uint8_t> output(expected.size() / 2);
		KdfSp800_56C_Hmac_Sha256(sharedSecret, salt, output, label);

		// Assert:
		EXPECT_EQ(expected, test::ToHexString(output));
	}

	TEST(TEST_CLASS, Kdf_Hmac_Sha256_Test_Vector_D) {
		// Arrange:
		auto salt = test::HexStringToVector("00000000000000000000000000000000");
		auto sharedSecret = test::HexStringToVector("A8863B7EB7CADD66C616DFEA7C646F0F507A37819F615A7229E80EC38C524971E1961211F024A976");
		auto label = test::HexStringToVector("69F4C64716B4ED6ACA174C34E95AC10A1E9B710FE46A49FD44978101CB172BA6");
		auto expected = std::string("6B9BDC2303195C79F2D831B19BDFB1E6074632C81F77247854155A3D595B4EEF");

		// Act:
		std::vector<uint8_t> output(expected.size() / 2);
		KdfSp800_56C_Hmac_Sha256(sharedSecret, salt, output, label);

		// Assert:
		EXPECT_EQ(expected, test::ToHexString(output));
	}

	// endregion

	TEST(TEST_CLASS, PassesTestVector) {
		// Arrange: private key used is the one from KeyPairTests
#ifdef SIGNATURE_SCHEME_KECCAK
		auto expectedSharedKey = utils::ParseByteArray<SharedKey>("E9BF812E9E29B1D4C8D01E3DA11EAB3715A582CD2AA66EABBDAFEA7DFB9B2422");
#else
		auto expectedSharedKey = utils::ParseByteArray<SharedKey>("3B3524D2E92F89423456E43A3FD25C52C71CA4C680C32F022C23506BB23BDB0C");
#endif

		auto rawKeyString = std::string("ED4C70D78104EB11BCD73EBDC512FEBC8FBCEB36A370C957FF7E266230BB5D57");
		auto keyPair = KeyPair::FromString(rawKeyString);
		auto otherPublicKey = ParseKey("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
		auto salt = utils::ParseByteArray<Salt>("C06B2CC5D7B66900B2493CF68BE10B7AA8690D973B7F0B65D0DAE4F7AA464716");

		// Sanity: otherPublicKey is actually some *other* account
		EXPECT_NE(keyPair.publicKey(), otherPublicKey);

		// Act:
		auto sharedKey = DeriveSharedKey(keyPair, otherPublicKey, salt);

		// Assert:
		EXPECT_EQ(expectedSharedKey, sharedKey);
	}

	namespace {
		auto CreateKeyPair(const Key& privateKey) {
			auto index = 0u;
			return KeyPair::FromPrivate(PrivateKey::Generate([&privateKey, &index]() { return privateKey[index++]; }));
		}

		void AssertDeriveSharedKey(
				const consumer<Key&, Key&, Salt&>& mutate,
				const consumer<const SharedKey&, const SharedKey&>& assertKeys) {
			// Arrange: the public key needs to be valid, else unpacking will fail
			auto privateKey1 = test::GenerateRandomByteArray<Key>();
			auto otherPublicKey1 = test::GenerateKeyPair().publicKey();
			auto salt1 = test::GenerateRandomByteArray<Salt>();

			auto privateKey2 = privateKey1;
			auto otherPublicKey2 = otherPublicKey1;
			auto salt2 = salt1;

			mutate(privateKey2, otherPublicKey2, salt2);

			auto keyPair1 = CreateKeyPair(privateKey1);
			auto keyPair2 = CreateKeyPair(privateKey2);

			// Act:
			auto sharedKey1 = DeriveSharedKey(keyPair1, otherPublicKey1, salt1);
			auto sharedKey2 = DeriveSharedKey(keyPair2, otherPublicKey2, salt2);

			// Assert:
			assertKeys(sharedKey1, sharedKey2);
		}

		void AssertDerivedSharedKeysAreEqual(const consumer<Key&, Key&, Salt&>& mutate) {
			AssertDeriveSharedKey(mutate, [](const auto& sharedKey1, const auto& sharedKey2) {
				EXPECT_EQ(sharedKey1, sharedKey2);
			});
		}

		void AssertDerivedSharedKeysAreDifferent(const consumer<Key&, Key&, Salt&>& mutate) {
			AssertDeriveSharedKey(mutate, [](const auto& sharedKey1, const auto& sharedKey2) {
				EXPECT_NE(sharedKey1, sharedKey2);
			});
		}
	}

	TEST(TEST_CLASS, SharedKeysGeneratedWithSameInputsAreEqual) {
		AssertDerivedSharedKeysAreEqual([] (const auto&, const auto&, const auto&) {});
	}

	TEST(TEST_CLASS, SharedKeysGeneratedForDifferentKeyPairsAreDifferent) {
		AssertDerivedSharedKeysAreDifferent([] (auto& privateKey, const auto&, const auto&) {
			privateKey[0] ^= 0xFF;
		});
	}

	TEST(TEST_CLASS, SharedKeysGeneratedForDifferentOtherPublicKeysAreDifferent) {
		AssertDerivedSharedKeysAreDifferent([] (const auto&, auto& otherPublicKey, const auto&) {
			otherPublicKey[0] ^= 0xFF;
		});
	}

	TEST(TEST_CLASS, SharedKeysGeneratedWithDifferentSaltsAreDifferent) {
		AssertDerivedSharedKeysAreDifferent([] (const auto&, const auto&, auto& salt) {
			salt[0] ^= 0xFF;
		});
	}

	TEST(TEST_CLASS, MutualSharedKeysAreEqual) {
		// Arrange:
		auto privateKey1 = test::GenerateRandomByteArray<Key>();
		auto privateKey2 = test::GenerateRandomByteArray<Key>();
		auto keyPair1 = CreateKeyPair(privateKey1);
		auto keyPair2 = CreateKeyPair(privateKey2);

		auto salt = test::GenerateRandomByteArray<Salt>();

		// Act:
		auto sharedKey1 = DeriveSharedKey(keyPair1, keyPair2.publicKey(), salt);
		auto sharedKey2 = DeriveSharedKey(keyPair2, keyPair1.publicKey(), salt);

		// Assert:
		EXPECT_EQ(sharedKey2, sharedKey1);
	}

	TEST(TEST_CLASS, PublicKeyNotOnTheCurveResultsInZeroSharedKey) {
		// Arrange:
		auto keyPair = test::GenerateKeyPair();
		Key publicKey{};
		publicKey[Key::Size - 1] = 1; // not on the curve

		auto salt = test::GenerateRandomByteArray<Salt>();

		// Act:
		auto sharedKey = DeriveSharedKey(keyPair, publicKey, salt);

		// Assert:
		EXPECT_EQ(SharedKey(), sharedKey);
	}
}}
