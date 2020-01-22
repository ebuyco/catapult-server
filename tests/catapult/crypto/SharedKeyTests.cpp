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
#include "catapult/crypto/Hashes.h"
#include "catapult/crypto/KeyUtils.h"
#include "catapult/utils/HexParser.h"
#include "tests/test/nodeps/KeyTestUtils.h"
#include "tests/TestHarness.h"

namespace catapult { namespace crypto {

#define TEST_CLASS SharedKeyTests

	// region HKDF Sha256
	// data taken from : RFC 5869

	namespace {

		// generic implementation to check test vectors
		void Hkdf_Hmac_Sha256(
				const  std::vector<uint8_t>& sharedSecret,
				const std::vector<uint8_t>& salt,
				std::vector<uint8_t>& output,
				const std::vector<uint8_t>& label) {

			Hash256 prk;
			Hmac_Sha256(salt, sharedSecret, prk);

			// T(i - 1) || label || counter
			std::vector<uint8_t> buffer;
			buffer.resize(Hash256::Size +  label.size() + sizeof(uint8_t));

			size_t repetitions = (output.size() + Hash256::Size - 1) / Hash256::Size;
			size_t position = 0;

			// inline first iteration
			uint32_t counter = 1;
			std::memcpy(buffer.data(), label.data(), label.size());
			std::memcpy(buffer.data() + label.size(), &counter, sizeof(uint8_t));

			Hash256 previousOkm;
			Hmac_Sha256(prk, { buffer.data(), label.size() + sizeof(uint8_t) }, previousOkm);

			auto written = std::min(output.size() - position, Hash256::Size);
			std::memcpy(&output[position], previousOkm.data(), written);
			position += written;
			++counter;

			for (; counter <= repetitions; ++counter) {
				std::memcpy(buffer.data(), previousOkm.data(), Hash256::Size);
				std::memcpy(buffer.data() + Hash256::Size, label.data(), label.size());
				std::memcpy(buffer.data() + Hash256::Size + label.size(), &counter, sizeof(uint8_t));

				Hmac_Sha256(prk, buffer, previousOkm);

				written = std::min(output.size() - position, Hash256::Size);
				std::memcpy(&output[position], previousOkm.data(), written);
				position += written;
			}
		}
	}

	TEST(TEST_CLASS, Hkdf_Hmac_Sha256_Test_Vector_1) {
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

	TEST(TEST_CLASS, Hkdf_Hmac_Sha256_Test_Vector_2) {
		// Arrange:
		auto salt = test::HexStringToVector(
				"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
				"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
				"A0A1A2A3A4A5A6A7A8A9AAABACADAEAF");
		auto sharedSecret = test::HexStringToVector(
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
				"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F");
		auto label = test::HexStringToVector(
				"B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
				"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
				"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
		auto expected = std::string(
				"B11E398DC80327A1C8E7F78C596A49344F012EDA2D4EFAD8A050CC4C19AFA97C"
				"59045A99CAC7827271CB41C65E590E09DA3275600C2F09B8367793A9ACA3DB71"
				"CC30C58179EC3E87C14C01D5C1F3434F1D87");

		// Act:
		std::vector<uint8_t> output(expected.size() / 2);
		Hkdf_Hmac_Sha256(sharedSecret, salt, output, label);

		// Assert:
		EXPECT_EQ(expected, test::ToHexString(output));
	}

	TEST(TEST_CLASS, Hkdf_Hmac_Sha256_Test_Vector_3) {
		// Arrange:
		auto salt = test::HexStringToVector("");
		auto sharedSecret = test::HexStringToVector("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
		auto label = test::HexStringToVector("");
		auto expected = std::string("8DA4E775A563C18F715F802A063C5A31B8A11F5C5EE1879EC3454E5F3C738D2D9D201395FAA4B61A96C8");

		// Act:
		std::vector<uint8_t> output(expected.size() / 2);
		Hkdf_Hmac_Sha256(sharedSecret, salt, output, label);

		// Assert:
		EXPECT_EQ(expected, test::ToHexString(output));
	}

	TEST(TEST_CLASS, Hkdf_Hmac_Sha256_32_Tests) {
		// Arrange:
		std::vector<uint8_t> salt(32);
		auto label = test::HexStringToVector("6361746170756c74");

		for (auto i = 0; i < 10; ++i) {
			// - calculate expected output using generic implementation
			auto sharedSecret = test::GenerateRandomByteArray<SharedSecret>();
			std::vector<uint8_t> secretVec(sharedSecret.cbegin(), sharedSecret.cend());
			std::vector<uint8_t> expectedOutput(32);
			Hkdf_Hmac_Sha256(secretVec, salt, expectedOutput, label);

			// Act:
			SharedKey sharedKey;
			Hkdf_Hmac_Sha256_32(sharedSecret, sharedKey);

			// Assert:
			std::vector<uint8_t> sharedKeyVec(sharedKey.cbegin(), sharedKey.cend());
			EXPECT_EQ(expectedOutput, sharedKeyVec);
		}
	}

	// endregion

	// region Kdf Hmac_Sha256

	namespace {

#ifdef _MSC_VER
#define BSWAP(VAL) _byteswap_ulong(VAL)
#else
#define BSWAP(VAL) __builtin_bswap32(VAL)
#endif

		void KdfSp800_56C_Hmac_Sha256(
				const  std::vector<uint8_t>& sharedSecret,
				const std::vector<uint8_t>& salt,
				std::vector<uint8_t>& output,
				const std::vector<uint8_t>& label) {
			std::vector<uint8_t> buffer;
			buffer.resize(sizeof(uint32_t) + sharedSecret.size() + label.size());

			size_t repetitions = (output.size() + Hash256::Size - 1) / Hash256::Size;

			size_t position = 0;
			for (uint32_t counter = 1; counter <= repetitions; ++counter) {
				uint32_t temp = BSWAP(counter);
				std::memcpy(buffer.data(), &temp, sizeof(temp));
				std::memcpy(&buffer[sizeof(uint32_t)], sharedSecret.data(), sharedSecret.size());
				std::memcpy(&buffer[sizeof(uint32_t) + sharedSecret.size()], label.data(), label.size());

				Hash256 hash;
				Hmac_Sha256(salt, buffer, hash);

				auto written = std::min(output.size() - position, Hash256::Size);
				std::memcpy(&output[position], hash.data(), written);

				position += written;
			}
		}
	}

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
