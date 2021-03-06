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

#pragma once
#include "catapult/types.h"
#include <set>
#include <vector>

namespace catapult { namespace crypto { class KeyPair; } }

namespace catapult { namespace test {

	/// Unlocked test entry payload size.
	constexpr auto Unlocked_Test_Entry_Payload_Size = 32u + 16 + 32 + 16;

#pragma pack(push, 1)
	/// Unlocked test entry.
	struct UnlockedTestEntry {
		/// Announcer public key.
		catapult::Key Key;

		/// Encrypted unlocked entry.
		std::array<uint8_t, Unlocked_Test_Entry_Payload_Size> Payload;

		/// Returns \c true if this unlocked test entry is equal to \a rhs.
		bool operator==(const UnlockedTestEntry& rhs) const {
			return Key == rhs.Key && Payload == rhs.Payload;
		}
	};
#pragma pack(pop)

	/// Insertion operator for outputting \a entry to \a out.
	std::ostream& operator<<(std::ostream& out, const UnlockedTestEntry& entry);

	/// Unlocked entry encryption flag.
	enum class EncryptionMutationFlag {
		/// No mutation.
		None,

		/// Mutate aes-cbc encryption padding.
		Mutate_Padding
	};

	/// Creates encrypted unlocked entry around \a entryBuffer using \a keyPair with \a encryptionMutationFlag.
	UnlockedTestEntry PrepareUnlockedTestEntry(
			const crypto::KeyPair& keyPair,
			const RawBuffer& entryBuffer,
			EncryptionMutationFlag encryptionMutationFlag = EncryptionMutationFlag::None);

	/// Creates encrypted unlocked entry around \a entryBuffer using \a keyPair and \a announcerPublicKey with \a encryptionMutationFlag.
	UnlockedTestEntry PrepareUnlockedTestEntry(
			const Key& announcerPublicKey,
			const crypto::KeyPair& keyPair,
			const RawBuffer& entryBuffer,
			EncryptionMutationFlag encryptionMutationFlag = EncryptionMutationFlag::None);

	/// Converts unlocked \a entry to buffer.
	std::vector<uint8_t> ConvertUnlockedTestEntryToBuffer(const UnlockedTestEntry& entry);

	/// Unlocked test entry order comparator.
	struct UnlockedTestEntryComparator {
		bool operator()(const UnlockedTestEntry& lhs, const UnlockedTestEntry& rhs) const {
			return lhs.Key < rhs.Key;
		}
	};

	/// Test entries.
	using UnlockedTestEntries = std::set<UnlockedTestEntry, UnlockedTestEntryComparator>;

	/// Asserts that contents of file (\a filename) matches \a expectedEntries.
	void AssertUnlockedEntriesFileContents(const std::string& filename, const UnlockedTestEntries& expectedEntries);
}}
