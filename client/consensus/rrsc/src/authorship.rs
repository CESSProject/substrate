// This file is part of Substrate.

// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! RRSC authority selection and slot claiming.

use super::Epoch;
use cessp_consensus_rrsc::{
	digests::{PreDigest, PrimaryPreDigest, SecondaryPlainPreDigest, SecondaryVRFPreDigest},
	make_transcript_data, AuthorityId, RRSCAuthorityWeight, Slot,
};
use codec::Encode;
use sp_application_crypto::AppKey;
use sp_consensus_vrf::schnorrkel::{VRFOutput, VRFProof};
use sp_core::{blake2_256, crypto::ByteArray, U256};
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};

/// Get the expected secondary author for the given slot and with given
/// authorities. This should always assign the slot to some authority unless the
/// authorities list is empty.
pub(super) fn secondary_slot_author(
	slot: Slot,
	authorities: &[(AuthorityId, RRSCAuthorityWeight)],
	randomness: [u8; 32],
) -> Option<&AuthorityId> {
	if authorities.is_empty() {
		return None;
	}

	let rand = U256::from((randomness, slot).using_encoded(blake2_256));

	let authorities_len = U256::from(authorities.len());
	let idx = rand % authorities_len;

	let expected_author = authorities.get(idx.as_u32() as usize).expect(
		"authorities not empty; index constrained to list length; \
				this is a valid index; qed",
	);

	Some(&expected_author.0)
}

/// Claim a secondary slot if it is our turn to propose, returning the
/// pre-digest to use when authoring the block, or `None` if it is not our turn
/// to propose.
fn claim_secondary_slot(
	slot: Slot,
	epoch: &Epoch,
	keys: &[(AuthorityId, usize)],
	keystore: &SyncCryptoStorePtr,
	author_secondary_vrf: bool,
) -> Option<(PreDigest, AuthorityId)> {
	let Epoch { secondary_authorities, randomness, epoch_index, .. } = epoch;

	if secondary_authorities.is_empty() {
		return None;
	}

	let expected_author = secondary_slot_author(slot, secondary_authorities, *randomness)?;

	for (authority_id, authority_index) in keys {
		if authority_id == expected_author {
			let pre_digest = if author_secondary_vrf {
				let transcript_data = make_transcript_data(randomness, slot, *epoch_index);
				let result = SyncCryptoStore::sr25519_vrf_sign(
					&**keystore,
					AuthorityId::ID,
					authority_id.as_ref(),
					transcript_data,
				);
				if let Ok(Some(signature)) = result {
					Some(PreDigest::SecondaryVRF(SecondaryVRFPreDigest {
						slot,
						vrf_output: VRFOutput(signature.output),
						vrf_proof: VRFProof(signature.proof),
						authority_index: *authority_index as u32,
					}))
				} else {
					None
				}
			} else if SyncCryptoStore::has_keys(
				&**keystore,
				&[(authority_id.to_raw_vec(), AuthorityId::ID)],
			) {
				Some(PreDigest::SecondaryPlain(SecondaryPlainPreDigest {
					slot,
					authority_index: *authority_index as u32,
				}))
			} else {
				None
			};

			if let Some(pre_digest) = pre_digest {
				return Some((pre_digest, authority_id.clone()));
			}
		}
	}

	None
}

/// Tries to claim the given slot number. This method starts by trying to claim
/// a primary VRF based slot. If we are not able to claim it, then if we have
/// secondary slots enabled for the given epoch, we will fallback to trying to
/// claim a secondary slot.
pub fn claim_slot(
	slot: Slot,
	epoch: &Epoch,
	keystore: &SyncCryptoStorePtr,
) -> Option<(PreDigest, AuthorityId)> {
	claim_slot_using_keys(slot, epoch, keystore)
}

/// Like `claim_slot`, but allows passing an explicit set of key pairs. Useful if we intend
/// to make repeated calls for different slots using the same key pairs.
pub fn claim_slot_using_keys(
	slot: Slot,
	epoch: &Epoch,
	keystore: &SyncCryptoStorePtr,
) -> Option<(PreDigest, AuthorityId)> {
	let primary_authorities_keys = epoch
		.primary_authorities
		.iter()
		.enumerate()
		.map(|(index, a)| (a.0.clone(), index))
		.collect::<Vec<_>>();
	primary_slot_author(slot, epoch, keystore, &primary_authorities_keys).or_else(|| {
		if epoch.config.allowed_slots.is_secondary_plain_slots_allowed()
			|| epoch.config.allowed_slots.is_secondary_vrf_slots_allowed()
		{
			let secondary_authorities_keys = epoch
				.secondary_authorities
				.iter()
				.enumerate()
				.map(|(index, a)| (a.0.clone(), index))
				.collect::<Vec<_>>();
			claim_secondary_slot(
				slot,
				&epoch,
				&secondary_authorities_keys,
				&keystore,
				epoch.config.allowed_slots.is_secondary_vrf_slots_allowed(),
			)
		} else {
			None
		}
	})
}

/// Claim a primary slot if it is our turn.  Returns `None` if it is not our turn.
/// This hashes the slot number, epoch, genesis hash, and chain randomness into
/// the VRF.  If the VRF produces a value less than `threshold`, it is our turn,
/// so it returns `Some(_)`. Otherwise, it returns `None`.
fn primary_slot_author(
	slot: Slot,
	epoch: &Epoch,
	keystore: &SyncCryptoStorePtr,
	keys: &[(AuthorityId, usize)],
) -> Option<(PreDigest, AuthorityId)> {
	let Epoch {
		primary_authorities,
		randomness,
		epoch_index,
		..
	} = epoch;

	if primary_authorities.is_empty() {
		return None;
	}

	let slot_autority_index = *slot as usize % keys.len();
	let (authority_id, authority_index) = &keys[slot_autority_index];

	let transcript_data = make_transcript_data(randomness, slot, *epoch_index);

	let result = SyncCryptoStore::sr25519_vrf_sign(
		&**keystore,
		AuthorityId::ID,
		authority_id.as_ref(),
		transcript_data,
	);
	if let Ok(Some(signature)) = result {
		let pre_digest = PreDigest::Primary(PrimaryPreDigest {
			slot,
			vrf_output: VRFOutput(signature.output),
			vrf_proof: VRFProof(signature.proof),
			authority_index: *authority_index as u32,
		});
		return Some((pre_digest, authority_id.clone()));
	};
	None
}

#[cfg(test)]
mod tests {
	use super::*;
	use cessp_consensus_rrsc::{AllowedSlots, AuthorityId, RRSCEpochConfiguration};
	use sc_keystore::LocalKeystore;
	use sp_core::{crypto::Pair as _, sr25519::Pair};
	use std::sync::Arc;

	#[test]
	fn claim_secondary_plain_slot_works() {
		let keystore: SyncCryptoStorePtr = Arc::new(LocalKeystore::in_memory());
		let valid_public_key = SyncCryptoStore::sr25519_generate_new(
			&*keystore,
			AuthorityId::ID,
			Some(sp_core::crypto::DEV_PHRASE),
		)
		.unwrap();

		let authorities = vec![
			(AuthorityId::from(Pair::generate().0.public()), 5),
			(AuthorityId::from(Pair::generate().0.public()), 7),
		];

		let primary_authorities = vec![
			(AuthorityId::from(Pair::generate().0.public()), 5),
			(AuthorityId::from(Pair::generate().0.public()), 7),
		];

		let secondary_authorities = vec![
			(AuthorityId::from(Pair::generate().0.public()), 5),
			(AuthorityId::from(Pair::generate().0.public()), 7),
		];

		let mut epoch = Epoch {
			epoch_index: 10,
			start_slot: 0.into(),
			duration: 20,
			authorities: authorities.clone(),
			primary_authorities: primary_authorities.clone(),
			secondary_authorities: secondary_authorities.clone(),
			randomness: Default::default(),
			config: RRSCEpochConfiguration {
				c: (3, 10),
				allowed_slots: AllowedSlots::PrimaryAndSecondaryPlainSlots,
			},
		};

		assert!(claim_slot(10.into(), &epoch, &keystore).is_none());

		epoch.authorities.push((valid_public_key.clone().into(), 10));
		epoch.primary_authorities.push((valid_public_key.clone().into(), 10));
		epoch.secondary_authorities.push((valid_public_key.clone().into(), 10));
		assert_eq!(claim_slot(10.into(), &epoch, &keystore).unwrap().1, valid_public_key.into());
	}
}
