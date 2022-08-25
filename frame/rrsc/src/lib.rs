// This file is part of Substrate.

// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Consensus extension module for RRSC consensus. Collects on-chain randomness
//! from VRF outputs and manages epoch transitions.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused_must_use, unsafe_code, unused_variables, unused_must_use)]

use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
	dispatch::DispatchResultWithPostInfo,
	traits::{
		ConstU32, DisabledValidators, EstimateNextSessionRotation, FindAuthor, FindKeyOwner, Get, KeyOwnerProofSystem, OnTimestampSet,
		OneSessionHandler, ValidatorSet, ValidatorSetWithIdentification, WrapperOpaque,  Randomness as RandomnessT,
	},
	weights::{Pays, Weight},
	BoundedVec, WeakBoundedVec,
};
use frame_system::offchain::{SendTransactionTypes, SubmitTransaction};
use sp_application_crypto::{ByteArray, RuntimeAppPublic};
use sp_runtime::{
	generic::DigestItem,
	offchain::storage::{MutateStorageError, StorageRetrievalError, StorageValueRef},
	traits::{AtLeast32BitUnsigned, IsMember, One, SaturatedConversion, Saturating, Zero},
	transaction_validity:: {
		InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
		TransactionValidityError, ValidTransaction, 
	},
	ConsensusEngineId, KeyTypeId, Permill, RuntimeDebug
};
use sp_session::{GetSessionNumber, GetValidatorCount};
use sp_staking::{
	offence::{Kind, Offence, ReportOffence},
	SessionIndex,
};
use scale_info::TypeInfo;
use sp_std::prelude::*;

use cessp_consensus_rrsc::{
	digests::{NextConfigDescriptor, NextEpochDescriptor, PreDigest},
	ConsensusLog, Epoch, EquivocationProof, RRSCAuthorityWeight, RRSCEpochConfiguration, Slot,
	RRSC_ENGINE_ID,
};
// use schnorrkel::{keys::PublicKey, vrf::VRFInOut};
use sp_consensus_vrf::schnorrkel as sp_schnorrkel;

// use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
pub use cessp_consensus_rrsc::{
	AuthorityId, PUBLIC_KEY_LENGTH, RANDOMNESS_LENGTH, VRF_OUTPUT_LENGTH,
};

mod default_weights;
mod equivocation;
mod randomness;
mod vrf_solver;

#[cfg(any(feature = "runtime-benchmarks", test))]
mod benchmarking;
#[cfg(all(feature = "std", test))]
mod mock;
#[cfg(all(feature = "std", test))]
mod tests;

pub use equivocation::{EquivocationHandler, HandleEquivocation, RRSCEquivocationOffence};
pub use randomness::{
	CurrentBlockRandomness, RandomnessFromOneEpochAgo, RandomnessFromTwoEpochsAgo,
};
pub use vrf_solver::VrfSolver;

pub use pallet::*;

pub trait WeightInfo {
	fn plan_config_change() -> Weight;
	fn report_equivocation(validator_count: u32) -> Weight;
}

/// Trigger an epoch change, if any should take place.
pub trait EpochChangeTrigger {
	/// Trigger an epoch change, if any should take place. This should be called
	/// during every block, after initialization is done.
	fn trigger<T: Config>(now: T::BlockNumber);
}

/// A type signifying to RRSC that an external trigger
/// for epoch changes (e.g. pallet-session) is used.
pub struct ExternalTrigger;

impl EpochChangeTrigger for ExternalTrigger {
	fn trigger<T: Config>(_: T::BlockNumber) {} // nothing - trigger is external.
}

/// A type signifying to RRSC that it should perform epoch changes
/// with an internal trigger, recycling the same authorities forever.
pub struct SameAuthoritiesForever;

impl EpochChangeTrigger for SameAuthoritiesForever {
	fn trigger<T: Config>(now: T::BlockNumber) {
		if <Pallet<T>>::should_epoch_change(now) {
			let authorities = <Pallet<T>>::authorities();
			let next_authorities = authorities.clone();

			<Pallet<T>>::enact_epoch_change(authorities, next_authorities);
		}
	}
}

const UNDER_CONSTRUCTION_SEGMENT_LENGTH: u32 = 256;

type MaybeRandomness = Option<sp_schnorrkel::Randomness>;

const DB_PREFIX: &[u8] = b"cess/rrsc/";

/// How many blocks do we wait for heartbeat transaction to be included
/// before sending another one.
const INCLUDE_THRESHOLD: u32 = 3;

/// Status of the offchain worker code.
///
/// This stores the block number at which heartbeat was requested and when the worker
/// has actually managed to produce it.
/// Note we store such status for every `authority_index` separately.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
struct VrfInOutStatus<BlockNumber> {
	/// An index of the session that we are supposed to send heartbeat for.
	pub session_index: SessionIndex,
	/// A block number at which the heartbeat for that session has been actually sent.
	///
	/// It may be 0 in case the sending failed. In such case we should just retry
	/// as soon as possible (i.e. in a worker running for the next block).
	pub sent_at: BlockNumber,
}

impl<BlockNumber: PartialEq + AtLeast32BitUnsigned + Copy> VrfInOutStatus<BlockNumber> {
	/// Returns true if heartbeat has been recently sent.
	///
	/// Parameters:
	/// `session_index` - index of current session.
	/// `now` - block at which the offchain worker is running.
	///
	/// This function will return `true` iff:
	/// 1. the session index is the same (we don't care if it went up or down)
	/// 2. the heartbeat has been sent recently (within the threshold)
	///
	/// The reasoning for 1. is that it's better to send an extra heartbeat than
	/// to stall or not send one in case of a bug.
	fn is_recent(&self, session_index: SessionIndex, now: BlockNumber) -> bool {
		self.session_index == session_index && self.sent_at + INCLUDE_THRESHOLD.into() > now
	}
}

/// Error which may occur while executing the off-chain code.
#[cfg_attr(test, derive(PartialEq))]
enum OffchainErr<BlockNumber> {
	TooEarly,
	WaitingForInclusion(BlockNumber),
	AlreadyOnline(u32),
	FailedSigning,
	FailedToAcquireLock,
	NetworkState,
	SubmitTransaction,
}

impl<BlockNumber: sp_std::fmt::Debug> sp_std::fmt::Debug for OffchainErr<BlockNumber> {
	fn fmt(&self, fmt: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		match *self {
			OffchainErr::TooEarly => write!(fmt, "Too early to send vrf inout."),
			OffchainErr::WaitingForInclusion(ref block) => {
				write!(fmt, "Vrf inout already sent at {:?}. Waiting for inclusion.", block)
			},
			OffchainErr::AlreadyOnline(auth_idx) => {
				write!(fmt, "Authority {} is already online", auth_idx)
			},
			OffchainErr::FailedSigning => write!(fmt, "Failed to sign vrf inout"),
			OffchainErr::FailedToAcquireLock => write!(fmt, "Failed to acquire lock"),
			OffchainErr::NetworkState => write!(fmt, "Failed to fetch network state"),
			OffchainErr::SubmitTransaction => write!(fmt, "Failed to submit transaction"),
		}
	}
}

type OffchainResult<T, A> = Result<A, OffchainErr<<T as frame_system::Config>::BlockNumber>>;

pub type AuthIndex = u32;

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct VrfInOut<BlockNumber> 
where
	BlockNumber: PartialEq + Eq + Decode + Encode,
{
	/// Block number at the time heartbeat is created..
	pub block_number: BlockNumber,
	/// Index of the current session.
	pub session_index: SessionIndex,
	/// An index of the authority on the list of validators.
	pub authority_index: AuthIndex,
	/// The length of session validator set
	pub validators_len: u32,
	/// The session key
	pub key: AuthorityId,
	/// The vrf inout
	pub vrf_inout: ([u8; 32], [u8; 64]),
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	/// The RRSC Pallet
	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::config]
	#[pallet::disable_frame_system_supertrait_check]
	pub trait Config: SendTransactionTypes<Call<Self>> + pallet_timestamp::Config + frame_system::Config {
		/// The amount of time, in slots, that each epoch should last.
		/// NOTE: Currently it is not possible to change the epoch duration after
		/// the chain has started. Attempting to do so will brick block production.
		#[pallet::constant]
		type EpochDuration: Get<u64>;

		/// The expected average block time at which RRSC should be creating
		/// blocks. Since RRSC is probabilistic it is not trivial to figure out
		/// what the expected average block time should be based on the slot
		/// duration and the security parameter `c` (where `1 - c` represents
		/// the probability of a slot being empty).
		#[pallet::constant]
		type ExpectedBlockTime: Get<Self::Moment>;

		/// RRSC requires some logic to be triggered on every block to query for whether an epoch
		/// has ended and to perform the transition to the next epoch.
		///
		/// Typically, the `ExternalTrigger` type should be used. An internal trigger should only be
		/// used when no other module is responsible for changing authority set.
		type EpochChangeTrigger: EpochChangeTrigger;

		/// A way to check whether a given validator is disabled and should not be authoring blocks.
		/// Blocks authored by a disabled validator will lead to a panic as part of this module's
		/// initialization.
		type DisabledValidators: DisabledValidators;

		/// The proof of key ownership, used for validating equivocation reports.
		/// The proof must include the session index and validator count of the
		/// session at which the equivocation occurred.
		type KeyOwnerProof: Parameter + GetSessionNumber + GetValidatorCount;

		/// The identification of a key owner, used when reporting equivocations.
		type KeyOwnerIdentification: Parameter;

		/// A system for proving ownership of keys, i.e. that a given key was part
		/// of a validator set, needed for validating equivocation reports.
		type KeyOwnerProofSystem: KeyOwnerProofSystem<
			(KeyTypeId, AuthorityId),
			Proof = Self::KeyOwnerProof,
			IdentificationTuple = Self::KeyOwnerIdentification,
		>;

		/// The equivocation handling subsystem, defines methods to report an
		/// offence (after the equivocation has been validated) and for submitting a
		/// transaction to report an equivocation (from an offchain context).
		/// NOTE: when enabling equivocation handling (i.e. this type isn't set to
		/// `()`) you must use this pallet's `ValidateUnsigned` in the runtime
		/// definition.
		type HandleEquivocation: HandleEquivocation<Self>;

		type WeightInfo: WeightInfo;

		/// Max number of authorities allowed
		#[pallet::constant]
		type MaxAuthorities: Get<u32>;

		/// The maximum number of keys that can be added.
		type MaxKeys: Get<u32>;

		/// The overarching event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		/// A type for retrieving the validators supposed to be online in a session.
		type ValidatorSet: ValidatorSetWithIdentification<Self::AccountId>;

		/// A type for retrieving the validatorId by key.
		type FindKeyOwner: FindKeyOwner<Self::AccountId>;

		/// A trait that allows us to estimate the current session progress and also the
		/// average session length.
		///
		/// This parameter is used to determine the longevity of `vrf-inout` transaction and a
		/// rough time when we should start considering sending vrf-inout, since the workers
		/// avoids sending them at the very beginning of the session, assuming there is a
		/// chance the authority will produce a block and they won't be necessary.
		type NextSessionRotation: EstimateNextSessionRotation<Self::BlockNumber>;


		/// A configuration for base priority of unsigned transactions.
		///
		/// This is exposed so that it can be tuned for particular runtime, when
		/// multiple pallets send unsigned transactions.
		#[pallet::constant]
		type UnsignedPriority: Get<TransactionPriority>;

	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A new vrf inout was received from `AuthorityId`.
		VrfInOutReceived { authority_id: cessp_consensus_rrsc::AuthorityId },
		/// At the end of the session, no offence was committed.
		AllGood,
	}

	#[pallet::error]
	pub enum Error<T> {
		/// An equivocation proof provided as part of an equivocation report is invalid.
		InvalidEquivocationProof,
		/// A key ownership proof provided as part of an equivocation report is invalid.
		InvalidKeyOwnershipProof,
		/// A given equivocation report is valid but already previously reported.
		DuplicateOffenceReport,
		/// Non existent public key.
		InvalidKey,
		/// Duplicated heartbeat.
		DuplicatedVrfInOut,
	}

	/// Current epoch index.
	#[pallet::storage]
	#[pallet::getter(fn epoch_index)]
	pub type EpochIndex<T> = StorageValue<_, u64, ValueQuery>;

	/// Current epoch authorities.
	#[pallet::storage]
	#[pallet::getter(fn authorities)]
	pub type Authorities<T: Config> = StorageValue<
		_,
		WeakBoundedVec<(AuthorityId, RRSCAuthorityWeight), T::MaxAuthorities>,
		ValueQuery,
	>;

	/// The slot at which the first epoch actually started. This is 0
	/// until the first block of the chain.
	#[pallet::storage]
	#[pallet::getter(fn genesis_slot)]
	pub type GenesisSlot<T> = StorageValue<_, Slot, ValueQuery>;

	/// Current slot number.
	#[pallet::storage]
	#[pallet::getter(fn current_slot)]
	pub type CurrentSlot<T> = StorageValue<_, Slot, ValueQuery>;

	/// The epoch randomness for the *current* epoch.
	///
	/// # Security
	///
	/// This MUST NOT be used for gambling, as it can be influenced by a
	/// malicious validator in the short term. It MAY be used in many
	/// cryptographic protocols, however, so long as one remembers that this
	/// (like everything else on-chain) it is public. For example, it can be
	/// used where a number is needed that cannot have been chosen by an
	/// adversary, for purposes such as public-coin zero-knowledge proofs.
	// NOTE: the following fields don't use the constants to define the
	// array size because the metadata API currently doesn't resolve the
	// variable to its underlying value.
	#[pallet::storage]
	#[pallet::getter(fn randomness)]
	pub type Randomness<T> = StorageValue<_, sp_schnorrkel::Randomness, ValueQuery>;

	/// Pending epoch configuration change that will be applied when the next epoch is enacted.
	#[pallet::storage]
	pub(super) type PendingEpochConfigChange<T> = StorageValue<_, NextConfigDescriptor>;

	/// Next epoch randomness.
	#[pallet::storage]
	pub(super) type NextRandomness<T> = StorageValue<_, sp_schnorrkel::Randomness, ValueQuery>;

	/// Next epoch authorities.
	#[pallet::storage]
	pub(super) type NextAuthorities<T: Config> = StorageValue<
		_,
		WeakBoundedVec<(AuthorityId, RRSCAuthorityWeight), T::MaxAuthorities>,
		ValueQuery,
	>;

	/// Randomness under construction.
	///
	/// We make a tradeoff between storage accesses and list length.
	/// We store the under-construction randomness in segments of up to
	/// `UNDER_CONSTRUCTION_SEGMENT_LENGTH`.
	///
	/// Once a segment reaches this length, we begin the next one.
	/// We reset all segments and return to `0` at the beginning of every
	/// epoch.
	#[pallet::storage]
	pub(super) type SegmentIndex<T> = StorageValue<_, u32, ValueQuery>;

	/// TWOX-NOTE: `SegmentIndex` is an increasing integer, so this is okay.
	#[pallet::storage]
	pub(super) type UnderConstruction<T: Config> = StorageMap<
		_,
		Twox64Concat,
		u32,
		BoundedVec<sp_schnorrkel::Randomness, ConstU32<UNDER_CONSTRUCTION_SEGMENT_LENGTH>>,
		ValueQuery,
	>;

	/// Temporary value (cleared at block finalization) which is `Some`
	/// if per-block initialization has already been called for current block.
	#[pallet::storage]
	#[pallet::getter(fn initialized)]
	pub(super) type Initialized<T> = StorageValue<_, MaybeRandomness>;

	/// This field should always be populated during block processing unless
	/// secondary plain slots are enabled (which don't contain a VRF output).
	///
	/// It is set in `on_initialize`, before it will contain the value from the last block.
	#[pallet::storage]
	#[pallet::getter(fn author_vrf_randomness)]
	pub(super) type AuthorVrfRandomness<T> = StorageValue<_, MaybeRandomness, ValueQuery>;

	/// The block numbers when the last and current epoch have started, respectively `N-1` and
	/// `N`.
	/// NOTE: We track this is in order to annotate the block number when a given pool of
	/// entropy was fixed (i.e. it was known to chain observers). Since epochs are defined in
	/// slots, which may be skipped, the block numbers may not line up with the slot numbers.
	#[pallet::storage]
	pub(super) type EpochStart<T: Config> =
		StorageValue<_, (T::BlockNumber, T::BlockNumber), ValueQuery>;

	/// How late the current block is compared to its parent.
	///
	/// This entry is populated as part of block execution and is cleaned up
	/// on block finalization. Querying this storage entry outside of block
	/// execution context should always yield zero.
	#[pallet::storage]
	#[pallet::getter(fn lateness)]
	pub(super) type Lateness<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

	/// The configuration for the current epoch. Should never be `None` as it is initialized in
	/// genesis.
	#[pallet::storage]
	pub(super) type EpochConfig<T> = StorageValue<_, RRSCEpochConfiguration>;

	/// The configuration for the next epoch, `None` if the config will not change
	/// (you can fallback to `EpochConfig` instead in that case).
	#[pallet::storage]
	pub(super) type NextEpochConfig<T> = StorageValue<_, RRSCEpochConfiguration>;

	/// The current set of keys that may issue a heartbeat.
	#[pallet::storage]
	#[pallet::getter(fn keys)]
	pub(crate) type Keys<T: Config> =
		StorageValue<_, WeakBoundedVec<AuthorityId, T::MaxKeys>, ValueQuery>;

	/// For each session index, we keep a mapping of `SessionIndex` and `AuthIndex` to
	/// `WrapperOpaque<BoundedOpaqueNetworkState>`.
	#[pallet::storage]
	#[pallet::getter(fn received_vrf_inout)]
	pub(crate) type ReceivedVrfInOut<T: Config> = StorageDoubleMap<
		_,
		Twox64Concat,
		SessionIndex,
		Twox64Concat,
		T::AccountId,
		WrapperOpaque<
			VrfInOut<T::BlockNumber>,
		>,
	>;
		
	/// A type for representing the validator id in a session.
	pub type ValidatorId<T> = <<T as Config>::ValidatorSet as ValidatorSet<
		<T as frame_system::Config>::AccountId,
	>>::ValidatorId;

	/// A tuple of (ValidatorId, Identification) where `Identification` is the full identification of
	/// `ValidatorId`.
	pub type IdentificationTuple<T> = (
		ValidatorId<T>,
		<<T as Config>::ValidatorSet as ValidatorSetWithIdentification<
			<T as frame_system::Config>::AccountId,
		>>::Identification,
	);

	#[cfg_attr(feature = "std", derive(Default))]
	#[pallet::genesis_config]
	pub struct GenesisConfig {
		pub authorities: Vec<(AuthorityId, RRSCAuthorityWeight)>,
		pub epoch_config: Option<RRSCEpochConfiguration>,
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig {
		fn build(&self) {
			SegmentIndex::<T>::put(0);
			Pallet::<T>::initialize_authorities(&self.authorities);
			EpochConfig::<T>::put(
				self.epoch_config.clone().expect("epoch_config must not be None"),
			);
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		/// Initialization
		fn on_initialize(now: BlockNumberFor<T>) -> Weight {
			Self::do_initialize(now);
			0
		}

		/// Block finalization
		fn on_finalize(_n: BlockNumberFor<T>) {
			// at the end of the block, we can safely include the new VRF output
			// from this block into the under-construction randomness. If we've determined
			// that this block was the first in a new epoch, the changeover logic has
			// already occurred at this point, so the under-construction randomness
			// will only contain outputs from the right epoch.
			if let Some(Some(randomness)) = Initialized::<T>::take() {
				Self::deposit_randomness(&randomness);
			}

			// remove temporary "environment" entry from storage
			Lateness::<T>::kill();
		}

		fn offchain_worker(block_number: BlockNumberFor<T>) {
			let session_index = T::ValidatorSet::session_index();
			let validators_len = Keys::<T>::decode_len().unwrap_or_default() as u32;
			let _result: OffchainResult<T, ()> = Self::local_authority_keys().map(move |(account, key)| {
				Self::send_vrf_inout(
					account,
					key,
					session_index,
					block_number,
					validators_len,
				)
			}).collect::<_>();
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Report authority equivocation/misbehavior. This method will verify
		/// the equivocation proof and validate the given key ownership proof
		/// against the extracted offender. If both are valid, the offence will
		/// be reported.
		#[pallet::weight(<T as Config>::WeightInfo::report_equivocation(
			key_owner_proof.validator_count(),
		))]
		pub fn report_equivocation(
			origin: OriginFor<T>,
			equivocation_proof: Box<EquivocationProof<T::Header>>,
			key_owner_proof: T::KeyOwnerProof,
		) -> DispatchResultWithPostInfo {
			let reporter = ensure_signed(origin)?;

			Self::do_report_equivocation(Some(reporter), *equivocation_proof, key_owner_proof)
		}

		/// Report authority equivocation/misbehavior. This method will verify
		/// the equivocation proof and validate the given key ownership proof
		/// against the extracted offender. If both are valid, the offence will
		/// be reported.
		/// This extrinsic must be called unsigned and it is expected that only
		/// block authors will call it (validated in `ValidateUnsigned`), as such
		/// if the block author is defined it will be defined as the equivocation
		/// reporter.
		#[pallet::weight(<T as Config>::WeightInfo::report_equivocation(
			key_owner_proof.validator_count(),
		))]
		pub fn report_equivocation_unsigned(
			origin: OriginFor<T>,
			equivocation_proof: Box<EquivocationProof<T::Header>>,
			key_owner_proof: T::KeyOwnerProof,
		) -> DispatchResultWithPostInfo {
			ensure_none(origin)?;

			Self::do_report_equivocation(
				T::HandleEquivocation::block_author(),
				*equivocation_proof,
				key_owner_proof,
			)
		}

		/// Plan an epoch config change. The epoch config change is recorded and will be enacted on
		/// the next call to `enact_epoch_change`. The config will be activated one epoch after.
		/// Multiple calls to this method will replace any existing planned config change that had
		/// not been enacted yet.
		#[pallet::weight(<T as Config>::WeightInfo::plan_config_change())]
		pub fn plan_config_change(
			origin: OriginFor<T>,
			config: NextConfigDescriptor,
		) -> DispatchResult {
			ensure_root(origin)?;
			PendingEpochConfigChange::<T>::put(config);
			Ok(())
		}

		#[pallet::weight(0)]
		pub fn submit_vrf_inout(
			origin: OriginFor<T>,
			vrf_inout: VrfInOut<T::BlockNumber>,
			_signature: <cessp_consensus_rrsc::AuthorityId as RuntimeAppPublic>::Signature,
		) -> DispatchResult {
			ensure_none(origin)?;
			let current_session = T::ValidatorSet::session_index();
			let account = T::FindKeyOwner::key_owner(AuthorityId::ID, vrf_inout.key.as_ref())
														.ok_or(Error::<T>::InvalidKey)?;
			let exists =
				ReceivedVrfInOut::<T>::contains_key(&current_session, &account);
			let keys = Keys::<T>::get();
			let public = keys.get(vrf_inout.authority_index as usize);
			if let (false, Some(public)) = (exists, public) {
				Self::deposit_event(Event::<T>::VrfInOutReceived { authority_id: public.clone() });

				ReceivedVrfInOut::<T>::insert(
					&current_session,
					&account,
					WrapperOpaque::from(vrf_inout.clone()),
				);

				Ok(())
			} else if exists {
				Err(Error::<T>::DuplicatedVrfInOut)?
			} else {
				Err(Error::<T>::InvalidKey)?
			}
		}
	}

	/// Invalid transaction custom error. Returned when validators_len field in heartbeat is
	/// incorrect.
	pub(crate) const INVALID_VALIDATORS_LEN: u8 = 10;

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;
		fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			if let Call::report_equivocation_unsigned { equivocation_proof, key_owner_proof } = call {
				// discard equivocation report not coming from the local node
				match source {
					TransactionSource::Local | TransactionSource::InBlock => { /* allowed */ },
					_ => {
						log::warn!(
							target: "runtime::rrsc",
							"rejecting unsigned report equivocation transaction because it is not local/in-block.",
						);
	
						return InvalidTransaction::Call.into()
					},
				}
				Self::validate_unsigned(equivocation_proof, key_owner_proof)
			} else if let Call::submit_vrf_inout{ vrf_inout, signature } = call {
				// check if session index from heartbeat is recent
				let current_session = T::ValidatorSet::session_index();
				if vrf_inout.session_index != current_session {
					return InvalidTransaction::Stale.into()
				}

				// verify that the incoming (unverified) pubkey is actually an authority id
				let keys = Keys::<T>::get();
				if keys.len() as u32 != vrf_inout.validators_len {
					return InvalidTransaction::Custom(INVALID_VALIDATORS_LEN).into()
				}
				let authority_id = match keys.get(vrf_inout.authority_index as usize) {
					Some(id) => id,
					None => return InvalidTransaction::BadProof.into(),
				};

				let (inout, _) = {
					let mut transcript = merlin::Transcript::new(b"RRSC");
					transcript.append_u64(b"current epoch", EpochIndex::<T>::get());
					transcript.append_message(b"chain randomness", &Self::randomness()[..]);
					schnorrkel::PublicKey::from_bytes(authority_id.as_slice())
						.and_then(|p| {
							let (output, proof) = vrf_inout.vrf_inout;
							p.vrf_verify(transcript, &schnorrkel::vrf::VRFOutput::from_bytes(&output)?, &schnorrkel::vrf::VRFProof::from_bytes(&proof)?)
						})
						.map_err(|s| InvalidTransaction::BadProof)?
				};
				let vrf_random = u128::from_le_bytes(inout.make_bytes::<[u8; 16]>(cessp_consensus_rrsc::RRSC_VRF_PREFIX));
				// TODO: store vrf_random onchain

				// check signature (this is expensive so we do it last).
				let signature_valid = vrf_inout.using_encoded(|encoded_vrf_inout| {
					authority_id.verify(&encoded_vrf_inout, &signature)
				});

				if !signature_valid {
					return InvalidTransaction::BadProof.into()
				}

				ValidTransaction::with_tag_prefix("ImOnline")
					.priority(T::UnsignedPriority::get())
					.and_provides((current_session, authority_id))
					.longevity(
						TryInto::<u64>::try_into(
							T::NextSessionRotation::average_session_length() / 2u32.into(),
						)
						.unwrap_or(64_u64),
					)
					.propagate(true)
					.build()
			} else {
				InvalidTransaction::Call.into()
			}
		}

		fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
			Self::pre_dispatch(call)
		}
	}
}

/// A RRSC public key
pub type RRSCKey = [u8; PUBLIC_KEY_LENGTH];

impl<T: Config> FindAuthor<u32> for Pallet<T> {
	fn find_author<'a, I>(digests: I) -> Option<u32>
	where
		I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
	{
		for (id, mut data) in digests.into_iter() {
			if id == RRSC_ENGINE_ID {
				let pre_digest: PreDigest = PreDigest::decode(&mut data).ok()?;
				return Some(pre_digest.authority_index());
			}
		}

		return None;
	}
}

impl<T: Config> IsMember<AuthorityId> for Pallet<T> {
	fn is_member(authority_id: &AuthorityId) -> bool {
		<Pallet<T>>::authorities().iter().any(|id| &id.0 == authority_id)
	}
}

impl<T: Config> pallet_session::ShouldEndSession<T::BlockNumber> for Pallet<T> {
	fn should_end_session(now: T::BlockNumber) -> bool {
		// it might be (and it is in current implementation) that session module is calling
		// should_end_session() from it's own on_initialize() handler
		// => because pallet_session on_initialize() is called earlier than ours, let's ensure
		// that we have synced with digest before checking if session should be ended.
		Self::do_initialize(now);

		Self::should_epoch_change(now)
	}
}

impl<T: Config> Pallet<T> {
	/// Determine the RRSC slot duration based on the Timestamp module configuration.
	pub fn slot_duration() -> T::Moment {
		// we double the minimum block-period so each author can always propose within
		// the majority of their slot.
		<T as pallet_timestamp::Config>::MinimumPeriod::get().saturating_mul(2u32.into())
	}

	/// Determine whether an epoch change should take place at this block.
	/// Assumes that initialization has already taken place.
	pub fn should_epoch_change(now: T::BlockNumber) -> bool {
		// The epoch has technically ended during the passage of time
		// between this block and the last, but we have to "end" the epoch now,
		// since there is no earlier possible block we could have done it.
		//
		// The exception is for block 1: the genesis has slot 0, so we treat
		// epoch 0 as having started at the slot of block 1. We want to use
		// the same randomness and validator set as signalled in the genesis,
		// so we don't rotate the epoch.
		now != One::one() && {
			let diff = CurrentSlot::<T>::get().saturating_sub(Self::current_epoch_start());
			*diff >= T::EpochDuration::get()
		}
	}

	/// Return the _best guess_ block number, at which the next epoch change is predicted to happen.
	///
	/// Returns None if the prediction is in the past; This implies an error internally in the RRSC
	/// and should not happen under normal circumstances.
	///
	/// In other word, this is only accurate if no slots are missed. Given missed slots, the slot
	/// number will grow while the block number will not. Hence, the result can be interpreted as an
	/// upper bound.
	// ## IMPORTANT NOTE
	//
	// This implementation is linked to how [`should_epoch_change`] is working. This might need to
	// be updated accordingly, if the underlying mechanics of slot and epochs change.
	//
	// WEIGHT NOTE: This function is tied to the weight of `EstimateNextSessionRotation`. If you
	// update this function, you must also update the corresponding weight.
	pub fn next_expected_epoch_change(now: T::BlockNumber) -> Option<T::BlockNumber> {
		let next_slot = Self::current_epoch_start().saturating_add(T::EpochDuration::get());
		next_slot.checked_sub(*CurrentSlot::<T>::get()).map(|slots_remaining| {
			// This is a best effort guess. Drifts in the slot/block ratio will cause errors here.
			let blocks_remaining: T::BlockNumber = slots_remaining.saturated_into();
			now.saturating_add(blocks_remaining)
		})
	}

	/// DANGEROUS: Enact an epoch change. Should be done on every block where `should_epoch_change`
	/// has returned `true`, and the caller is the only caller of this function.
	///
	/// Typically, this is not handled directly by the user, but by higher-level validator-set
	/// manager logic like `pallet-session`.
	pub fn enact_epoch_change(
		authorities: WeakBoundedVec<(AuthorityId, RRSCAuthorityWeight), T::MaxAuthorities>,
		next_authorities: WeakBoundedVec<(AuthorityId, RRSCAuthorityWeight), T::MaxAuthorities>,
	) {
		// PRECONDITION: caller has done initialization and is guaranteed
		// by the session module to be called before this.
		debug_assert!(Self::initialized().is_some());

		// Update epoch index
		let epoch_index = EpochIndex::<T>::get()
			.checked_add(1)
			.expect("epoch indices will never reach 2^64 before the death of the universe; qed");

		EpochIndex::<T>::put(epoch_index);
		Authorities::<T>::put(authorities.clone());

		// Update epoch randomness.
		let next_epoch_index = epoch_index
			.checked_add(1)
			.expect("epoch indices will never reach 2^64 before the death of the universe; qed");

		// Returns randomness for the current epoch and computes the *next*
		// epoch randomness.
		let randomness = Self::randomness_change_epoch(next_epoch_index);
		Randomness::<T>::put(randomness);

		// Update the next epoch authorities.
		NextAuthorities::<T>::put(&next_authorities);

		// Update the start blocks of the previous and new current epoch.
		<EpochStart<T>>::mutate(|(previous_epoch_start_block, current_epoch_start_block)| {
			*previous_epoch_start_block = sp_std::mem::take(current_epoch_start_block);
			*current_epoch_start_block = <frame_system::Pallet<T>>::block_number();
		});

		// After we update the current epoch, we signal the *next* epoch change
		// so that nodes can track changes.
		let next_randomness = NextRandomness::<T>::get();

		let next_epoch = NextEpochDescriptor {
			authorities: next_authorities.to_vec(),
			randomness: next_randomness,
		};
		Self::deposit_consensus(ConsensusLog::NextEpochData(next_epoch));

		if let Some(next_config) = NextEpochConfig::<T>::get() {
			EpochConfig::<T>::put(next_config);
		}

		if let Some(pending_epoch_config_change) = PendingEpochConfigChange::<T>::take() {
			let next_epoch_config: RRSCEpochConfiguration =
				pending_epoch_config_change.clone().into();
			NextEpochConfig::<T>::put(next_epoch_config);

			Self::deposit_consensus(ConsensusLog::NextConfigData(pending_epoch_config_change));
		}
	}

	/// Finds the start slot of the current epoch. only guaranteed to
	/// give correct results after `do_initialize` of the first block
	/// in the chain (as its result is based off of `GenesisSlot`).
	pub fn current_epoch_start() -> Slot {
		Self::epoch_start(EpochIndex::<T>::get())
	}

	/// Produces information about the current epoch.
	pub fn current_epoch() -> Epoch {
		Epoch {
			epoch_index: EpochIndex::<T>::get(),
			start_slot: Self::current_epoch_start(),
			duration: T::EpochDuration::get(),
			authorities: Self::authorities().to_vec(),
			randomness: Self::randomness(),
			config: EpochConfig::<T>::get()
				.expect("EpochConfig is initialized in genesis; we never `take` or `kill` it; qed"),
		}
	}

	/// Produces information about the next epoch (which was already previously
	/// announced).
	pub fn next_epoch() -> Epoch {
		let next_epoch_index = EpochIndex::<T>::get().checked_add(1).expect(
			"epoch index is u64; it is always only incremented by one; \
			 if u64 is not enough we should crash for safety; qed.",
		);

		Epoch {
			epoch_index: next_epoch_index,
			start_slot: Self::epoch_start(next_epoch_index),
			duration: T::EpochDuration::get(),
			authorities: NextAuthorities::<T>::get().to_vec(),
			randomness: NextRandomness::<T>::get(),
			config: NextEpochConfig::<T>::get().unwrap_or_else(|| {
				EpochConfig::<T>::get().expect(
					"EpochConfig is initialized in genesis; we never `take` or `kill` it; qed",
				)
			}),
		}
	}

	fn epoch_start(epoch_index: u64) -> Slot {
		// (epoch_index * epoch_duration) + genesis_slot

		const PROOF: &str = "slot number is u64; it should relate in some way to wall clock time; \
							 if u64 is not enough we should crash for safety; qed.";

		let epoch_start = epoch_index.checked_mul(T::EpochDuration::get()).expect(PROOF);

		epoch_start.checked_add(*GenesisSlot::<T>::get()).expect(PROOF).into()
	}

	pub fn deposit_consensus<U: Encode>(new: U) {
		let log = DigestItem::Consensus(RRSC_ENGINE_ID, new.encode());
		<frame_system::Pallet<T>>::deposit_log(log.into())
	}

	fn deposit_randomness(randomness: &sp_schnorrkel::Randomness) {
		let segment_idx = SegmentIndex::<T>::get();
		let mut segment = UnderConstruction::<T>::get(&segment_idx);
		if segment.try_push(*randomness).is_ok() {
			// push onto current segment: not full.
			UnderConstruction::<T>::insert(&segment_idx, &segment);
		} else {
			// move onto the next segment and update the index.
			let segment_idx = segment_idx + 1;
			let bounded_randomness =
				BoundedVec::<_, ConstU32<UNDER_CONSTRUCTION_SEGMENT_LENGTH>>::try_from(vec![
					randomness.clone(),
				])
				.expect("UNDER_CONSTRUCTION_SEGMENT_LENGTH >= 1");
			UnderConstruction::<T>::insert(&segment_idx, bounded_randomness);
			SegmentIndex::<T>::put(&segment_idx);
		}
	}

	fn do_initialize(now: T::BlockNumber) {
		// since do_initialize can be called twice (if session module is present)
		// => let's ensure that we only modify the storage once per block
		let initialized = Self::initialized().is_some();
		if initialized {
			return;
		}

		let maybe_pre_digest: Option<PreDigest> =
			<frame_system::Pallet<T>>::digest()
				.logs
				.iter()
				.filter_map(|s| s.as_pre_runtime())
				.filter_map(|(id, mut data)| {
					if id == RRSC_ENGINE_ID {
						PreDigest::decode(&mut data).ok()
					} else {
						None
					}
				})
				.next();

		let is_primary = matches!(maybe_pre_digest, Some(PreDigest::Primary(..)));

		let maybe_randomness: MaybeRandomness = maybe_pre_digest.and_then(|digest| {
			// on the first non-zero block (i.e. block #1)
			// this is where the first epoch (epoch #0) actually starts.
			// we need to adjust internal storage accordingly.
			if *GenesisSlot::<T>::get() == 0 {
				GenesisSlot::<T>::put(digest.slot());
				debug_assert_ne!(*GenesisSlot::<T>::get(), 0);

				// deposit a log because this is the first block in epoch #0
				// we use the same values as genesis because we haven't collected any
				// randomness yet.
				let next = NextEpochDescriptor {
					authorities: Self::authorities().to_vec(),
					randomness: Self::randomness(),
				};

				Self::deposit_consensus(ConsensusLog::NextEpochData(next))
			}

			// the slot number of the current block being initialized
			let current_slot = digest.slot();

			// how many slots were skipped between current and last block
			let lateness = current_slot.saturating_sub(CurrentSlot::<T>::get() + 1);
			let lateness = T::BlockNumber::from(*lateness as u32);

			Lateness::<T>::put(lateness);
			CurrentSlot::<T>::put(current_slot);

			let authority_index = digest.authority_index();

			if T::DisabledValidators::is_disabled(authority_index) {
				panic!(
					"Validator with index {:?} is disabled and should not be attempting to author blocks.",
					authority_index,
				);
			}

			// Extract out the VRF output if we have it
			digest.vrf_output().and_then(|vrf_output| {
				// Reconstruct the bytes of VRFInOut using the authority id.
				Authorities::<T>::get()
					.get(authority_index as usize)
					.and_then(|author| {
						sp_schnorrkel::PublicKey::from_bytes(author.0.as_slice()).ok()
					})
					.and_then(|pubkey| {
						let transcript = cessp_consensus_rrsc::make_transcript(
							&Self::randomness(),
							current_slot,
							EpochIndex::<T>::get(),
						);

						vrf_output.0.attach_input_hash(&pubkey, transcript).ok()
					})
					.map(|inout| inout.make_bytes(&cessp_consensus_rrsc::RRSC_VRF_INOUT_CONTEXT))
			})
		});

		// For primary VRF output we place it in the `Initialized` storage
		// item and it'll be put onto the under-construction randomness later,
		// once we've decided which epoch this block is in.
		Initialized::<T>::put(if is_primary { maybe_randomness } else { None });

		// Place either the primary or secondary VRF output into the
		// `AuthorVrfRandomness` storage item.
		AuthorVrfRandomness::<T>::put(maybe_randomness);

		// enact epoch change, if necessary.
		T::EpochChangeTrigger::trigger::<T>(now)
	}

	/// Call this function exactly once when an epoch changes, to update the
	/// randomness. Returns the new randomness.
	fn randomness_change_epoch(next_epoch_index: u64) -> sp_schnorrkel::Randomness {
		let this_randomness = NextRandomness::<T>::get();
		let segment_idx: u32 = SegmentIndex::<T>::mutate(|s| sp_std::mem::replace(s, 0));

		// overestimate to the segment being full.
		let rho_size = (segment_idx.saturating_add(1) * UNDER_CONSTRUCTION_SEGMENT_LENGTH) as usize;

		let next_randomness = compute_randomness(
			this_randomness,
			next_epoch_index,
			(0..segment_idx).flat_map(|i| UnderConstruction::<T>::take(&i)),
			Some(rho_size),
		);
		NextRandomness::<T>::put(&next_randomness);
		this_randomness
	}

	pub fn initialize_authorities(authorities: &[(AuthorityId, RRSCAuthorityWeight)]) {
		if !authorities.is_empty() {
			assert!(Authorities::<T>::get().is_empty(), "Authorities are already initialized!");
			let bounded_authorities =
				WeakBoundedVec::<_, T::MaxAuthorities>::try_from(authorities.to_vec())
					.expect("Initial number of authorities should be lower than T::MaxAuthorities");
			Authorities::<T>::put(&bounded_authorities);
			NextAuthorities::<T>::put(&bounded_authorities);
		}
	}

	fn do_report_equivocation(
		reporter: Option<T::AccountId>,
		equivocation_proof: EquivocationProof<T::Header>,
		key_owner_proof: T::KeyOwnerProof,
	) -> DispatchResultWithPostInfo {
		let offender = equivocation_proof.offender.clone();
		let slot = equivocation_proof.slot;

		// validate the equivocation proof
		if !cessp_consensus_rrsc::check_equivocation_proof(equivocation_proof) {
			return Err(Error::<T>::InvalidEquivocationProof.into());
		}

		let validator_set_count = key_owner_proof.validator_count();
		let session_index = key_owner_proof.session();

		let epoch_index = (*slot.saturating_sub(GenesisSlot::<T>::get()) / T::EpochDuration::get())
			.saturated_into::<u32>();

		// check that the slot number is consistent with the session index
		// in the key ownership proof (i.e. slot is for that epoch)
		if epoch_index != session_index {
			return Err(Error::<T>::InvalidKeyOwnershipProof.into());
		}

		// check the membership proof and extract the offender's id
		let key = (cessp_consensus_rrsc::KEY_TYPE, offender);
		let offender = T::KeyOwnerProofSystem::check_proof(key, key_owner_proof)
			.ok_or(Error::<T>::InvalidKeyOwnershipProof)?;

		let offence =
			RRSCEquivocationOffence { slot, validator_set_count, offender, session_index };

		let reporters = match reporter {
			Some(id) => vec![id],
			None => vec![],
		};

		T::HandleEquivocation::report_offence(reporters, offence)
			.map_err(|_| Error::<T>::DuplicateOffenceReport)?;

		// waive the fee since the report is valid and beneficial
		Ok(Pays::No.into())
	}

	/// Submits an extrinsic to report an equivocation. This method will create
	/// an unsigned extrinsic with a call to `report_equivocation_unsigned` and
	/// will push the transaction to the pool. Only useful in an offchain
	/// context.
	pub fn submit_unsigned_equivocation_report(
		equivocation_proof: EquivocationProof<T::Header>,
		key_owner_proof: T::KeyOwnerProof,
	) -> Option<()> {
		T::HandleEquivocation::submit_unsigned_equivocation_report(
			equivocation_proof,
			key_owner_proof,
		)
		.ok()
	}

	fn send_vrf_inout(
		account: T::AccountId, 
		key: AuthorityId,
		session_index: SessionIndex,
		block_number: T::BlockNumber,
		validators_len: u32,
	) -> OffchainResult<T, ()> {
		let authority_index = 0;
		let prepare_vrf_inout = || -> OffchainResult<T, Call<T>> {
			let keys = Keys::<T>::get();
			let public = keys.get(authority_index as usize).unwrap();
			let epoch_index = EpochIndex::<T>::get();
			let vrf_inout_sign = sp_io::crypto::sr25519_vrf_sign(AuthorityId::ID, key.as_ref(), Self::randomness().to_vec(), epoch_index)
																		.ok_or(OffchainErr::FailedSigning)?;
			let vrf_inout = VrfInOut {
				block_number,
				session_index,
				authority_index,
				validators_len,
				key: key.clone(),
				vrf_inout: vrf_inout_sign,
			};

			let signature = key.sign(&vrf_inout.encode()).ok_or(OffchainErr::FailedSigning)?;

			Ok(Call::submit_vrf_inout{ vrf_inout, signature })
		};
		
		// acquire lock for that authority at current heartbeat to make sure we don't
		// send concurrent heartbeats.
		Self::with_vrf_inout_lock(authority_index, session_index, block_number, || {
			let call = prepare_vrf_inout()?;
			log::info!(
				target: "runtime:rrsc_vrf",
				"[index: {:?}] Reporting vrf inout at block: {:?} (session: {:?}): {:?}",
				authority_index,
				block_number,
				session_index,
				call,
			);

			log::info!("Submitting vrf transaction!");
			SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
				.map_err(|_| OffchainErr::SubmitTransaction)?;

			Ok(())
		})
	}

	fn local_authority_keys() -> impl Iterator<Item = (T::AccountId, AuthorityId)> {
		// on-chain storage
		//
		// At index `idx`:
		// 1. A (ImOnline) public key to be used by a validator at index `idx` to send im-online
		//          heartbeats.
		//let authorities = Keys::<T>::get();

		// local keystore
		//
		// All `ImOnline` public (+private) keys currently in the local keystore.
		let local_keys = AuthorityId::all();

		// local_keys.sort();

		// authorities.into_iter().enumerate().filter_map(move |(index, authority)| {
		// 	local_keys
		// 		.binary_search(&authority)
		// 		.ok()
		// 		.map(|location| (index as u32, local_keys[location].clone()))
		// })
		local_keys.into_iter().filter_map(move |key| {
			T::FindKeyOwner::key_owner(AuthorityId::ID, key.as_ref())
				.and_then(|acc| Some((acc, key.clone())))
		})
	}

	fn with_vrf_inout_lock<R>(
		authority_index: u32,
		session_index: SessionIndex,
		now: T::BlockNumber,
		f: impl FnOnce() -> OffchainResult<T, R>,
	) -> OffchainResult<T, R> {
		let key = {
			let mut key = DB_PREFIX.to_vec();
			key.extend(authority_index.encode());
			key
		};
		let storage = StorageValueRef::persistent(&key);
		let res = storage.mutate(
			|status: Result<Option<VrfInOutStatus<T::BlockNumber>>, StorageRetrievalError>| {
				// Check if there is already a lock for that particular block.
				// This means that the heartbeat has already been sent, and we are just waiting
				// for it to be included. However if it doesn't get included for INCLUDE_THRESHOLD
				// we will re-send it.
				match status {
					// we are still waiting for inclusion.
					Ok(Some(status)) if status.is_recent(session_index, now) =>
						Err(OffchainErr::WaitingForInclusion(status.sent_at)),
					// attempt to set new status
					_ => Ok(VrfInOutStatus { session_index, sent_at: now }),
				}
			},
		);
		if let Err(MutateStorageError::ValueFunctionFailed(err)) = res {
			return Err(err)
		}

		let mut new_status = res.map_err(|_| OffchainErr::FailedToAcquireLock)?;

		// we got the lock, let's try to send the heartbeat.
		let res = f();

		// clear the lock in case we have failed to send transaction.
		if res.is_err() {
			new_status.sent_at = 0u32.into();
			storage.set(&new_status);
		}

		res
	}

}

impl<T: Config> OnTimestampSet<T::Moment> for Pallet<T> {
	fn on_timestamp_set(moment: T::Moment) {
		let slot_duration = Self::slot_duration();
		assert!(!slot_duration.is_zero(), "RRSC slot duration cannot be zero.");

		let timestamp_slot = moment / slot_duration;
		let timestamp_slot = Slot::from(timestamp_slot.saturated_into::<u64>());

		assert!(
			CurrentSlot::<T>::get() == timestamp_slot,
			"Timestamp slot must match `CurrentSlot`"
		);
	}
}

impl<T: Config> frame_support::traits::EstimateNextSessionRotation<T::BlockNumber> for Pallet<T> {
	fn average_session_length() -> T::BlockNumber {
		T::EpochDuration::get().saturated_into()
	}

	fn estimate_current_session_progress(_now: T::BlockNumber) -> (Option<Permill>, Weight) {
		let elapsed = CurrentSlot::<T>::get().saturating_sub(Self::current_epoch_start()) + 1;

		(
			Some(Permill::from_rational(*elapsed, T::EpochDuration::get())),
			// Read: Current Slot, Epoch Index, Genesis Slot
			T::DbWeight::get().reads(3),
		)
	}

	fn estimate_next_session_rotation(now: T::BlockNumber) -> (Option<T::BlockNumber>, Weight) {
		(
			Self::next_expected_epoch_change(now),
			// Read: Current Slot, Epoch Index, Genesis Slot
			T::DbWeight::get().reads(3),
		)
	}
}

impl<T: Config> frame_support::traits::Lateness<T::BlockNumber> for Pallet<T> {
	fn lateness(&self) -> T::BlockNumber {
		Self::lateness()
	}
}

impl<T: Config> sp_runtime::BoundToRuntimeAppPublic for Pallet<T> {
	type Public = AuthorityId;
}

impl<T: Config> OneSessionHandler<T::AccountId> for Pallet<T> {
	type Key = AuthorityId;

	fn on_genesis_session<'a, I: 'a>(validators: I)
	where
		I: Iterator<Item = (&'a T::AccountId, AuthorityId)>,
	{
		let authorities = validators.map(|(_, k)| (k, 1)).collect::<Vec<_>>();
		Self::initialize_authorities(&authorities);
	}

	fn on_new_session<'a, I: 'a>(_changed: bool, validators: I, queued_validators: I)
	where
		I: Iterator<Item = (&'a T::AccountId, AuthorityId)>,
	{
		let authorities = validators.map(|(_account, k)| (k, 1)).collect::<Vec<_>>();
		let bounded_authorities = WeakBoundedVec::<_, T::MaxAuthorities>::force_from(
			authorities,
			Some(
				"Warning: The session has more validators than expected. \
				A runtime configuration adjustment may be needed.",
			),
		);

		let next_authorities = queued_validators.map(|(_account, k)| (k, 1)).collect::<Vec<_>>();
		let next_bounded_authorities = WeakBoundedVec::<_, T::MaxAuthorities>::force_from(
			next_authorities.clone(),
			Some(
				"Warning: The session has more queued validators than expected. \
				A runtime configuration adjustment may be needed.",
			),
		);

		Self::enact_epoch_change(bounded_authorities, next_bounded_authorities)
	}

	fn on_disabled(i: u32) {
		Self::deposit_consensus(ConsensusLog::OnDisabled(i))
	}
}

// compute randomness for a new epoch. rho is the concatenation of all
// VRF outputs in the prior epoch.
//
// an optional size hint as to how many VRF outputs there were may be provided.
fn compute_randomness(
	last_epoch_randomness: sp_schnorrkel::Randomness,
	epoch_index: u64,
	rho: impl Iterator<Item = sp_schnorrkel::Randomness>,
	rho_size_hint: Option<usize>,
) -> sp_schnorrkel::Randomness {
	let mut s = Vec::with_capacity(40 + rho_size_hint.unwrap_or(0) * VRF_OUTPUT_LENGTH);
	s.extend_from_slice(&last_epoch_randomness);
	s.extend_from_slice(&epoch_index.to_le_bytes());

	for vrf_output in rho {
		s.extend_from_slice(&vrf_output[..]);
	}

	sp_io::hashing::blake2_256(&s)
}

pub mod migrations {
	use super::*;
	use frame_support::pallet_prelude::{StorageValue, ValueQuery};

	/// Something that can return the storage prefix of the `RRSC` pallet.
	pub trait RRSCPalletPrefix: Config {
		fn pallet_prefix() -> &'static str;
	}

	struct __OldNextEpochConfig<T>(sp_std::marker::PhantomData<T>);
	impl<T: RRSCPalletPrefix> frame_support::traits::StorageInstance for __OldNextEpochConfig<T> {
		fn pallet_prefix() -> &'static str {
			T::pallet_prefix()
		}
		const STORAGE_PREFIX: &'static str = "NextEpochConfig";
	}

	type OldNextEpochConfig<T> =
		StorageValue<__OldNextEpochConfig<T>, Option<NextConfigDescriptor>, ValueQuery>;

	/// A storage migration that adds the current epoch configuration for RRSC
	/// to storage.
	pub fn add_epoch_configuration<T: RRSCPalletPrefix>(
		epoch_config: RRSCEpochConfiguration,
	) -> Weight {
		let mut writes = 0;
		let mut reads = 0;

		if let Some(pending_change) = OldNextEpochConfig::<T>::get() {
			PendingEpochConfigChange::<T>::put(pending_change);

			writes += 1;
		}

		reads += 1;

		OldNextEpochConfig::<T>::kill();

		EpochConfig::<T>::put(epoch_config.clone());
		NextEpochConfig::<T>::put(epoch_config);

		writes += 3;

		T::DbWeight::get().writes(writes) + T::DbWeight::get().reads(reads)
	}
}
