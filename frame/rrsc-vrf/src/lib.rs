// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use cessp_consensus_rrsc::AuthorityId;
use frame_support::{
	traits::{
		EstimateNextSessionRotation, FindKeyOwner, Get, OneSessionHandler, ValidatorSet,
		ValidatorSetWithIdentification, WrapperOpaque, Randomness
	},
	BoundedSlice, WeakBoundedVec,
};
use frame_system::offchain::{SendTransactionTypes, SubmitTransaction};
use scale_info::TypeInfo;
use sp_application_crypto::RuntimeAppPublic;
use sp_core::crypto::ByteArray;
use sp_runtime::{
	offchain::storage::{MutateStorageError, StorageRetrievalError, StorageValueRef},
	traits::{AtLeast32BitUnsigned, Convert, Saturating, TrailingZeroInput},
	PerThing, Perbill, Permill, RuntimeDebug, SaturatedConversion,
};
use sp_staking::{
	offence::{Kind, Offence, ReportOffence},
	SessionIndex,
};
use sp_std::{convert::TryInto, prelude::*};
use core::marker::PhantomData;

pub mod sr25519 {
	mod app_sr25519 {
		use sp_application_crypto::{app_crypto, key_types::RRSC, sr25519};
		app_crypto!(sr25519, RRSC);
	}

	sp_application_crypto::with_pair! {
		/// A keypair using sr25519 as its crypto.
		pub type AuthorityPair = app_sr25519::Pair;
	}

	/// A signature using sr25519 as its crypto.
	pub type AuthoritySignature = app_sr25519::Signature;

	// An identifier using sr25519 as its crypto.
	pub type AuthorityId = cessp_consensus_rrsc::AuthorityId;
}

const DB_PREFIX: &[u8] = b"cess/vrf-inout/";
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

pub use pallet::*;

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
	/// The vrf inout
	pub vrf_inout: ([u8; 32], [u8; 64]),
}

type OffchainResult<T, A> = Result<A, OffchainErr<<T as frame_system::Config>::BlockNumber>>;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: SendTransactionTypes<Call<Self>> + frame_system::Config {
		// The identifier type for an authority.
		// type AuthorityId: Member
		// 	+ Parameter
		// 	+ RuntimeAppPublic
		// 	+ Ord
		// 	+ MaybeSerializeDeserialize
		// 	+ MaxEncodedLen;

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

		/// Something that provides randomness in the runtime.
		type Randomness: Randomness<Self::Hash, Self::BlockNumber>;

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
		/// Non existent public key.
		InvalidKey,
		/// Duplicated heartbeat.
		DuplicatedVrfInOut,
	}

	#[pallet::storage]
	#[pallet::getter(fn vrf_inout_after)]
	pub(crate) type VrfInOutAfter<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

	/// The current set of keys that may submit vrf inout.
	#[pallet::storage]
	#[pallet::getter(fn keys)]
	pub(crate) type Keys<T: Config> =
		StorageValue<_, WeakBoundedVec<cessp_consensus_rrsc::AuthorityId, T::MaxKeys>, ValueQuery>;

	/// For each session index, we keep a mapping of `SessionIndex` and `AuthIndex` to
	/// `WrapperOpaque<BoundedOpaqueNetworkState>`.
	#[pallet::storage]
	#[pallet::getter(fn received_vrf_inout)]
	pub(crate) type ReceivedVrfInOut<T: Config> = StorageDoubleMap<
		_,
		Twox64Concat,
		SessionIndex,
		Twox64Concat,
		AuthIndex,
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

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub keys: Vec<cessp_consensus_rrsc::AuthorityId>,
		pub phantom_data: PhantomData<T>,
	}

	#[cfg(feature = "std")]
	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			GenesisConfig { keys: Default::default(), phantom_data: Default::default() }
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			Pallet::<T>::initialize_keys(&self.keys);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(0)]
		pub fn submit_vrf_inout(
			origin: OriginFor<T>, 
			vrf_inout: VrfInOut<T::BlockNumber>,
			_signature: <cessp_consensus_rrsc::AuthorityId as RuntimeAppPublic>::Signature,
		) -> DispatchResult{
			ensure_none(origin)?;

			let current_session = T::ValidatorSet::session_index();
			let exists =
				ReceivedVrfInOut::<T>::contains_key(&current_session, &vrf_inout.authority_index);
			let keys = Keys::<T>::get();
			let public = keys.get(vrf_inout.authority_index as usize);
			if let (false, Some(public)) = (exists, public) {
				Self::deposit_event(Event::<T>::VrfInOutReceived { authority_id: public.clone() });

				ReceivedVrfInOut::<T>::insert(
					&current_session,
					&vrf_inout.authority_index,
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

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: BlockNumberFor<T>) {
			let session_index = T::ValidatorSet::session_index();
			let validators_len = Keys::<T>::decode_len().unwrap_or_default() as u32;
			let _result: OffchainResult<T, ()> = Self::local_authority_keys().map(move |(account, key)| {
				log::info!("local_authority_keys");
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

	/// Invalid transaction custom error. Returned when validators_len field in heartbeat is
	/// incorrect.
	pub(crate) const INVALID_VALIDATORS_LEN: u8 = 10;

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			if let Call::submit_vrf_inout{ vrf_inout, signature } = call {
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
					transcript.append_u64(b"current epoch", 10);
					transcript.append_message(b"chain randomness", &vec![]);
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
	}
}

impl<T: Config> Pallet<T> {

	fn local_authority_keys() -> impl Iterator<Item = (T::AccountId, AuthorityId)> {
		// on-chain storage
		//
		// At index `idx`:
		// 1. A (ImOnline) public key to be used by a validator at index `idx` to send im-online
		//          heartbeats.
		// let authorities = Keys::<T>::get();

		// local keystore
		//
		// All `ImOnline` public (+private) keys currently in the local keystore.
		let mut local_keys = cessp_consensus_rrsc::AuthorityId::all();

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

	fn initialize_keys(keys: &[cessp_consensus_rrsc::AuthorityId]) {
		if !keys.is_empty() {
			assert!(Keys::<T>::get().is_empty(), "Keys are already initialized!");
			let bounded_keys = <BoundedSlice<'_, _, T::MaxKeys>>::try_from(keys)
				.expect("More than the maximum number of keys provided");
			Keys::<T>::put(bounded_keys);
		}
	}

	fn send_vrf_inout(
		account: T::AccountId,
		key: AuthorityId,
		session_index: SessionIndex,
		block_number: T::BlockNumber,
		validators_len: u32,
	) -> OffchainResult<T, ()> {
		let authority_index = 0;
		log::info!("send_vrf_inout!");
		let prepare_vrf_inout = || -> OffchainResult<T, Call<T>> {
			let keys = Keys::<T>::get();
			let public = keys.get(authority_index as usize).unwrap();
			let vrf_inout_sign = sp_io::crypto::sr25519_vrf_sign(AuthorityId::ID, key.as_ref(), public.as_slice().to_vec(), 10)
																		.ok_or(OffchainErr::FailedSigning)?;
			let vrf_inout = VrfInOut {
				block_number,
				session_index,
				authority_index,
				validators_len,
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
}

impl<T: Config> sp_runtime::BoundToRuntimeAppPublic for Pallet<T> {
	type Public = cessp_consensus_rrsc::AuthorityId;
}

impl<T: Config> OneSessionHandler<T::AccountId> for Pallet<T> {
	type Key = cessp_consensus_rrsc::AuthorityId;

	fn on_genesis_session<'a, I: 'a>(validators: I)
	where
		I: Iterator<Item = (&'a T::AccountId, cessp_consensus_rrsc::AuthorityId)>,
	{
		let keys = validators.map(|x| x.1).collect::<Vec<_>>();
		Self::initialize_keys(&keys);
	}

	fn on_new_session<'a, I: 'a>(_changed: bool, validators: I, _queued_validators: I)
	where
		I: Iterator<Item = (&'a T::AccountId, cessp_consensus_rrsc::AuthorityId)>,
	{
		// Tell the offchain worker to start making the next session's heartbeats.
		// Since we consider producing blocks as being online,
		// the heartbeat is deferred a bit to prevent spamming.
		let block_number = <frame_system::Pallet<T>>::block_number();
		let half_session = T::NextSessionRotation::average_session_length() / 2u32.into();
		<VrfInOutAfter<T>>::put(block_number + half_session);

		// Remember who the authorities are for the new session.
		let keys = validators.map(|x| x.1).collect::<Vec<_>>();
		let bounded_keys = WeakBoundedVec::<_, T::MaxKeys>::force_from(
			keys,
			Some(
				"Warning: The session has more keys than expected. \
  				A runtime configuration adjustment may be needed.",
			),
		);
		Keys::<T>::put(bounded_keys);
	}

	fn on_before_session_ending() {
		let session_index = T::ValidatorSet::session_index();
		let keys = Keys::<T>::get();
		let current_validators = T::ValidatorSet::validators();

		// Remove all received vrf inout from the current session, 
		// they have already been processed and won't be needed
		// anymore.
		
	}

	fn on_disabled(_i: u32) {
		// ignore
	}
}