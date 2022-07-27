#![cfg_attr(not(feature = "std"), no_std)]

use frame_system::{
	self as system,
	offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
		Signer,	SignedPayload, SigningTypes, SubmitTransaction
	},
};

use sp_runtime::{
	offchain::{
		http,
		storage::{MutateStorageError, StorageRetrievalError, StorageValueRef},
		Duration,
	},
	traits::Zero,
	transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
	RuntimeDebug,
};

use sp_core::crypto::KeyTypeId;
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"rrsc");

pub mod crypto {
	pub use super::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};

	app_crypto!(sr25519, KEY_TYPE);

	pub struct AuthorityId;
	
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for AuthorityId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	// implemented for mock runtime in test
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
	for AuthorityId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}	
}

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;


	#[pallet::config]
	pub trait Config: CreateSignedTransaction<Call<Self>> + frame_system::Config {
		/// The identifier type for an offchain worker.
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

		/// The overarching event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		/// The overarching dispatch call type.
		type Call: From<Call<Self>>;

		/// Maximum number of vrfinout.
		#[pallet::constant]
		type VrfInOut: Get<u32>;

		#[pallet::constant]
		type UnsignedInterval: Get<Self::BlockNumber>;

	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	#[pallet::getter(fn vrf_inout)]
	pub(super) type VrfInOut<T: Config> = StorageValue<_, BoundedVec<u32, T::VrfInOut>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn next_unsigned_at)]
	pub(super) type NextUnsignedAt<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

	#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
	pub struct VrfInOutPayload<Public, BlockNumber> {
		block_number: BlockNumber,
		vrf_inout: u32,
		public: Public,
	}

	impl<T: SigningTypes> SignedPayload<T> for VrfInOutPayload<T::Public, T::BlockNumber> {
		fn public(&self) -> T::Public {
			self.public.clone()
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: T::BlockNumber) {
			if sp_io::offchain::is_validator() {
				Self::fetch_vrf_inout_and_send_raw_unsigned(block_number);
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {

		#[pallet::weight(0)]
		pub fn submit_vrf_inout_unsigned(
			origin: OriginFor<T>,
			vrf_inout_payload: VrfInOutPayload<T::Public, T::BlockNumber>,
			_signature: T::Signature,
		) -> DispatchResultWithPostInfo {
			log::info!("submit_vrf_inout START {:?}", vrf_inout_payload);
			ensure_none(origin)?;

			// Todo: generate vrf for the node
			Self::add_vrf_inout(None, vrf_inout_payload.vrf_inout);

			let current_block = <system::Pallet<T>>::block_number();
			<NextUnsignedAt<T>>::put(current_block + T::UnsignedInterval::get());
			log::info!("submit_vrf_inout END {:?}", vrf_inout_payload);
			Ok(().into())
		}
	}

	/// Events for the pallet.
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// Event generated when new price is accepted to contribute to the average.
		NewInOutVrf { vrf_inout: u32, maybe_who: Option<T::AccountId> },
	}

	impl<T: Config> Pallet<T> {

		fn fetch_vrf_inout_and_send_raw_unsigned(
			block_number: T::BlockNumber
		) -> Result<(), &'static str> {
			let next_unsigned_at = <NextUnsignedAt<T>>::get();
			if next_unsigned_at > block_number {
				return Err("Too early to send unsigned transaction")
			}

			// Todo: Vrf_inout should be calculated using vrf function
			let vrf_inout = 100;

			let transaction_results = Signer::<T, T::AuthorityId>::all_accounts()
			.send_unsigned_transaction(
				|account| VrfInOutPayload { block_number, vrf_inout, public: account.public.clone() },
				|payload, signature| Call::submit_vrf_inout_unsigned {
					vrf_inout_payload: payload,
					signature,
				},
			);

			for (_account_id, result) in transaction_results.into_iter() {
				if result.is_err() {
					return Err("Unable to submit transaction")
				}
			}

			Ok(())
		}

		fn add_vrf_inout(maybe_who: Option<T::AccountId>, vrf_inout: u32) {
			Self::deposit_event(Event::NewInOutVrf { vrf_inout, maybe_who });
		}

		fn validate_transaction_parameters(
			block_number: &T::BlockNumber,
			vrf_inout: &u32,
		) -> TransactionValidity {
			// Now let's check if the transaction has any chance to succeed.
			let next_unsigned_at = <NextUnsignedAt<T>>::get();
			if &next_unsigned_at > block_number {
				return InvalidTransaction::Stale.into()
			}

			// Let's make sure to reject transactions from the future.
			let current_block = <system::Pallet<T>>::block_number();
			if &current_block < block_number {
				return InvalidTransaction::Future.into()
			}
	
			ValidTransaction::with_tag_prefix("OffchainWorker-rrsc-vrf-inout")
				//.priority(T::UnsignedPriority::get().saturating_add(avg_price as _))
				.and_provides(next_unsigned_at)
				.longevity(5)
				.propagate(true)
				.build()
		}
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			if let Call::submit_vrf_inout_unsigned {
				vrf_inout_payload: ref payload,
				ref signature,
			} = call
			{
				let signature_valid =
					SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone());
				if !signature_valid {
					return InvalidTransaction::BadProof.into()
				}
				Self::validate_transaction_parameters(&payload.block_number, &payload.vrf_inout)
			} else {
				InvalidTransaction::Call.into()
			}
		}
	}
	
}