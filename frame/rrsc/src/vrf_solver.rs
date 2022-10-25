use frame_election_provider_support::{Assignment, NposSolver};
use frame_support::traits::Get;
use sp_std::prelude::*;
use sp_npos_elections::{
	ElectionResult, ExtendedBalance, IdentifierT, PerThing128, VoteWeight,
};
use super::{Config, EpochIndex, ReceivedVrfRandom};
use codec::EncodeLike;

/// A wrapper for [`sp_npos_elections::seq_phragmen`] that implements [`NposSolver`].
pub struct VrfSolver<AccountId, Accuracy, T, Balancing = ()>(
	sp_std::marker::PhantomData<(AccountId, Accuracy, T, Balancing)>,
);

impl<
		AccountId: IdentifierT + EncodeLike<<T as frame_system::Config>::AccountId>,
		Accuracy: PerThing128,
		T: Config,
		Balancing: Get<Option<(usize, ExtendedBalance)>>,
	> NposSolver for VrfSolver<AccountId, Accuracy, T, Balancing>
{
	type AccountId = AccountId;
	type Accuracy = Accuracy;
	type Error = sp_npos_elections::Error;
	fn solve(
		winners: usize,
		targets: Vec<Self::AccountId>,
		_voters: Vec<(Self::AccountId, VoteWeight, impl IntoIterator<Item = Self::AccountId>)>,
	) -> Result<ElectionResult<Self::AccountId, Self::Accuracy>, Self::Error> {
		let to_elect = winners;
		
		let epoch_index = EpochIndex::<T>::get();
		let mut account_index_hash = vec![];
		for (_, account_id) in targets.into_iter().enumerate() {
			let vrf_random = match epoch_index {
				0 => 0u128,
				_ => ReceivedVrfRandom::<T>::get(&epoch_index.saturating_sub(1), account_id.clone())
						.unwrap_or(u128::max_value()),
			};
			account_index_hash.push((account_id, vrf_random));
		}

		account_index_hash.sort_by_key(|h| h.1);

		let winners: Vec<(AccountId, u128)> = account_index_hash
			.into_iter()
			.take(to_elect)
			.map(|h| (h.0, 100))
			.collect();
		let assignments = winners
			.clone()
			.into_iter()
			.map(|h| Assignment { who: h.0.clone(), distribution: vec![(h.0, Accuracy::from_percent(100.into()))] })
			.collect();

		Ok(ElectionResult { winners, assignments })
	}

}