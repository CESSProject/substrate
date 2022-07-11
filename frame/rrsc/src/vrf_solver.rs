use frame_election_provider_support::NposSolver;
use frame_support::traits::Get;
use sp_std::prelude::*;
use sp_npos_elections::{
	ElectionResult, ExtendedBalance, IdentifierT, PerThing128, Support, VoteWeight,
};

/// A wrapper for [`sp_npos_elections::seq_phragmen`] that implements [`NposSolver`].
pub struct VrfSolver<AccountId, Accuracy, Balancing = ()>(
	sp_std::marker::PhantomData<(AccountId, Accuracy, Balancing)>,
);

impl<
		AccountId: IdentifierT,
		Accuracy: PerThing128,
		Balancing: Get<Option<(usize, ExtendedBalance)>>,
	> NposSolver for VrfSolver<AccountId, Accuracy, Balancing>
{
	type AccountId = AccountId;
	type Accuracy = Accuracy;
	type Error = sp_npos_elections::Error;
	fn solve(
		winners: usize,
		targets: Vec<Self::AccountId>,
		voters: Vec<(Self::AccountId, VoteWeight, impl IntoIterator<Item = Self::AccountId>)>,
	) -> Result<ElectionResult<Self::AccountId, Self::Accuracy>, Self::Error> {
		//TODO select validators from candidates
	}
}