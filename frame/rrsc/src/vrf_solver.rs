use frame_election_provider_support::{Assignment, NposSolver};
use frame_support::traits::{Get, Randomness, ValidatorCredits};
use sp_std::prelude::*;
use sp_npos_elections::{
	ElectionResult, ExtendedBalance, IdentifierT, PerThing128, VoteWeight,
};
use super::{Config, CurrentBlockRandomness, EpochIndex};
use codec::{alloc::string::ToString, Decode};

/// A wrapper for elect by vrf that implements [`NposSolver`].
pub struct VrfSolver<AccountId, Accuracy, T, Credits, Balancing = ()>(
	sp_std::marker::PhantomData<(AccountId, Accuracy, T, Credits, Balancing)>,
);

impl<
		AccountId: IdentifierT,
		Accuracy: PerThing128,
		T: Config,
		Credits: ValidatorCredits<AccountId>,
		Balancing: Get<Option<(usize, ExtendedBalance)>>,
	> NposSolver for VrfSolver<AccountId, Accuracy, T, Credits, Balancing>
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
		
		let credits = Credits::credits(EpochIndex::<T>::get());
		let full_credit = Credits::full_credit();
		// final_score = `random_score` * 80% + `credit` * 20%
		let mut account_scores: Vec<(AccountId, u32)> = targets
			.into_iter()
			.enumerate()
			.map(|(account_index, account_id)| {
				let random_number = Self::random_number("authorities", &account_index);
				let random_score = random_number % full_credit;
				let credit = match credits.get(&account_id) {
					Some(c) => *c,
					None => 0,
				};
				let final_score = random_score.saturating_mul(8)
							.saturating_add(credit.saturating_mul(2))
							.saturating_div(10);
				(account_id, final_score)
			})
			.collect();

		account_scores.sort_by_key(|h| h.1);
		account_scores.reverse();


		let winners: Vec<(AccountId, u128)> = account_scores
			.into_iter()
			.take(to_elect)
			.map(|h| (h.0, 100u128))
			.collect();
		let assignments = winners
			.clone()
			.into_iter()
			.map(|h| Assignment { who: h.0.clone(), distribution: vec![(h.0, Accuracy::from_percent(100.into()))] })
			.collect();

		Ok(ElectionResult { winners, assignments })
	}
}

impl <
AccountId: IdentifierT,
Accuracy: PerThing128,
T: Config,
Credits: ValidatorCredits<AccountId>,
Balancing: Get<Option<(usize, ExtendedBalance)>>,
> VrfSolver<AccountId, Accuracy, T, Credits, Balancing> {
	pub fn random_number(context: &str,authority_index: &usize) -> u32 {
		let mut b_context = context.to_string();
		b_context.push_str(authority_index.to_string().as_str());
		let (hash, _) = CurrentBlockRandomness::<T>::random(&b_context.as_bytes());
		log::info!("{:?} Before Hash:: {:?}", b_context, hash);
		let hash = 	match hash {
				Some(h) => h,
				None => T::Hash::default(),
		};
		log::info!("{:?} Hash:: {:?}", b_context, hash);
		let random_number = u32::decode(&mut hash.as_ref())
								.expect("secure hashes should always be bigger than u32; qed");
		random_number
	}
}