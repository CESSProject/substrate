use frame_election_provider_support::{Assignment, NposSolver};
use frame_support::traits::{Get, Randomness, ValidatorCredits};
use sp_std::prelude::*;
use sp_npos_elections::{
	ElectionResult, ExtendedBalance, IdentifierT, PerThing128, VoteWeight,
};
use super::{Config, CurrentBlockRandomness, EpochIndex};
use codec::alloc::string::ToString;

/// A wrapper for elect by vrf that implements [`NposSolver`].
pub struct VrfSolver<AccountId, Accuracy, T, Balancing = ()>(
	sp_std::marker::PhantomData<(AccountId, Accuracy, T, Balancing)>,
);

impl<
		AccountId: IdentifierT,
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
		voters: Vec<(Self::AccountId, VoteWeight, impl IntoIterator<Item = Self::AccountId>)>,
	) -> Result<ElectionResult<Self::AccountId, Self::Accuracy>, Self::Error> {
		let to_elect = winners;
		
		let credits = T::ValidatorCredits::credits(EpochIndex::<T>::get());
		let full_credit = T::ValidatorCredits::full_credit();
		let mut account_index_hash = vec![];
		for (account_index, account_id) in targets.into_iter().enumerate() {
			let hash = Self::random_hash("authorities", &account_index);
			// let hash_score = <u32>::decode(hash.as_ref());
			// let credit = match credits.get(&account_id.into()) {
			// 	Some(c) => *c,
			// 	None => 0,
			// };
			
			account_index_hash.push((account_id, hash));
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

	/* Delete after completing fn solve()
	// Calling code
	sp_npos_elections::seq_phragmen(winners, targets, voters, Balancing::get())

	// function
	pub fn seq_phragmen<AccountId: IdentifierT, P: PerThing128>(
		to_elect: usize,
		candidates: Vec<AccountId>,
		voters: Vec<(AccountId, VoteWeight, impl IntoIterator<Item = AccountId>)>,
		balancing: Option<(usize, ExtendedBalance)>,
	) -> Result<ElectionResult<AccountId, P>, crate::Error> {
		let (candidates, voters) = setup_inputs(candidates, voters);
	
		let (candidates, mut voters) = seq_phragmen_core::<AccountId>(to_elect, candidates, voters)?;
	
		if let Some((iterations, tolerance)) = balancing {
			// NOTE: might create zero-edges, but we will strip them again when we convert voter into
			// assignment.
			let _iters = balancing::balance::<AccountId>(&mut voters, iterations, tolerance);
		}
	
		let mut winners = candidates
			.into_iter()
			.filter(|c_ptr| c_ptr.borrow().elected)
			// defensive only: seq-phragmen-core returns only up to rounds.
			.take(to_elect)
			.collect::<Vec<_>>();
	
		// sort winners based on desirability.
		winners.sort_by_key(|c_ptr| c_ptr.borrow().round);
	
		let mut assignments =
			voters.into_iter().filter_map(|v| v.into_assignment()).collect::<Vec<_>>();
		let _ = assignments
			.iter_mut()
			.map(|a| a.try_normalize().map_err(|e| crate::Error::ArithmeticError(e)))
			.collect::<Result<(), _>>()?;
		let winners = winners
			.into_iter()
			.map(|w_ptr| (w_ptr.borrow().who.clone(), w_ptr.borrow().backed_stake))
			.collect();
	
		Ok(ElectionResult { winners, assignments })
	}
	*/
}

impl <
AccountId: IdentifierT,
Accuracy: PerThing128,
T: Config,
Balancing: Get<Option<(usize, ExtendedBalance)>>,
> VrfSolver<AccountId, Accuracy, T, Balancing> {
	pub fn random_hash(context: &str,authority_index: &usize) -> T::Hash {
		let mut b_context = context.to_string();
		b_context.push_str(authority_index.to_string().as_str());
		let (hash, _) = CurrentBlockRandomness::<T>::random(&b_context.as_bytes());
		log::info!("{:?} Before Hash:: {:?}", b_context, hash);
		let hash = 	match hash {
				Some(h) => h,
				None => T::Hash::default(),
		};
		log::info!("{:?} Hash:: {:?}", b_context, hash);
		hash
	}
}