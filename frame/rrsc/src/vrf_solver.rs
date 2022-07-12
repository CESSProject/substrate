use sp_std::rc::Rc;
use core::cell::RefCell;
use frame_election_provider_support::NposSolver;
use frame_support::traits::Get;
use sp_std::prelude::*;
use sp_npos_elections::{
	ElectionResult, ExtendedBalance, IdentifierT, PerThing128, VoteWeight, Candidate,
};
use frame_support::traits::Randomness;
use super::randomness::CurrentBlockRandomness;
use codec::alloc::string::ToString;

/// A wrapper for [`sp_npos_elections::seq_phragmen`] that implements [`NposSolver`].
pub struct VrfSolver<AccountId, Accuracy, T, Balancing = ()>(
	sp_std::marker::PhantomData<(AccountId, Accuracy, T, Balancing)>,
);

impl<
		AccountId: IdentifierT,
		Accuracy: PerThing128,
		T: super::pallet::Config,
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
		let (candidates, _) = sp_npos_elections::setup_inputs(targets, voters);

		let max_authorities = <T as super::Config>::MaxAuthorities::get() as usize;
		let mut account_index_hash: Vec<(usize, &Rc<RefCell<Candidate<Self::AccountId>>>, T::Hash)> = vec![];

		for (account_index, account_id) in candidates.iter().enumerate() {
			let hash = Self::random_hash("authorities", &account_index);
			account_index_hash.push((account_index, &account_id, hash));
		}

		account_index_hash.sort_by_key(|h| h.2);
		let mut winner_accounts = account_index_hash[0..max_authorities]
			.iter()
			.enumerate()
			.map(|(_, a)| a.1.clone())
			.collect::<Vec<_>>();

		todo!()
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
T: super::Config,
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