# RRSC (Random Rotational Selection Consensus)

## What is Consensus in Blockchain?

A consensus is a method used by nodes within a network to come into agreement. All nodes should come into agreement on a single state of the network at a given time. The nodes in a decentralized network stay synced with each other by adhering to the consensus mechanism. In the blockchain network, the consensus method helps generate new blocks and maintain the state of the network.

## Substrate Consensus

### Block Production: BABE

Blind Assignment for Blockchain Extension (BABE) is a block production mechanism that runs on validator nodes and determines the authors of new blocks.

Follow the following links to read more about BABE:

● https://wiki.polkadot.network/docs/learn-consensus#block-production-babe

● https://research.web3.foundation/en/latest/polkadot/block-production/Babe.html

BABE uses VRF for determining the next validator in every slot.

Slots are discrete units of time six seconds in length. Each slot can contain a block, but may not. Slots make up epochs - on Polkadot, 2400 slots make one epoch, which makes epochs four hours long.

In every slot, each validator "rolls a die". They execute a function (the VRF) that takes as input the following:

● The "secret key", a key specifically made for these die rolls.

● An epoch randomness value, which is the hash of VRF values from the blocks in the epoch before last (N-2), so past randomness affects the current pending randomness (N).

● The slot number.

The output is two values: a RESULT (the random value) and a PROOF (a proof that the random value was generated correctly).

The RESULT is then compared to a threshold defined in the implementation of the protocol (specifically, in the Polkadot Host). If the value is less than the threshold, then the validator who rolled this number is a viable block production candidate for that slot. The validator then attempts to create a block and submits this block into the network along with the previously obtained PROOF and RESULT. Under VRF, every validator rolls a number for themselves, checks it against a threshold, and produces a block if the random roll is under that threshold.

The astute reader will notice that due to the way this works, some slots may have no validators as block producer candidates because all validator candidates rolled too high and missed the threshold. We clarify how we resolve this issue and make sure that Polkadot block times remain near constant-time in the wiki page on consensus.

## Random Rotational Selection(R²S)

The Random Rotational Selection consensus selects a set of validators (11 to be exact) every 24 hours using the VRF function and amount of nominator stake backing up the validators. These 11 validators will generate blocks in a round-robin fashion for the next 24 hours till the next set of validators are selected.

The R²S is different from BABE in that it eliminates Forking. By randomly selecting 11 validators from a pool of validators we allow every node to have equal opportunity to be part of the consensus and incentives for the numbers of valid blocks they generate.

The process is as follows: -
1. All validators will run the VRF function to determine the current 11 validator nodes that will generate blocks for next 24 hours.

2. If there are more than 11 validators, the first 11 with most stake will be selected.

3. If there are less than 11 validators, the remaining validators will run a second round of VRF function and join the validators of first round to make a total of 11. 

4. The above 3 steps will be repeated every 24 hours.

The 11 validators will generate blocks in a round robin fashion. There is a possibility of a node failing to generate block at a specific time. This will result in slashing(Penalty to the validator who does not validating blocks in time).

In case of a validator node being slashed of all of it's stake, the validator will be removed from the validator sets, and that slot will either be needed to be covered by secondery validators or no block is generated during that slot.
