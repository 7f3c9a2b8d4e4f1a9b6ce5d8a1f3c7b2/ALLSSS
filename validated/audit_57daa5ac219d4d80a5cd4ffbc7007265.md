# Audit Report

## Title
Missing LIB Height Validation in NextTerm Allows Irreversible Block Rollback

## Summary
The NextTerm consensus behavior does not validate that the provided Round's `ConfirmedIrreversibleBlockHeight` is not lower than the current Last Irreversible Block (LIB) height. This allows a miner with outdated state to produce a NextTerm block that rolls back the LIB, violating the fundamental blockchain guarantee that finalized blocks remain irreversible.

## Finding Description

The vulnerability exists in the validation and processing flow of the NextTerm consensus behavior through a missing validation check that is present in other consensus behaviors.

**Missing Validation in NextTerm:**

When NextTerm behavior is validated, the `LibInformationValidationProvider` is NOT added to the validation pipeline. [1](#0-0) 

In contrast, UpdateValue behavior DOES include this critical validator: [2](#0-1) 

The `LibInformationValidationProvider` is designed to check that `ConfirmedIrreversibleBlockHeight` does not decrease: [3](#0-2) 

**Round Generation from Local State:**

When a miner generates NextTerm consensus data, the Round is created by copying the LIB from their local current round state: [4](#0-3) 

The current round is retrieved from the miner's local state: [5](#0-4) 

**Unchecked Storage:**

When `ProcessNextTerm` executes, it converts the `NextTermInput` to a Round and stores it directly without LIB validation: [6](#0-5) 

The round is stored via `AddRoundInformation`: [7](#0-6) 

Which directly sets the round in state without any validation: [8](#0-7) 

**Attack Scenario:**
1. Network has current LIB at height 1000
2. Miner is scheduled to produce NextTerm block
3. Miner has outdated state (either due to network delays or intentional delay in syncing) with LIB at height 900
4. Miner generates NextTerm with `ConfirmedIrreversibleBlockHeight = 900`
5. Block passes validation (no LIB check for NextTerm)
6. Upon execution, the outdated LIB value (900) is stored
7. The network's LIB has rolled back from 1000 to 900, making 100 previously finalized blocks reversible again

## Impact Explanation

This is a **CRITICAL** severity vulnerability because it breaks the core consensus guarantee of irreversibility.

**Consensus Integrity Violation:**
- The Last Irreversible Block height moves backward, violating the blockchain invariant that finalized blocks must remain irreversible
- Blocks between the old and new LIB (heights 901-1000 in the example) become reversible again despite having been previously finalized
- Enables chain reorganization attacks on previously finalized blocks

**Cross-Chain Security Breach:**
- Cross-chain bridges and side chains rely on LIB for finality guarantees when indexing cross-chain transactions
- A rolled-back LIB could allow manipulation of cross-chain merkle proofs that were previously considered final
- Could enable double-spend attacks across chains

**Economic and State Integrity Impact:**
- Transactions in previously irreversible blocks can be reverted
- Smart contract state that depended on finalized blocks becomes unreliable
- DApps and users lose confidence in transaction finality

**Affected Parties:**
- All network participants relying on block finality guarantees
- Cross-chain protocols and bridges
- DApps with transactions in the affected block range
- Users expecting finalized transactions to be irreversible

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attacker Prerequisites:**
- Must be a valid miner in the current or previous miner set (required to produce NextTerm blocks)
- Must have ability to control their local node state or leverage network delays

**Attack Complexity: LOW**
The attack is straightforward:
1. Wait to be scheduled for NextTerm block production (occurs naturally during term transitions)
2. Either deliberately delay syncing recent UpdateValue blocks OR exploit natural network partitions/delays
3. Generate NextTerm with outdated LIB from stale local state
4. The block passes all validation checks (no LIB validator for NextTerm)
5. LIB automatically rolls back upon execution

**Feasibility:**
- **Natural Occurrence:** Network partitions or delays during term transitions naturally create state inconsistencies between miners
- **Malicious Exploitation:** A miner can intentionally delay syncing to maintain outdated state
- **No Additional Privileges:** Beyond being in the miner set, no special capabilities are required

**Detection Difficulty:**
- Hard to distinguish from legitimate network synchronization issues
- Could be attributed to "normal" network delays
- May not be immediately obvious until chain reorganization is attempted

**Frequency:**
- NextTerm blocks are produced regularly at every term transition
- Network conditions naturally create opportunities for state inconsistencies
- Attack can be disguised as infrastructure problems

## Recommendation

Add `LibInformationValidationProvider` to the NextTerm validation pipeline, consistent with UpdateValue behavior:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS LINE
    break;
```

This ensures that any NextTerm block with a `ConfirmedIrreversibleBlockHeight` lower than the current LIB will be rejected during validation, preventing LIB rollback attacks.

## Proof of Concept

A proof of concept would involve:
1. Setting up a test network with multiple miners
2. Advancing the LIB to a certain height through normal UpdateValue blocks
3. Having a miner scheduled for NextTerm intentionally delay syncing recent blocks
4. The miner produces NextTerm with outdated LIB from their stale state
5. Observing that the block is accepted and the LIB rolls backward
6. Verifying that previously finalized blocks are now reversible

The test would demonstrate that without `LibInformationValidationProvider`, NextTerm blocks can successfully decrease the `ConfirmedIrreversibleBlockHeight` stored in the consensus contract state, violating the irreversibility guarantee.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L226-226)
```csharp
        TryToGetCurrentRoundInformation(out var currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L163-163)
```csharp
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L196-196)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L105-105)
```csharp
        State.Rounds.Set(round.RoundNumber, round);
```
