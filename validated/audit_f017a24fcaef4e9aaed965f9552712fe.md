# Audit Report

## Title
Miners Can Manipulate ImpliedIrreversibleBlockHeight to Compromise LIB Finality

## Summary
The AEDPoS consensus contract fails to validate that the `ImpliedIrreversibleBlockHeight` value equals the current block height during block production. The validation only checks that this value does not decrease, allowing malicious miners to set arbitrary values. With approximately 1/3 of miners colluding, this enables manipulation of the Last Irreversible Block (LIB) calculation, breaking the chain's finality guarantees.

## Finding Description

The vulnerability exists in the consensus block production and validation flow for `UpdateValue` transactions.

**Intended Behavior:**
When a miner produces a block, the `ImpliedIrreversibleBlockHeight` should be set to the current block height: [1](#0-0) 

This value is extracted into the `UpdateValueInput` transaction: [2](#0-1) 

**The Validation Gap:**
The `LibInformationValidationProvider` performs the following check before execution: [3](#0-2) 

This validation **only** ensures the value does not decrease. Critically, there is **no validation** that:
- `ImpliedIrreversibleBlockHeight <= Context.CurrentHeight` (preventing future heights)
- `ImpliedIrreversibleBlockHeight == Context.CurrentHeight` (enforcing correct value)

**Direct Assignment Without Validation:**
During block execution, the value from the transaction input is directly assigned to state: [4](#0-3) 

**Impact on LIB Calculation:**
The manipulated values directly influence the LIB calculation: [5](#0-4) 

The algorithm collects implied heights from miners who mined in the current round, sorts them, and takes the value at index `(count-1)/3`. This means approximately 1/3 of miners can control which value is selected as the LIB height.

**After-Execution Validation Also Fails:**
The post-execution validation recovers the round from the header and compares it with the state: [6](#0-5) 

This validation only checks that the header matches the state after recovery, but does not validate that the `ImpliedIrreversibleBlockHeight` value is correct. If a miner manipulates both the header and transaction input with the same wrong value, they will match and pass validation.

## Impact Explanation

**Critical Severity - Finality Compromise:**

**Scenario 1: ImpliedIrreversibleBlockHeight Set Too HIGH**
- Malicious miners report future block heights (e.g., height 1100 while producing block 1000)
- With 1/3+ miners colluding, the LIB calculation selects an artificially inflated height
- Blocks that haven't been produced yet are marked as irreversible
- This breaks the fundamental finality guarantee: blocks could be marked irreversible before proper consensus
- Cross-chain bridges relying on LIB could accept fraudulent transfers
- Applications depending on finality would be deceived

**Scenario 2: ImpliedIrreversibleBlockHeight Set Too LOW**  
- Malicious miners report heights far below current height
- With 1/3+ miners colluding, they suppress LIB advancement indefinitely
- Legitimate blocks never achieve finality
- Enables long-range reorganization attacks
- Cross-chain operations stall as LIB fails to progress
- Economic activities requiring finality become impossible

This vulnerability affects all network participants, cross-chain bridges, and any applications depending on block finality guarantees, which is fundamental to blockchain security.

## Likelihood Explanation

**Prerequisites:**
- Attacker must control approximately 1/3+ of elected miners to significantly influence LIB calculation
- Miners are elected through DPoS voting system

**Attack Complexity: Low**
1. Miner produces a block normally through the consensus flow
2. Instead of using the honest `ImpliedIrreversibleBlockHeight = Context.CurrentHeight`, they set it to an arbitrary value (as long as it doesn't decrease)
3. Modify both the block header consensus extra data and the transaction input to contain the same manipulated value
4. Submit the block - validation passes because:
   - Before execution: Only checks value doesn't decrease ✓
   - After execution: Header matches state because both were manipulated ✓

**Feasibility:**
- Block producers have control over block header content and transaction inclusion
- No validation enforces `ImpliedIrreversibleBlockHeight == Context.CurrentHeight`
- The validation gap is consistently exploitable on every block
- No detection mechanism exists

**Likelihood: Medium** - Requires control of 1/3+ mining power, but once achieved, the attack is trivial to execute and impossible to detect through current validation logic.

## Recommendation

Add explicit validation that `ImpliedIrreversibleBlockHeight` must equal the current block height. This should be added to the validation logic:

**In `LibInformationValidationProvider.ValidateHeaderInformation`:**
```csharp
// After line 30, add:
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
    providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
    providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != validationContext.CurrentHeight)
{
    validationResult.Message = "Implied lib height must equal current height.";
    return validationResult;
}
```

Alternatively, add validation in `ProcessUpdateValue`:
```csharp
// After line 248, add:
Assert(updateValueInput.ImpliedIrreversibleBlockHeight == Context.CurrentHeight, 
    "Implied irreversible block height must equal current height.");
```

## Proof of Concept

A proof of concept would involve:
1. Setting up a test network with multiple miners
2. Having a miner produce a block with manipulated `ImpliedIrreversibleBlockHeight` (set to `Context.CurrentHeight + 100`)
3. Ensuring both the header consensus extra data and transaction input contain this manipulated value
4. Verifying the block passes validation (only checks non-decreasing)
5. Observing the manipulated value is stored in state
6. With 1/3+ miners using manipulated values, verifying the LIB calculation produces an incorrect result

The test would demonstrate that blocks pass validation despite having incorrect `ImpliedIrreversibleBlockHeight` values, and that these incorrect values influence the LIB calculation as described.

## Notes

The root cause is an **incomplete trust model**: the code assumes miners will honestly set `ImpliedIrreversibleBlockHeight = Context.CurrentHeight` but doesn't enforce this assumption through validation. The validation only checks monotonicity (non-decreasing), not correctness (equality to current height). This is a classic case of missing input validation for a consensus-critical parameter.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L48-48)
```csharp
            ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-30)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-32)
```csharp
            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-101)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```
