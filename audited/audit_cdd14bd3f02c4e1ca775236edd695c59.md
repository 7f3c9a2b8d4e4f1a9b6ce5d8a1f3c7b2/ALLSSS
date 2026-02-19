# Audit Report

## Title
Missing Upper Bound Validation for ImpliedIrreversibleBlockHeight Allows LIB Manipulation

## Summary
The AEDPoS consensus contract accepts `ImpliedIrreversibleBlockHeight` values in `UpdateValue` transactions without validating they do not exceed the current block height. This allows miners to submit artificially high values that, when >= 1/3 of miners participate, can manipulate the Last Irreversible Block (LIB) calculation to mark future/non-existent blocks as finalized, violating consensus integrity.

## Finding Description

The vulnerability exists in the consensus update flow where miners' `ImpliedIrreversibleBlockHeight` values are accepted without proper upper bound validation:

**1. System Correctly Generates Values:**
When generating consensus block extra data, the system properly sets the value to the current block height: [1](#0-0) 

**2. Missing Upper Bound Validation:**
The `LibInformationValidationProvider` only validates that `ImpliedIrreversibleBlockHeight` does not decrease from the previous value, but does not check if it exceeds the current block height: [2](#0-1) 

**3. Direct Assignment Without Validation:**
`ProcessUpdateValue` directly assigns the input value to the miner's round information without any upper bound check: [3](#0-2) 

**4. Values Used in LIB Calculation:**
The LIB calculator retrieves `ImpliedIrreversibleBlockHeight` values from miners in the previous round, sorts them, and takes the value at position `(count-1)/3`. If >= 1/3 of miners provide inflated values, the resulting LIB will be artificially high: [4](#0-3) 

**5. Miners Can Submit Custom UpdateValue Transactions:**
Miners call the public `UpdateValue` method with `UpdateValueInput`, which they control and sign: [5](#0-4) 

**Attack Flow:**
1. Miner at block height 1000 creates a custom `UpdateValue` transaction
2. Sets `ImpliedIrreversibleBlockHeight = 11000` (instead of 1000)
3. Validation only checks the value doesn't decrease (passes)
4. `ProcessUpdateValue` stores the inflated value (11000) in state
5. In subsequent blocks, `LastIrreversibleBlockHeightCalculator` uses these values
6. If >= 1/3 miners provide inflated values, the LIB at position `(count-1)/3` becomes inflated
7. Blockchain marks future/non-existent blocks as irreversible

**Root Cause:**
The protocol assumes miners will honestly set `ImpliedIrreversibleBlockHeight = Context.CurrentHeight` but never validates this invariant. The constraint is enforced at generation time but not at validation/acceptance time.

## Impact Explanation

**Critical Consensus Invariant Violation:**
- **Premature Finalization**: The LIB mechanism would mark blocks that haven't been produced (or don't exist yet) as irreversible, breaking the fundamental finality guarantee
- **Chain State Inconsistency**: Nodes may reject blocks or experience divergent views of finality, potentially causing chain halts or forks
- **Cross-Chain Impact**: Invalid LIB heights could be propagated to cross-chain mechanisms that rely on finality for settlement, causing cross-chain transaction failures or security issues
- **Consensus Integrity Breakdown**: The BFT consensus assumption requires 2/3+1 honest agreement on the LIB, but inflated values subvert this calculation

**Severity Justification:**
This is a **Critical** impact because it violates a core consensus invariant (LIB correctness). The Last Irreversible Block is a fundamental security primitive that applications, cross-chain protocols, and the blockchain itself rely upon for finality guarantees. Manipulating this value can cause system-wide failures and undermines the trust model of the entire blockchain.

## Likelihood Explanation

**Attack Prerequisites:**
- Attacker must be an active miner in the consensus round
- Must create a custom `UpdateValue` transaction instead of using the system-generated one
- Requires >= 1/3 of miners to provide inflated values for the attack to succeed

**Technical Complexity:**
- **Low**: Simply modify the `ImpliedIrreversibleBlockHeight` field in `UpdateValueInput` before signing
- **No on-chain validation** prevents the attack once the preconditions are met
- The inflated value passes all existing validation checks

**Feasibility Assessment:**
- Requires >= 1/3 miner collusion or control (at the BFT assumption boundary)
- However, the protocol **should enforce correct behavior** even within BFT assumptions (defense in depth)
- Once a miner decides to attack, there are no technical barriers

**Detection:**
- Would be detected post-facto when LIB jumps to impossible heights
- No preventive on-chain mechanism exists
- Observable through monitoring but not preventable once transactions are accepted

**Likelihood Rating:** Medium-High given that:
1. The missing validation makes execution straightforward once >= 1/3 miner threshold is achieved
2. While requiring >= 1/3 miners is a significant prerequisite, the protocol should still enforce invariants rather than rely solely on honesty

## Recommendation

Add upper bound validation in `LibInformationValidationProvider` to enforce that `ImpliedIrreversibleBlockHeight` cannot exceed a reasonable upper bound relative to the current block height:

```csharp
// In LibInformationValidationProvider.ValidateHeaderInformation
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
    providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0)
{
    var impliedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    
    // Check that it doesn't decrease
    if (baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight > impliedHeight)
    {
        validationResult.Message = "Incorrect implied lib height.";
        return validationResult;
    }
    
    // NEW: Check that it doesn't exceed current block height
    if (impliedHeight > validationContext.ExtraData.Round.RealTimeMinersInformation[pubkey].ActualMiningTimes.Last().Seconds / 1000)
    {
        validationResult.Message = "Implied lib height exceeds current block height.";
        return validationResult;
    }
}
```

Alternatively, add validation directly in `ProcessUpdateValue` before storing the value:

```csharp
// In ProcessUpdateValue
if (updateValueInput.ImpliedIrreversibleBlockHeight > Context.CurrentHeight)
{
    Assert(false, "ImpliedIrreversibleBlockHeight cannot exceed current block height.");
}
minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

## Proof of Concept

```csharp
[Fact]
public async Task ImpliedIrreversibleBlockHeight_CanBeInflated_WithoutValidation()
{
    // Setup: Initialize consensus with initial miners
    var initialMiners = GenerateInitialMiners(5);
    await InitializeConsensus(initialMiners);
    
    // Produce first round of blocks normally
    await ProduceNormalBlocks(initialMiners, roundsCount: 2);
    
    // Get current state
    var currentRound = await GetCurrentRoundInformation();
    var currentHeight = await GetCurrentBlockHeight(); // e.g., 100
    
    // Attack: Miner creates UpdateValue with inflated ImpliedIrreversibleBlockHeight
    var maliciousMiner = initialMiners[0];
    var maliciousUpdateInput = CreateUpdateValueInput(currentRound, maliciousMiner);
    
    // Inflate the value far beyond current height
    maliciousUpdateInput.ImpliedIrreversibleBlockHeight = currentHeight + 10000; // e.g., 10100
    
    // Submit the malicious UpdateValue transaction
    var result = await ExecuteUpdateValue(maliciousMiner, maliciousUpdateInput);
    
    // Vulnerability: Transaction succeeds despite inflated value
    result.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify the inflated value was stored
    var updatedRound = await GetCurrentRoundInformation();
    var storedHeight = updatedRound.RealTimeMinersInformation[maliciousMiner.Pubkey]
        .ImpliedIrreversibleBlockHeight;
    
    // Assertion: The inflated value is accepted and stored
    storedHeight.ShouldBe(currentHeight + 10000);
    
    // If 1/3+ miners do this, LIB calculation will use inflated values
    // causing future/non-existent blocks to be marked as irreversible
}
```

## Notes

This vulnerability represents a protocol invariant violation where the system correctly generates values but fails to enforce that participants use them. While the attack requires >= 1/3 miner participation (at the BFT assumption boundary), best practices in consensus protocol design dictate that invariants should be enforced through validation rather than relying solely on assumed honesty. This is a defense-in-depth issue where the missing validation creates an exploitable gap in the consensus security model.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
