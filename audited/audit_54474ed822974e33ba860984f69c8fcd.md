### Title
Miners Can Manipulate ImpliedIrreversibleBlockHeight to Compromise LIB Finality

### Summary
Miners can arbitrarily manipulate their `ImpliedIrreversibleBlockHeight` value when producing blocks, as the validation only checks that this value does not decrease but fails to verify it equals the current block height. This allows colluding miners controlling approximately 1/3 of the network to either artificially advance the Last Irreversible Block (LIB) height to finalize invalid blocks, or suppress it to prevent legitimate blocks from becoming irreversible, breaking the chain's finality guarantees.

### Finding Description

The vulnerability exists in the consensus block production and validation flow. When a miner produces a block, the `ImpliedIrreversibleBlockHeight` is intended to be set to the current block height in `GetConsensusExtraDataToPublishOutValue`: [1](#0-0) 

However, a malicious miner can modify both the block header consensus extra data and the transaction input to contain any arbitrary value for `ImpliedIrreversibleBlockHeight`. The value is then extracted and included in the `UpdateValueInput`: [2](#0-1) 

The validation performed by `LibInformationValidationProvider` only checks that the new value does not decrease from the miner's previous value: [3](#0-2) 

Critically, there is **no validation** that:
- `ImpliedIrreversibleBlockHeight <= Context.CurrentHeight` (preventing future heights)
- `ImpliedIrreversibleBlockHeight == Context.CurrentHeight` (enforcing correct value)

When the block is executed, the manipulated value is stored directly: [4](#0-3) 

This manipulated value then influences the LIB calculation, which collects implied heights from all miners who have mined, sorts them, and takes the value at index `(count-1)/3`: [5](#0-4) 

The after-execution validation also fails to catch this, as it only verifies the header round matches the stored round by recovering values from the header: [6](#0-5) 

### Impact Explanation

**If ImpliedIrreversibleBlockHeight is set TOO HIGH:**
- Malicious miners can report future block heights (e.g., height 1100 while producing block 1000)
- With approximately 1/3+ of miners colluding, the LIB calculation will select an artificially inflated height
- This can finalize blocks that have not undergone proper validation or consensus
- Invalid transactions, double-spends, or unauthorized state changes could become irreversible
- Cross-chain bridges and applications relying on LIB for finality would accept fraudulent blocks as confirmed
- **Severity: Critical** - Breaks fundamental finality guarantees of the blockchain

**If ImpliedIrreversibleBlockHeight is set TOO LOW:**
- Malicious miners can report much lower heights than their actual block height
- With approximately 1/3+ of miners colluding, they can suppress LIB advancement indefinitely
- Legitimate blocks remain reversible, preventing finality
- Enables long-range reorganization attacks and double-spending
- Cross-chain operations stall as LIB fails to advance
- Economic activities requiring finality guarantees become impossible
- **Severity: Critical** - Creates chain instability and enables double-spend attacks

The vulnerability affects all network participants, validators, cross-chain bridges, and any applications depending on block finality.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must control approximately 1/3+ of elected miners to significantly influence the LIB calculation
- Single malicious miner can slightly skew LIB but impact is limited without collusion
- Miners are elected through the DPoS voting system, requiring either compromise of elected nodes or malicious validators being elected

**Attack Complexity:**
The attack is straightforward to execute:
1. Call `GenerateConsensusTransactions` to obtain proper consensus data
2. Modify the `ImpliedIrreversibleBlockHeight` value in both block header extra data and transaction input to desired manipulated value
3. Submit the block normally - validation will pass as long as value doesn't decrease

**Feasibility:**
- Entry point is the normal block production flow accessible to all elected miners
- No special privileges required beyond being an elected miner
- The validation gap is consistently exploitable on every block produced
- No detection mechanism exists to identify manipulated values

**Economic Rationality:**
- Cost: Requires controlling 1/3+ mining power through election, which has voting/staking costs
- Benefit: Can finalize fraudulent blocks or prevent finality, enabling high-value exploits
- The attack cost is proportional to the value at stake, making it economically viable for high-value targets

**Likelihood: Medium to High** given that elected miners are already trusted nodes, but the missing validation creates an exploitable trust gap.

### Recommendation

Add strict validation in `LibInformationValidationProvider` to enforce that `ImpliedIrreversibleBlockHeight` must equal the current block height being produced:

```csharp
// In LibInformationValidationProvider.ValidateHeaderInformation
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
    providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0)
{
    var minerImpliedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    
    // Check it doesn't decrease
    if (baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight > minerImpliedHeight)
    {
        validationResult.Message = "Incorrect implied lib height.";
        return validationResult;
    }
    
    // NEW: Check it equals current block height being validated
    if (minerImpliedHeight != validationContext.ExtraData.BlockHeight)
    {
        validationResult.Message = "Implied lib height must equal current block height.";
        return validationResult;
    }
    
    // NEW: Additional safety check - cannot exceed current height
    if (minerImpliedHeight > validationContext.ExtraData.BlockHeight)
    {
        validationResult.Message = "Implied lib height cannot exceed current block height.";
        return validationResult;
    }
}
```

Additionally, add defensive checks in `ProcessUpdateValue`:
```csharp
// Before line 248
Assert(
    updateValueInput.ImpliedIrreversibleBlockHeight <= Context.CurrentHeight,
    "Implied irreversible block height cannot exceed current height."
);
Assert(
    updateValueInput.ImpliedIrreversibleBlockHeight == Context.CurrentHeight,
    "Implied irreversible block height must equal current height."
);
```

Add test cases to verify:
1. Blocks with `ImpliedIrreversibleBlockHeight > CurrentHeight` are rejected
2. Blocks with `ImpliedIrreversibleBlockHeight < CurrentHeight` (but not decreasing) are rejected
3. Only blocks with `ImpliedIrreversibleBlockHeight == CurrentHeight` are accepted

### Proof of Concept

**Initial State:**
- Network has 7 elected miners
- Current block height: 1000
- Current LIB: 995
- Miner A's previous `ImpliedIrreversibleBlockHeight`: 999

**Attack Scenario 1: Artificially High LIB**
1. Three colluding miners (A, B, C) produce blocks 1001, 1002, 1003
2. Each manipulates their `ImpliedIrreversibleBlockHeight`:
   - Miner A sets it to 1050 (instead of 1001)
   - Miner B sets it to 1050 (instead of 1002)  
   - Miner C sets it to 1050 (instead of 1003)
3. Validation passes because values don't decrease from previous values
4. When LIB is calculated for round with these miners:
   - Heights collected: [1001, 1002, 1050, 1050, 1050] (from 5 miners)
   - Sorted: [1001, 1002, 1050, 1050, 1050]
   - LIB = heights[(5-1)/3] = heights[1] = 1002
   
   But if 4 colluding miners report 1050:
   - Heights: [1001, 1050, 1050, 1050, 1050]
   - LIB = heights[1] = 1050
5. **Result**: LIB jumps to height 1050, finalizing blocks 1004-1050 that don't exist yet or haven't been properly validated

**Attack Scenario 2: Suppressed LIB**
1. Three colluding miners set their `ImpliedIrreversibleBlockHeight` to 990 (much lower than actual height ~1000)
2. Validation passes because 990 doesn't decrease from their previous values
3. LIB calculation receives many values around 990 instead of 1000
4. **Result**: LIB remains stuck around 990-995, preventing legitimate blocks 996-1000 from becoming irreversible, enabling potential reorganization attacks

**Success Condition:** The manipulated `ImpliedIrreversibleBlockHeight` values are stored in state and used in LIB calculation without rejection, demonstrating the validation gap allows arbitrary height manipulation within the non-decreasing constraint.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L20-33)
```csharp
        public void Deconstruct(out long libHeight)
        {
            if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L19-19)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
```
