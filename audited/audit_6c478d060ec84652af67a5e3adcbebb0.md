### Title
Continuous Blocks Limit Bypass via RoundNumber Manipulation in UpdateValue/TinyBlock Behaviors

### Summary
The `GetUpdateValueRound` and `GetTinyBlockRound` methods copy RoundNumber directly without validation, and no validation provider checks that the RoundNumber in the simplified round matches the current round for UpdateValue/TinyBlock behaviors. This allows a malicious miner to provide an arbitrary RoundNumber (e.g., 1 or 2) in their block header to bypass the continuous blocks limit enforced by `ContinuousBlocksValidationProvider`, enabling unlimited consecutive block production and monopolization of the consensus.

### Finding Description

The vulnerability exists across multiple locations: [1](#0-0) [2](#0-1) 

Both methods copy `RoundNumber` directly from the current round without any validation. For NextRound and NextTerm behaviors, explicit validation exists: [3](#0-2) 

However, for UpdateValue and TinyBlock behaviors, the validation providers list does not include any check that validates the RoundNumber matches the current round: [4](#0-3) 

The `ContinuousBlocksValidationProvider` uses the unvalidated `ProvidedRound.RoundNumber` from the block header to decide whether to enforce the continuous blocks limit: [5](#0-4) 

The check at line 13 skips continuous blocks validation if `ProvidedRound.RoundNumber <= 2`. Since there is no validation ensuring the provided RoundNumber matches the actual current round, an attacker can set RoundNumber to 1 or 2 to bypass this critical protection.

The continuous blocks limit is designed to prevent miners from monopolizing block production: [6](#0-5) 

### Impact Explanation

**Consensus Integrity Compromise:**
- A malicious miner can bypass the MaximumTinyBlocksCount (8 blocks) limit by providing a fake RoundNumber ≤ 2 in their block headers
- This allows unlimited consecutive block production, enabling complete monopolization of the blockchain
- Other legitimate miners are starved of block production opportunities
- The attacker gains censorship power over transactions and can manipulate transaction ordering

**Severity Justification:**
This is a **Critical** vulnerability because:
1. It completely undermines the fairness guarantee of the AEDPoS consensus mechanism
2. Enables a single miner to control 100% of block production instead of their fair share (1/N where N = number of miners)
3. Breaks the decentralization properties fundamental to consensus security
4. Can lead to long-range censorship and transaction manipulation attacks

### Likelihood Explanation

**High Likelihood:**

**Reachable Entry Point:** Any active miner in the consensus set can exploit this by producing blocks with UpdateValue or TinyBlock behavior, which are standard consensus operations.

**Feasible Preconditions:**
- Attacker must be in the current miner list (requires stake/election, but this is normal for any miner)
- No special privileges beyond normal miner status required

**Execution Practicality:**
The attack is trivial to execute:
1. When producing a block with UpdateValue or TinyBlock behavior, modify the consensus extra data
2. Set `RoundNumber = 1` or `RoundNumber = 2` in the simplified round
3. The block passes validation because no validator checks if this matches the actual current round
4. The continuous blocks check is bypassed (line 13 condition fails)
5. Miner can continue producing blocks indefinitely

**Economic Rationality:**
- Attack cost: Minimal (just modifying a field in the consensus header)
- Attack benefit: Complete control of block production, MEV extraction, censorship capability
- Risk/reward ratio heavily favors the attacker

**Detection Difficulty:** The manipulation may be difficult to detect initially as the round information in state remains correct; only the block header contains the fake RoundNumber.

### Recommendation

**Immediate Fix:**
Add explicit RoundNumber validation for UpdateValue and TinyBlock behaviors in `ValidateBeforeExecution`:

In `AEDPoSContract_Validation.cs`, after line 51, add:
```csharp
// Validate RoundNumber matches for UpdateValue and TinyBlock
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue || 
    extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
{
    if (extraData.Round.RoundNumber != validationContext.CurrentRoundNumber)
        return new ValidationResult 
        { 
            Success = false, 
            Message = $"Round number mismatch: provided {extraData.Round.RoundNumber}, expected {validationContext.CurrentRoundNumber}" 
        };
}
```

**Alternative Fix:**
Modify `ContinuousBlocksValidationProvider` to use the validated `BaseRound.RoundNumber` instead of `ProvidedRound.RoundNumber`: [7](#0-6) 

Change line 13 from:
```csharp
if (validationContext.ProvidedRound.RoundNumber > 2 &&
```
To:
```csharp
if (validationContext.BaseRound.RoundNumber > 2 &&
```

**Test Cases:**
1. Test that UpdateValue/TinyBlock with mismatched RoundNumber is rejected
2. Test that RoundNumber = 1 when actual round > 2 is rejected
3. Test that continuous blocks limit is properly enforced regardless of provided RoundNumber
4. Regression test for legitimate first two rounds behavior

### Proof of Concept

**Initial State:**
- Current round number: 100 (well past round 2)
- Miner M has produced 8 consecutive blocks (MaximumTinyBlocksCount limit reached)
- `LatestPubkeyToTinyBlocksCount.BlocksCount` for M = -1 (below zero, should fail validation)

**Attack Sequence:**

1. Miner M creates a block with UpdateValue behavior
2. In `GetConsensusBlockExtraData`, the normal flow would create a simplified round with RoundNumber = 100
3. **Attacker modifies** the consensus extra data to set `RoundNumber = 1` before submitting the block
4. During `ValidateBeforeExecution`:
   - `TryToGetCurrentRoundInformation` fetches baseRound with RoundNumber = 100
   - Validation providers execute:
     - `MiningPermissionValidationProvider`: PASS (miner is in list)
     - `TimeSlotValidationProvider`: PASS (within time slot)
     - `ContinuousBlocksValidationProvider`: 
       - Line 13: `validationContext.ProvidedRound.RoundNumber > 2` evaluates to FALSE (1 is not > 2)
       - **Entire continuous blocks check is SKIPPED**
       - Returns Success = true
5. Block is accepted despite exceeding continuous blocks limit
6. Miner M can repeat indefinitely, producing all blocks

**Expected Result:** Block should be rejected due to continuous blocks limit violation

**Actual Result:** Block is accepted, miner continues monopolizing block production

**Success Condition:** Miner M produces > 8 consecutive blocks when this should be impossible under normal consensus rules

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L11-56)
```csharp
    public Round GetUpdateValueRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
            RealTimeMinersInformation =
            {
                [pubkey] = new MinerInRound
                {
                    Pubkey = pubkey,
                    OutValue = minerInRound.OutValue,
                    Signature = minerInRound.Signature,
                    ProducedBlocks = minerInRound.ProducedBlocks,
                    ProducedTinyBlocks = minerInRound.ProducedTinyBlocks,
                    PreviousInValue = minerInRound.PreviousInValue,
                    ActualMiningTimes = { minerInRound.ActualMiningTimes },
                    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
                    Order = minerInRound.Order,
                    IsExtraBlockProducer = minerInRound.IsExtraBlockProducer
                }
            }
        };
        foreach (var information in RealTimeMinersInformation)
            if (information.Key == pubkey)
            {
                round.RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound =
                    minerInRound.SupposedOrderOfNextRound;
                round.RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = minerInRound.FinalOrderOfNextRound;
            }
            else
            {
                round.RealTimeMinersInformation.Add(information.Key, new MinerInRound
                {
                    Pubkey = information.Value.Pubkey,
                    SupposedOrderOfNextRound = information.Value.SupposedOrderOfNextRound,
                    FinalOrderOfNextRound = information.Value.FinalOrderOfNextRound,
                    Order = information.Value.Order,
                    IsExtraBlockProducer = information.Value.IsExtraBlockProducer,
                    PreviousInValue = information.Value.PreviousInValue
                });
            }

        return round;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L58-82)
```csharp
    public Round GetTinyBlockRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
            RealTimeMinersInformation =
            {
                [pubkey] = new MinerInRound
                {
                    Pubkey = minerInRound.Pubkey,
                    ActualMiningTimes = { minerInRound.ActualMiningTimes },
                    ProducedBlocks = minerInRound.ProducedBlocks,
                    ProducedTinyBlocks = minerInRound.ProducedTinyBlocks,
                    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight
                }
            }
        };

        foreach (var otherPubkey in RealTimeMinersInformation.Keys.Except(new List<string> { pubkey }))
            round.RealTimeMinersInformation.Add(otherPubkey, new MinerInRound());

        return round;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-92)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };

        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L8-28)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Is sender produce too many continuous blocks?
        var validationResult = new ValidationResult();

        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
        {
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```
