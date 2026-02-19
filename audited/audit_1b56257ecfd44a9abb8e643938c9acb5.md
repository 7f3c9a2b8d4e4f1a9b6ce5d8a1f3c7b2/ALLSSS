### Title
Dictionary Key-Pubkey Mismatch Enables Consensus DoS via Corrupted Round Structure

### Summary
The `GetUpdateValueRound()` function and round validation logic lack checks ensuring that dictionary keys in `RealTimeMinersInformation` match the `Pubkey` field within their corresponding `MinerInRound` values. A malicious authorized miner can exploit this by submitting `NextRoundInput` or `NextTermInput` with mismatched key-Pubkey mappings, corrupting the round structure and causing legitimate miners to be unable to produce blocks, resulting in consensus halting.

### Finding Description

The vulnerability exists in the round data structure integrity validation. At multiple critical points, the code fails to validate the invariant that dictionary keys must equal their corresponding `MinerInRound.Pubkey` values: [1](#0-0) 

When `GetUpdateValueRound()` iterates through `RealTimeMinersInformation` and adds entries using `information.Key`, it propagates any existing key-Pubkey mismatches without validation. The `Pubkey` field is set to `information.Value.Pubkey` (line 46), which may differ from the dictionary key.

**Entry Points**: The `NextRound()` and `NextTerm()` methods process user-provided round data: [2](#0-1) [3](#0-2) 

The `ToRound()` conversion blindly copies the dictionary without validation: [4](#0-3) 

**Missing Validation**: The validation providers check various properties but NOT key-Pubkey consistency: [5](#0-4) 

None of the seven validation providers verify that dictionary keys match their `MinerInRound.Pubkey` values. The `NextRoundMiningOrderValidationProvider` only checks `FinalOrderOfNextRound`: [6](#0-5) 

**Storage Without Validation**: The corrupted round is stored directly: [7](#0-6) 

### Impact Explanation

**Consensus Denial of Service**: Once a corrupted round is stored in state, legitimate miners whose actual pubkeys are not dictionary keys will fail when attempting to produce blocks. The `ProcessUpdateValue` function accesses the dictionary using the miner's pubkey: [8](#0-7) 

If the miner's pubkey is not a key (because their `MinerInRound` object is stored under a different key like "MaliciousKey"), line 242 throws `KeyNotFoundException`, preventing the miner from producing blocks.

**Severity**: HIGH
- **Complete consensus halt** if enough miners are locked out
- **Miner disenfranchisement** - legitimate miners cannot participate in consensus
- **Data corruption** - inconsistent round structures persist across subsequent rounds through `GetUpdateValueRound()` propagation
- **Recovery difficulty** - requires governance intervention or chain fork to restore correct round structure

### Likelihood Explanation

**Attacker Capabilities**: Attacker must be an authorized miner in the current miner list, which is verified by: [9](#0-8) 

This is a realistic prerequisite as:
1. Miners are elected through the Election contract
2. A malicious actor could get elected as a miner
3. Even a single compromised miner node is sufficient

**Attack Complexity**: LOW
1. Attacker crafts `NextRoundInput` with corrupted `RealTimeMinersInformation` where keys ≠ Pubkey values
2. Attacker produces a block with this input during their mining time slot
3. No cryptographic signatures or complex operations required
4. Validation passes because no validator checks key-Pubkey consistency

**Detection**: The attack may go unnoticed initially as the block would be accepted and the corrupted round stored. Only when affected miners attempt to produce blocks would failures surface.

**Economic Rationality**: HIGH
- Competitor miners could use this to eliminate rivals from consensus
- Attacker maintains their own mining capability while disabling others
- Low cost (single malicious transaction) vs high impact (consensus disruption)

### Recommendation

**1. Add Key-Pubkey Consistency Validator**

Create a new validation provider:
```csharp
public class RoundStructureIntegrityValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var providedRound = validationContext.ProvidedRound;
        
        foreach (var kvp in providedRound.RealTimeMinersInformation)
        {
            if (kvp.Key != kvp.Value.Pubkey)
            {
                return new ValidationResult
                {
                    Success = false,
                    Message = $"Dictionary key '{kvp.Key}' does not match MinerInRound.Pubkey '{kvp.Value.Pubkey}'"
                };
            }
        }
        
        return new ValidationResult { Success = true };
    }
}
```

Add this validator to the validation pipeline for NextRound and NextTerm behaviors in `ValidateBeforeExecution`.

**2. Add Defensive Check in ToRound()**

In `NextRoundInput.cs` and `NextTermInput.cs`, add validation before copying:
```csharp
public Round ToRound()
{
    // Validate key-Pubkey consistency
    foreach (var kvp in RealTimeMinersInformation)
    {
        Assert(kvp.Key == kvp.Value.Pubkey, 
            $"Invalid round structure: key '{kvp.Key}' != Pubkey '{kvp.Value.Pubkey}'");
    }
    
    return new Round { /* ... */ };
}
```

**3. Add Test Cases**
- Test that `NextRound` with mismatched keys is rejected
- Test that `NextTerm` with mismatched keys is rejected
- Test that legitimate rounds with consistent key-Pubkey mappings are accepted
- Test recovery path if corrupted round somehow enters state

### Proof of Concept

**Initial State**:
- Round N with legitimate miners: Alice, Bob, Charlie
- Alice is the current extra block producer (authorized to call NextRound)

**Attack Steps**:

1. Alice (malicious miner) crafts `NextRoundInput` for round N+1:
```
RealTimeMinersInformation = {
    "Alice": MinerInRound{Pubkey: "Alice", ...},
    "MaliciousKey": MinerInRound{Pubkey: "Bob", ...},
    "Charlie": MinerInRound{Pubkey: "Charlie", ...}
}
```

2. Alice produces block calling `NextRound()` with this corrupted input during her time slot

3. Validation passes (no validator checks key-Pubkey consistency)

4. `ProcessNextRound()` stores the corrupted round via `AddRoundInformation()`

5. Bob attempts to produce his block in round N+1

**Expected Result**: Bob successfully produces block

**Actual Result**: 
- `ProcessUpdateValue()` tries to access `currentRound.RealTimeMinersInformation["Bob"]`
- Key "Bob" doesn't exist (his info is under "MaliciousKey")
- `KeyNotFoundException` thrown
- Bob's transaction fails
- Bob cannot produce blocks
- Consensus halts if enough miners affected

**Success Condition**: Bob's inability to produce blocks despite being a legitimate miner in the round, caused by key-Pubkey mismatch in stored round structure.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L44-52)
```csharp
                round.RealTimeMinersInformation.Add(information.Key, new MinerInRound
                {
                    Pubkey = information.Value.Pubkey,
                    SupposedOrderOfNextRound = information.Value.SupposedOrderOfNextRound,
                    FinalOrderOfNextRound = information.Value.FinalOrderOfNextRound,
                    Order = information.Value.Order,
                    IsExtraBlockProducer = information.Value.IsExtraBlockProducer,
                    PreviousInValue = information.Value.PreviousInValue
                });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-242)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```
