# Audit Report

## Title
Dictionary Key-Pubkey Mismatch Enables Consensus DoS via Corrupted Round Structure

## Summary
The AEDPoS consensus contract fails to validate that dictionary keys in `RealTimeMinersInformation` match their corresponding `MinerInRound.Pubkey` values. A malicious elected miner can exploit this validation gap by submitting a corrupted `NextRoundInput` or `NextTermInput` with mismatched key-Pubkey mappings, causing legitimate miners to be locked out of consensus and resulting in blockchain halt.

## Finding Description

The vulnerability exists due to a missing structural invariant validation in the round data integrity checks. The protocol assumes that for each entry in `RealTimeMinersInformation`, the dictionary key must equal the `Pubkey` field of the `MinerInRound` value, but this invariant is never validated.

**Attack Entry Points:**

The `NextRound()` and `NextTerm()` methods are public endpoints that accept user-provided round data: [1](#0-0) 

**Vulnerable Data Conversion:**

The `ToRound()` conversion methods blindly copy the `RealTimeMinersInformation` dictionary without any key-Pubkey consistency validation: [2](#0-1) [3](#0-2) 

**Missing Validation:**

The validation providers applied to NextRound/NextTerm behaviors do NOT check key-Pubkey consistency: [4](#0-3) 

The `NextRoundMiningOrderValidationProvider` only validates mining order counts, not structural integrity: [5](#0-4) 

**Impact on Victim Miners:**

Once the corrupted round is stored via `AddRoundInformation()`: [6](#0-5) 

Victim miners whose pubkeys are not dictionary keys will fail permission checks. The `PreCheck()` method verifies miner authorization using `IsInMinerList()`: [7](#0-6) 

Which checks if the pubkey exists in the dictionary keys: [8](#0-7) 

Additionally, direct dictionary access will throw `KeyNotFoundException`: [9](#0-8) 

**Corruption Propagation:**

The `GetUpdateValueRound()` method propagates existing mismatches by using dictionary keys that may differ from Pubkey values: [10](#0-9) 

## Impact Explanation

**Severity: HIGH - Consensus Denial of Service**

The impact is critical because it directly compromises blockchain availability:

1. **Complete Consensus Halt**: If the attacker targets enough miners (e.g., 2/3 of the miner set), the blockchain cannot progress as insufficient miners can produce blocks.

2. **Miner Disenfranchisement**: Legitimate elected miners are permanently locked out of consensus participation despite being properly authorized, violating the core consensus guarantee.

3. **Persistent State Corruption**: The corrupted round structure persists in state and propagates to subsequent rounds, making recovery extremely difficult without governance intervention or chain fork.

4. **Byzantine Attack Success**: A single malicious miner can compromise the entire consensus mechanism, defeating the Byzantine fault tolerance guarantees.

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Prerequisites:**
- Must be an elected miner in the current miner list
- This is realistic as miners are elected through the public Election contract
- Even a single compromised or malicious elected miner is sufficient

**Attack Complexity: LOW**
1. Attacker waits for their scheduled mining time slot
2. Crafts a `NextRoundInput` where some miners' `MinerInRound` objects are stored under arbitrary keys instead of their pubkeys
3. Includes this malicious input in their NextRound transaction
4. No cryptographic operations or complex exploits required

**Detection Difficulty:**
The attack succeeds silently - the malicious block is accepted as valid. Failures only become apparent when victim miners attempt to produce blocks and fail permission checks.

**Economic Incentive:**
- Competing miners could eliminate rivals from consensus
- Attacker maintains their own mining capability while disabling others
- Very low cost (single transaction) versus high impact (consensus disruption)

## Recommendation

Add explicit validation to ensure dictionary keys match their `MinerInRound.Pubkey` values:

```csharp
// Add new validation provider
public class RoundStructureValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var providedRound = validationContext.ProvidedRound;
        
        // Validate key-Pubkey consistency
        foreach (var kvp in providedRound.RealTimeMinersInformation)
        {
            if (kvp.Key != kvp.Value.Pubkey)
            {
                return new ValidationResult 
                { 
                    Message = $"Dictionary key '{kvp.Key}' does not match MinerInRound.Pubkey '{kvp.Value.Pubkey}'" 
                };
            }
        }
        
        return new ValidationResult { Success = true };
    }
}
```

Register this provider in the validation chain:

```csharp
// In AEDPoSContract_Validation.cs ValidateBeforeExecution method
var validationProviders = new List<IHeaderInformationValidationProvider>
{
    new MiningPermissionValidationProvider(),
    new TimeSlotValidationProvider(),
    new ContinuousBlocksValidationProvider(),
    new RoundStructureValidationProvider() // ADD THIS
};
```

## Proof of Concept

```csharp
// POC Test demonstrating the vulnerability
[Fact]
public async Task MaliciousMiner_CanCorruptRoundStructure_CausingConsensusDoS()
{
    // Setup: Initialize consensus with 3 miners (Alice, Bob, Charlie)
    var miners = new[] { "Alice_Pubkey", "Bob_Pubkey", "Charlie_Pubkey" };
    await InitializeConsensusWithMiners(miners);
    
    // Attack: Charlie produces a block with corrupted NextRoundInput
    var maliciousNextRoundInput = new NextRoundInput
    {
        RoundNumber = 2,
        RealTimeMinersInformation = 
        {
            // Alice's data stored under WRONG key
            ["MaliciousKey"] = new MinerInRound 
            { 
                Pubkey = "Alice_Pubkey",  // Pubkey != dictionary key
                Order = 1,
                ExpectedMiningTime = Timestamp.FromDateTime(DateTime.UtcNow.AddSeconds(4000))
            },
            ["Bob_Pubkey"] = new MinerInRound 
            { 
                Pubkey = "Bob_Pubkey", 
                Order = 2,
                ExpectedMiningTime = Timestamp.FromDateTime(DateTime.UtcNow.AddSeconds(8000))
            },
            ["Charlie_Pubkey"] = new MinerInRound 
            { 
                Pubkey = "Charlie_Pubkey", 
                Order = 3,
                ExpectedMiningTime = Timestamp.FromDateTime(DateTime.UtcNow.AddSeconds(12000))
            }
        },
        RandomNumber = ByteString.CopyFromUtf8("random")
    };
    
    // Execute attack
    await CharlieProducesBlockWithInput(maliciousNextRoundInput);
    
    // Verify: Alice can no longer produce blocks (DoS achieved)
    var aliceCanMine = await AliceAttemptsToProduce();
    Assert.False(aliceCanMine); // Fails because "Alice_Pubkey" not in dictionary keys
    
    // Verify: Consensus is disrupted
    var currentRound = await GetCurrentRound();
    Assert.False(currentRound.IsInMinerList("Alice_Pubkey")); // Returns false despite Alice being legitimate miner
    Assert.True(currentRound.RealTimeMinersInformation.ContainsKey("MaliciousKey")); // Corrupted key exists
}
```

## Notes

This vulnerability represents a critical failure in the consensus mechanism's structural invariant validation. The fix requires adding validation at the earliest point where user-provided round data enters the system, before it is converted via `ToRound()` and stored. The validation must be applied to both `NextRound` and `NextTerm` behaviors to fully address the issue.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L25-40)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-91)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L242-242)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L35-53)
```csharp
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
```
