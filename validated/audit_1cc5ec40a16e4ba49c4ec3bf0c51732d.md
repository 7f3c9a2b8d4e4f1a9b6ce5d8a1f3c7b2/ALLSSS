# Audit Report

## Title
Missing Validation Allows Consensus DoS via Zero FinalOrderOfNextRound Values

## Summary
The `ProcessUpdateValue` method in the AEDPoS consensus contract accepts arbitrary `SupposedOrderOfNextRound` values and `TuneOrderInformation` entries without validation, allowing malicious miners to corrupt consensus state with invalid order values (including 0). While `NextRoundMiningOrderValidationProvider` detects this corruption during round transitions, the invalid data has already been written to state, creating a denial-of-service condition that blocks all subsequent round transitions with no built-in recovery mechanism.

## Finding Description

The vulnerability exists in the consensus state update flow where miners submit `UpdateValueInput` data during normal block production.

**Root Cause - Missing Input Validation:**

In `ProcessUpdateValue`, user-controlled values from `UpdateValueInput` are directly assigned to consensus state without range validation: [1](#0-0) 

Additionally, the `TuneOrderInformation` dictionary allows arbitrary key-value pairs to overwrite any miner's `FinalOrderOfNextRound`: [2](#0-1) 

**Why Existing Protections Fail:**

The `UpdateValueValidationProvider` only validates that `OutValue` and `Signature` are non-null/non-empty, and that `PreviousInValue` matches the hash of the previous `OutValue`. It does NOT validate `SupposedOrderOfNextRound` or `FinalOrderOfNextRound` values: [3](#0-2) 

**Detection at NextRound (Too Late):**

The issue is only detected when `NextRoundMiningOrderValidationProvider` validates round transitions. This provider checks that the count of miners with `FinalOrderOfNextRound > 0` equals the count of miners with non-null `OutValue`: [4](#0-3) 

However, this validation only runs for `NextRound` behavior, not for `UpdateValue`: [5](#0-4) 

**Expected vs Actual Behavior:**

By design, `ApplyNormalConsensusData` calculates order values that are always in the valid range [1, minersCount]: [6](#0-5) 

The `GetAbsModulus` function ensures non-negative results: [7](#0-6) 

However, miners control the `UpdateValueInput` they submit via the public `UpdateValue` method: [8](#0-7) 

The only access control is that the sender must be in the miner list: [9](#0-8) 

**Attack Execution:**

A malicious miner can craft an `UpdateValueInput` with:
- Their own `SupposedOrderOfNextRound = 0` 
- `TuneOrderInformation` entries setting other miners' `FinalOrderOfNextRound = 0`

These invalid values bypass validation and get written to state. When any miner attempts `NextRound`, the validation fails because miners have `FinalOrderOfNextRound = 0` but non-null `OutValue`, causing the check to fail and permanently blocking round transitions.

## Impact Explanation

**Complete Consensus Halt:**
- Once invalid `FinalOrderOfNextRound` values are written to state, all subsequent `NextRound` attempts fail validation
- The blockchain cannot progress to the next round
- Block production halts completely
- All network participants experience service interruption
- DApps and users cannot submit transactions
- Economic activity on the chain stops entirely

**No Built-In Recovery:**
The `SupplyCurrentRoundInformation` method called before `NextRound` only fills missing `OutValue`/`Signature` data for non-participating miners - it does not fix corrupted `FinalOrderOfNextRound` values: [10](#0-9) 

Recovery would require governance intervention or chain restart.

**Severity:** High - Complete denial of service of consensus mechanism with no automatic recovery path.

## Likelihood Explanation

**Attack Feasibility:**
- **Entry Point:** Public `UpdateValue` method is the standard entry point for all miners during normal block production
- **Access Control:** Only requires being in the miner list (miners are not trusted roles in the threat model)
- **Technical Complexity:** Low - malicious miner modifies node software to generate invalid `UpdateValueInput` 
- **Collusion Requirement:** Single malicious miner can execute if they produce a block late enough in the round to set invalid values via `TuneOrderInformation` for other miners

**Attack Sequence:**
1. Malicious miner waits for honest miners to submit their `UpdateValue` transactions
2. Malicious miner produces their block with crafted `UpdateValueInput`:
   - `SupposedOrderOfNextRound = 0`
   - `TuneOrderInformation` containing entries for all/most miners with value 0
3. Transaction passes validation (only `OutValue`/`Signature` checked)
4. Invalid values written to consensus state
5. All subsequent `NextRound` attempts fail validation
6. Chain halted

**Economic Considerations:**
While miners have economic incentive to maintain chain operation, a malicious miner could use this for:
- Extortion (demand payment to fix the chain)
- Competitive attack against the network
- Political/ideological attack

**Overall Likelihood:** Medium - Practical to execute with single malicious miner, but requires miner participation which may be uncommon in practice.

## Recommendation

Add validation in `ProcessUpdateValue` to enforce that order values fall within valid ranges:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    
    // Validate SupposedOrderOfNextRound is in valid range [1, minersCount]
    Assert(updateValueInput.SupposedOrderOfNextRound > 0 && 
           updateValueInput.SupposedOrderOfNextRound <= minersCount,
           "Invalid SupposedOrderOfNextRound value.");
    
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
    minerInRound.Signature = updateValueInput.Signature;
    minerInRound.OutValue = updateValueInput.OutValue;
    minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
    minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
    minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

    minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
    minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

    if (IsSecretSharingEnabled())
    {
        PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
    }

    // Validate TuneOrderInformation entries are in valid range
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
    {
        Assert(tuneOrder.Value > 0 && tuneOrder.Value <= minersCount,
               $"Invalid FinalOrderOfNextRound value for miner {tuneOrder.Key}.");
        Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key),
               $"Unknown miner in TuneOrderInformation: {tuneOrder.Key}");
        currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
    }

    // Rest of method unchanged...
}
```

This ensures invalid order values are rejected before being written to state, preventing the DoS attack.

## Proof of Concept

```csharp
[Fact]
public async Task ConsensusDoS_Via_Zero_FinalOrderOfNextRound_Test()
{
    // Initialize consensus with miners
    InitializeContracts();
    await InitializeCandidates(EconomicContractsTestConstants.InitialCoreDataCenterCount);
    
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var firstMiner = currentRound.RealTimeMinersInformation.Values.OrderBy(m => m.Order).First();
    var minerKeyPair = InitialCoreDataCenterKeyPairs.First(k => k.PublicKey.ToHex() == firstMiner.Pubkey);
    
    // Miner produces normal block first
    KeyPairProvider.SetKeyPair(minerKeyPair);
    BlockTimeProvider.SetBlockTime(firstMiner.ExpectedMiningTime);
    var tester = GetAEDPoSContractStub(minerKeyPair);
    
    // Craft malicious UpdateValueInput with SupposedOrderOfNextRound = 0
    var maliciousInput = new UpdateValueInput
    {
        OutValue = HashHelper.ComputeFrom("test"),
        Signature = HashHelper.ComputeFrom("sig"),
        PreviousInValue = Hash.Empty,
        RoundId = currentRound.RoundId,
        ActualMiningTime = Context.CurrentBlockTime,
        SupposedOrderOfNextRound = 0, // INVALID: Should be >= 1
        ImpliedIrreversibleBlockHeight = 1,
        RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(minerKeyPair))
    };
    
    // Also corrupt other miners via TuneOrderInformation
    foreach (var miner in currentRound.RealTimeMinersInformation.Keys.Where(k => k != firstMiner.Pubkey))
    {
        maliciousInput.TuneOrderInformation.Add(miner, 0); // INVALID: Should be >= 1
    }
    
    // Attack: UpdateValue accepts invalid data without validation
    await tester.UpdateValue.SendAsync(maliciousInput);
    
    // Verify state is corrupted
    currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    currentRound.RealTimeMinersInformation[firstMiner.Pubkey].FinalOrderOfNextRound.ShouldBe(0); // Corrupted!
    
    // Try to progress to NextRound - this should FAIL
    var nextRoundInput = await PrepareNextRoundInput(currentRound);
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await tester.NextRound.SendAsync(nextRoundInput);
    });
    
    // Validation fails: "Invalid FinalOrderOfNextRound"
    exception.Message.ShouldContain("Invalid FinalOrderOfNextRound");
    
    // Chain is now stuck - cannot progress to next round
    // No built-in recovery mechanism exists
}
```

## Notes

This vulnerability demonstrates a critical gap in the defense-in-depth approach. While `NextRoundMiningOrderValidationProvider` acts as a fail-safe to prevent propagation of corrupted state to the next round, it does not prevent the corruption from entering state in the first place. The validation should occur at the `UpdateValue` entry point before state modification, not retroactively at `NextRound`. The lack of range validation on user-controlled order values combined with unrestricted `TuneOrderInformation` manipulation creates a practical DoS vector requiring only a single malicious miner.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-21)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L245-248)
```csharp
    private static int GetAbsModulus(long longValue, int intValue)
    {
        return (int)Math.Abs(longValue % intValue);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L171-221)
```csharp
    private void SupplyCurrentRoundInformation()
    {
        var currentRound = GetCurrentRoundInformation(new Empty());
        Context.LogDebug(() => $"Before supply:\n{currentRound.ToString(Context.RecoverPublicKey().ToHex())}");
        var notMinedMiners = currentRound.RealTimeMinersInformation.Values.Where(m => m.OutValue == null).ToList();
        if (!notMinedMiners.Any()) return;
        TryToGetPreviousRoundInformation(out var previousRound);
        foreach (var miner in notMinedMiners)
        {
            Context.LogDebug(() => $"Miner pubkey {miner.Pubkey}");

            Hash previousInValue = null;
            Hash signature = null;

            // Normal situation: previous round information exists and contains this miner.
            if (previousRound != null && previousRound.RealTimeMinersInformation.ContainsKey(miner.Pubkey))
            {
                // Check this miner's:
                // 1. PreviousInValue in current round; (means previous in value recovered by other miners)
                // 2. InValue in previous round; (means this miner hasn't produce blocks for a while)
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
                }
            }

            if (previousInValue == null)
            {
                // Handle abnormal situation.

                // The fake in value shall only use once during one term.
                previousInValue = HashHelper.ComputeFrom(miner);
                signature = previousInValue;
            }

            // Fill this two fields at last.
            miner.InValue = previousInValue;
            miner.Signature = signature;

            currentRound.RealTimeMinersInformation[miner.Pubkey] = miner;
        }

        TryToUpdateRoundInformation(currentRound);
        Context.LogDebug(() => $"After supply:\n{currentRound.ToString(Context.RecoverPublicKey().ToHex())}");
    }
```
