# Audit Report

## Title
Missing Validation Allows Consensus DoS via Zero FinalOrderOfNextRound Values

## Summary
The AEDPoS consensus contract's `ProcessUpdateValue` method accepts miner-provided `UpdateValueInput` containing `SupposedOrderOfNextRound` and `TuneOrderInformation` values without validating they fall within the valid range [1, minersCount]. This allows malicious miners to set `FinalOrderOfNextRound` to 0, which corrupts the consensus state. While `NextRoundMiningOrderValidationProvider` detects this during round transitions, it occurs after the invalid data has been committed, creating an unrecoverable denial-of-service condition that blocks all future round progressions.

## Finding Description

The vulnerability exists in the consensus data processing flow where miner-submitted values are trusted without validation.

**Root Cause - Missing Input Validation:**

In `ProcessUpdateValue`, the `SupposedOrderOfNextRound` from `UpdateValueInput` is directly assigned to both fields without range validation: [1](#0-0) 

Additionally, `TuneOrderInformation` allows setting arbitrary `FinalOrderOfNextRound` values for any miner: [2](#0-1) 

**Inadequate Validation Provider:**

The `UpdateValueValidationProvider` only validates cryptographic fields (OutValue, Signature) and PreviousInValue correctness, but does NOT check mining order values: [3](#0-2) 

**Late Detection Creates DoS:**

The issue is only detected when `NextRoundMiningOrderValidationProvider` executes during round transition attempts: [4](#0-3) 

This validator checks that miners with `FinalOrderOfNextRound > 0` equals miners with `OutValue != null`. If a miner has `FinalOrderOfNextRound = 0` but has mined (OutValue present), the counts mismatch and validation fails.

**Expected Behavior Bypassed:**

By design, `ApplyNormalConsensusData` calculates proper values in range [1, minersCount]: [5](#0-4) 

The `GetAbsModulus` helper ensures values are in valid range: [6](#0-5) 

Since `GetAbsModulus` returns [0, minersCount-1] and adds 1, the result is always [1, minersCount]. However, miners control `UpdateValueInput` and can bypass this calculation by submitting arbitrary values directly.

**Attack Execution Flow:**
1. Malicious miner modifies their node software to generate `UpdateValueInput` with `SupposedOrderOfNextRound = 0`
2. Submits via public `UpdateValue` method during their mining slot
3. Contract accepts and commits the invalid value to state
4. When any miner attempts `NextRound`, validation fails due to count mismatch
5. Round transition permanently blocked - no new rounds can begin
6. Blockchain consensus halted

## Impact Explanation

**Severity: High (Consensus DoS)**

This vulnerability enables complete denial-of-service of the blockchain's consensus mechanism:

- **Direct Impact**: Chain cannot transition to next round, halting all block production
- **Scope**: Affects all network participants - no transactions can be processed
- **Recovery**: No built-in contract method to reset corrupted `FinalOrderOfNextRound` values; requires governance intervention or chain restart
- **Persistence**: State corruption persists until manually corrected

**Attack Efficiency:**
- Single malicious miner can cause DoS by corrupting their own `FinalOrderOfNextRound`
- Alternatively, a miner could use `TuneOrderInformation` to corrupt other miners' values if coordination allows
- Attack cost is minimal - just requires modified node software

**Parties Affected:**
- All users cannot submit transactions
- DApps experience complete service outage  
- Economic activity on chain stops entirely
- Validator rewards cannot be distributed

## Likelihood Explanation

**Likelihood: Medium-High**

**Feasibility Factors:**

*Technical Complexity:* Low
- Miners run their own node software on their infrastructure
- Modifying `UpdateValueInput` generation is straightforward code change
- No complex cryptographic or multi-step exploitation required

*Entry Point:* Public and Accessible
- `UpdateValue` is the standard public method miners call when producing blocks [7](#0-6) 
- Called during normal consensus operation, no special permissions needed beyond being a miner

*Attack Variants:*
1. Single malicious miner sets own `FinalOrderOfNextRound = 0`
2. Coordinated miners set multiple values to 0
3. Malicious miner uses `TuneOrderInformation` to corrupt others (if extractable)

*Economic Considerations:*
- Miners typically have economic incentive to maintain chain operation
- However, malicious actors, competing chains, or extortionists could exploit
- Attack provides leverage for ransom/extortion scenarios
- Griefing competitors in multi-chain ecosystems

**Detection:** Attack is undetectable until NextRound is attempted, by which time state is already corrupted.

## Recommendation

**Primary Fix: Add Input Validation in ProcessUpdateValue**

Validate that `SupposedOrderOfNextRound` and all `TuneOrderInformation` values are within valid range [1, minersCount]:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    
    // Validate SupposedOrderOfNextRound is in valid range
    Assert(
        updateValueInput.SupposedOrderOfNextRound >= 1 && 
        updateValueInput.SupposedOrderOfNextRound <= minersCount,
        $"Invalid SupposedOrderOfNextRound. Must be between 1 and {minersCount}.");
    
    // Validate all TuneOrderInformation values
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
    {
        Assert(
            tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount,
            $"Invalid FinalOrderOfNextRound in TuneOrderInformation. Must be between 1 and {minersCount}.");
    }
    
    // Rest of existing logic...
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
    minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
    // ... continue with rest of method
}
```

**Additional Hardening:**
- Add validation to `UpdateValueValidationProvider` as defense-in-depth
- Consider uniqueness check to prevent duplicate `FinalOrderOfNextRound` values across miners
- Add monitoring/alerting for anomalous order values in production

**Recovery Mechanism:**
- Implement governance-controlled method to reset consensus state in emergency scenarios
- Add circuit breaker for consensus failures

## Proof of Concept

```csharp
[Fact]
public async Task ConsensusDoS_ViaZeroFinalOrderOfNextRound()
{
    // Setup: Initialize chain with 3 miners
    var initialMiners = new[] { "miner1", "miner2", "miner3" };
    await InitializeConsensusWithMiners(initialMiners);
    
    // Miner1 produces first block normally
    await ProduceNormalBlock("miner1");
    
    // Attacker (miner2) submits malicious UpdateValue with SupposedOrderOfNextRound = 0
    var maliciousInput = new UpdateValueInput
    {
        OutValue = GenerateValidOutValue(),
        Signature = GenerateValidSignature(),
        PreviousInValue = GetPreviousInValue("miner2"),
        SupposedOrderOfNextRound = 0, // MALICIOUS VALUE
        ActualMiningTime = Timestamp.FromDateTime(DateTime.UtcNow),
        RoundId = GetCurrentRoundId(),
        ImpliedIrreversibleBlockHeight = GetCurrentHeight()
    };
    
    // Submit malicious UpdateValue - should be accepted (vulnerability)
    var updateResult = await ConsensusStub.UpdateValue.SendAsync(maliciousInput);
    updateResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify miner2 has FinalOrderOfNextRound = 0 in state
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    currentRound.RealTimeMinersInformation["miner2"].FinalOrderOfNextRound.ShouldBe(0);
    
    // Miner3 produces normal block
    await ProduceNormalBlock("miner3");
    
    // Attempt to transition to NextRound - should FAIL due to validation
    var nextRoundInput = GenerateNextRoundInput(currentRound);
    var nextRoundResult = await ConsensusStub.NextRound.SendWithExceptionAsync(nextRoundInput);
    
    // Assert: NextRound validation fails
    nextRoundResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    nextRoundResult.TransactionResult.Error.ShouldContain("Invalid FinalOrderOfNextRound");
    
    // Consensus is now permanently stuck - no recovery possible
    // Chain cannot progress to next round
}
```

**Notes:**
- This vulnerability breaks a critical consensus invariant: all miners who produced blocks must have valid mining orders for the next round
- The validation occurs too late (at NextRound) to prevent the DoS
- Even with economic disincentives, malicious actors can exploit this for extortion or competitive advantage
- No automatic recovery mechanism exists in the codebase

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
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
