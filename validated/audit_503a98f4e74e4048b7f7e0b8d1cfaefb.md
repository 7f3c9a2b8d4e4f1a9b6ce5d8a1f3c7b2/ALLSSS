# Audit Report

## Title
Time Slot Validation Bypass via Unvalidated ActualMiningTime in Consensus Header

## Summary
The AEDPoS consensus validation logic fails to verify that miner-provided `ActualMiningTime` values in consensus extra data match the actual block timestamp. This allows malicious miners to bypass time slot restrictions by providing fake timestamps that fall within valid boundaries, enabling block production outside assigned time windows and violating fundamental consensus ordering guarantees.

## Finding Description

The vulnerability exists in the consensus header validation flow where time slot enforcement relies on attacker-controlled data without integrity verification.

**Attack Execution Path:**

During validation, `ValidateBeforeExecution` recovers `BaseRound` by merging unvalidated data from `ProvidedRound` (consensus extra data): [1](#0-0) 

The recovery methods blindly add `ActualMiningTimes` from the attacker-controlled `ProvidedRound` to `BaseRound`: [2](#0-1) [3](#0-2) 

`TimeSlotValidationProvider` then validates using the recovered `BaseRound`, extracting the attacker-controlled `latestActualMiningTime`: [4](#0-3) 

**Why Protections Fail:**

When honest miners generate consensus extra data, they populate `ActualMiningTimes` with `Context.CurrentBlockTime`: [5](#0-4) [6](#0-5) 

However, **no validation exists** to verify this relationship. The `UpdateValueValidationProvider` only checks cryptographic values, not timestamps: [7](#0-6) 

Post-execution hash validation explicitly excludes `ActualMiningTimes` from the integrity check: [8](#0-7) 

After validation passes, `ProcessUpdateValue` records the fake timestamp in blockchain state without verification: [9](#0-8) 

## Impact Explanation

**Consensus Integrity Violation:**
This vulnerability breaks the fundamental time slot ordering mechanism of AEDPoS consensus. Miners can produce blocks outside their assigned time slots by providing fake `ActualMiningTime` values that fall within valid boundaries, regardless of the actual block time.

**Concrete Harm:**
- Malicious miners gain unfair block production advantages through continuous mining
- Violates round-robin scheduling and expected mining time guarantees
- Enables consensus manipulation and potential centralization
- Disrupts fair block reward distribution
- Honest miners lose rightful block production opportunities

**Severity:** HIGH - Directly violates a critical consensus invariant with a concrete exploitation path and significant impact on network security and fairness.

## Likelihood Explanation

**Attacker Capabilities:**
- Must be a valid miner in the active miner list
- Full control over consensus extra data generation and signing
- No special privileges beyond normal miner status required

**Attack Complexity:**
- LOW - Attacker modifies `ActualMiningTime` in consensus header extra data before signing
- No complex contract interactions required
- Attack occurs in data the attacker fully controls before submission

**Feasibility:**
- HIGHLY FEASIBLE - Any active miner can execute at any time
- No preconditions beyond being in the miner list
- Attack is deterministic and repeatable
- Difficult to detect as fake timestamps can be crafted to appear plausible within valid ranges

## Recommendation

Add explicit validation in `ValidateBeforeExecution` or `ProcessUpdateValue` to verify that the provided `ActualMiningTime` matches `Context.CurrentBlockTime`:

```csharp
// In ProcessUpdateValue or a new validation provider
if (updateValueInput.ActualMiningTime != Context.CurrentBlockTime)
{
    Assert(false, "ActualMiningTime must match block timestamp");
}
```

Alternatively, during block execution, validate that the last `ActualMiningTime` added to the round matches the block header time. This ensures miners cannot provide fake timestamps that differ from the actual block production time.

## Proof of Concept

```csharp
[Fact]
public async Task ActualMiningTime_CanBeFaked_BypassesTimeSlotValidation()
{
    // Setup: Malicious miner in round 
    var maliciousMiner = InitialCoreDataCenterKeyPairs[0];
    await BlockMiningService.MineBlockAsync();
    
    // Get current round and expected mining time
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerInfo = currentRound.RealTimeMinersInformation[maliciousMiner.PublicKey.ToHex()];
    var actualBlockTime = TimestampHelper.GetUtcNow();
    
    // Attack: Generate consensus extra data with FAKE ActualMiningTime
    // Set fake time to be within valid slot but different from actual block time
    var fakeTime = minerInfo.ExpectedMiningTime.AddMilliseconds(100); 
    var attackRound = currentRound.Clone();
    attackRound.RealTimeMinersInformation[maliciousMiner.PublicKey.ToHex()]
        .ActualMiningTimes.Add(fakeTime); // FAKE TIME
    
    // Create block with mismatched times:
    // - BlockHeader.Time = actualBlockTime 
    // - ConsensusExtraData.ActualMiningTime = fakeTime
    var block = await GenerateBlockWithFakeActualMiningTime(
        actualBlockTime, fakeTime, maliciousMiner);
    
    // Validation should fail but passes - vulnerability confirmed
    var validationResult = await ConsensusStub.ValidateConsensusBeforeExecution
        .CallAsync(block.Header.ConsensusExtraData);
    
    Assert.True(validationResult.Success); // Validation passes with fake time!
    
    // Verify fake time is recorded in state
    var updatedRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var recordedTime = updatedRound.RealTimeMinersInformation[maliciousMiner.PublicKey.ToHex()]
        .ActualMiningTimes.Last();
    Assert.Equal(fakeTime, recordedTime); // Fake time is in blockchain state
    Assert.NotEqual(actualBlockTime, recordedTime); // Proves bypass
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-20)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L35-44)
```csharp
    public Round RecoverFromTinyBlock(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-50)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L62-63)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L162-163)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-193)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-243)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
```
