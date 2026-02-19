# Audit Report

## Title
Missing Miners Count Validation in NextTerm Allows Bypass of Maximum Miner Restrictions

## Summary
The `ProcessNextTerm` method does not validate that the number of miners in the provided `NextTermInput` is within the governance-controlled maximum count. A malicious miner can call the public `NextTerm` RPC method with a crafted input containing excessive miner entries, bypassing the restriction enforced by `SetMaximumMinersCount`.

## Finding Description

The vulnerability exists in the consensus term transition logic where miner count validation is missing. 

The `NextTerm` RPC method is publicly accessible and processes term transitions via `ProcessConsensusInformation`: [1](#0-0) 

The only permission check performed is `PreCheck`, which validates that the **caller** is in the current or previous miner list, but does not validate the **content** of the input: [2](#0-1) 

In `ProcessNextTerm`, the critical vulnerability occurs where the miner list is constructed directly from all keys in `nextRound.RealTimeMinersInformation` without validating the count: [3](#0-2) 

While `UpdateMinersCountToElectionContract` is called, this only **reports** a calculated count to the Election Contract, but does not **enforce** it on the actual miner list being set: [4](#0-3) 

The `GetMinersCount` method calculates what the count **should be** based on `State.MaximumMinersCount.Value`, but this calculation is only used for reporting, not validation: [5](#0-4) 

The `SetMinerList` helper method has no count validation either: [6](#0-5) 

The `RoundTerminateValidationProvider` used for `NextTerm` behavior only validates round and term number correctness, not miner count: [7](#0-6) 

The `NextTermInput.ToRound()` conversion performs no validation on the miner count: [8](#0-7) 

## Impact Explanation

**Consensus Integrity Impact:**
- An attacker can bypass the governance-controlled maximum miners count restriction set via `SetMaximumMinersCount`, which requires parliament authorization: [9](#0-8) 

- The attacker can set an arbitrarily large miner list (e.g., 1000 miners) when the maximum should be enforced, directly violating the protocol's consensus safety parameters.

**Operational Impact:**
- Excessive miners would severely degrade consensus performance and block production efficiency due to increased round-trip communication overhead
- Could cause denial-of-service conditions from computational overhead of managing too many validators
- Mining reward calculations and distribution would be diluted across an inflated miner set, affecting economic security
- Election snapshot and treasury release operations would process excessive miner data, causing state bloat

**Governance Impact:**
- Undermines the governance control mechanism for managing validator set size
- Violates the critical protocol invariant that miner count is bounded by governance-approved limits
- Breaks the trust model where Parliament controls consensus parameters

## Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be a current or previous round miner to pass the `PreCheck` permission validation
- This is a realistic precondition as any miner in the active validator set can execute this attack
- No additional privileges beyond being an active consensus participant are required

**Attack Complexity:**
- Low complexity: attacker constructs a `NextTermInput` with excessive `RealTimeMinersInformation` entries (the protobuf map has no size restrictions)
- Single direct RPC call to `NextTerm` with crafted input
- No complex multi-step state manipulation required
- No timing or race condition exploitation needed

**Execution Practicality:**
- Attack executes in a single transaction
- Only requires crafting valid round/term numbers (current + 1) which are publicly observable
- All other validation checks (round number, term number) are trivially satisfied
- No economic cost barrier as transaction fees are standard

**Detection/Operational Constraints:**
- The attack would be immediately visible on-chain as the miner list suddenly expands beyond governance limits
- However, prevention is difficult as the transaction passes all current validations
- Recovery requires coordinating another term transition with correct miner count
- Potential for chain halt if excessive miner count causes consensus failure

## Recommendation

Add explicit miner count validation in `ProcessNextTerm` before setting the miner list:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // ADD VALIDATION HERE
    var maxMinersCount = State.MaximumMinersCount.Value;
    Assert(nextRound.RealTimeMinersInformation.Count <= maxMinersCount,
        $"Miner count {nextRound.RealTimeMinersInformation.Count} exceeds maximum allowed {maxMinersCount}.");
    
    RecordMinedMinerListOfCurrentRound();
    // ... rest of the method
}
```

Additionally, consider adding this validation in the `RoundTerminateValidationProvider.ValidationForNextTerm` method to reject invalid inputs during the pre-execution validation phase:

```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Existing term number check
    if (validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Incorrect term number for next round." };
    
    // ADD: Validate miner count
    var maxMinersCount = validationContext.MaximumMinersCount; // Would need to add this to context
    if (extraData.Round.RealTimeMinersInformation.Count > maxMinersCount)
        return new ValidationResult { Message = "Miner count exceeds maximum allowed." };
    
    return new ValidationResult { Success = true };
}
```

## Proof of Concept

```csharp
[Fact]
public async Task NextTerm_WithExcessiveMiners_ShouldBypassMaximumCount()
{
    // Setup: Initialize consensus with maximum miner count of 5
    await InitializeConsensusContract();
    await SetMaximumMinersCount(5);
    
    // Get current round and term information
    var currentRound = await GetCurrentRoundInformation();
    var currentTerm = await GetCurrentTermNumber();
    
    // Attack: Create NextTermInput with 100 miners (exceeds max of 5)
    var maliciousInput = new NextTermInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentTerm + 1,
        RealTimeMinersInformation = { }, // Add 100 miner entries
        // ... other required fields
    };
    
    for (int i = 0; i < 100; i++)
    {
        maliciousInput.RealTimeMinersInformation.Add(
            GenerateMinerPublicKey(i),
            new MinerInRound { /* ... */ }
        );
    }
    
    // Execute: Call NextTerm as a current miner
    var result = await ConsensusContract.NextTerm(maliciousInput);
    
    // Verify: The miner list was set with 100 miners, bypassing the limit of 5
    var newMinerList = await GetCurrentMinerList();
    Assert.Equal(100, newMinerList.Pubkeys.Count); // Should be 5, but is 100
    
    // Impact: Governance limit was bypassed
    var maxCount = await GetMaximumMinersCount();
    Assert.True(newMinerList.Pubkeys.Count > maxCount.Value); // Proves bypass
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L53-61)
```csharp
    private void UpdateMinersCountToElectionContract(Round input)
    {
        var minersCount = GetMinersCount(input);
        if (minersCount != 0 && State.ElectionContract.Value != null)
            State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
            {
                MinersCount = minersCount
            });
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L70-82)
```csharp
    private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
    {
        // Miners for one specific term should only update once.
        var minerListFromState = State.MinerListMap[termNumber];
        if (gonnaReplaceSomeone || minerListFromState == null)
        {
            State.MainChainCurrentMinerList.Value = minerList;
            State.MinerListMap[termNumber] = minerList;
            return true;
        }

        return false;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-191)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L381-391)
```csharp
    private int GetMinersCount(Round input)
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        if (!TryToGetRoundInformation(1, out _)) return 0;
        return Math.Min(input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount
            ? AEDPoSContractConstants.SupposedMinersCount
            : AEDPoSContractConstants.SupposedMinersCount.Add(
                (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
                .Div(State.MinerIncreaseInterval.Value).Mul(2)), State.MaximumMinersCount.Value);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-29)
```csharp
    public override Empty SetMaximumMinersCount(Int32Value input)
    {
        EnsureElectionContractAddressSet();

        Assert(input.Value > 0, "Invalid max miners count.");

        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set max miners count.");

        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });

        return new Empty();
    }
```
