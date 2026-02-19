### Title
Missing Miners Count Validation in NextTerm Allows Bypass of Maximum Miner Restrictions

### Summary
The `ProcessNextTerm` method does not validate that the number of miners in the provided `NextTermInput` is within the maximum allowed count set by governance. A malicious miner can directly call the public `NextTerm` RPC method with a crafted `NextTermInput` containing excessive `RealTimeMinersInformation` entries, bypassing the miner count restriction enforced by `SetMaximumMinersCount`.

### Finding Description

The vulnerability exists in the `ProcessNextTerm` method where the `NextTermInput` is converted to a `Round` object and the miner list is set without validating the count: [1](#0-0) 

The critical issue is at lines 163 and 188-190: the method converts `NextTermInput.ToRound()` and directly uses all keys from `nextRound.RealTimeMinersInformation` to create the new miner list without checking if the count exceeds `State.MaximumMinersCount.Value`.

While `UpdateMinersCountToElectionContract` is called at line 176, this only **reports** the count to the Election Contract via `GetMinersCount`: [2](#0-1) 

The `GetMinersCount` method calculates what the count **should be** based on the maximum constraint, but doesn't **enforce** it: [3](#0-2) 

The `NextTerm` RPC method is publicly accessible: [4](#0-3) 

The only permission check is `PreCheck`, which only validates that the **caller** is in the current or previous miner list, not the **content** of the input: [5](#0-4) 

The validation performed by `RoundTerminateValidationProvider` for `NextTerm` behavior only checks round/term number correctness, not miner count: [6](#0-5) 

### Impact Explanation

**Consensus Integrity Impact:**
- An attacker can bypass the governance-controlled maximum miners count restriction set via `SetMaximumMinersCount`, which requires parliament authorization: [7](#0-6) 

- The attacker can set an arbitrarily large miner list (e.g., 1000 miners) when the maximum should be enforced.

**Operational Impact:**
- Excessive miners would degrade consensus performance and block production efficiency
- Could cause DoS conditions due to computational overhead from managing too many validators
- Mining reward calculations and distribution would be affected across an inflated miner set
- Election snapshot and treasury release operations would process excessive miner data

**Governance Impact:**
- Undermines the governance control mechanism for managing miner count
- Violates the critical invariant of "miner schedule integrity" in the consensus system

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be a current or previous round miner to pass the `PreCheck` permission validation
- This is a realistic precondition as any miner in the active set can execute this

**Attack Complexity:**
- Low complexity: attacker simply constructs a `NextTermInput` with excessive `RealTimeMinersInformation` entries
- The `NextTermInput.Create` factory method itself performs no validation: [8](#0-7) 

**Execution Practicality:**
- Direct RPC call to `NextTerm` with crafted input
- No complex state setup required beyond being an active miner
- Attack executes in a single transaction

**Detection/Operational Constraints:**
- The attack would be immediately visible on-chain as the miner list suddenly expands
- However, prevention is difficult as the transaction passes all current validations
- Reverting requires another term transition with correct miner count

### Recommendation

Add explicit validation in `ProcessNextTerm` to enforce the maximum miners count before setting the miner list:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // Add validation for maximum miners count
    var maximumMinersCount = GetMaximumMinersCount(new Empty()).Value;
    Assert(nextRound.RealTimeMinersInformation.Count <= maximumMinersCount, 
        $"Miners count {nextRound.RealTimeMinersInformation.Count} exceeds maximum allowed {maximumMinersCount}");
    
    RecordMinedMinerListOfCurrentRound();
    // ... rest of method
}
```

Additionally, add a validation provider specifically for miner count checks in the `ValidateBeforeExecution` flow for `NextTerm` behavior.

**Test Cases:**
1. Test that `NextTerm` rejects input when `RealTimeMinersInformation.Count > MaximumMinersCount`
2. Test that `NextTerm` accepts input when count equals maximum
3. Test edge case where maximum is set to a lower value mid-operation

### Proof of Concept

**Initial State:**
- Blockchain has 7 active miners
- `SetMaximumMinersCount` has been called by parliament to set limit to 21 miners
- Attacker is one of the 7 current miners

**Attack Steps:**
1. Attacker constructs a `NextTermInput`:
   - Sets `TermNumber = CurrentTermNumber + 1`
   - Sets `RoundNumber = CurrentRoundNumber + 1`
   - Populates `RealTimeMinersInformation` with 100 fake miner public keys
   - Each fake miner has basic `MinerInRound` structure with Order, ExpectedMiningTime, etc.
   - Generates valid `RandomNumber` via VRF

2. Attacker calls `NextTerm` RPC with this crafted input

3. **Expected Result:** Transaction should fail with "Miners count exceeds maximum"

4. **Actual Result:** 
   - Transaction succeeds
   - `PreCheck` passes (attacker is current miner)
   - `ProcessNextTerm` executes without count validation
   - Lines 188-190 create `MinerList` with all 100 fake miners
   - `SetMinerList` stores the list with 100 miners
   - Maximum miners count of 21 is bypassed

**Success Condition:** Query `GetCurrentMinerList` returns 100 miners instead of being capped at 21, confirming the bypass.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-196)
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

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-330)
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

**File:** protobuf/aedpos_contract.proto (L37-39)
```text
    // Update consensus information, create a new term.
    rpc NextTerm (NextTermInput) returns (google.protobuf.Empty) {
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L7-23)
```csharp
    public static NextTermInput Create(Round round, ByteString randomNumber)
    {
        return new NextTermInput
        {
            RoundNumber = round.RoundNumber,
            RealTimeMinersInformation = { round.RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = round.ExtraBlockProducerOfPreviousRound,
            BlockchainAge = round.BlockchainAge,
            TermNumber = round.TermNumber,
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = round.IsMinerListJustChanged,
            RoundIdForValidation = round.RoundIdForValidation,
            MainChainMinersRoundNumber = round.MainChainMinersRoundNumber,
            RandomNumber = randomNumber
        };
    }
```
