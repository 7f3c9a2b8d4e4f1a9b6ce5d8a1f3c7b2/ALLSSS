### Title
Missing Upper Bound Validation on MaximumMinersCount Enables Consensus DoS via ExecutionCallThreshold Exhaustion

### Summary
The `SetMaximumMinersCount` function lacks upper bound validation, allowing governance to configure a miner count that would cause the `ExtractInformationToUpdateConsensus` function to exceed AElf's ExecutionCallThreshold of 15,000 method calls. If MaximumMinersCount is set to approximately 1,500 or higher, every miner's UpdateValue transaction would fail, halting consensus and preventing block production. [1](#0-0) 

### Finding Description
The `ExtractInformationToUpdateConsensus` function performs three LINQ operations on `RealTimeMinersInformation.Values` (lines 22-33), each with O(N) complexity where N is the number of miners: [2](#0-1) 

Each operation involves `Where().ToDictionary()` calls that iterate through all miners. With approximately 3-5 method calls per miner per operation, the total call count approaches 9N-15N. AElf enforces an ExecutionCallThreshold of 15,000 method calls per transaction: [3](#0-2) [4](#0-3) 

At approximately N=1,700 miners, the total method calls (~15,300) would exceed the threshold, causing the transaction to fail with `RuntimeCallThresholdExceededException`. The `SetMaximumMinersCount` function only validates that the input is positive, with no upper bound check: [5](#0-4) 

This function is called during every block production via the consensus flow: [6](#0-5) 

### Impact Explanation
If governance sets MaximumMinersCount above approximately 1,500-1,700 and that many miners are elected, the network would experience complete consensus failure:
- Every miner attempting to produce a block would have their UpdateValue transaction fail
- No blocks could be produced, halting the entire blockchain
- The network would remain halted until governance reduces MaximumMinersCount below the threshold
- All consensus operations, not just this function, would be affected as similar LINQ patterns exist throughout: [7](#0-6) [8](#0-7) 

This represents a complete operational DoS of the consensus mechanism, though no funds are directly at risk.

### Likelihood Explanation
The likelihood is LOW but non-zero:

**Preconditions:**
1. Parliament governance must approve a proposal to set MaximumMinersCount to 1,500+
2. The Election contract must successfully elect that many miners
3. Both conditions must persist long enough for the issue to manifest

**Feasibility:**
- The natural growth path (starting at 17 miners, +2 per year) would take ~740 years to reach the threshold: [9](#0-8) [10](#0-9) 

- However, governance can set any value through Parliament proposals: [11](#0-10) 

**Detection:**
- Would be immediately obvious upon first block production attempt after the change
- Could occur due to misconfiguration rather than malicious intent
- No economic incentive for attackers (only causes operational disruption)

### Recommendation
Add validation in `SetMaximumMinersCount` to enforce a safe upper bound based on ExecutionCallThreshold limitations:

```csharp
public override Empty SetMaximumMinersCount(Int32Value input)
{
    EnsureElectionContractAddressSet();
    
    Assert(input.Value > 0, "Invalid max miners count.");
    // Add upper bound check to prevent execution threshold exhaustion
    Assert(input.Value <= 1000, "Max miners count exceeds safe operational limit.");
    
    RequiredMaximumMinersCountControllerSet();
    // ... rest of implementation
}
```

The bound of 1,000 provides a safety margin below the threshold where LINQ operations would approach 9,000-15,000 calls. Additional recommendations:

1. Document the maximum safe value in constants:
```csharp
public const int MaximumSafeMinersCount = 1000;
```

2. Add integration tests verifying LINQ operations complete within ExecutionCallThreshold at boundary values

3. Consider optimizing frequently-called LINQ operations to reduce call counts per miner

### Proof of Concept

**Initial State:**
- Parliament governance configured and operational
- Consensus contract initialized with default miner count (17)

**Attack Steps:**
1. Governance creates Parliament proposal to call `SetMaximumMinersCount(Int32Value { Value = 2000 })`
2. Parliament members approve and release the proposal
3. MaximumMinersCount is set to 2,000 with no validation error
4. Over time (or through rapid election manipulation), 2,000 miners are elected to the active miner set
5. First miner attempts to produce a block and calls UpdateValue, which internally calls `ExtractInformationToUpdateConsensus`
6. The three LINQ operations at lines 22-33 iterate through 2,000 miners
7. Total method calls: ~9 + (9 × 2000) = 18,009 calls
8. ExecutionObserver throws `RuntimeCallThresholdExceededException` when count reaches 15,000
9. UpdateValue transaction fails
10. Block production fails
11. All subsequent miners experience the same failure
12. Network consensus is completely halted

**Expected Result:** Transaction executes successfully or fails with clear validation error at step 2

**Actual Result:** Transaction succeeds at step 2-3 but causes network-wide consensus failure at steps 6-12, requiring governance intervention to reduce MaximumMinersCount

**Success Condition:** Network cannot produce any blocks until MaximumMinersCount is reduced below the safe threshold (~1,500)

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-28)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L31-43)
```csharp
    private void RequiredMaximumMinersCountControllerSet()
    {
        if (State.MaximumMinersCountController.Value != null) return;
        EnsureParliamentContractAddressSet();

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MaximumMinersCountController.Value = defaultAuthority;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L88-95)
```csharp
    private int GetAutoIncreasedMinersCount()
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        return AEDPoSContractConstants.SupposedMinersCount.Add(
            (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
            .Div(State.MinerIncreaseInterval.Value).Mul(2));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-33)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);

        var decryptedPreviousInValues = RealTimeMinersInformation.Values.Where(v =>
                v.Pubkey != pubkey && v.DecryptedPieces.ContainsKey(pubkey))
            .ToDictionary(info => info.Pubkey, info => info.DecryptedPieces[pubkey]);

        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L5-7)
```csharp
    public const int ExecutionCallThreshold = 15000;

    public const int ExecutionBranchThreshold = 15000;
```

**File:** src/AElf.Sdk.CSharp/ExecutionObserver.cs (L21-26)
```csharp
    public void CallCount()
    {
        if (_callThreshold != -1 && _callCount == _callThreshold)
            throw new RuntimeCallThresholdExceededException($"Contract call threshold {_callThreshold} exceeded.");

        _callCount++;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L144-145)
```csharp
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L18-61)
```csharp
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
        }

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }

        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L19-20)
```csharp
            if (RealTimeMinersInformation.Values.All(bpInfo => bpInfo.ExpectedMiningTime != null))
                return RealTimeMinersInformation.Values.Select(bpInfo => bpInfo.ExpectedMiningTime.Seconds).Sum();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```
