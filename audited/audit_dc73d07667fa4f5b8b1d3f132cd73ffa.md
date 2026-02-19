### Title
Unbounded Beneficiary Removal in UpdateBasicMinerRewardWeights Can Cause DOS via Execution Call Threshold

### Summary
The `UpdateBasicMinerRewardWeights()` function calls `RemoveBeneficiaries` with all miner addresses from the previous term without batching or pagination. If the number of miners grows large (estimated 200-400+ miners), this operation can exceed AElf's ExecutionCallThreshold (15,000 method calls), causing the transaction to fail and blocking the entire reward distribution mechanism for that term.

### Finding Description

The vulnerability exists in the reward distribution flow that executes automatically during term transitions: [1](#0-0) 

The `Release` method calls `UpdateStateBeforeDistribution`, which in turn calls `UpdateBasicMinerRewardWeights`: [2](#0-1) 

This function calls `RemoveBeneficiaries` with addresses from all miners in the previous term. The address list is doubled by `GetAddressesFromCandidatePubkeys`, which includes both direct addresses and profit receiver addresses: [3](#0-2) 

The Profit contract's `RemoveBeneficiaries` implementation has no batching or pagination - it simply iterates through all beneficiaries: [4](#0-3) 

Each iteration calls `RemoveBeneficiary`, which performs multiple state operations: [5](#0-4) 

AElf enforces an ExecutionCallThreshold (default 15,000) to prevent infinite loops: [6](#0-5) 

When this threshold is exceeded, the ExecutionObserver throws an exception that fails the transaction: [7](#0-6) 

The BasicReward scheme is initialized with `CanRemoveBeneficiaryDirectly = false` (only indices 2, 5, 6 have it set to true): [8](#0-7) 

### Impact Explanation

When the execution call threshold is exceeded, the `Release` transaction fails completely, preventing:
- Distribution of mining rewards to all miners for that term
- Distribution of citizen welfare rewards
- Distribution of subsidy rewards
- Progression of the reward mechanism

Since `Release` is automatically called by the AEDPoS contract during term transitions, this creates a permanent DOS condition where rewards cannot be distributed until the miner count is reduced or the code is upgraded. All accumulated rewards for that period become inaccessible.

The severity is HIGH because:
1. It completely blocks the core reward distribution mechanism
2. Affects all participants (miners, citizens, candidates)
3. Cannot be bypassed through alternative transaction paths
4. Accumulates value that becomes locked

### Likelihood Explanation

The MaximumMinersCount defaults to int.MaxValue and can grow over time: [9](#0-8) 

While current mainnet has ~17-21 miners (safe), the likelihood increases as:
1. The auto-increase mechanism adds 2 miners per MinerIncreaseInterval
2. Governance can increase MaximumMinersCount through parliament proposals
3. The system is designed to support network growth

Rough calculation:
- For N miners, `GetAddressesFromCandidatePubkeys` creates 2N addresses
- Each `RemoveBeneficiary` call involves ~15-25 method calls (state reads, RemoveProfitDetails processing, state writes)
- Total calls ≈ 2N × 20 = 40N
- Threshold of 15,000 / 40 ≈ 375 miners
- Additional overhead from Release and other functions reduces this to ~200-300 miners

The attack complexity is NONE - this is not an active attack but a design flaw that manifests automatically as the network grows. The DOS occurs naturally when the miner count crosses the threshold.

### Recommendation

Implement batched removal with pagination:

1. Add a batch size parameter (e.g., 50-100 beneficiaries per call) to `RemoveBeneficiaries`
2. Modify `UpdateBasicMinerRewardWeights` to split the beneficiary list into batches and make multiple calls if needed
3. Store intermediate state between batches to resume if a batch fails
4. Add explicit checks for remaining call budget before processing each batch
5. Alternatively, redesign to avoid full removal - mark beneficiaries as inactive instead of removing, and lazy-clean them during profit claims

Add invariant checks:
- Assert that 2N × estimated_calls_per_removal < ExecutionCallThreshold before starting
- Add monitoring/alerts when miner count approaches the danger threshold

Test cases:
- Test with 100, 200, 300+ miners to validate batching works
- Test that partial batch completion is handled correctly
- Test that exceeding threshold is caught before execution

### Proof of Concept

Initial state:
1. Network has grown to 300+ miners through auto-increase mechanism over time
2. Previous term had 300 active miners
3. New term begins, triggering automatic Release call

Execution sequence:
1. AEDPoS contract automatically calls `Treasury.Release()` during term transition
2. `Release()` calls `UpdateStateBeforeDistribution()`
3. `UpdateStateBeforeDistribution()` calls `UpdateBasicMinerRewardWeights()`
4. `UpdateBasicMinerRewardWeights()` calls `GetAddressesFromCandidatePubkeys(300 miners)` → returns 600 addresses
5. Calls `RemoveBeneficiaries` with 600 addresses
6. `RemoveBeneficiaries` loops through all 600, calling `RemoveBeneficiary` for each
7. After ~375 iterations (approximately 15,000 total method calls), ExecutionCallThreshold is exceeded
8. RuntimeCallThresholdExceededException is thrown
9. Transaction fails with ContractError status

Expected result: Reward distribution completes successfully

Actual result: Transaction fails, rewards cannot be distributed, reward mechanism is permanently blocked until code upgrade or miner count reduction

Success condition: Transaction error log contains "RuntimeCallThresholdExceededException" and Release transaction status is ContractError

### Citations

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L56-68)
```csharp
        for (var i = 0; i < 7; i++)
        {
            var index = i;
            Context.LogDebug(() => profitItemNameList[index]);
            State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
            {
                IsReleaseAllBalanceEveryTimeByDefault = true,
                // Distribution of Citizen Welfare will delay one period.
                DelayDistributePeriodCount = i == 3 ? 1 : 0,
                // Subsidy, Flexible Reward and Welcome Reward can remove beneficiary directly (due to replaceable.)
                CanRemoveBeneficiaryDirectly = new List<int> { 2, 5, 6 }.Contains(i)
            });
        }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L123-166)
```csharp
    public override Empty Release(ReleaseInput input)
    {
        RequireAEDPoSContractStateSet();
        Assert(
            Context.Sender == State.AEDPoSContract.Value,
            "Only AElf Consensus Contract can release profits from Treasury.");
        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.TreasuryHash.Value,
            Period = input.PeriodNumber,
            AmountsMap = { State.SymbolList.Value.Value.ToDictionary(s => s, s => 0L) }
        });
        RequireElectionContractStateSet();
        var previousTermInformation = State.AEDPoSContract.GetPreviousTermInformation.Call(new Int64Value
        {
            Value = input.PeriodNumber
        });

        var currentMinerList = State.AEDPoSContract.GetCurrentMinerList.Call(new Empty()).Pubkeys
            .Select(p => p.ToHex()).ToList();
        var maybeNewElectedMiners = new List<string>();
        maybeNewElectedMiners.AddRange(currentMinerList);
        maybeNewElectedMiners.AddRange(previousTermInformation.RealTimeMinersInformation.Keys);
        var replaceCandidates = State.ReplaceCandidateMap[input.PeriodNumber];
        if (replaceCandidates != null)
        {
            Context.LogDebug(() =>
                $"New miners from replace candidate map: {replaceCandidates.Value.Aggregate((l, r) => $"{l}\n{r}")}");
            maybeNewElectedMiners.AddRange(replaceCandidates.Value);
            State.ReplaceCandidateMap.Remove(input.PeriodNumber);
        }

        maybeNewElectedMiners = maybeNewElectedMiners
            .Where(p => State.LatestMinedTerm[p] == 0 && !GetInitialMinerList().Contains(p)).ToList();
        if (maybeNewElectedMiners.Any())
            Context.LogDebug(() => $"New elected miners: {maybeNewElectedMiners.Aggregate((l, r) => $"{l}\n{r}")}");
        else
            Context.LogDebug(() => "No new elected miner.");

        UpdateStateBeforeDistribution(previousTermInformation, maybeNewElectedMiners);
        ReleaseTreasurySubProfitItems(input.PeriodNumber);
        UpdateStateAfterDistribution(previousTermInformation, currentMinerList);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L657-663)
```csharp
    private List<Address> GetAddressesFromCandidatePubkeys(ICollection<string> pubkeys)
    {
        var addresses = pubkeys.Select(k => Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(k)))
            .ToList();
        addresses.AddRange(pubkeys.Select(GetProfitsReceiver));
        return addresses;
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L777-822)
```csharp
    private void UpdateBasicMinerRewardWeights(IReadOnlyCollection<Round> previousTermInformation)
    {
        if (previousTermInformation.First().RealTimeMinersInformation != null)
            State.ProfitContract.RemoveBeneficiaries.Send(new RemoveBeneficiariesInput
            {
                SchemeId = State.BasicRewardHash.Value,
                Beneficiaries =
                {
                    GetAddressesFromCandidatePubkeys(previousTermInformation.First().RealTimeMinersInformation.Keys)
                }
            });

        var averageProducedBlocksCount = CalculateAverage(previousTermInformation.Last().RealTimeMinersInformation
            .Values
            .Select(i => i.ProducedBlocks).ToList());
        // Manage weights of `MinerBasicReward`
        State.ProfitContract.AddBeneficiaries.Send(new AddBeneficiariesInput
        {
            SchemeId = State.BasicRewardHash.Value,
            EndPeriod = previousTermInformation.Last().TermNumber,
            BeneficiaryShares =
            {
                previousTermInformation.Last().RealTimeMinersInformation.Values.Select(i =>
                {
                    long shares;
                    if (State.IsReplacedEvilMiner[i.Pubkey])
                    {
                        // The new miner may have more shares than his actually contributes, but it's ok.
                        shares = i.ProducedBlocks;
                        // Clear the state asap.
                        State.IsReplacedEvilMiner.Remove(i.Pubkey);
                    }
                    else
                    {
                        shares = CalculateShares(i.ProducedBlocks, averageProducedBlocksCount);
                    }

                    return new BeneficiaryShare
                    {
                        Beneficiary = GetProfitsReceiver(i.Pubkey),
                        Shares = shares
                    };
                })
            }
        });
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L224-263)
```csharp
    public override Empty RemoveBeneficiary(RemoveBeneficiaryInput input)
    {
        Assert(input.SchemeId != null, "Invalid scheme id.");
        Assert(input.Beneficiary != null, "Invalid Beneficiary address.");

        var scheme = State.SchemeInfos[input.SchemeId];

        Assert(scheme != null, "Scheme not found.");

        var currentDetail = State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];

        if (scheme == null || currentDetail == null) return new Empty();

        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager or token holder contract can add beneficiary.");

        var removedDetails = RemoveProfitDetails(scheme, input.Beneficiary, input.ProfitDetailId);

        foreach (var (removedMinPeriod, removedShares) in removedDetails.Where(d => d.Key != 0))
        {
            if (scheme.DelayDistributePeriodCount > 0)
            {
                for (var removedPeriod = removedMinPeriod;
                     removedPeriod < removedMinPeriod.Add(scheme.DelayDistributePeriodCount);
                     removedPeriod++)
                {
                    if (scheme.CachedDelayTotalShares.ContainsKey(removedPeriod))
                    {
                        scheme.CachedDelayTotalShares[removedPeriod] =
                            scheme.CachedDelayTotalShares[removedPeriod].Sub(removedShares);
                    }
                }
            }
        }

        State.SchemeInfos[input.SchemeId].TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L401-410)
```csharp
    public override Empty RemoveBeneficiaries(RemoveBeneficiariesInput input)
    {
        foreach (var beneficiary in input.Beneficiaries)
            RemoveBeneficiary(new RemoveBeneficiaryInput
            {
                SchemeId = input.SchemeId, Beneficiary = beneficiary
            });

        return new Empty();
    }
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L5-5)
```csharp
    public const int ExecutionCallThreshold = 15000;
```

**File:** src/AElf.Sdk.CSharp/ExecutionObserver.cs (L21-27)
```csharp
    public void CallCount()
    {
        if (_callThreshold != -1 && _callCount == _callThreshold)
            throw new RuntimeCallThresholdExceededException($"Contract call threshold {_callThreshold} exceeded.");

        _callCount++;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L52-52)
```csharp
        State.MaximumMinersCount.Value = int.MaxValue;
```
