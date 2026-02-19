### Title
Side Chain Fails to Validate Incoming Parent Chain Miner List Size Leading to DoS and Storage Exhaustion

### Summary
The `UpdateInformationFromCrossChain()` function on side chains does not validate the size of the incoming parent chain miner list against the side chain's own `MaximumMinersCount` limit. If the parent chain has an excessively large miner list (due to misconfiguration or bugs), the side chain will accept and process it without bounds checking, leading to potential DoS through excessive gas consumption in token distribution and state storage exhaustion.

### Finding Description

The vulnerability exists in the cross-chain consensus information update flow: [1](#0-0) 

The function extracts miner keys from `consensusInformation.Round.RealTimeMinersInformation.Keys` and directly stores them in `State.MainChainCurrentMinerList.Value` without any size validation. It does not check the count against the side chain's own `State.MaximumMinersCount.Value`.

The critical path is:
1. Cross-chain contract calls `UpdateInformationFromCrossChain` with parent chain consensus data
2. Function extracts all miner keys without validation (lines 57-61)
3. Function calls `DistributeResourceTokensToPreviousMiners()` which iterates over all miners: [2](#0-1) 

The distribution function performs O(miners × symbols) operations, executing token transfers for each miner for each symbol. Lines 84-94 show the nested iteration that transfers tokens to every miner in the list.

While the parent chain enforces its own MaximumMinersCount through governance: [3](#0-2) [4](#0-3) 

The side chain has NO independent validation to protect itself from receiving an oversized miner list from the parent chain.

### Impact Explanation

**Operational DoS Impact:**
If the parent chain has an extremely large miner list (e.g., 10,000 miners due to misconfigured MaximumMinersCount), the side chain's `DistributeResourceTokensToPreviousMiners()` function would:
- Iterate 10,000 × number_of_symbols times
- Execute 10,000 × number_of_symbols token transfers
- Potentially exceed block gas limits or cause transaction timeouts
- Block normal consensus operations on the side chain

**State Storage Exhaustion:**
The unbounded miner list is stored in `State.MainChainCurrentMinerList.Value`, consuming storage proportional to the number of miners. With thousands of miners, this represents significant state bloat.

**Affected Parties:**
- Side chain operators face DoS of consensus operations
- Side chain users experience service degradation
- Resource token distribution mechanisms become unusable

### Likelihood Explanation

**Preconditions:**
1. Parent chain governance sets `MaximumMinersCount` to an extremely large value (e.g., 5,000+)
2. OR parent chain has a bug that bypasses MaximumMinersCount validation
3. Side chain indexes parent chain blocks via normal cross-chain mechanisms

**Feasibility:**
- Parent chain governance can legitimately set MaximumMinersCount via parliament proposals: [5](#0-4) 

- Cross-chain data validation only verifies the data matches cached parent chain blocks, not that it's reasonable: [6](#0-5) 

**Attack Complexity:**
Medium - Requires parent chain governance action or exploiting a parent chain bug, but does not require compromising miners or breaking cryptographic assumptions. The side chain has no defense against legitimate but excessive parent chain data.

**Probability:**
While unlikely in normal operations (typical miner count is 17), the lack of defensive validation means the side chain is vulnerable to parent chain misconfigurations or bugs. Given the governance-driven nature of MaximumMinersCount changes, this represents a realistic operational risk.

### Recommendation

**Immediate Fix:**
Add validation in `UpdateInformationFromCrossChain()` to check the incoming miner list size against the side chain's own limits:

```csharp
// After line 57
var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;

// Add validation
var maxAllowedMiners = State.MaximumMinersCount.Value;
Assert(minersKeys.Count <= maxAllowedMiners, 
    $"Incoming miner list size ({minersKeys.Count}) exceeds side chain maximum ({maxAllowedMiners})");

State.MainChainCurrentMinerList.Value = new MinerList
{
    Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
};
```

**Additional Hardening:**
1. Add a reasonable absolute upper bound (e.g., 1000 miners) regardless of configured MaximumMinersCount
2. Add gas estimation checks before executing `DistributeResourceTokensToPreviousMiners()`
3. Consider batching token distribution if miner count exceeds a threshold

**Test Cases:**
1. Test with miner list size exceeding side chain MaximumMinersCount
2. Test with extremely large miner list (1000+ miners)
3. Test that normal updates with reasonable miner counts still work

### Proof of Concept

**Initial State:**
- Side chain initialized with MaximumMinersCount = 100
- Parent chain has MaximumMinersCount = 10,000 (set via governance)
- Parent chain has 5,000 active miners in its RealTimeMinersInformation

**Exploitation Steps:**
1. Parent chain produces blocks with 5,000-miner consensus information
2. Miner on side chain proposes cross-chain indexing with parent chain data: [7](#0-6) 

3. Data passes validation (matches cached parent chain blocks)
4. Cross-chain contract calls consensus contract's `UpdateInformationFromCrossChain`
5. Side chain stores all 5,000 miners without validation (exceeding its own 100-miner limit)
6. `DistributeResourceTokensToPreviousMiners()` attempts to iterate over 5,000 miners
7. If 2 token symbols configured, this results in 10,000 token transfer operations

**Expected vs Actual:**
- **Expected:** Side chain rejects miner list exceeding its MaximumMinersCount (100)
- **Actual:** Side chain accepts and processes all 5,000 miners, causing gas exhaustion or transaction timeout

**Success Condition:**
Transaction fails with "Insufficient gas" or timeout, or succeeds but consumes excessive resources, demonstrating the DoS vector.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L32-64)
```csharp
    public override Empty UpdateInformationFromCrossChain(BytesValue input)
    {
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");

        Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");

        // For now we just extract the miner list from main chain consensus information, then update miners list.
        if (input == null || input.Value.IsEmpty) return new Empty();

        var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);

        // check round number of shared consensus, not term number
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();

        Context.LogDebug(() =>
            $"Shared miner list of round {consensusInformation.Round.RoundNumber}:" +
            $"{consensusInformation.Round.ToString("M")}");

        DistributeResourceTokensToPreviousMiners();

        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;

        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L66-96)
```csharp
    private void DistributeResourceTokensToPreviousMiners()
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var minerList = State.MainChainCurrentMinerList.Value.Pubkeys;
        foreach (var symbol in Context.Variables.GetStringArray(AEDPoSContractConstants.PayTxFeeSymbolListName)
                     .Union(Context.Variables.GetStringArray(AEDPoSContractConstants.PayRentalSymbolListName)))
        {
            var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
            {
                Owner = Context.Self,
                Symbol = symbol
            }).Balance;
            var amount = balance.Div(minerList.Count);
            Context.LogDebug(() => $"Consensus Contract {symbol} balance: {balance}. Every miner can get {amount}");
            if (amount <= 0) continue;
            foreach (var pubkey in minerList)
            {
                var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(pubkey.ToHex()));
                Context.LogDebug(() => $"Will send {amount} {symbol}s to {pubkey}");
                State.TokenContract.Transfer.Send(new TransferInput
                {
                    To = address,
                    Amount = amount,
                    Symbol = symbol
                });
            }
        }
    }
```

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

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/MaximumMinersCountTests.cs (L42-52)
```csharp
        await ParliamentReachAnAgreementAsync(new CreateProposalInput
        {
            ToAddress = ContractAddresses[ConsensusSmartContractAddressNameProvider.Name],
            ContractMethodName = nameof(ConsensusStub.SetMaximumMinersCount),
            Params = new Int32Value
            {
                Value = targetMinersCount
            }.ToByteString(),
            ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
            OrganizationAddress = defaultOrganizationAddress
        });
```

**File:** src/AElf.CrossChain.Core/Indexing/Application/CrossChainIndexingDataValidationService.cs (L161-166)
```csharp
            if (!parentChainBlockDataList[i].Equals(parentChainBlockData))
            {
                Logger.LogDebug(
                    $"Incorrect parent chain data. Parent chain height: {targetHeight}.");
                return false;
            }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L282-291)
```csharp
    public override Empty ProposeCrossChainIndexing(CrossChainBlockData input)
    {
        Context.LogDebug(() => "Proposing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        ClearCrossChainIndexingProposalIfExpired();
        var crossChainDataDto = ValidateCrossChainDataBeforeIndexing(input);
        ProposeCrossChainBlockData(crossChainDataDto, Context.Sender);
        return new Empty();
    }
```
