# Audit Report

## Title
Insufficient Validation of Cross-Chain Consensus Data Enables Denial of Service via Division by Zero

## Summary
The `UpdateInformationFromCrossChain()` function in the AEDPoS consensus contract accepts cross-chain consensus information without validating that the miner list is non-empty. When an empty miner list is stored, subsequent cross-chain updates trigger a division-by-zero exception during resource token distribution, permanently blocking all future consensus updates from the parent chain.

## Finding Description

The vulnerability exists in the cross-chain consensus information update mechanism for side chains. The `UpdateInformationFromCrossChain()` method is called by the CrossChain contract to update the side chain's view of the parent chain's miner list. [1](#0-0) 

The consensus contract performs minimal validation, checking only that the round number is increasing, but does NOT validate that the miner list contains at least one miner: [2](#0-1) 

The protobuf definition allows an empty map for `real_time_miners_information`: [3](#0-2) 

The vulnerable execution flow occurs in two stages:

**First call with empty miner list:**
The function first distributes tokens to the previous miner list, then stores the new (potentially empty) miner list from the consensus data: [4](#0-3) 

**Second call (with any data):**
The function calls `DistributeResourceTokensToPreviousMiners()` which retrieves the stored (now empty) miner list and attempts division by zero: [5](#0-4) 

The `Div` extension method performs standard C# division without zero-checking: [6](#0-5) 

This throws `DivideByZeroException` when the divisor is zero, causing transaction failure and preventing state updates that would fix the corrupted miner list.

## Impact Explanation

**Severity: HIGH - Permanent Denial of Service**

1. **Irreversible Cross-Chain Update Failure:** Once an empty miner list is stored, ALL subsequent calls to `UpdateInformationFromCrossChain()` will fail with an unhandled exception before reaching the state update logic. The side chain cannot receive any further consensus updates from the main chain.

2. **Resource Token Distribution Halt:** Side chains distribute transaction fees and rental fees to main chain miners through this mechanism. Once broken, main chain miners stop receiving compensation from the side chain, disrupting the economic incentive model.

3. **Cross-Chain Synchronization Break:** The side chain permanently loses the ability to synchronize its miner list with the main chain, breaking the fundamental parent-child chain relationship in AElf's cross-chain architecture.

4. **No Recovery Mechanism:** There is no built-in way to reset or repair the corrupted miner list state. The contract would require an upgrade or emergency governance intervention to recover.

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability can be triggered through the following path:

1. **Entry Point:** The function is only callable by the CrossChain contract, which forwards parent chain block data during cross-chain indexing: [7](#0-6) [8](#0-7) 

2. **Governance-Based Trigger:** Cross-chain data indexing requires governance approval, but validators must approve the entire parent chain block data package without necessarily inspecting the binary consensus extra data.

3. **Realistic Scenarios:**
   - A bug in parent chain consensus could produce invalid consensus data with an empty miner list
   - Governance validators may not thoroughly inspect binary protobuf consensus data
   - An intentional attack where malicious governance proposals include crafted cross-chain data

4. **Detection Difficulty:** The vulnerability manifests only on the SECOND call after storing invalid data, making it non-obvious during standard testing.

## Recommendation

Add validation to ensure the miner list is non-empty before storing it:

```csharp
public override Empty UpdateInformationFromCrossChain(BytesValue input)
{
    Assert(
        Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
        "Only Cross Chain Contract can call this method.");

    Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");

    if (input == null || input.Value.IsEmpty) return new Empty();

    var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);

    if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
        return new Empty();

    // ADD VALIDATION HERE
    var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
    Assert(minersKeys.Count > 0, "Miner list cannot be empty.");

    DistributeResourceTokensToPreviousMiners();

    State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;
    State.MainChainCurrentMinerList.Value = new MinerList
    {
        Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
    };

    return new Empty();
}
```

Additionally, add defensive programming to `DistributeResourceTokensToPreviousMiners()`:

```csharp
private void DistributeResourceTokensToPreviousMiners()
{
    if (State.TokenContract.Value == null)
        State.TokenContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

    var minerList = State.MainChainCurrentMinerList.Value.Pubkeys;
    
    // ADD DEFENSIVE CHECK
    if (minerList.Count == 0) return;
    
    foreach (var symbol in Context.Variables.GetStringArray(AEDPoSContractConstants.PayTxFeeSymbolListName)
                 .Union(Context.Variables.GetStringArray(AEDPoSContractConstants.PayRentalSymbolListName)))
    {
        // ... rest of the method
    }
}
```

## Proof of Concept

```csharp
[Fact]
public async Task UpdateInformationFromCrossChain_EmptyMinerList_CausesDivisionByZero()
{
    // Setup: Initialize side chain with valid miner list
    SetToSideChain();
    InitialContracts();
    
    var mockedCrossChain = SampleAccount.Accounts.Last();
    var mockedCrossChainStub = GetTester<AEDPoSContractImplContainer.AEDPoSContractImplStub>(
        ContractAddresses[ConsensusSmartContractAddressNameProvider.Name],
        mockedCrossChain.KeyPair);

    // First update: Establish valid state
    var validHeader = new AElfConsensusHeaderInformation
    {
        Round = new Round
        {
            RoundNumber = 2,
            RealTimeMinersInformation =
            {
                { Accounts[0].KeyPair.PublicKey.ToHex(), new MinerInRound() },
                { Accounts[1].KeyPair.PublicKey.ToHex(), new MinerInRound() }
            }
        }
    };
    
    await mockedCrossChainStub.UpdateInformationFromCrossChain.SendAsync(
        new BytesValue { Value = validHeader.ToByteString() });

    // Malicious update: Empty miner list
    var emptyMinerListHeader = new AElfConsensusHeaderInformation
    {
        Round = new Round
        {
            RoundNumber = 3,
            RealTimeMinersInformation = { } // EMPTY MAP
        }
    };
    
    // First call with empty list succeeds (distributes to previous non-empty list)
    await mockedCrossChainStub.UpdateInformationFromCrossChain.SendAsync(
        new BytesValue { Value = emptyMinerListHeader.ToByteString() });

    // Second call fails with division by zero
    var nextHeader = new AElfConsensusHeaderInformation
    {
        Round = new Round
        {
            RoundNumber = 4,
            RealTimeMinersInformation =
            {
                { Accounts[0].KeyPair.PublicKey.ToHex(), new MinerInRound() }
            }
        }
    };
    
    // This should throw DivideByZeroException
    var result = await mockedCrossChainStub.UpdateInformationFromCrossChain.SendWithExceptionAsync(
        new BytesValue { Value = nextHeader.ToByteString() });
    
    result.TransactionResult.Error.ShouldContain("Attempted to divide by zero");
}
```

## Notes

This vulnerability demonstrates a critical gap in input validation for cross-chain consensus data. While the CrossChain contract is trusted, it does not perform semantic validation of consensus information, relying on the consensus contract to validate business logic constraints. The consensus contract, however, only validates round number ordering and assumes the miner list is well-formed. This creates a validation gap that can be exploited through governance-approved malicious data or accidental bugs in parent chain consensus logic.

The permanent nature of the DoS (once triggered, cannot be recovered without contract upgrade) significantly elevates the severity of this issue.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L227-234)
```csharp
    private void UpdateConsensusInformation(ByteString bytes)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        Context.SendInline(State.CrossChainInteractionContract.Value,
            nameof(State.CrossChainInteractionContract.UpdateInformationFromCrossChain),
            new BytesValue { Value = bytes });
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L783-787)
```csharp
            if (i == parentChainBlockData.Count - 1 &&
                blockInfo.ExtraData.TryGetValue(ConsensusExtraDataName, out var bytes))
            {
                Context.LogDebug(() => "Updating consensus information..");
                UpdateConsensusInformation(bytes);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L34-36)
```csharp
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L46-47)
```csharp
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L53-61)
```csharp
        DistributeResourceTokensToPreviousMiners();

        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;

        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L72-81)
```csharp
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
```

**File:** protobuf/aedpos_contract.proto (L247-247)
```text
    map<string, MinerInRound> real_time_miners_information = 2;
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```
