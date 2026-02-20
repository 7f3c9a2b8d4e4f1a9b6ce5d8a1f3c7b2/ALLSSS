# Audit Report

## Title
Dictionary Access Without Key Validation in IsCurrentMiner During Miner List Changes Causes KeyNotFoundException

## Summary
The `IsCurrentMiner` method in the AEDPoS consensus contract contains a conditional safety check that is bypassed when `IsMinerListJustChanged = true`, leading to unguarded dictionary accesses that throw `KeyNotFoundException` when addresses not in the current round attempt authorization checks during term transitions or miner replacements.

## Finding Description

The vulnerability exists in the `IsCurrentMiner(string pubkey)` private method where a safety check only validates dictionary key existence when the miner list has NOT changed: [1](#0-0) 

When `IsMinerListJustChanged` is true, this check is completely bypassed, yet the code proceeds to directly access the `RealTimeMinersInformation` dictionary without validation: [2](#0-1) 

The `IsMinerListJustChanged` flag is set to true when generating the first round of a new term: [3](#0-2) 

And when replacing evil miners within a term: [4](#0-3) 

The vulnerability is triggered when `ConvertAddressToPubkey` returns a pubkey that exists in the previous round but not in the current round, because it searches BOTH rounds: [5](#0-4) 

Additional vulnerable dictionary accesses exist when calling `ArrangeAbnormalMiningTime`: [6](#0-5) [7](#0-6) 

And using `.Single()` which throws if the key doesn't exist: [8](#0-7) 

Public entry points that invoke `IsCurrentMiner` include **ClaimTransactionFees**: [9](#0-8) [10](#0-9) 

**DonateResourceToken**: [11](#0-10) 

**ProposeCrossChainIndexing**: [12](#0-11) [13](#0-12) [14](#0-13) 

**ReleaseCrossChainIndexingProposal**: [15](#0-14) 

## Impact Explanation

This causes authorization checks to throw unhandled exceptions instead of returning false during term transitions and miner replacements. The transaction failures occur when addresses that were miners in the previous round but not in the current round attempt to call authorization-protected functions. While the protocol continues to function for legitimate current miners, the exception-throwing behavior creates operational disruption during consensus transitions, which are regularly occurring events in AEDPoS.

## Likelihood Explanation

This occurs deterministically during every term transition or miner replacement when addresses not in the current miner set attempt authorization-protected operations. Term changes occur regularly in AEDPoS based on configured `PeriodSeconds`, and miner replacements occur when miners miss time slots. The execution path is straightforward:

1. Term transition/miner replacement sets `IsMinerListJustChanged = true`
2. An address not in the current round calls a protected function
3. `ConvertAddressToPubkey` finds the pubkey in the previous round
4. `IsCurrentMiner` bypasses safety check (lines 142-144)
5. Dictionary access at line 158, 182, or 205 throws `KeyNotFoundException`

## Recommendation

Add proper key validation before all dictionary accesses in the `IsCurrentMiner` method, even when `IsMinerListJustChanged` is true. The safety check should be modified to validate key existence regardless of the flag state, or explicit checks should be added before each dictionary access.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Set up a consensus round with a set of miners
2. Transition to a new term/round with different miners (setting `IsMinerListJustChanged = true`)
3. Have an address from the previous round (but not in current round) call `ClaimTransactionFees` or similar
4. Observe the `KeyNotFoundException` being thrown at line 158 instead of graceful authorization denial

## Notes

The conditional check bypass at lines 142-144 appears intentional to handle the case where the extra block producer from the previous round should still be authorized during the transition period (lines 150-154). However, the subsequent code fails to properly handle cases where other pubkeys from the previous round are not in the current round's dictionary, resulting in exceptions instead of returning false for unauthorized callers.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L128-130)
```csharp
        var possibleKeys = currentRound.RealTimeMinersInformation.Keys.ToList();
        if (TryToGetPreviousRoundInformation(out var previousRound))
            possibleKeys.AddRange(previousRound.RealTimeMinersInformation.Keys);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L142-144)
```csharp
        if (!currentRound.IsMinerListJustChanged)
            if (!currentRound.RealTimeMinersInformation.ContainsKey(pubkey))
                return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L158-158)
```csharp
        var minerInRound = currentRound.RealTimeMinersInformation[pubkey];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L182-182)
```csharp
            currentRound.ArrangeAbnormalMiningTime(pubkey, Context.CurrentBlockTime, true);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L205-205)
```csharp
                    currentRound.RealTimeMinersInformation.Single(i => i.Key == pubkey).Value.Order;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L42-42)
```csharp
        round.IsMinerListJustChanged = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L14-14)
```csharp
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L24-24)
```csharp
        var minerInRound = RealTimeMinersInformation[pubkey];
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L867-869)
```csharp
    public override Empty ClaimTransactionFees(TotalTransactionFeesMap input)
    {
        AssertSenderIsCurrentMiner();
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L897-906)
```csharp
    private void AssertSenderIsCurrentMiner()
    {
        if (State.ConsensusContract.Value == null)
        {
            State.ConsensusContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);
        }

        Assert(State.ConsensusContract.IsCurrentMiner.Call(Context.Sender).Value, "No permission.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L913-915)
```csharp
    public override Empty DonateResourceToken(TotalResourceTokensMaps input)
    {
        AssertSenderIsCurrentMiner();
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L282-286)
```csharp
    public override Empty ProposeCrossChainIndexing(CrossChainBlockData input)
    {
        Context.LogDebug(() => "Proposing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L293-297)
```csharp
    public override Empty ReleaseCrossChainIndexingProposal(ReleaseCrossChainIndexingProposalInput input)
    {
        Context.LogDebug(() => "Releasing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L288-294)
```csharp
    private void AssertAddressIsCurrentMiner(Address address)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        var isCurrentMiner = State.CrossChainInteractionContract.CheckCrossChainIndexingPermission.Call(address)
            .Value;
        Assert(isCurrentMiner, "No permission.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L25-28)
```csharp
    public override BoolValue CheckCrossChainIndexingPermission(Address input)
    {
        return IsCurrentMiner(input);
    }
```
