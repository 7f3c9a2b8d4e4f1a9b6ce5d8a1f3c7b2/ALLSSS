# Audit Report

## Title
Global Per-Block Execution Lock Creates Denial of Service for Consensus and Cross-Chain Operations

## Summary
The `EnsureTransactionOnlyExecutedOnceInOneBlock()` helper function uses a single global state variable to enforce per-block execution limits, preventing ALL methods that call it from executing in the same block rather than implementing per-method limits. This affects four critical consensus operations in AEDPoS (`UpdateValue`, `UpdateTinyBlockInformation`, `NextRound`, `NextTerm`) and two cross-chain operations (`ProposeCrossChainIndexing`, `ReleaseCrossChainIndexingProposal`), causing denial of service that delays consensus progression and cross-chain communication by at least one block.

## Finding Description

The root cause exists in both the AEDPoS consensus contract and CrossChain contract, where `EnsureTransactionOnlyExecutedOnceInOneBlock()` uses a single global `LatestExecutedHeight` state variable instead of a per-method tracking mechanism. [1](#0-0) [2](#0-1) 

This helper is called from the shared `ProcessConsensusInformation()` method: [3](#0-2) 

Which is invoked by four different public consensus methods: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

The same pattern exists in the CrossChain contract: [8](#0-7) [9](#0-8) 

Used by two cross-chain methods: [10](#0-9) [11](#0-10) 

When the first method executes in a block, it sets `State.LatestExecutedHeight.Value = Context.CurrentHeight`, causing all subsequent method calls in the same block to fail with "Cannot execute this tx." regardless of which specific operation they perform. This creates a global mutex across functionally independent operations.

## Impact Explanation

**Consensus Availability Impact:** Only ONE of four critical consensus operations can execute per block. If `UpdateValue` or `UpdateTinyBlockInformation` executes first, it blocks `NextRound` or `NextTerm` from executing in the same block, delaying:
- Round transitions (critical for consensus progression)
- Term transitions (required for miner list updates and reward distribution)
- Mining information updates

**Cross-Chain Availability Impact:** Only ONE of `ProposeCrossChainIndexing` or `ReleaseCrossChainIndexingProposal` can execute per block, delaying cross-chain communication and merkle path verification.

**Race Condition Risk:** Multiple miners can legitimately submit different consensus operations (verified by permission checks that only require miner list membership). When their transactions are included in the same block, one will fail unpredictably, creating operational instability.

The impact is HIGH because it affects core protocol operations with high frequency of occurrence. While limited to one-block delays (not permanent DOS), the criticality of affected operations and frequency of conflicts justify this severity rating.

## Likelihood Explanation

**Attacker Capabilities:** Only current miners can call these methods, verified by permission checks: [12](#0-11) [13](#0-12) 

However, miners are precisely the parties that need to execute these operations, making this a realistic scenario.

**Feasibility:** HIGH - This occurs naturally during normal operations when:
- A block needs both mining information updates AND round/term transitions
- Cross-chain indexing proposals need to be proposed AND released in the same block  
- Multiple miners submit different consensus operations that get included in the same block

**Attack Complexity:** Minimal - a miner simply needs to submit a consensus transaction that executes before other operations in the block. No complex setup required.

**Detection:** Failed transactions show "Cannot execute this tx." error without indicating which operation blocked them, providing no actionable debugging information.

The likelihood is HIGH because consensus operations serve different purposes and conflicts will occur regularly during normal protocol operation, not just during intentional attacks.

## Recommendation

Replace the global `SingletonState<long> LatestExecutedHeight` with a per-method tracking mechanism using `MappedState<string, long> LatestExecutedHeightPerMethod` where the key is the method name.

**Modified Implementation:**

```csharp
private void EnsureTransactionOnlyExecutedOnceInOneBlock(string methodName)
{
    Assert(State.LatestExecutedHeightPerMethod[methodName] != Context.CurrentHeight, 
           "Cannot execute this tx.");
    State.LatestExecutedHeightPerMethod[methodName] = Context.CurrentHeight;
}
```

This allows independent tracking of each method's execution, preventing duplicate calls of the SAME method while allowing different methods to execute in the same block.

## Proof of Concept

The vulnerability can be demonstrated by observing that at block height N:

1. Miner A calls `UpdateValue()` → Sets `LatestExecutedHeight = N` → Succeeds
2. Miner B calls `NextRound()` in the same block → Checks `LatestExecutedHeight (N) == CurrentHeight (N)` → **Fails** with "Cannot execute this tx."

This delays the critical `NextRound()` operation by one block, even though the two operations serve different purposes and should be independently executable. The same scenario applies to cross-chain operations where `ProposeCrossChainIndexing` blocks `ReleaseCrossChainIndexingProposal`.

The permission checks verify miner status but do not prevent multiple miners from submitting transactions to the same block, making this scenario achievable during normal protocol operation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AElfConsensusContractState.cs (L55-55)
```csharp
    public SingletonState<long> LatestExecutedHeight { get; set; }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L21-23)
```csharp
    private void ProcessConsensusInformation(dynamic input, [CallerMemberName] string callerMethodName = null)
    {
        EnsureTransactionOnlyExecutedOnceInOneBlock();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L108-112)
```csharp
    public override Empty UpdateTinyBlockInformation(TinyBlockInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContractState.cs (L28-28)
```csharp
    public SingletonState<long> LatestExecutedHeight { get; set; }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L288-295)
```csharp
    private void AssertAddressIsCurrentMiner(Address address)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        var isCurrentMiner = State.CrossChainInteractionContract.CheckCrossChainIndexingPermission.Call(address)
            .Value;
        Assert(isCurrentMiner, "No permission.");
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L895-899)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L293-302)
```csharp
    public override Empty ReleaseCrossChainIndexingProposal(ReleaseCrossChainIndexingProposalInput input)
    {
        Context.LogDebug(() => "Releasing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        Assert(input.ChainIdList.Count > 0, "Empty input not allowed.");
        ReleaseIndexingProposal(input.ChainIdList);
        RecordCrossChainData(input.ChainIdList);
        return new Empty();
    }
```
