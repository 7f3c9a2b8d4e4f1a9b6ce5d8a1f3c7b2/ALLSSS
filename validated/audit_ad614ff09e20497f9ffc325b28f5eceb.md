# Audit Report

## Title
Unbounded Nested Loop Complexity in Consensus Round Update Causes Block Production Denial of Service

## Summary
The `ApplyNormalConsensusData` function contains nested loops with O(c×n²) computational complexity that exceed AElf's execution branch threshold of 15,000 when `MaximumMinersCount` scales to 100+ miners with order conflicts, causing consensus DoS through `RuntimeBranchThresholdExceededException`.

## Finding Description

The vulnerability exists in the consensus round update logic where miners calculate next-round order assignments through a conflict resolution algorithm with unbounded computational complexity. [1](#0-0) 

The nested structure creates O(c×n²) complexity:
- **Outer loop** (line 28): Iterates over conflicts (miners with duplicate `FinalOrderOfNextRound`)
- **Middle loop** (line 31): Searches up to `2×minersCount` positions for available slots
- **Inner operation** (line 34): `.All()` method checks all `minersCount` miners for each candidate position

This function is invoked during normal block production through the execution path: [2](#0-1) 

Which routes to `GetConsensusExtraDataToPublishOutValue` for UpdateValue behavior: [3](#0-2) 

Which calls the vulnerable function: [4](#0-3) 

The critical failure point is that `SetMaximumMinersCount` has no upper bound validation: [5](#0-4) 

AElf enforces execution limits through branch counting at 15,000: [6](#0-5) 

The branch counter is incremented at every backward branch instruction (loop iteration): [7](#0-6) 

Backward branches are detected when jump targets precede current instruction: [8](#0-7) 

Testing confirms that 15,000 loop iterations trigger the exception: [9](#0-8) 

With minersCount=100 and conflicts=3, the total branch count reaches approximately 60,000 (3 × 200 × 100), which is 4× over the 15,000 threshold.

## Impact Explanation

**Operational DoS of Consensus:**
- When `ApplyNormalConsensusData` exceeds the branch threshold, `RuntimeBranchThresholdExceededException` is thrown
- The affected miner cannot generate valid consensus extra data, preventing block production
- If multiple miners encounter this condition simultaneously (which is likely given they all process the same round data), the blockchain experiences block production delays or complete consensus halts
- Recovery requires emergency governance action to reduce `MaximumMinersCount`, creating a catch-22 since governance proposals require functional block production

**Quantified Threshold Breach:**
- minersCount=50, conflicts=6: ~30,000 branches (2× over threshold)
- minersCount=100, conflicts=3: ~60,000 branches (4× over threshold)
- minersCount=200, conflicts=2: ~160,000 branches (10.7× over threshold)

**Severity:** High - Causes operational DoS of the core consensus mechanism. While it requires governance to set enabling parameters, this is a legitimate network scaling action, not malicious configuration.

## Likelihood Explanation

**Preconditions:**
1. Governance sets `MaximumMinersCount` to 100+ through Parliament proposal (legitimate scaling action)
2. Order conflicts occur among miners through hash collisions in signature-based order assignment

**Feasibility Analysis:**
- **Attack Complexity:** Medium - Does not require compromising governance; natural network scaling toward 100+ miners is a predictable evolution path
- **Conflict Probability:** Hash-based order assignment creates natural collision probability. With 100 miners choosing from 100 order slots based on signature hashes, the birthday paradox ensures multiple conflicts occur regularly
- **Execution Path:** Reachable through standard consensus flow during normal block production without special permissions
- **No Protections:** No complexity checks or upper bounds exist on miner count

**Probability Assessment:** Medium-to-High likelihood as the chain matures. Current production deployments with 17 miners are safe, but scaling toward 50-100 miners creates a critical risk zone where legitimate network growth triggers consensus failure. Malicious miners could intentionally manipulate their signatures to create conflicts, though natural hash collisions are sufficient to trigger the issue.

## Recommendation

**Immediate Mitigation:**
Add an upper bound check in `SetMaximumMinersCount`:

```csharp
public override Empty SetMaximumMinersCount(Int32Value input)
{
    EnsureElectionContractAddressSet();
    
    Assert(input.Value > 0, "Invalid max miners count.");
    Assert(input.Value <= 50, "Max miners count exceeds safe threshold."); // Add upper bound
    
    RequiredMaximumMinersCountControllerSet();
    Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
        "No permission to set max miners count.");
    // ... rest of method
}
```

**Long-term Solution:**
Refactor the conflict resolution algorithm to reduce computational complexity:

1. Use a hash set to track occupied orders instead of `.All()` checks (O(1) lookup)
2. Limit conflict resolution iterations with early exit conditions
3. Pre-allocate order assignments deterministically to minimize runtime conflicts
4. Consider incremental conflict resolution across multiple blocks rather than resolving all conflicts in a single transaction

## Proof of Concept

```csharp
[Fact]
public async Task Test_ConsensusDoS_With_HighMinerCount()
{
    // Setup: Set MaximumMinersCount to 100 through governance
    var proposalId = await CreateParliamentProposalAsync(
        ConsensusContractAddress,
        nameof(AEDPoSContract.SetMaximumMinersCount),
        new Int32Value { Value = 100 });
    await ApproveAndReleaseProposalAsync(proposalId);
    
    // Simulate 100 miners producing blocks with intentional order conflicts
    var round = await CreateRoundWith100Miners();
    
    // Create 3 miners with conflicting FinalOrderOfNextRound values
    round.RealTimeMinersInformation[miner1].FinalOrderOfNextRound = 50;
    round.RealTimeMinersInformation[miner2].FinalOrderOfNextRound = 50;
    round.RealTimeMinersInformation[miner3].FinalOrderOfNextRound = 50;
    
    // Attempt to apply consensus data - should exceed branch threshold
    var triggerInfo = new AElfConsensusTriggerInformation
    {
        Behaviour = AElfConsensusBehaviour.UpdateValue,
        Pubkey = ByteString.CopyFrom(miner4PublicKey),
        PreviousInValue = HashHelper.ComputeFrom("test"),
        InValue = HashHelper.ComputeFrom("test2")
    };
    
    // This should throw RuntimeBranchThresholdExceededException
    var result = await ConsensusContractStub.GetConsensusExtraData
        .SendWithExceptionAsync(triggerInfo.ToBytesValue());
    
    result.TransactionResult.Error.ShouldContain("RuntimeBranchThresholdExceededException");
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L25-40)
```csharp
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L56-59)
```csharp
    public override BytesValue GetConsensusExtraData(BytesValue input)
    {
        return GetConsensusBlockExtraData(input);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L28-31)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L14-14)
```csharp
        Assert(input.Value > 0, "Invalid max miners count.");
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L7-7)
```csharp
    public const int ExecutionBranchThreshold = 15000;
```

**File:** src/AElf.Sdk.CSharp/ExecutionObserver.cs (L29-36)
```csharp
    public void BranchCount()
    {
        if (_branchThreshold != -1 && _branchCount == _branchThreshold)
            throw new RuntimeBranchThresholdExceededException(
                $"Contract branch threshold {_branchThreshold} exceeded.");

        _branchCount++;
    }
```

**File:** src/AElf.CSharp.CodeOps/Patchers/Module/CallAndBranchCounts/Patcher.cs (L80-84)
```csharp
        static bool IsValidInstruction(Instruction instruction)
        {
            var targetInstruction = (Instruction) instruction.Operand;
            return targetInstruction.Offset < instruction.Offset; // What does this mean?
        }
```

**File:** test/AElf.Contracts.TestContract.Tests/PatchedContractSecurityTests.cs (L392-397)
```csharp
            await TestBasicSecurityContractStub.TestWhileInfiniteLoop.SendAsync(new Int32Input
                { Int32Value = 14999 });
            var txResult = await TestBasicSecurityContractStub.TestWhileInfiniteLoop.SendWithExceptionAsync(
                new Int32Input
                    { Int32Value = 15000 });
            txResult.TransactionResult.Error.ShouldContain(nameof(RuntimeBranchThresholdExceededException));
```
