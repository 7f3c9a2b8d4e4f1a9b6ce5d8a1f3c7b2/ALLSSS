### Title
Block Count Reduction Failure After Miner Set Size Decrease During Abnormal Status

### Summary
When the miner count is reduced via governance (using `SetMaximumMinersCount`) and the blockchain subsequently enters Abnormal status due to LIB falling behind, the block count reduction mechanism fails to reduce maximum blocks. The intersection count from previous rounds with more miners creates a disproportionately large factor, causing `Math.Min` to consistently return `MaximumTinyBlocksCount` (8) instead of progressively reducing blocks as intended, defeating the purpose of Abnormal status mitigation.

### Finding Description

The vulnerability exists in the `GetMaximumBlocksCount()` method's Abnormal status handling logic: [1](#0-0) 

The factor calculation multiplies the intersection count `minersOfLastTwoRounds` (L2) by the remaining rounds before Severe status, then divides by the current round's miner count: [2](#0-1) 

**Root Cause:**

The formula compares miners from **different miner sets**:
- `L2` = intersection count of miners who actually mined in rounds (R-1) and (R-2)
- `A` = `currentRound.RealTimeMinersInformation.Count` = scheduled miners in current round R

When governance reduces the miner count between terms (a legitimate operation), [3](#0-2)  L2 can significantly exceed A, creating an "apples-to-oranges" comparison.

**Concrete Scenario:**

1. Rounds (R-2) and (R-1): 25 miners (pre-reduction), all 25 mined in both rounds
2. Round R: Miner count reduced to 3 via `SetMaximumMinersCount` [4](#0-3) 
3. Network enters Abnormal status with R - R_LIB = 3

**Calculation:**
- L2 = 25 (all miners from previous rounds who mined)
- A = 3 (current miner count)
- factor = 25 × (8 - 3) = 125
- count = Min(8, Ceiling(125 / 3)) = Min(8, 42) = **8**

Throughout Abnormal status (R - R_LIB = 3 to 7):
- R - R_LIB = 3: Min(8, Ceiling(125/3)) = Min(8, 42) = 8
- R - R_LIB = 4: Min(8, Ceiling(100/3)) = Min(8, 34) = 8
- R - R_LIB = 5: Min(8, Ceiling(75/3)) = Min(8, 25) = 8
- R - R_LIB = 6: Min(8, Ceiling(50/3)) = Min(8, 17) = 8
- R - R_LIB = 7: Min(8, Ceiling(25/3)) = Min(8, 9) = 8

The count remains at 8 (no reduction) until Severe status is reached.

**Why Protections Fail:**

The constant `MaximumTinyBlocksCount` is hardcoded to 8: [5](#0-4) 

The Abnormal status threshold logic correctly identifies the status: [6](#0-5) 

However, the formula doesn't normalize for miner count changes, allowing historical miner counts to override current reduction requirements.

### Impact Explanation

**Consensus Integrity Impact:**

The Abnormal status is designed to progressively reduce block production when LIB falls behind, preventing excessive forks and allowing the network to stabilize. The comment explicitly states this purpose: [7](#0-6) 

When this mechanism fails:
1. **Increased Fork Risk**: Miners continue producing 8 tiny blocks each when they should be producing fewer, potentially creating more competing chains
2. **Delayed Finalization**: The network doesn't get the breathing room to catch up on LIB advancement
3. **Sudden Drop**: Instead of gradual reduction (8→5→3→2→1), blocks stay at 8 then suddenly drop to 1 at Severe status, causing jarring network behavior

**Who Is Affected:**
- All network participants during periods when both:
  - Governance has recently reduced miner count (a routine governance action)
  - Network experiences temporary synchronization issues causing Abnormal status

**Severity Justification (Medium):**
- Not direct fund theft, but impacts critical consensus mechanics
- Realistic preconditions (legitimate governance + network stress)
- Degrades consensus reliability and fork resolution
- Could prolong network instability periods

### Likelihood Explanation

**Feasible Preconditions:**

1. **Governance Miner Reduction**: The `SetMaximumMinersCount` function is a legitimate governance operation for right-sizing the validator set. Tests demonstrate reductions from 25 to 3 miners: [8](#0-7) 

2. **Abnormal Status Entry**: Network enters Abnormal status when `R_LIB + 2 < R < R_LIB + 8`, which can occur due to:
   - Network latency/partition
   - Malicious miner behavior
   - High transaction load
   - Shortly after term change when new miners are adjusting

**Execution Practicality:**

The vulnerability manifests through normal contract execution flow:
- `GetMaximumBlocksCount()` is called from `ProcessConsensusInformation` during every consensus behavior: [9](#0-8) 
- No special attacker capabilities required
- Occurs automatically when conditions align

**Probability Reasoning:**

- **Moderate Likelihood**: Requires confluence of governance action (miner reduction) and network stress (Abnormal status)
- **Increasing Probability**: More likely shortly after term changes when miner set adjusts
- **Detection**: Network operators may not immediately notice as blocks are still being produced, just not reducing as designed

### Recommendation

**Code-Level Mitigation:**

Normalize the intersection count relative to the historical miner set size. Replace lines 48-52 with:

```csharp
// Normalize L2 to account for miner set size changes
var previousRoundMinerCount = Math.Max(previousRoundMinedMinerList.Count, 
                                      previousPreviousRoundMinedMinerList.Count);
var normalizedIntersectionRatio = previousRoundMinerCount > 0 
    ? (decimal)minersOfLastTwoRounds / previousRoundMinerCount 
    : 0;
var adjustedFactor = (int)(normalizedIntersectionRatio * currentRound.RealTimeMinersInformation.Count)
    .Mul(blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
        (int)currentRoundNumber.Sub(libRoundNumber)));
var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
    Ceiling(adjustedFactor, currentRound.RealTimeMinersInformation.Count));
```

This normalizes the intersection count as a ratio of historical miners, then scales it by current miner count before applying the formula.

**Invariant Checks:**

Add assertion to ensure reduction actually occurs in Abnormal status:
```csharp
if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
{
    // ... existing calculation ...
    Assert(count < AEDPoSContractConstants.MaximumTinyBlocksCount, 
           "Block count must reduce during Abnormal status");
    return count;
}
```

**Regression Test Cases:**

1. Test scenario with miner reduction from 25→3 followed by Abnormal status entry
2. Verify count progressively reduces (not stuck at 8)
3. Test with various reduction ratios (25→17, 17→7, etc.)
4. Verify behavior when miner count increases (inverse scenario)

### Proof of Concept

**Initial State:**
1. Network operating normally with 25 miners in rounds (R-2) and (R-1)
2. All 25 miners successfully mined blocks in both rounds
3. Mined miner lists recorded via `RecordMinedMinerListOfCurrentRound()`: [10](#0-9) 

**Transaction Steps:**

1. **Governance reduces miner count**:
   - Parliament creates proposal to call `SetMaximumMinersCount(3)`
   - Proposal approved and released
   - Next term transition via `NextTerm()` applies reduction
   - Current round R now has 3 miners in `RealTimeMinersInformation`

2. **Network enters Abnormal status**:
   - Due to network issues, LIB stops advancing quickly
   - Current round reaches R = R_LIB + 3 (entering Abnormal status)
   - Blockchain status evaluator identifies status as Abnormal: [11](#0-10) 

3. **Block count calculation executes**:
   - `GetMaximumBlocksCount()` called during consensus processing
   - Retrieves previous miner lists with 25 miners each
   - Calculates intersection: 25 miners
   - Computes factor: 25 × (8 - 3) = 125
   - Returns: Min(8, Ceiling(125 / 3)) = 8

**Expected Result:**
Block count should reduce from 8 (e.g., to 5 when R - R_LIB = 3, then progressively down to 1)

**Actual Result:**
Block count remains at 8 throughout Abnormal status (R - R_LIB = 3 through 7), only dropping to 1 at Severe status

**Success Condition:**
Monitoring the `GetMaximumBlocksCount()` return value shows it returns 8 consistently during Abnormal status, failing to provide the intended progressive reduction to mitigate fork risk.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L17-20)
```csharp
    /// <summary>
    ///     Implemented GitHub PR #1952.
    ///     Adjust (mainly reduce) the count of tiny blocks produced by a miner each time to avoid too many forks.
    /// </summary>
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L35-39)
```csharp
        var blockchainMiningStatusEvaluator = new BlockchainMiningStatusEvaluator(libRoundNumber,
            currentRoundNumber, AEDPoSContractConstants.MaximumTinyBlocksCount);
        blockchainMiningStatusEvaluator.Deconstruct(out var blockchainMiningStatus);

        Context.LogDebug(() => $"Current blockchain mining status: {blockchainMiningStatus.ToString()}");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L42-54)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
        {
            var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
            var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
            var minersOfLastTwoRounds = previousRoundMinedMinerList
                .Intersect(previousPreviousRoundMinedMinerList).Count();
            var factor = minersOfLastTwoRounds.Mul(
                blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
                    (int)currentRoundNumber.Sub(libRoundNumber)));
            var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
                Ceiling(factor, currentRound.RealTimeMinersInformation.Count));
            Context.LogDebug(() => $"Maximum blocks count tune to {count}");
            return count;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L123-125)
```csharp
            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L1-50)
```csharp
using System;
using AElf.Contracts.Election;
using AElf.CSharp.Core;
using Google.Protobuf.WellKnownTypes;

namespace AElf.Contracts.Consensus.AEDPoS;

public partial class AEDPoSContract
{
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

    public override Empty ChangeMaximumMinersCountController(AuthorityInfo input)
    {
        RequiredMaximumMinersCountControllerSet();
        AssertSenderAddressWith(State.MaximumMinersCountController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");
```

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L1852-1887)
```csharp
        var minerCount = 3;
        await NextRound(InitialCoreDataCenterKeyPairs[0]);
        var dataCenterList = await ElectionContractStub.GetDataCenterRankingList.CallAsync(new Empty());
        dataCenterList.DataCenters.Count.ShouldBe(fullCount);
        var diffCount = fullCount.Sub(minerCount.Mul(5));
        var subsidy = ProfitItemsIds[ProfitType.BackupSubsidy];
        foreach (var keyPair in ValidationDataCenterKeyPairs.Take(diffCount))
        {
            var profitDetail = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
            {
                SchemeId = subsidy,
                Beneficiary = Address.FromPublicKey(keyPair.PublicKey)
            });
            profitDetail.Details[0].EndPeriod.ShouldNotBe(0);
            profitDetail.Details.Count.ShouldBe(1);
        }

        await ResetMinerCount(minerCount);
        await NextTerm(InitialCoreDataCenterKeyPairs[0]);
        var newMinerCount = await ElectionContractStub.GetMinersCount.CallAsync(new Empty());
        newMinerCount.Value.ShouldBe(minerCount);
        var dataCenterListAfterReduceBp =
            await ElectionContractStub.GetDataCenterRankingList.CallAsync(new Empty());

        dataCenterList.DataCenters.Count.Sub(dataCenterListAfterReduceBp.DataCenters.Count).ShouldBe(diffCount);
        foreach (var keyPair in ValidationDataCenterKeyPairs.Take(diffCount))
        {
            dataCenterListAfterReduceBp.DataCenters.ContainsKey(keyPair.PublicKey.ToHex()).ShouldBeFalse();
            var profitDetail = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
            {
                SchemeId = subsidy,
                Beneficiary = Address.FromPublicKey(keyPair.PublicKey)
            });
            profitDetail.Details[0].EndPeriod.ShouldBe(0);
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L67-69)
```csharp
        // Make sure the method GetMaximumBlocksCount executed no matter what consensus behaviour is.
        var minersCountInTheory = GetMaximumBlocksCount();
        ResetLatestProviderToTinyBlocksCount(minersCountInTheory);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L223-236)
```csharp
    private void RecordMinedMinerListOfCurrentRound()
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        State.MinedMinerListMap.Set(currentRound.RoundNumber, new MinerList
        {
            Pubkeys = { currentRound.GetMinedMiners().Select(m => ByteStringHelper.FromHexString(m.Pubkey)) }
        });

        // Remove information out of date.
        var removeTargetRoundNumber = currentRound.RoundNumber.Sub(3);
        if (removeTargetRoundNumber > 0 && State.MinedMinerListMap[removeTargetRoundNumber] != null)
            State.MinedMinerListMap.Remove(removeTargetRoundNumber);
    }
```
