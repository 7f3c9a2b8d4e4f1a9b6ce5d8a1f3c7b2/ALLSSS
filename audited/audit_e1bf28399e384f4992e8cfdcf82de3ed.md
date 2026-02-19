### Title
Integer Division in CalculateShares Causes Unfair Zero-Share Allocation for Miners at Threshold Boundary

### Summary
The `CalculateShares` function in TreasuryContract.cs uses integer division in its reward calculation formula, which can cause miners who meet the minimum block production threshold (average/2) to still receive 0 shares. This occurs when the squared block count is less than the average due to integer truncation, resulting in unfair reward distribution for miners who should qualify for basic mining rewards.

### Finding Description

The vulnerability exists in the `CalculateShares` function [1](#0-0)  which is called during basic miner reward weight updates. [2](#0-1) 

The function implements a two-threshold system:
1. If `producedBlocksCount < average/2`, return 0 shares (intended behavior)
2. If `producedBlocksCount < 4*average/5`, apply formula: `producedBlocksCount² / averageProducedBlocksCount`
3. Otherwise, return full `producedBlocksCount` shares

**Root Cause:** The integer division in step 2 can return 0 when `producedBlocksCount² < averageProducedBlocksCount`, which mathematically means `producedBlocksCount < sqrt(averageProducedBlocksCount)`.

**Why Protection Fails:** The first threshold check uses `<` (strictly less than), so miners producing exactly `average/2` blocks pass this check. However, when `average/2 < sqrt(average)` (which occurs when average < 4), these miners enter the formula and receive 0 shares due to integer division.

**Concrete Example:**
- Average produced blocks = 5
- Threshold 1: `5.Div(2) = 2` (due to integer division)
- Miner producing 2 blocks:
  - Check: `2 < 2` = FALSE (passes threshold)
  - Formula: `2 × 2 / 5 = 4 / 5 = 0` (integer division)
  - Result: 0 shares despite meeting minimum threshold

The `Div` extension method [3](#0-2)  performs standard integer division, confirming truncation behavior.

### Impact Explanation

**Direct Fund Impact - Reward Misallocation:**
- Miners producing blocks at or near the average/2 threshold unfairly receive 0 shares instead of proportional rewards
- These miners contributed legitimate block production but are treated identically to miners who produced far fewer blocks
- The "lost" rewards are redistributed to other miners, creating an unfair advantage

**Affected Parties:**
- Miners operating in networks/terms with low average block production (average < 4 blocks per miner)
- Miners who produce exactly at threshold boundaries due to network conditions or performance issues

**Severity Justification:**
This is a Medium severity issue because:
- It causes financial harm to specific miners who should qualify for rewards
- The impact is deterministic and repeatable whenever average block production is low
- It violates the intended reward distribution policy (miners above average/2 should receive shares)
- However, no funds are permanently lost - they're just redistributed unfairly

### Likelihood Explanation

**Occurrence Probability:**
This issue occurs automatically without attacker involvement whenever:
- Average block production per miner falls below 4 blocks in a term
- Miners produce blocks exactly at or slightly above the average/2 threshold

**Feasibility Conditions:**
- Happens naturally during normal consensus operations [4](#0-3) 
- No special permissions or attack vectors required
- Triggered during automatic treasury release operations [5](#0-4) 
- More likely in networks with frequent miner rotations, short terms, or performance issues

**Detection Constraints:**
- Difficult to detect without detailed analysis of share calculations
- Appears as legitimate reward distribution in normal operations
- Affected miners may not realize they received unfairly low rewards

### Recommendation

**Code-Level Mitigation:**

Replace the integer division formula with one that ensures minimum share allocation or uses rounding that favors the miner:

```csharp
private long CalculateShares(long producedBlocksCount, long averageProducedBlocksCount)
{
    if (producedBlocksCount < averageProducedBlocksCount.Div(2))
        return 0;

    if (producedBlocksCount < averageProducedBlocksCount.Div(5).Mul(4))
    {
        // Ensure minimum 1 share for miners who pass the threshold
        var shares = producedBlocksCount.Mul(producedBlocksCount).Div(averageProducedBlocksCount);
        return shares > 0 ? shares : 1;
    }

    return producedBlocksCount;
}
```

**Alternative Fix - Use Ceiling Division:**
Implement a ceiling division that rounds up instead of truncating:
```csharp
var numerator = producedBlocksCount.Mul(producedBlocksCount);
var shares = (numerator.Add(averageProducedBlocksCount).Sub(1)).Div(averageProducedBlocksCount);
```

**Invariant Check:**
Add assertion: "Miners producing >= average/2 blocks must receive > 0 shares"

**Test Cases:**
1. Test with averageProducedBlocksCount = 2, 3, 5, 10 and miners at exact threshold values
2. Verify miners at average/2 receive non-zero shares
3. Test boundary cases where sqrt(average) > average/2

### Proof of Concept

**Initial State:**
- Term with 5 miners
- Average block production = 5 blocks per miner
- One miner produces exactly 2 blocks (at the average/2 threshold)

**Execution:**
1. Consensus contract calls `Release()` at term end [6](#0-5) 
2. Treasury calls `UpdateBasicMinerRewardWeights()` [7](#0-6) 
3. For miner with 2 blocks, `CalculateShares(2, 5)` is called
4. First check: `2 < 2` = FALSE (passes)
5. Second check: `2 < 4` = TRUE (enters formula)
6. Calculation: `2 * 2 / 5 = 4 / 5 = 0` (integer division)
7. Miner receives 0 shares via `AddBeneficiaries` [8](#0-7) 

**Expected Result:**
Miner producing 2 blocks should receive proportional shares (at least 1 share)

**Actual Result:**
Miner receives 0 shares despite meeting the minimum threshold

**Success Condition:**
Miner's share allocation = 0 when it should be > 0, demonstrating unfair reward distribution

### Citations

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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L761-761)
```csharp
        UpdateBasicMinerRewardWeights(new List<Round> { previousPreviousTermInformation, previousTermInformation });
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L835-846)
```csharp
    private long CalculateShares(long producedBlocksCount, long averageProducedBlocksCount)
    {
        if (producedBlocksCount < averageProducedBlocksCount.Div(2))
            // If count < (1/2) * average_count, then this node won't share Basic Miner Reward.
            return 0;

        if (producedBlocksCount < averageProducedBlocksCount.Div(5).Mul(4))
            // If count < (4/5) * average_count, then ratio will be (count / average_count)
            return producedBlocksCount.Mul(producedBlocksCount).Div(averageProducedBlocksCount);

        return producedBlocksCount;
    }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```
