### Title
Stale IsReplacedEvilMiner Flag Causes Incorrect Reward Distribution for Returning Miners

### Summary
The `IsReplacedEvilMiner` flag in TreasuryContract can become stale when a miner is replaced mid-term but subsequently replaced again before term end. This stale flag persists across terms and incorrectly grants full share rewards to the miner when they return in a future term, bypassing the performance-based reward calculation that should penalize poor performance.

### Finding Description

**Root Cause:**
The `IsReplacedEvilMiner` flag is a global pubkey-mapped state that is set when a miner replacement occurs [1](#0-0)  but only cleared when processing rewards for miners present in the final term's miner list [2](#0-1) .

**Execution Path:**

1. During Term N, Miner A is replaced by Miner X via the consensus contract's `RecordCandidateReplacement` function, which calls `TreasuryContract.RecordMinerReplacement` [3](#0-2)  setting `IsReplacedEvilMiner[X] = true`.

2. Later in Term N, Miner X is replaced by Miner Y (due to going offline or evil behavior). The consensus contract updates the round information, removing X and adding Y. A new flag is set for Y, but X's flag remains true.

3. At the start of Term N+1, `Release(N)` is called [4](#0-3) , which invokes `UpdateBasicMinerRewardWeights` [5](#0-4) .

4. The function iterates through `previousTermInformation.Last().RealTimeMinersInformation.Values`, which contains the final miner list for Term N (including Y, but NOT X since X was replaced).

5. Y's flag is checked and cleared, but X's flag is never checked because X is not in the final miner list. The flag for X remains true indefinitely.

6. In a future Term M, Miner X returns (through election or as another replacement). When `Release(M)` processes rewards, it finds `IsReplacedEvilMiner[X] = true` (stale from Term N) and incorrectly assigns `shares = i.ProducedBlocks` instead of using the performance-based `CalculateShares()` function [6](#0-5) .

**Why Protections Fail:**
The flag clearing logic at line 807 only executes for miners in the current term's final miner list. There is no mechanism to clear flags for miners who were temporarily added but then removed before term end.

### Impact Explanation

**Direct Impact - Reward Misallocation:**
A miner with a stale `IsReplacedEvilMiner` flag receives unfair reward advantages. The flag grants full produced blocks as shares, bypassing the performance-based calculation that:
- Returns 0 shares if produced blocks < average/2
- Applies quadratic penalty if produced blocks < 0.8 × average
- Otherwise uses produced blocks count

**Quantified Damage:**
If Miner X produces only 5 blocks when average is 20 blocks:
- **Without stale flag:** `CalculateShares(5, 20)` = 0 shares (below 50% threshold)
- **With stale flag:** 5 shares (full produced blocks count)

This represents a 100% undeserved reward allocation. Over multiple terms with poor performance, this compounds the unfair advantage.

**Affected Parties:**
- **Honest miners:** Diluted rewards as dishonest/poor-performing miners receive undeserved shares
- **Treasury distribution:** Incorrect reward allocation violates the economic model's performance incentives
- **Protocol integrity:** Undermines the penalty mechanism designed to discourage poor miner performance

### Likelihood Explanation

**Attacker Capabilities:**
This vulnerability does not require malicious intent but occurs naturally through system operations. Requirements:
1. Miner must be added as a replacement (backup candidate stepping in)
2. Same miner must be replaced again before term end (due to poor performance/evil behavior)
3. Miner must return in a future term (through election or another replacement)

**Feasibility Conditions:**
- **Reachable Entry Point:** `RecordMinerReplacement` is called by the consensus contract during normal miner replacement operations
- **Execution Practicality:** Multiple replacements within a term are possible and expected (miners going offline, detected evil behavior)
- **No Special Permissions Required:** The stale flag accumulates through normal consensus operations
- **Detection Difficulty:** The stale flag is invisible on-chain and the incorrect reward calculation appears normal

**Probability:**
Medium-Low. While multiple replacements in a single term are possible, the specific miner must return in a future term for the vulnerability to manifest. The longer the time between terms, the more likely flags accumulate.

### Recommendation

**Code-Level Mitigation:**

Change the `IsReplacedEvilMiner` state from a simple boolean mapping to a term-specific mapping:

```csharp
// In TreasuryContractState.cs, replace:
public MappedState<string, bool> IsReplacedEvilMiner { get; set; }

// With:
public MappedState<string, MappedState<long, bool>> IsReplacedEvilMinerByTerm { get; set; }
```

Update `RecordMinerReplacement` to set the term-specific flag:
```csharp
State.IsReplacedEvilMinerByTerm[input.NewPubkey][input.CurrentTermNumber] = true;
```

Update `UpdateBasicMinerRewardWeights` to check and clear the term-specific flag:
```csharp
if (State.IsReplacedEvilMinerByTerm[i.Pubkey][previousTermInformation.Last().TermNumber])
{
    shares = i.ProducedBlocks;
    State.IsReplacedEvilMinerByTerm[i.Pubkey].Remove(previousTermInformation.Last().TermNumber);
}
```

**Additional Safeguard:**
Add a cleanup mechanism in the `Release` function to clear all flags for the term being processed, ensuring no stale flags persist.

**Test Cases:**
1. Test case where miner is replaced, then replaced again in same term, then returns in future term - verify normal share calculation
2. Test case where miner is replaced in Term N, continues into Term N+1, verify flag properly cleared after Term N
3. Stress test with multiple consecutive replacements across multiple terms

### Proof of Concept

**Initial State:**
- Term N in progress with normal miner set [A, B, C, D, E]
- Backup candidates include [X, Y, Z]

**Exploit Sequence:**

**Step 1 (Block 100, Term N):**
- Miner A goes offline
- Consensus calls `Election.ReplaceCandidateByBackup(A, X)`
- This triggers `Consensus.RecordCandidateReplacement(A, X)`
- Which calls `Treasury.RecordMinerReplacement(OldPubkey=A, NewPubkey=X, CurrentTermNumber=N)`
- **State:** `IsReplacedEvilMiner[X] = true`
- Current miners: [X, B, C, D, E]

**Step 2 (Block 150, Term N):**
- Miner X detected as evil or goes offline
- Consensus calls `Election.ReplaceCandidateByBackup(X, Y)`
- This triggers `Consensus.RecordCandidateReplacement(X, Y)`  
- Which calls `Treasury.RecordMinerReplacement(OldPubkey=X, NewPubkey=Y, CurrentTermNumber=N)`
- **State:** `IsReplacedEvilMiner[X] = true` (unchanged), `IsReplacedEvilMiner[Y] = true`
- Current miners: [Y, B, C, D, E]

**Step 3 (Block 200, Start of Term N+1):**
- Consensus calls `Treasury.Release(PeriodNumber=N)`
- `UpdateBasicMinerRewardWeights` processes final Term N miner list: [Y, B, C, D, E]
- Flag checked and cleared for Y: `IsReplacedEvilMiner[Y]` → removed
- **Flag for X NOT checked** (X not in final miner list)
- **State:** `IsReplacedEvilMiner[X] = true` (STALE)

**Step 4 (Term M, several terms later):**
- Miner X is elected normally or replaces another miner
- X mines only 5 blocks (poor performance)
- Average produced blocks = 20

**Step 5 (Start of Term M+1):**
- Consensus calls `Treasury.Release(PeriodNumber=M)`
- `UpdateBasicMinerRewardWeights` processes Term M miner list including X
- Checks `IsReplacedEvilMiner[X]` → **true (stale from Term N)**
- Assigns shares = 5 (full produced blocks)
- **Expected:** shares = 0 (via `CalculateShares(5, 20)` since 5 < 10)
- **Actual:** shares = 5

**Success Condition:**
Miner X receives non-zero reward shares despite producing less than 50% of average blocks, which should result in zero shares according to the performance calculation logic [6](#0-5) .

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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L573-599)
```csharp
    public override Empty RecordMinerReplacement(RecordMinerReplacementInput input)
    {
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) == Context.Sender,
            "Only AEDPoS Contract can record miner replacement.");

        if (State.ProfitContract.Value == null)
            State.ProfitContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

        if (!input.IsOldPubkeyEvil)
        {
            var latestMinedTerm = State.LatestMinedTerm[input.OldPubkey];
            State.LatestMinedTerm[input.NewPubkey] = latestMinedTerm;
            State.LatestMinedTerm.Remove(input.OldPubkey);
        }
        else
        {
            var replaceCandidates = State.ReplaceCandidateMap[input.CurrentTermNumber] ?? new StringList();
            replaceCandidates.Value.Add(input.NewPubkey);
            State.ReplaceCandidateMap[input.CurrentTermNumber] = replaceCandidates;
        }

        State.IsReplacedEvilMiner[input.NewPubkey] = true;

        return new Empty();
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
