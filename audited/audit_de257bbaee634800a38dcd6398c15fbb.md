### Title
Duplicate Miner Entries in Welcome Reward Distribution Due to Unfiltered List Merge

### Summary
The `Release()` function merges `currentMinerList` and `previousTermInformation.RealTimeMinersInformation.Keys` without deduplication, allowing newly elected miners serving consecutive terms to appear twice in the filtered list. While `UpdateBasicMinerRewardWeights` is not affected (it uses Round objects directly), the vulnerability manifests in `UpdateWelcomeRewardWeights`, where duplicate entries cause the same miner to receive double shares (2 instead of 1) in the Welcome Reward scheme.

### Finding Description

The vulnerability exists in the list merging and filtering logic: [1](#0-0) 

The code merges two potentially overlapping lists without deduplication. When a miner appears in both `currentMinerList` (term N+1) and `previousTermInformation.RealTimeMinersInformation.Keys` (term N), they are added twice to `maybeNewElectedMiners`. The subsequent `Where` filter only checks conditions (`LatestMinedTerm[p] == 0` and not in initial miner list) but does not eliminate duplicates.

**Root Cause**: No `.Distinct()` call or deduplication logic after merging the lists.

**Why Protections Fail**: 
- The filter at lines 155-156 removes entries based on state conditions but preserves duplicates if both entries pass the same conditions
- For a newly elected miner serving terms N and N+1 for the first time, both entries have `LatestMinedTerm == 0` and pass the filter

**Clarification on Question**: The question asks about `UpdateBasicMinerRewardWeights`, but this function is NOT affected: [2](#0-1) [3](#0-2) 

`UpdateBasicMinerRewardWeights` receives Round objects directly and uses `RealTimeMinersInformation`, which is a dictionary with unique keys, preventing duplicates.

**Actual Vulnerability Location**: The duplicate entries affect `UpdateWelcomeRewardWeights`: [4](#0-3) [5](#0-4) 

The loop at lines 872-877 adds each entry in `newElectedMiners` as a beneficiary with 1 share, without checking for duplicates. The Profit contract's `AddBeneficiaries` implementation confirms no deduplication occurs: [6](#0-5) 

Each call to `AddBeneficiary` increments `TotalShares` and adds a new `ProfitDetail` entry for the beneficiary address.

### Impact Explanation

**Direct Fund Impact - Reward Misallocation**:
- A newly elected miner serving consecutive terms receives 2 shares instead of 1 in the Welcome Reward scheme
- With N new miners, if one has a duplicate, total shares become N+1 instead of N
- The affected miner receives approximately `2/(N+1)` of the welcome reward pool instead of `1/N`, nearly doubling their share
- Other legitimate new miners receive diluted rewards: `1/(N+1)` instead of `1/N`

**Who is Affected**:
- Newly elected miners serving their first consecutive terms receive excess rewards
- Other new miners in the same cohort receive reduced rewards
- The Welcome Reward pool distribution becomes unfair and violates the intended "1 share per new miner" design

**Severity Justification**: 
This is a **Medium-High** severity issue because:
1. It causes systematic reward misallocation (violates Economics & Treasury invariants)
2. It occurs automatically for a common scenario (new miners serving consecutive terms)
3. The misallocation is significant (approximately 2x for affected miners)
4. It undermines the fairness of the reward distribution mechanism

### Likelihood Explanation

**Attacker Capabilities**: No attacker needed - this is a logic bug that triggers automatically.

**Attack Complexity**: None - the vulnerability manifests naturally when:
1. A new miner is elected for the first time in term N
2. The same miner continues to term N+1
3. `Release(N)` is called by the consensus contract

**Feasibility Conditions**:
- **Highly Feasible**: In a DPoS system, newly elected miners frequently serve multiple consecutive terms if they perform well
- The scenario requires no special conditions beyond normal protocol operation
- `LatestMinedTerm` is only set at the end of `Release()` via `UpdateStateAfterDistribution`, so the first time a new miner appears in consecutive terms, they will have `LatestMinedTerm == 0` and appear in both lists [7](#0-6) 

**Probability**: HIGH - This occurs for every new miner who serves their first two terms consecutively, which is a standard outcome in validator elections.

### Recommendation

**Code-Level Mitigation**:
Add deduplication after the merge and before the filter:

```csharp
maybeNewElectedMiners.AddRange(currentMinerList);
maybeNewElectedMiners.AddRange(previousTermInformation.RealTimeMinersInformation.Keys);
// Add deduplication
maybeNewElectedMiners = maybeNewElectedMiners.Distinct().ToList();
```

Or apply `.Distinct()` after the filter:

```csharp
maybeNewElectedMiners = maybeNewElectedMiners
    .Where(p => State.LatestMinedTerm[p] == 0 && !GetInitialMinerList().Contains(p))
    .Distinct()
    .ToList();
```

**Invariant Checks**:
Add an assertion in `UpdateWelcomeRewardWeights` to ensure no duplicate beneficiaries:

```csharp
var uniqueMiners = newElectedMiners.Distinct().ToList();
Assert(uniqueMiners.Count == newElectedMiners.Count, 
    "Duplicate miners detected in welcome reward distribution");
```

**Test Cases**:
1. Test scenario where a new miner appears in consecutive terms for the first time
2. Verify welcome reward shares equal the number of unique new miners
3. Verify no miner receives more than 1 share in the welcome reward scheme

### Proof of Concept

**Initial State**:
- Term 4 completes with miners [A, B, C] (all established)
- New miner D is elected for terms 5 and 6
- `LatestMinedTerm[D] = 0` (never mined before)

**Transaction Steps**:
1. Consensus contract calls `Release(5)` to process term 5
2. Inside `Release(5)`:
   - `previousTermInformation = GetPreviousTermInformation(5)` → term 5 data, contains D
   - `currentMinerList = GetCurrentMinerList()` → term 6 miners, contains D
   - Line 144: `maybeNewElectedMiners.AddRange(currentMinerList)` → adds D
   - Line 145: `maybeNewElectedMiners.AddRange(previousTermInformation.RealTimeMinersInformation.Keys)` → adds D again
   - Now `maybeNewElectedMiners = [D, ..., D, ...]` (D appears twice)
   - Lines 155-156: Filter checks `LatestMinedTerm[D] == 0` ✓ and `!GetInitialMinerList().Contains(D)` ✓
   - Both D entries pass filter → `maybeNewElectedMiners = [D, D]` after filtering
3. Line 762: `UpdateWelcomeRewardWeights(previousTermInformation, [D, D])`
4. Lines 872-877: Loop iterates twice:
   - First iteration: Adds beneficiary D with 1 share
   - Second iteration: Adds beneficiary D with 1 share again
5. Profit contract receives `AddBeneficiaries` with D listed twice
6. Profit contract calls `AddBeneficiary` twice for address D, incrementing shares twice

**Expected Result**: Miner D should have 1 share in Welcome Reward scheme

**Actual Result**: Miner D has 2 shares in Welcome Reward scheme

**Success Condition**: Query the Profit contract's scheme for D's shares after `Release(5)` completes - it will show 2 shares instead of the expected 1 share.

### Notes

While the original question specifically asks about `UpdateBasicMinerRewardWeights`, my investigation reveals that function is protected from this issue because it uses `RealTimeMinersInformation` dictionaries directly rather than the merged list. The actual vulnerability manifests in `UpdateWelcomeRewardWeights`, which does consume the potentially duplicated list. The root cause (unfiltered merge creating duplicates) and impact (double shares) are as described in the question, but the affected component differs. This is a valid finding that requires fixing to maintain fair reward distribution.

### Citations

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L141-156)
```csharp
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
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L761-761)
```csharp
        UpdateBasicMinerRewardWeights(new List<Round> { previousPreviousTermInformation, previousTermInformation });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L762-762)
```csharp
        UpdateWelcomeRewardWeights(previousTermInformation, newElectedMiners);
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L766-769)
```csharp
    private void UpdateStateAfterDistribution(Round previousTermInformation, List<string> currentMinerList)
    {
        foreach (var miner in currentMinerList) State.LatestMinedTerm[miner] = previousTermInformation.TermNumber;
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L848-880)
```csharp
    private void UpdateWelcomeRewardWeights(Round previousTermInformation, List<string> newElectedMiners)
    {
        var previousMinerAddresses =
            GetAddressesFromCandidatePubkeys(previousTermInformation.RealTimeMinersInformation.Keys);
        var possibleWelcomeBeneficiaries = new RemoveBeneficiariesInput
        {
            SchemeId = State.VotesWeightRewardHash.Value,
            Beneficiaries = { previousMinerAddresses }
        };
        State.ProfitContract.RemoveBeneficiaries.Send(possibleWelcomeBeneficiaries);
        State.ProfitContract.RemoveSubScheme.Send(new RemoveSubSchemeInput
        {
            SchemeId = State.VotesWeightRewardHash.Value,
            SubSchemeId = State.BasicRewardHash.Value
        });

        if (newElectedMiners.Any())
        {
            Context.LogDebug(() => "Welcome reward will go to new miners.");
            var newBeneficiaries = new AddBeneficiariesInput
            {
                SchemeId = State.VotesWeightRewardHash.Value,
                EndPeriod = previousTermInformation.TermNumber.Add(1)
            };
            foreach (var minerAddress in newElectedMiners.Select(GetProfitsReceiver))
                newBeneficiaries.BeneficiaryShares.Add(new BeneficiaryShare
                {
                    Beneficiary = minerAddress,
                    Shares = 1
                });

            if (newBeneficiaries.BeneficiaryShares.Any()) State.ProfitContract.AddBeneficiaries.Send(newBeneficiaries);
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L388-399)
```csharp
    public override Empty AddBeneficiaries(AddBeneficiariesInput input)
    {
        foreach (var beneficiaryShare in input.BeneficiaryShares)
            AddBeneficiary(new AddBeneficiaryInput
            {
                SchemeId = input.SchemeId,
                BeneficiaryShare = beneficiaryShare,
                EndPeriod = input.EndPeriod
            });

        return new Empty();
    }
```
