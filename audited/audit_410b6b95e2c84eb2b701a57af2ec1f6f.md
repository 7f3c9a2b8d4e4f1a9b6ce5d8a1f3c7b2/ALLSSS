### Title
Missing Upper Bound Validation on MaximumMinersCount Enables Consensus DoS via Execution Limit Exhaustion

### Summary
The `SetMaximumMinersCount` function lacks upper bound validation, only checking that the value is positive. [1](#0-0)  If governance sets this to a value exceeding consensus execution limits (approximately 2,000-2,500 miners), the `ExtractInformationToUpdateConsensus` function's LINQ queries over `RealTimeMinersInformation.Values` would exceed AElf's 15,000 method call limit, causing complete consensus failure as miners cannot execute `UpdateValue` transactions.

### Finding Description

**Root Cause:**
The `SetMaximumMinersCount` method only validates `input.Value > 0` without any upper bound check. [1](#0-0)  Documentation explicitly states the limit is "unlimited by default." [2](#0-1) 

**Vulnerable Execution Path:**
1. `SetMaximumMinersCount` accepts an excessive value (e.g., 5,000) [3](#0-2) 
2. Election contract's `GetVictories` elects miners up to this count [4](#0-3) 
3. `GenerateFirstRoundOfNewTerm` creates a Round with thousands of entries in `RealTimeMinersInformation` dictionary [5](#0-4) 
4. When miners produce blocks, `GenerateConsensusTransactions` calls `ExtractInformationToUpdateConsensus` [6](#0-5) 
5. Three LINQ queries iterate over all miners in `RealTimeMinersInformation.Values`: [7](#0-6) 
   - Lines 22-24: Filter and create tuneOrderInformation dictionary
   - Lines 26-28: Filter and create decryptedPreviousInValues dictionary  
   - Lines 30-33: Filter and create minersPreviousInValues dictionary
6. Each LINQ query performs ~2n operations (Where predicate + ToDictionary selector) = ~6n total
7. `ProcessUpdateValue` iterates over these dictionaries [8](#0-7) 
8. If secret sharing is enabled, `PerformSecretSharing` adds additional iterations [9](#0-8) 

**Why Protections Fail:**
AElf enforces a 15,000 method call limit and 15,000 branch count limit per transaction. [10](#0-9)  With approximately 10n total operations across all LINQ queries and processing loops, the limit is exceeded at ~2,000-2,500 miners. Additionally, the resulting `UpdateValueInput` containing dictionaries with thousands of entries could exceed the 5MB transaction size limit. [11](#0-10) 

### Impact Explanation

**Concrete Harm:**
Complete consensus halt—no new blocks can be produced because all miners' `UpdateValue` transactions fail when execution limits are exceeded. [12](#0-11) 

**Who Is Affected:**
- All network participants: blockchain becomes frozen
- Miners: unable to produce blocks or earn rewards
- Users: all transactions halt
- dApps: complete service disruption

**Severity Justification:**
Critical operational impact—permanent consensus DoS until governance can reverse the MaximumMinersCount setting, which itself requires block production to execute the reversal proposal.

### Likelihood Explanation

**Attacker Capabilities Required:**
1. **Accidental Scenario (Higher Likelihood):** Governance makes configuration error (e.g., typo: 10,000 instead of 100) and proposal is approved without thorough validation
2. **Intentional Scenario (Lower Likelihood):** Attacker registers 2,000+ candidates (requires significant token stakes), obtains votes, and convinces governance to approve high MaximumMinersCount

**Attack Complexity:**
Medium. The accidental misconfiguration path is straightforward—governance simply proposes and approves an excessively high value. The intentional attack path requires substantial economic resources to register and get votes for thousands of candidates.

**Feasibility Conditions:**
- Governance approval for high MaximumMinersCount (normal operation, not compromise)
- Sufficient candidates exist (2,000+ for intentional attack) OR any number for accidental misconfiguration where even the attempt to accommodate that many causes issues

**Probability Reasoning:**
Medium likelihood. While DPoS systems typically operate with 17-100 miners [13](#0-12) , the complete absence of validation means governance could accidentally or intentionally set values causing DoS. Test files only validate small values (3-7), indicating no consideration for upper bounds. [14](#0-13) 

### Recommendation

**Code-Level Mitigation:**
Add upper bound validation in `SetMaximumMinersCount`:

```csharp
public override Empty SetMaximumMinersCount(Int32Value input)
{
    EnsureElectionContractAddressSet();
    
    Assert(input.Value > 0, "Invalid max miners count.");
    // Add upper bound check based on execution limits
    Assert(input.Value <= 1000, "Maximum miners count cannot exceed 1000 to prevent execution limit exhaustion.");
    
    RequiredMaximumMinersCountControllerSet();
    // ... rest of method
}
```

**Invariant Checks:**
- MaximumMinersCount must be > 0 AND <= reasonable upper bound (suggested: 1000, derived from 15,000 limit / ~15 operations per miner with safety margin)
- Add validation that estimated execution cost for UpdateValue with N miners stays within limits

**Test Cases:**
1. Verify `SetMaximumMinersCount` rejects values > 1000
2. Stress test `ExtractInformationToUpdateConsensus` with maximum allowed miner count
3. Measure method call count for various miner counts to validate upper bound safety
4. Test consensus behavior at boundary conditions (999, 1000, 1001 miners)

### Proof of Concept

**Required Initial State:**
- AEDPoS contract deployed with parliament governance controller
- 2,500+ candidates registered and voted for (or fewer candidates with backup mechanism)

**Transaction Steps:**
1. Governance creates proposal to call `SetMaximumMinersCount(Int32Value{Value = 2500})`
2. Parliament approves and releases proposal
3. `SetMaximumMinersCount` executes successfully (no validation prevents it)
4. Election occurs, `UpdateMinersCount` sets `State.MinersCount.Value = 2500`
5. Next term transition calls `GenerateFirstRoundOfNewTerm` with 2,500 miners
6. First miner attempts to produce block with `UpdateValue` behavior
7. `ExtractInformationToUpdateConsensus` executes ~15,000+ method calls across LINQ queries
8. Transaction fails with method call limit exceeded error

**Expected vs Actual Result:**
- **Expected:** `SetMaximumMinersCount` should reject values that would exceed execution limits
- **Actual:** Value accepted, consensus subsequently fails when execution limits are exceeded during `UpdateValue`

**Success Condition:**
Consensus DoS confirmed when no miner can successfully execute `UpdateValue` transactions due to execution limit exhaustion, halting block production.

### Citations

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

**File:** docs-sphinx/reference/smart-contract-api/consensus.rst (L28-28)
```text
| SetMaximumMinersCount                | `google.protobuf.Int32Value <#google.protobuf.Int32Value>`__                               | `google.protobuf.Empty <#google.protobuf.Empty>`__                       | Set the maximum count of miners, by default, is unlimited. If you want to control the count of miners, you need to set it through parliament.   |
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L52-84)
```csharp
    private List<ByteString> GetVictories(List<string> currentMiners)
    {
        var validCandidates = GetValidCandidates();

        List<ByteString> victories;

        Context.LogDebug(() => $"Valid candidates: {validCandidates.Count} / {State.MinersCount.Value}");

        var diff = State.MinersCount.Value - validCandidates.Count;
        // Valid candidates not enough.
        if (diff > 0)
        {
            victories =
                new List<ByteString>(validCandidates.Select(v => ByteStringHelper.FromHexString(v)));
            var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));

            victories.AddRange(backups.OrderBy(p => p)
                .Take(Math.Min(diff, currentMiners.Count))
                // ReSharper disable once ConvertClosureToMethodGroup
                .Select(v => ByteStringHelper.FromHexString(v)));
            Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
            return victories;
        }

        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L23-38)
```csharp
        for (var i = 0; i < sortedMiners.Count; i++)
        {
            var minerInRound = new MinerInRound();

            // The first miner will be the extra block producer of first round of each term.
            if (i == 0) minerInRound.IsExtraBlockProducer = true;

            minerInRound.Pubkey = sortedMiners[i];
            minerInRound.Order = i + 1;
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
            // Should be careful during validation.
            minerInRound.PreviousInValue = Hash.Empty;

            round.RealTimeMinersInformation.Add(sortedMiners[i], minerInRound);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L144-146)
```csharp
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
                    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-33)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);

        var decryptedPreviousInValues = RealTimeMinersInformation.Values.Where(v =>
                v.Pubkey != pubkey && v.DecryptedPieces.ContainsKey(pubkey))
            .ToDictionary(info => info.Pubkey, info => info.DecryptedPieces[pubkey]);

        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L291-296)
```csharp
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);

        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
```

**File:** docs-sphinx/architecture/smart-contract/restrictions/others.rst (L13-15)
```text
- AElf's contract patcher will patch method call count observer for your contract. This is used to prevent infinitely method call like recursion. The number of method called in your contract will be counted during transaction execution. The observer will pause transaction execution if the number exceeds 15,000. The limit adjustment is governed by ``Parliament``.

- AElf's contract patcher will patch method branch count observer for your contract. This is used to prevent infinitely loop case. The number of code control transfer in your contract will be counted during transaction execution. The observer will pause transaction execution if the number exceeds 15,000. The limit adjustment is governed by ``Parliament``.
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L1-100)
```csharp
namespace AElf.Kernel.TransactionPool;

public class TransactionPoolConsts
{
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/MaximumMinersCountTests.cs (L27-29)
```csharp
    [InlineData(7)]
    [InlineData(3)]
    public async Task SetMaximumMinersCountTest(int targetMinersCount)
```
