### Title
Missing Size Validation in NextTerm Allows DOS via Excessive Miner Entries

### Summary
The `NextTerm` function accepts a `NextTermInput` parameter without validating the size of `RealTimeMinersInformation`, allowing a malicious miner to craft a transaction with thousands of fake miner entries. While the claimed "millions of entries" is prevented by the 5MB transaction size limit, an attacker can still inject approximately 10,000-20,000 entries, causing execution timeout and denial-of-service on critical term transitions. [1](#0-0) 

### Finding Description

**Location:** `NextTermInput.ToRound()` is called during term transitions without size validation.

**Root Cause:** The `NextTerm` method accepts user-provided `NextTermInput` and immediately converts it to a `Round` object by copying the entire `RealTimeMinersInformation` map: [2](#0-1) 

The conversion happens at: [3](#0-2) 

**Why Protections Fail:**

1. **No Size Validation:** The validation provider only checks round/term number increments and null InValues, but does NOT validate the size or content of `RealTimeMinersInformation`: [4](#0-3) 

2. **No Miner List Verification:** There is no check that the provided miner list matches the expected list from the Election contract's `GetVictories` method.

3. **Excessive Iteration:** After the copy, `ProcessNextTerm` iterates through all entries multiple times: [5](#0-4) 

**Execution Path:**
1. Malicious miner crafts `NextTermInput` with thousands of fake entries in `RealTimeMinersInformation`
2. Calls `NextTerm(malicious_input)` during their block production slot
3. `ProcessConsensusInformation` calls `ProcessNextTerm(input)` 
4. `input.ToRound()` copies all fake entries
5. Multiple foreach loops iterate through thousands of entries, consuming execution resources
6. Transaction exceeds execution thresholds and times out

### Impact Explanation

**Harm:** Denial-of-service on consensus term transitions, preventing the blockchain from advancing to the next term with updated miners.

**Protocol Damage:** 
- Term transitions are critical for updating the miner set based on election results
- Failed term transitions prevent new elected miners from joining
- Consensus stalls until the malicious behavior is detected and mitigated
- Network requires manual intervention or waiting for the malicious miner's time slot to pass

**Affected Parties:**
- All network participants (validators and users)
- Newly elected miners prevented from joining
- System continuity and liveness guarantees

**Quantification:**
- Transaction size limit (5MB) allows approximately 10,000-26,000 fake miner entries (estimated at 200-500 bytes per entry) [6](#0-5) 

- Expected legitimate maximum: The Election contract limits victories to `State.MinersCount.Value`, typically 100-1000 miners [7](#0-6) 

- Execution threshold is 15,000 calls/branches, which thousands of entries could exceed: [8](#0-7) 

**Severity: Medium** - Operational impact on critical consensus function, but requires malicious miner privileges.

### Likelihood Explanation

**Attacker Capabilities:**
- Must be an active miner in the current round (checked by `PreCheck`): [9](#0-8) 

- Must have block production rights during their time slot
- Can craft arbitrary `NextTermInput` transactions

**Attack Complexity:** Low - Simple transaction crafting with fake miner entries

**Feasibility:** 
- The legitimate flow generates `NextTermInput` from Election contract victories: [10](#0-9) 

- However, the miner can submit their own crafted transaction instead
- No validation checks the miner list against expected values

**Detection:** Low - The malicious transaction would appear to pass validation but timeout during execution

**Probability:** Low-Medium - Requires compromising an active miner, but simple to execute once that access is obtained.

### Recommendation

**Code-Level Mitigation:**

1. **Add size validation in `ProcessNextTerm` before calling `ToRound()`:**
```csharp
Assert(input.RealTimeMinersInformation.Count <= State.MaximumMinersCount.Value, 
       "Miner count exceeds maximum allowed.");
```

2. **Verify miner list matches Election contract expectations:**
```csharp
if (State.IsMainChain.Value)
{
    var expectedVictories = State.ElectionContract.GetVictories.Call(new Empty());
    Assert(input.RealTimeMinersInformation.Count == expectedVictories.Value.Count,
           "Miner count mismatch with Election contract.");
    foreach (var victory in expectedVictories.Value)
    {
        Assert(input.RealTimeMinersInformation.ContainsKey(victory.ToHex()),
               "Unexpected miner in miner list.");
    }
}
```

3. **Add validation in `RoundTerminateValidationProvider`:**
```csharp
// In ValidationForNextTerm method
if (validationContext.ExtraData.Round.RealTimeMinersInformation.Count > 1000)
{
    return new ValidationResult { 
        Message = "Excessive miner count in NextTerm input." 
    };
}
```

**Invariant Checks:**
- `RealTimeMinersInformation.Count <= MaximumMinersCount`
- `RealTimeMinersInformation.Keys` matches `ElectionContract.GetVictories()` pubkeys

**Test Cases:**
- Test `NextTerm` with 10,000 fake miner entries (should fail validation)
- Test `NextTerm` with miner list not matching Election contract (should fail)
- Test `NextTerm` with legitimate miner list from Election contract (should succeed)

### Proof of Concept

**Required Initial State:**
- Attacker is an active miner in the current round
- Current term is about to end
- Attacker has block production rights for the NextTerm behavior

**Attack Steps:**
1. Wait for legitimate time to produce NextTerm block
2. Instead of using `GenerateConsensusTransactions` output, craft malicious `NextTermInput`:
   - Set correct `round_number` (current + 1)
   - Set correct `term_number` (current + 1)
   - Inject 15,000 fake entries in `real_time_miners_information` map
   - Set all `InValue` fields to null
   - Copy other required fields from current round
3. Submit crafted transaction to `NextTerm` method
4. Transaction passes `ValidateConsensusBeforeExecution` (only checks round/term numbers)
5. In `ProcessNextTerm`, `ToRound()` copies 15,000 entries
6. Foreach loop at lines 179-183 attempts to iterate 15,000 times
7. Transaction exceeds execution threshold and times out

**Expected Result:** Legitimate term transition with ~100 miners from Election contract

**Actual Result:** Transaction timeout, failed term transition, consensus DOS

**Success Condition:** Term transition fails, blockchain cannot advance to next term, requiring manual intervention or alternative miner to produce valid term transition.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-163)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L178-190)
```csharp
        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L1-6)
```csharp
namespace AElf.Kernel.TransactionPool;

public class TransactionPoolConsts
{
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
}
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

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L1-13)
```csharp
namespace AElf.Kernel.SmartContract;

public class SmartContractConstants
{
    public const int ExecutionCallThreshold = 15000;

    public const int ExecutionBranchThreshold = 15000;

    public const int StateSizeLimit = 128 * 1024;

    // The prefix `vs` occupies 2 lengths.
    public const int StateKeyMaximumLength = 255 - 2;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L172-179)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextTerm), NextTermInput.Create(round,randomNumber))
                    }
                };
```
