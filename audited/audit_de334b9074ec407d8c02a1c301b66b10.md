### Title
Transaction Size Limit Violation via Unbounded Miner Count in UpdateValue Consensus Operation

### Summary
The `ExtractInformationToUpdateConsensus()` function copies four dictionaries (TuneOrderInformation, EncryptedPieces, DecryptedPieces, MinersPreviousInValues) bounded by the number of miners into `UpdateValueInput`. When the miner count exceeds approximately 10,000, the resulting transaction exceeds the 5MB transaction size limit, causing transaction rejection and consensus failure.

### Finding Description

**Exact Location:** [1](#0-0) 

**Root Cause:**
The function unconditionally copies entire dictionaries whose size is proportional to the number of validators. With approximately 520 bytes per validator across all four dictionaries, reaching 10,000 validators would result in ~5.2MB of data in the `UpdateValueInput` message alone.

**Missing Protections:**

1. **No upper bound on MaximumMinersCount:** The default value is `int.MaxValue`: [2](#0-1) 

2. **Minimal validation when setting limit:** Only checks value > 0: [3](#0-2) 

3. **No size validation in UpdateValueValidationProvider:** [4](#0-3) 

4. **Transaction size limit enforcement rejects oversized transactions:** [5](#0-4) [6](#0-5) 

**Execution Path:**
During normal block production, the consensus mechanism calls `GenerateConsensusTransactions()` which invokes `ExtractInformationToUpdateConsensus()` to create the `UpdateValue` transaction: [7](#0-6) 

If the serialized transaction exceeds 5MB, it is rejected at the node level, preventing block production.

### Impact Explanation

**Concrete Harm:**
- Complete consensus failure: validators cannot submit `UpdateValue` transactions
- Block production halts as the UPDATE_VALUE consensus behavior cannot execute
- Blockchain becomes non-operational until miner count is reduced through governance

**Affected Parties:**
- All network validators unable to produce blocks
- All users unable to submit transactions
- Entire blockchain network experiences downtime

**Severity: HIGH**
This causes complete denial of service of the consensus mechanism, the most critical component of the blockchain. Recovery requires emergency governance action to reduce MaximumMinersCount.

### Likelihood Explanation

**Preconditions:**
1. Governance must set `MaximumMinersCount` to approximately 10,000+ through the `SetMaximumMinersCount` method: [8](#0-7) 

2. Sufficient candidates must exist (requiring ~1 billion ELF in deposits at 100,000 ELF per candidate)

3. Elections must select the full validator set: [9](#0-8) 

**Feasibility:**
- **Not a malicious attack:** Governance might legitimately set high MaximumMinersCount for decentralization goals without understanding the transaction size constraint
- **Economic barrier is high:** Requires substantial token supply for candidate deposits
- **Auto-increase is impractical:** Natural growth at 2 miners per year would take millennia: [10](#0-9) 

**Likelihood: LOW-MEDIUM**
While requiring governance action and significant economic investment, the lack of documented limits and the default `int.MaxValue` setting suggest the system was designed to support unlimited growth, making accidental misconfiguration plausible.

### Recommendation

**1. Add Maximum Bound Validation:**
Implement a practical upper limit in `SetMaximumMinersCount` based on transaction size constraints:

```csharp
// In AEDPoSContract_MaximumMinersCount.cs, line 14
public override Empty SetMaximumMinersCount(Int32Value input)
{
    EnsureElectionContractAddressSet();
    
    Assert(input.Value > 0, "Invalid max miners count.");
    Assert(input.Value <= 5000, "Max miners count exceeds transaction size limit."); // NEW CHECK
    // ... rest of method
}
```

**2. Add Size Validation in UpdateValueValidationProvider:**
Validate the size of UpdateValueInput before execution to provide early warning.

**3. Add Documentation:**
Document the transaction size constraint and practical upper limit for MaximumMinersCount in both code comments and governance documentation.

**4. Add Test Cases:**
Create regression tests that verify:
- UpdateValue transactions remain under 5MB at maximum supported miner counts
- SetMaximumMinersCount rejects values that would cause transaction size violations
- Consensus continues to function at the practical maximum miner count

### Proof of Concept

**Initial State:**
- Blockchain initialized with default configuration
- Parliament governance contract operational

**Attack Sequence:**

1. **Governance Action:** Parliament approves and executes proposal to set MaximumMinersCount to 10,000:
   - Call `SetMaximumMinersCount(10000)`
   - Election contract updated via `UpdateMinersCount`

2. **Candidate Registration:** Over time, 10,000 candidates register (each locking 100,000 ELF)

3. **Election Cycle:** Elections select 10,000 validators based on vote weights

4. **Consensus Failure:** When any validator attempts block production:
   - Node calls `GenerateConsensusTransactions()`
   - `ExtractInformationToUpdateConsensus()` creates UpdateValueInput with ~5.2MB of dictionary data
   - Transaction serialization exceeds 5MB limit
   - Node rejects transaction with "Transaction size exceeded" error
   - Block production fails

**Expected Result:** UpdateValue transaction successfully created and executed

**Actual Result:** Transaction rejected, consensus halts, blockchain stops producing blocks

**Success Condition:** Blockchain remains non-operational until MaximumMinersCount is reduced through emergency governance intervention

### Notes

The vulnerability stems from a design oversight where the unbounded growth model (default `int.MaxValue`) conflicts with the fixed transaction size limit (5MB). While the economic cost is high and governance action is required, the lack of validation makes this a realistic scenario for blockchains pursuing high decentralization. The recommended mitigation enforces a practical upper bound that respects the transaction size constraint while still allowing significant validator set growth.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L44-47)
```csharp
            TuneOrderInformation = { tuneOrderInformation },
            EncryptedPieces = { minerInRound.EncryptedPieces },
            DecryptedPieces = { decryptedPreviousInValues },
            MinersPreviousInValues = { minersPreviousInValues },
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L52-52)
```csharp
        State.MaximumMinersCount.Value = int.MaxValue;
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L88-95)
```csharp
    private int GetAutoIncreasedMinersCount()
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        return AEDPoSContractConstants.SupposedMinersCount.Add(
            (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
            .Div(State.MinerIncreaseInterval.Value).Mul(2));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
```

**File:** src/AElf.Kernel.TransactionPool/Infrastructure/BasicTransactionValidationProvider.cs (L32-41)
```csharp
        if (transaction.CalculateSize() > TransactionPoolConsts.TransactionSizeLimit)
        {
            await LocalEventBus.PublishAsync(new TransactionValidationStatusChangedEvent
            {
                TransactionId = transactionId,
                TransactionResultStatus = TransactionResultStatus.NodeValidationFailed,
                Error = "Transaction size exceeded."
            });
            return false;
        }
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L5-5)
```csharp
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L144-145)
```csharp
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
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
