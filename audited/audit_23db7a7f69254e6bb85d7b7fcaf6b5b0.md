### Title
DoS Vulnerability in Secret Sharing: Missing Key Validation in PerformSecretSharing Blocks Honest Miners During Miner List Changes

### Summary
The `PerformSecretSharing` method processes `DecryptedPieces` keys without validating their existence in the current round's miner list. When the miner list changes between rounds (due to evil miner replacement or term transitions), honest miners who hold decrypted pieces from removed miners will have their `UpdateValue` transactions fail with `KeyNotFoundException`, preventing them from participating in consensus.

### Finding Description

The vulnerability exists in the `PerformSecretSharing` method, not in `RevealSharedInValues` as initially suspected. [1](#0-0) 

When processing `UpdateValue` transactions, the code accesses `round.RealTimeMinersInformation[decryptedPreviousInValue.Key]` directly without checking if the key exists. In contrast, the same codebase shows the correct pattern in `UpdateLatestSecretPieces`: [2](#0-1) 

The miner list can change between rounds through the `RecordCandidateReplacement` mechanism: [3](#0-2) 

The secret sharing flow creates the vulnerability:
1. In round N-1, miners encrypt pieces for all current miners including miner D
2. Miner A decrypts pieces from D and stores them in `DecryptedPieces[D]`
3. Round N starts with D removed from the miner list (evil miner detection or term change)
4. Miner A calls `UpdateValue` with `DecryptedPieces` containing key D
5. `PerformSecretSharing` attempts to access `round.RealTimeMinersInformation[D]` where D no longer exists
6. `KeyNotFoundException` is thrown, transaction fails

The `UpdateValue` method has no exception handling: [4](#0-3) 

The validation provider does not check `DecryptedPieces` keys: [5](#0-4) 

Note: The originally suspected issue in `RevealSharedInValues` is not exploitable because it operates on immutable previous round data where keys were valid when added: [6](#0-5) 

### Impact Explanation

**Operational DoS of Consensus**: Honest miners cannot successfully call `UpdateValue` when they possess decrypted pieces from miners who were removed from the miner list. This blocks their participation in consensus.

**Affected Parties**: All honest miners who received encrypted pieces from miners subsequently removed due to:
- Evil miner detection (missed time slots)
- Term changes with miner list updates  
- Candidate replacement operations

**Severity Justification**: High severity because:
- Occurs during normal protocol operation (miner list changes are expected)
- Affects multiple honest miners simultaneously
- No attacker required - natural system state triggers the bug
- Disrupts critical consensus process
- Cannot be recovered without code fix

### Likelihood Explanation

**High Probability**: The vulnerability triggers automatically during legitimate operations:

1. **Miner List Changes Are Common**: The system explicitly supports miner replacement: [7](#0-6) 

2. **Evil Miner Detection**: Miners missing time slots are regularly detected and replaced: [7](#0-6) 

3. **No Attacker Required**: Honest miners following the protocol will naturally decrypt pieces from all miners in their round, including those who may later be removed.

4. **Execution Complexity**: None - the bug triggers through normal `UpdateValue` calls.

5. **Detection**: Transaction failures will be immediately visible but root cause may be unclear without code inspection.

### Recommendation

Add existence validation before accessing the dictionary, following the pattern already implemented in `UpdateLatestSecretPieces`:

```csharp
private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
    string publicKey)
{
    minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
    foreach (var decryptedPreviousInValue in input.DecryptedPieces)
        // ADD THIS CHECK:
        if (round.RealTimeMinersInformation.ContainsKey(decryptedPreviousInValue.Key))
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);

    foreach (var previousInValue in input.MinersPreviousInValues)
        // ADD THIS CHECK:
        if (round.RealTimeMinersInformation.ContainsKey(previousInValue.Key))
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
}
```

**Invariant to Enforce**: Before accessing `RealTimeMinersInformation[key]`, always validate `ContainsKey(key)` returns true.

**Test Cases**:
1. Test UpdateValue with DecryptedPieces containing removed miner keys
2. Test miner replacement mid-round followed by UpdateValue from remaining miners
3. Test term change followed by UpdateValue with stale DecryptedPieces

### Proof of Concept

**Initial State**:
- Round N-1 active with miners [A, B, C, D, E]
- All miners encrypt and exchange pieces during round N-1
- Miner A decrypts pieces from miners B, C, D successfully

**Exploitation Steps**:

1. **Miner D Detected as Evil**: D misses time slots triggering evil miner detection [7](#0-6) 

2. **Round N Starts**: New miner list is [A, B, C, F, G] (D and E replaced by F and G)

3. **Miner A Calls UpdateValue**: Provides `DecryptedPieces` map containing keys [B, C, D] (legitimately decrypted in previous round)

4. **PerformSecretSharing Executes**: 
   - Processes key B: `round.RealTimeMinersInformation[B]` ✓ succeeds
   - Processes key C: `round.RealTimeMinersInformation[C]` ✓ succeeds  
   - Processes key D: `round.RealTimeMinersInformation[D]` ✗ throws `KeyNotFoundException`

5. **Transaction Fails**: Miner A's UpdateValue transaction is rejected

**Expected Result**: Transaction succeeds, silently skipping removed miners (like `UpdateLatestSecretPieces` does)

**Actual Result**: Transaction fails with exception, miner A cannot participate in consensus

**Success Condition**: Miner A's transaction failure can be reproduced whenever DecryptedPieces contains keys of miners removed from current round.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L287-297)
```csharp
    private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
        string publicKey)
    {
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);

        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L143-146)
```csharp
        foreach (var decryptedPiece in triggerInformation.DecryptedPieces)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(decryptedPiece.Key))
                updatedRound.RealTimeMinersInformation[decryptedPiece.Key].DecryptedPieces[pubkey] =
                    decryptedPiece.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L131-157)
```csharp
    public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
    {
        Assert(Context.Sender == State.ElectionContract.Value,
            "Only Election Contract can record candidate replacement information.");

        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;

        // Notify Treasury Contract to update replacement information. (Update from old record.)
        State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey,
            CurrentTermNumber = State.CurrentTermNumber.Value
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L13-54)
```csharp
    private void RevealSharedInValues(Round currentRound, string publicKey)
    {
        Context.LogDebug(() => "About to reveal shared in values.");

        if (!currentRound.RealTimeMinersInformation.ContainsKey(publicKey)) return;

        if (!TryToGetPreviousRoundInformation(out var previousRound)) return;

        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;

        foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
        {
            // Skip himself.
            if (pair.Key == publicKey) continue;

            if (!currentRound.RealTimeMinersInformation.Keys.Contains(pair.Key)) continue;

            var publicKeyOfAnotherMiner = pair.Key;
            var anotherMinerInPreviousRound = pair.Value;

            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

            // Reveal another miner's in value for target round:

            var orders = anotherMinerInPreviousRound.DecryptedPieces.Select((t, i) =>
                    previousRound.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();

            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
        }
    }
```
