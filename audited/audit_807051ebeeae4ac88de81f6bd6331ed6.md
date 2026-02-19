### Title
Secret Sharing Information Leaked Through SecretSharingInformation Event Before State Cleanup

### Summary
The `SecretSharingInformation` event exposes the complete previous round data including all `EncryptedPieces` and `DecryptedPieces` from persistent state before these secrets are cleaned up. While `DeleteSecretSharingInformation()` clears secrets from block extra data, it does not clean the Round objects already persisted in state, allowing any observer to capture secret sharing material through public event logs.

### Finding Description

The vulnerability exists in the interaction between event emission and state management in the AEDPoS consensus contract.

**Execution Path:**
When a new round is added via `AddRoundInformation()`, the function saves the round to state and then fires a `SecretSharingInformation` event: [1](#0-0) 

The event includes `PreviousRound = State.Rounds[round.RoundNumber.Sub(1)]`, which retrieves the previous round directly from persistent state without any sanitization.

**Root Cause:**
The previous round in state contains complete `encrypted_pieces` and `decrypted_pieces` maps for all miners, as defined in the protobuf schema: [2](#0-1) 

These pieces are added to rounds during consensus processing: [3](#0-2) 

**Why Protections Fail:**
The `DeleteSecretSharingInformation()` function only operates on in-memory Round objects used for block extra data: [4](#0-3) 

This function is called on the Round returned in block consensus data: [5](#0-4) 

However, this does NOT clean the Round objects already persisted in `State.Rounds`. When the `SecretSharingInformation` event is fired, it includes the unmodified state data with all secrets intact.

The event is publicly observable as marked in the protobuf definition: [6](#0-5) 

### Impact Explanation

**Privacy Breach:** All encrypted and decrypted pieces used in the secret sharing protocol are exposed through public event logs accessible to any observer.

**Random Number Predictability:** The secret sharing mechanism uses Shamir's Secret Sharing where miners' InValues are split into pieces. With access to sufficient decrypted pieces (2/3 threshold), an observer could reconstruct miners' InValues before they are officially revealed, breaking the unpredictability guarantee of the random number generation.

**Consensus Integrity Risk:** The random numbers generated from these InValues are used in consensus mechanisms. Premature knowledge of these values could allow attackers to predict future consensus behavior or manipulate systems that depend on these random values.

**Affected Parties:** All network participants relying on the confidentiality and unpredictability of the secret sharing mechanism, including the consensus protocol itself and any applications using these random numbers.

### Likelihood Explanation

**No Special Privileges Required:** Any observer can monitor blockchain event logs without authentication or authorization.

**Automatic Execution:** The vulnerability triggers automatically during normal consensus operation whenever `AddRoundInformation()` is called in: [7](#0-6) [8](#0-7) 

**100% Occurrence Rate:** Every round transition exposes the previous round's secrets through the event.

**Passive Attack:** The leak happens passively through the protocol's normal event emission. The event processor confirms this data is actively consumed: [9](#0-8) 

**No Detection:** Event observation is passive and undetectable by the network.

### Recommendation

**Primary Fix:** Sanitize the previous round data before including it in the event. Modify `AddRoundInformation()` to clear secret sharing information from the round retrieved from state:

```csharp
var previousRound = State.Rounds[round.RoundNumber.Sub(1)].Clone();
previousRound.DeleteSecretSharingInformation();

Context.Fire(new SecretSharingInformation
{
    CurrentRoundId = round.RoundId,
    PreviousRound = previousRound,
    PreviousRoundId = previousRound.RoundId
});
```

**Alternative Approach:** Use the existing `GetCheckableRound()` pattern demonstrated here: [10](#0-9) 

Apply similar logic to create a sanitized copy of the previous round that excludes `EncryptedPieces` and `DecryptedPieces` before event emission.

**State Cleanup:** Consider implementing cleanup logic that removes secret sharing information from rounds in state after they are no longer needed (e.g., when Round N+1 is added, clean secrets from Round N-1).

**Test Cases:** Add tests verifying that `SecretSharingInformation` events do not contain `encrypted_pieces` or `decrypted_pieces` data in the `previous_round` field.

### Proof of Concept

1. **Initial State:** Blockchain running with active AEDPoS consensus
2. **Monitor Events:** Subscribe to `SecretSharingInformation` events on the consensus contract
3. **Trigger:** Wait for any miner to produce a block transitioning to the next round (normal consensus operation)
4. **Event Emission:** The `ProcessNextRound()` or `ProcessNextTerm()` function calls `AddRoundInformation()`, which fires the event
5. **Capture Data:** Extract the `previous_round` field from the emitted event
6. **Verify Leak:** Inspect `previous_round.real_time_miners_information` for each miner's `encrypted_pieces` and `decrypted_pieces` maps
7. **Success Condition:** Confirm that all secret sharing pieces are visible in the event log, demonstrating that secrets are exposed before any cleanup mechanism removes them from state

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-115)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });
```

**File:** protobuf/aedpos_contract.proto (L293-296)
```text
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
```

**File:** protobuf/aedpos_contract.proto (L428-436)
```text
message SecretSharingInformation {
    option (aelf.is_event) = true;
    // The previous round information.
    Round previous_round = 1 [(aelf.is_indexed) = true];
    // The current round id.
    int64 current_round_id = 2;
    // The previous round id.
    int64 previous_round_id = 3;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L196-196)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L287-293)
```csharp
    private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
        string publicKey)
    {
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_GetLighterRound.cs (L7-14)
```csharp
    public void DeleteSecretSharingInformation()
    {
        var encryptedPieces = RealTimeMinersInformation.Values.Select(i => i.EncryptedPieces);
        foreach (var encryptedPiece in encryptedPieces) encryptedPiece.Clear();

        var decryptedPieces = RealTimeMinersInformation.Values.Select(i => i.DecryptedPieces);
        foreach (var decryptedPiece in decryptedPieces) decryptedPiece.Clear();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L50-50)
```csharp
        if (!isGeneratingTransactions) information.Round.DeleteSecretSharingInformation();
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingInformationLogEventProcessor.cs (L38-43)
```csharp
    protected override async Task ProcessLogEventAsync(Block block, LogEvent logEvent)
    {
        var secretSharingInformation = new SecretSharingInformation();
        secretSharingInformation.MergeFrom(logEvent);
        await _secretSharingService.AddSharingInformationAsync(secretSharingInformation);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
    }
```
