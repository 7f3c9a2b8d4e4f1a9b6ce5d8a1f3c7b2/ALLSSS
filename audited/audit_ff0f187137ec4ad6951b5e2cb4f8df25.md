# Audit Report

## Title
DoS Vulnerability in Secret Sharing: Missing Key Validation in PerformSecretSharing Blocks Honest Miners During Miner List Changes

## Summary
The `PerformSecretSharing` method directly accesses `round.RealTimeMinersInformation[key]` without validating key existence, while the off-chain `SecretSharingService` caches decrypted pieces from all previous round miners. When term transitions remove miners from the list, honest miners' `UpdateValue` transactions fail with `KeyNotFoundException`, blocking their consensus participation.

## Finding Description

The vulnerability exists in the interaction between on-chain contract execution and off-chain secret sharing service state management. During AEDPoS secret sharing, miners decrypt pieces from all miners in the previous round and cache them off-chain indexed by round ID. When miner lists change at term boundaries, these cached pieces contain keys for removed miners, causing transaction failures.

**Vulnerable Code Path:**

The `PerformSecretSharing` method accesses the dictionary without validation: [1](#0-0) 

In contrast, `UpdateLatestSecretPieces` demonstrates the correct pattern with key existence checks: [2](#0-1) 

**Root Cause - Off-Chain Service Behavior:**

The `SecretSharingService` iterates over ALL miners from the previous round when collecting decrypted pieces: [3](#0-2) 

These pieces are stored in an in-memory cache indexed by round ID: [4](#0-3) 

Later retrieved and included in consensus transactions: [5](#0-4) 

**Miner List Changes:**

Term transitions create new rounds with different miner lists: [6](#0-5) 

New `MinerInRound` objects are created without carrying over any previous state: [7](#0-6) 

**Missing Validation:**

The `UpdateValueValidationProvider` does not check `DecryptedPieces` keys: [8](#0-7) 

The `UpdateValue` entry point has no exception handling: [9](#0-8) 

**Complete Attack Scenario:**

1. Round N-1 active with miners {A, B, C, D}
2. Off-chain service decrypts pieces from all four miners, stores with key = N
3. `ProcessNextTerm` called: Round N starts with miners {A, B, C} (D removed)
4. Miner A prepares `UpdateValue` for Round N
5. `GetDecryptedPieces(N)` returns cached pieces including key "D"
6. Transaction submitted with `DecryptedPieces["D"]`
7. `PerformSecretSharing` executes: `round.RealTimeMinersInformation["D"].DecryptedPieces.Add(...)`
8. `KeyNotFoundException` thrown - D not in Round N's miner list
9. Transaction fails, Miner A blocked from consensus

## Impact Explanation

**High Impact - Consensus DoS:**

This vulnerability causes operational denial-of-service against honest miners during normal protocol operations. When term transitions occur with miner list changes, ALL miners who participated in the previous round and followed the secret sharing protocol will hold decrypted pieces from removed miners. Their `UpdateValue` transactions will systematically fail until they clear their off-chain cache or the code is fixed.

**Affected Scope:**
- All honest miners from previous term who processed secret sharing
- Occurs during every term transition with miner list changes  
- Multiple miners simultaneously blocked
- No attacker action required
- Critical consensus functionality disrupted

**Severity Factors:**
- Breaks consensus availability invariant
- Natural system operations trigger the bug (term changes are expected)
- Cannot be recovered by honest miners without restarting nodes or manual cache clearing
- Affects core protocol security mechanism (consensus participation)

## Likelihood Explanation

**High Likelihood - Triggered by Normal Operations:**

This vulnerability activates automatically during legitimate protocol operations with no malicious actor required:

1. **Term Transitions Are Regular**: The AEDPoS protocol explicitly manages term changes with miner list updates as demonstrated in the `ProcessNextTerm` implementation.

2. **Evil Miner Detection Is Standard**: The system regularly detects and marks miners who miss time slots, leading to miner list changes: [10](#0-9) 

3. **Zero Attack Complexity**: Honest miners following the standard protocol will naturally decrypt pieces from all current miners. When the miner list changes, the bug triggers automatically on their next `UpdateValue` attempt.

4. **No Special Preconditions**: Only requires normal secret sharing to be enabled and a term transition with miner list changes - both are standard protocol operations.

5. **Immediate Visibility**: Transaction failures are immediate and visible, though the root cause may be unclear without deep code inspection.

## Recommendation

Add key existence validation in `PerformSecretSharing` to match the pattern used in `UpdateLatestSecretPieces`:

```csharp
private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
    string publicKey)
{
    minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
    
    foreach (var decryptedPreviousInValue in input.DecryptedPieces)
    {
        // Add key existence check before accessing
        if (round.RealTimeMinersInformation.ContainsKey(decryptedPreviousInValue.Key))
        {
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
        }
    }

    foreach (var previousInValue in input.MinersPreviousInValues)
    {
        // Add key existence check here as well
        if (round.RealTimeMinersInformation.ContainsKey(previousInValue.Key))
        {
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
        }
    }
}
```

Additionally, consider clearing the off-chain `SecretSharingService` cache on term transitions to prevent stale data accumulation.

## Proof of Concept

```csharp
[Fact]
public async Task UpdateValue_WithRemovedMinerInDecryptedPieces_ShouldThrowKeyNotFoundException()
{
    // Setup: Create initial round with 4 miners
    var initialMiners = new[] { "MinerA", "MinerB", "MinerC", "MinerD" };
    var round1 = CreateRoundWithMiners(1, 1, initialMiners);
    
    // Simulate secret sharing - miners have decrypted pieces from all miners including D
    var decryptedPieces = new Dictionary<string, ByteString>
    {
        { "MinerD", ByteString.CopyFromUtf8("encrypted_piece_from_D") }
    };
    
    // Term transition: Create round 2 with MinerD removed (evil miner detected)
    var round2Miners = new[] { "MinerA", "MinerB", "MinerC" };
    var round2 = CreateRoundWithMiners(2, 1, round2Miners);
    await SetCurrentRound(round2);
    
    // MinerA attempts UpdateValue with decrypted pieces including removed MinerD
    var updateInput = new UpdateValueInput
    {
        DecryptedPieces = { decryptedPieces },
        OutValue = HashHelper.ComputeFrom("test"),
        Signature = HashHelper.ComputeFrom("sig"),
        // ... other required fields
    };
    
    // Execute as MinerA
    var result = await ExecuteContractWithMinerAsync("MinerA", c => c.UpdateValue(updateInput));
    
    // Verify: Transaction should fail with KeyNotFoundException
    result.Status.ShouldBe(TransactionResultStatus.Failed);
    result.Error.ShouldContain("KeyNotFoundException");
    // This proves honest MinerA is blocked from consensus participation
}
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-190)
```csharp
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L291-293)
```csharp
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L143-146)
```csharp
        foreach (var decryptedPiece in triggerInformation.DecryptedPieces)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(decryptedPiece.Key))
                updatedRound.RealTimeMinersInformation[decryptedPiece.Key].DecryptedPieces[pubkey] =
                    decryptedPiece.Value;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L106-138)
```csharp
        foreach (var pair in secretSharingInformation.PreviousRound.RealTimeMinersInformation
                     .OrderBy(m => m.Value.Order).ToDictionary(m => m.Key, m => m.Value.Order))
        {
            var pubkey = pair.Key;
            var order = pair.Value;

            var plainMessage = secretShares[order - 1];
            var receiverPublicKey = ByteArrayHelper.HexStringToByteArray(pubkey);
            var encryptedPiece = await _accountService.EncryptMessageAsync(receiverPublicKey, plainMessage);
            encryptedPieces[pubkey] = encryptedPiece;
            if (secretSharingInformation.PreviousRound.RealTimeMinersInformation.ContainsKey(selfPubkey) &&
                secretSharingInformation.PreviousRound.RealTimeMinersInformation[selfPubkey].EncryptedPieces
                    .ContainsKey(pubkey))
                secretSharingInformation.PreviousRound.RealTimeMinersInformation[selfPubkey]
                        .EncryptedPieces[pubkey]
                    = ByteString.CopyFrom(encryptedPiece);
            else
                continue;

            if (!secretSharingInformation.PreviousRound.RealTimeMinersInformation.ContainsKey(pubkey)) continue;

            var encryptedShares =
                secretSharingInformation.PreviousRound.RealTimeMinersInformation[pubkey].EncryptedPieces;
            if (!encryptedShares.Any() || !encryptedShares.ContainsKey(selfPubkey)) continue;
            var interestingMessage = encryptedShares[selfPubkey];
            var senderPublicKey = ByteArrayHelper.HexStringToByteArray(pubkey);

            var decryptedPiece =
                await _accountService.DecryptMessageAsync(senderPublicKey, interestingMessage.ToByteArray());
            decryptedPieces[pubkey] = decryptedPiece;
            secretSharingInformation.PreviousRound.RealTimeMinersInformation[pubkey].DecryptedPieces[selfPubkey]
                = ByteString.CopyFrom(decryptedPiece);
        }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L141-141)
```csharp
        _decryptedPieces[secretSharingInformation.CurrentRoundId] = decryptedPieces;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L108-110)
```csharp
            var decryptedPieces = _secretSharingService.GetDecryptedPieces(hint.RoundId);
            foreach (var decryptedPiece in decryptedPieces)
                trigger.DecryptedPieces.Add(decryptedPiece.Key, ByteString.CopyFrom(decryptedPiece.Value));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
