# Audit Report

## Title
Unbounded State Growth via Unvalidated EncryptedPieces in Consensus Secret Sharing

## Summary
The AEDPoS consensus contract accepts an arbitrary number of encrypted secret sharing pieces from miners without validating that the count matches the expected miner count. A malicious elected miner can exploit this to cause unbounded blockchain state growth by repeatedly submitting oversized `EncryptedPieces` maps, leading to state bloat and operational DoS that threatens network decentralization.

## Finding Description

The vulnerability exists in the consensus secret sharing mechanism where encrypted pieces are added to persistent state without size validation.

**Vulnerable Location 1**: `UpdateLatestSecretPieces()` iterates through all entries in `triggerInformation.EncryptedPieces` and adds them to the round state without any count validation: [1](#0-0) 

**Vulnerable Location 2**: `PerformSecretSharing()` similarly adds all entries from `input.EncryptedPieces` without validation: [2](#0-1) 

**Root Cause**: The protobuf definition allows arbitrary map sizes for `encrypted_pieces`: [3](#0-2) [4](#0-3) 

**Expected Behavior**: According to the legitimate secret sharing implementation, each miner should provide exactly `minersCount` encrypted pieces (one per miner, typically 17 based on `SupposedMinersCount`): [5](#0-4) [6](#0-5) 

**Actual Behavior**: The contract accepts and stores any number of entries without checking against the expected count.

**Execution Path**:

1. Malicious miner modifies their node's `AEDPoSTriggerInformationProvider` to inject oversized `EncryptedPieces` map instead of legitimate pieces
2. When the miner produces a block, `GenerateConsensusTransactions` is called with malicious trigger information
3. `UpdateLatestSecretPieces` is invoked during consensus extra data generation, copying all malicious pieces to `updatedRound`
4. The round data is extracted via `ExtractInformationToUpdateConsensus`, which includes all encrypted pieces: [7](#0-6) 

5. A transaction calling `UpdateValue` is generated with the oversized input
6. When executed, `ProcessUpdateValue` calls `PerformSecretSharing`, which adds all pieces without validation
7. The bloated round is persisted to blockchain state: [8](#0-7) [9](#0-8) 

8. State is retained for 40,960 rounds: [10](#0-9) [11](#0-10) 

**Security Guarantee Broken**: The consensus protocol assumes miners will only submit data proportional to the miner count. This assumption is violated because there is no enforcement mechanism in the contract.

## Impact Explanation

**Operational Impact - State Bloat DoS**:
- A malicious miner can inject up to 5MB of encrypted pieces per UpdateValue transaction (AElf's transaction size limit)
- With 40,960 rounds kept in state, accumulated bloat can reach 200+ GB if exploited consistently (5MB × 40,960 = 204.8 GB)
- All full nodes must store and sync this bloated state
- New nodes face significantly increased sync times, potentially taking days or weeks instead of hours
- Storage costs increase proportionally for all node operators
- Eventually makes running a node economically impractical, threatening network decentralization
- Unlike temporary DoS attacks, this causes permanent state growth that cannot be easily removed

**Severity**: Medium to High - While this does not directly steal funds, it causes significant operational degradation that can make the blockchain impractical to operate over time and threatens the fundamental property of decentralization.

## Likelihood Explanation

**Attacker Capabilities**:
- Requires being in the active miner list (elected through the Election contract)
- Miners are semi-trusted but can become malicious or have their infrastructure compromised
- Once elected, miner has full control over their node's off-chain consensus data generation

**Attack Complexity**:
- Low - Simply modify node software's `AEDPoSTriggerInformationProvider.GetTriggerInformationForConsensusTransactions` to inject oversized maps
- No complex cryptographic operations or precise timing requirements
- Can be automated to execute on every block the miner produces

**Feasibility Conditions**:
- Secret sharing must be enabled (configuration-based, typically enabled on mainnet)
- Attacker must maintain miner status to exploit repeatedly
- Transaction size limit (5MB) caps per-attack impact but allows sustained exploitation

**Economic Rationality**:
- Standard transaction fees apply but are negligible compared to damage inflicted
- No tokens are burned or locked beyond normal transaction fees
- Attacker's election stake remains intact (no slashing for this behavior)
- Potential motivations: griefing, competitive advantage, extortion

**Detection**: While abnormal state growth would be visible in metrics, attributing it specifically to malicious encrypted pieces versus legitimate consensus data may be challenging initially, allowing sustained exploitation before detection.

**Probability**: Medium - Requires achieving miner status (moderate barrier) but is trivial to execute once achieved (low technical barrier).

## Recommendation

Add validation to ensure the number of encrypted pieces matches the expected miner count:

```csharp
private void UpdateLatestSecretPieces(Round updatedRound, string pubkey,
    AElfConsensusTriggerInformation triggerInformation)
{
    var minersCount = updatedRound.RealTimeMinersInformation.Count;
    
    // Validate encrypted pieces count
    Assert(triggerInformation.EncryptedPieces.Count <= minersCount,
        $"EncryptedPieces count exceeds miner count: {triggerInformation.EncryptedPieces.Count} > {minersCount}");
    
    foreach (var encryptedPiece in triggerInformation.EncryptedPieces)
    {
        // Only accept pieces for valid miners
        if (updatedRound.RealTimeMinersInformation.ContainsKey(encryptedPiece.Key))
            updatedRound.RealTimeMinersInformation[pubkey].EncryptedPieces
                .Add(encryptedPiece.Key, encryptedPiece.Value);
    }
    
    // Similar validation for decrypted pieces and revealed in values
    Assert(triggerInformation.DecryptedPieces.Count <= minersCount,
        "DecryptedPieces count exceeds miner count");
    Assert(triggerInformation.RevealedInValues.Count <= minersCount,
        "RevealedInValues count exceeds miner count");
        
    // ... rest of the function with existing logic
}
```

Apply similar validation in `PerformSecretSharing`:

```csharp
private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
    string publicKey)
{
    var minersCount = round.RealTimeMinersInformation.Count;
    
    Assert(input.EncryptedPieces.Count <= minersCount,
        "EncryptedPieces count exceeds miner count");
    Assert(input.DecryptedPieces.Count <= minersCount,
        "DecryptedPieces count exceeds miner count");
        
    minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
    // ... rest of the function
}
```

## Proof of Concept

```csharp
// This test demonstrates the vulnerability by showing a miner can submit
// an arbitrarily large EncryptedPieces map without validation

[Fact]
public async Task MaliciousMiner_CanInflateState_WithOversizedEncryptedPieces()
{
    // Setup: Initialize consensus with legitimate miners
    await InitializeConsensus();
    var maliciousMinerKeyPair = SampleAccount.Accounts[0].KeyPair;
    
    // Create oversized EncryptedPieces map (1000 entries instead of 17)
    var oversizedPieces = new Dictionary<string, ByteString>();
    for (int i = 0; i < 1000; i++)
    {
        oversizedPieces.Add($"fake_miner_{i}", ByteString.CopyFrom(new byte[4096]));
    }
    
    // Construct malicious UpdateValueInput
    var maliciousInput = new UpdateValueInput
    {
        OutValue = Hash.FromString("test"),
        Signature = Hash.FromString("test"),
        RoundId = 1,
        PreviousInValue = Hash.Empty,
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        SupposedOrderOfNextRound = 1,
        EncryptedPieces = { oversizedPieces }, // Oversized map
        ImpliedIrreversibleBlockHeight = 1,
        RandomNumber = ByteString.CopyFromUtf8("random")
    };
    
    // Execute: Submit the malicious update (should fail with validation but currently succeeds)
    var result = await AEDPoSContractStub.UpdateValue.SendAsync(maliciousInput);
    
    // Verify: Transaction succeeds (vulnerability confirmed)
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Oversized data is stored in state
    var round = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var miner = round.RealTimeMinersInformation[maliciousMinerKeyPair.PublicKey.ToHex()];
    
    // Expected: 17 pieces (one per miner)
    // Actual: 1000 pieces (vulnerability confirmed)
    miner.EncryptedPieces.Count.ShouldBe(1000);
}
```

## Notes

This vulnerability fundamentally breaks the consensus contract's assumption that miners will behave according to the secret sharing protocol. While the off-chain `SecretSharingService` correctly generates exactly `minersCount` pieces, the on-chain contract fails to enforce this invariant. The lack of validation allows a malicious miner to weaponize the secret sharing mechanism for state bloat attacks. The 40,960 round retention period amplifies the impact significantly, as each round's bloated data persists for an extended period before cleanup.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L139-141)
```csharp
        foreach (var encryptedPiece in triggerInformation.EncryptedPieces)
            updatedRound.RealTimeMinersInformation[pubkey].EncryptedPieces
                .Add(encryptedPiece.Key, encryptedPiece.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L284-284)
```csharp
        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L290-290)
```csharp
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
```

**File:** protobuf/aedpos_contract.proto (L210-210)
```text
    map<string, bytes> encrypted_pieces = 8;
```

**File:** protobuf/aedpos_contract.proto (L294-294)
```text
    map<string, bytes> encrypted_pieces = 14;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L10-10)
```csharp
    public const int KeepRounds = 40960;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L101-104)
```csharp
        var minersCount = secretSharingInformation.PreviousRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        var secretShares =
            SecretSharingHelper.EncodeSecret(newInValue.ToByteArray(), minimumCount, minersCount);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L45-45)
```csharp
            EncryptedPieces = { minerInRound.EncryptedPieces },
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L105-105)
```csharp
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L118-123)
```csharp
        var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
        if (
            roundNumberToRemove >
            1 && // Which means we won't remove the information of the first round of first term.
            GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount)
            State.Rounds.Remove(roundNumberToRemove);
```
