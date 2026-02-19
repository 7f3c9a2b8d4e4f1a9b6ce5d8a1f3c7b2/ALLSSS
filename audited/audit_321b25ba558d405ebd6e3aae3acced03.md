# Audit Report

## Title
Missing Size Validation on Encrypted Pieces Allows State Bloat Attack

## Summary
The AEDPoS consensus contract's secret sharing mechanism stores encrypted pieces without size validation, allowing a malicious miner to submit grossly oversized data (up to ~4.5MB per transaction) that persists across 40,960 rounds, causing cumulative state bloat and network-wide degradation.

## Finding Description

The vulnerability exists in the consensus secret sharing mechanism where encrypted pieces are stored in round state without any size constraints. The attack flow proceeds as follows:

**Entry Point:** A miner calls the public `UpdateValue()` method [1](#0-0) , which routes through `ProcessConsensusInformation()` [2](#0-1)  to `ProcessUpdateValue()`.

**Vulnerable Code Path:** When secret sharing is enabled, `ProcessUpdateValue()` calls `PerformSecretSharing()` [3](#0-2) , which directly adds the encrypted pieces to state without validation [4](#0-3) .

Similarly, `UpdateLatestSecretPieces()` iterates through trigger information and adds encrypted pieces directly to the round state without size checks [5](#0-4) .

**Missing Validation:** The `UpdateValueValidationProvider` only validates OutValue and PreviousInValue correctness, with no size validation on encrypted_pieces [6](#0-5) .

**Protobuf Definition:** The encrypted_pieces field is defined as `map<string, bytes>` with no size constraints in the protobuf specification [7](#0-6) .

**Only Protection:** The sole protection is the global transaction size limit of 5MB [8](#0-7) , which is insufficient as it permits ~4.5MB of bloated data per transaction.

**State Persistence:** The system retains 40,960 rounds in state before cleanup [9](#0-8) , with cleanup occurring in `AddRoundInformation()` [10](#0-9) .

## Impact Explanation

**State Bloat Severity:** Normal encrypted pieces total approximately 3KB per round. A malicious miner can inflate this to ~4.5MB per UpdateValue transaction, achieving a 1500x bloat factor.

**Cumulative Damage:** With 40,960 rounds kept in state, sustained attacks cause:
- 100 bloated rounds = 450MB of unnecessary state
- 1,000 bloated rounds = 4.5GB of unnecessary state
- Prolonged attacks could reach tens of gigabytes

**Network-Wide Impact:**
- All full nodes must store and synchronize bloated state
- New nodes experience significantly prolonged synchronization times
- State queries and consensus operations suffer performance degradation
- Storage infrastructure costs increase for all network participants
- Risk of chain instability if state size becomes unmanageable

This is a DoS attack vector affecting network availability and operational sustainability rather than direct fund theft.

## Likelihood Explanation

**Attacker Requirements:** The attacker must be a valid miner in the current or previous round, verified by PreCheck [11](#0-10) .

**Feasibility:** Miner status is achievable through the election process without extraordinary barriers. Once achieved, the attack requires only modifying node software to generate oversized encrypted_pieces when calling UpdateValue.

**Attack Complexity:** Low - no cryptographic bypasses or complex timing attacks required. The attacker simply populates the encrypted_pieces map with oversized byte arrays within the 5MB transaction limit.

**Detection and Remediation:** While monitoring could detect unusual transaction sizes, damage accumulates before governance can vote to exclude the malicious miner. During this remediation period, additional bloat accrues.

**Repeatability:** The attack can be executed repeatedly across multiple rounds during the attacker's mining tenure, and could be coordinated across multiple compromised miners for amplified impact.

## Recommendation

Implement strict size validation for encrypted_pieces in multiple layers:

1. **Contract-Level Validation:** Add size checks in `PerformSecretSharing()` and `UpdateLatestSecretPieces()`:
   - Validate total encrypted_pieces size does not exceed reasonable threshold (e.g., 10KB)
   - Validate individual piece sizes are within expected cryptographic parameters
   - Reject transactions that exceed these limits with descriptive error messages

2. **Validation Provider Enhancement:** Extend `UpdateValueValidationProvider` to include encrypted_pieces size validation before accepting the consensus information.

3. **Protobuf Constraints:** Document expected size constraints in comments and consider implementing runtime validation based on the expected number of miners and cryptographic piece sizes.

4. **Monitoring:** Implement metrics to track encrypted_pieces sizes in production to detect anomalies early.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. **Setup:** Deploy a test network with secret sharing enabled and obtain miner status for the attacker node
2. **Attack Execution:** 
   - Construct UpdateValueInput with legitimate OutValue, Signature, and other required fields
   - Populate encrypted_pieces map with oversized byte arrays (e.g., 17 entries of 250KB each = ~4.25MB)
   - Submit via UpdateValue() transaction
3. **Verification:**
   - Query round state to confirm bloated encrypted_pieces are stored
   - Verify state size increases by ~4MB per attacked round
   - Confirm no validation errors occur during transaction execution
   - Repeat across 100 rounds to demonstrate cumulative 400MB+ state bloat

The test would demonstrate that encrypted_pieces are stored without size validation, the bloat persists across the 40,960 round retention period, and network performance degrades measurably as state size grows.

---

## Notes

This vulnerability represents a **state bloat DoS attack** rather than a direct financial exploit. While the attacker must obtain miner status (a semi-trusted role), the absence of size validation creates an exploitable gap that can significantly degrade network health. The long retention period of 40,960 rounds amplifies the impact, making timely detection and remediation critical. Implementation of the recommended size validations would eliminate this attack vector while maintaining legitimate secret sharing functionality.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L45-47)
```csharp
            case UpdateValueInput updateValueInput:
                randomNumber = updateValueInput.RandomNumber;
                ProcessUpdateValue(updateValueInput);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L254-257)
```csharp
        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L287-290)
```csharp
    private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
        string publicKey)
    {
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L136-141)
```csharp
    private void UpdateLatestSecretPieces(Round updatedRound, string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        foreach (var encryptedPiece in triggerInformation.EncryptedPieces)
            updatedRound.RealTimeMinersInformation[pubkey].EncryptedPieces
                .Add(encryptedPiece.Key, encryptedPiece.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-49)
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

    /// <summary>
    ///     Check only one Out Value was filled during this updating.
    /// </summary>
    /// <param name="validationContext"></param>
    /// <returns></returns>
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }

    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
    }
```

**File:** protobuf/aedpos_contract.proto (L209-211)
```text
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 8;
    // The decrypted pieces of InValue.
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L5-5)
```csharp
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L10-10)
```csharp
    public const int KeepRounds = 40960;
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
