# Audit Report

## Title
Secret Sharing Reveal Blocked by Incorrect Threshold Check - Byzantine Fault Tolerance Broken

## Summary
The `RevealSharedInValues()` function in the AEDPoS consensus contract requires 100% of miners to provide decrypted pieces before revealing InValues, but Shamir's Secret Sharing algorithm only needs a 2/3 threshold. This allows a single malicious miner to block all InValue reveals by refusing to submit decrypted pieces, completely defeating the Byzantine fault tolerance that the secret sharing mechanism was designed to provide.

## Finding Description

The vulnerability exists in the `RevealSharedInValues()` method where the threshold check for decrypted pieces is incorrect.

**Root Cause:**

The function correctly calculates `minimumCount` as 2/3 of total miners [1](#0-0) , and correctly checks that `EncryptedPieces.Count >= minimumCount` [2](#0-1) . However, it then incorrectly checks `DecryptedPieces.Count >= minersCount` (requiring 100% of all miners) [3](#0-2) , even though the actual secret decoding operation only requires `minimumCount` pieces [4](#0-3) .

**Why This Breaks Byzantine Fault Tolerance:**

A miner's `DecryptedPieces` collection is populated by OTHER miners through the `PerformSecretSharing` method [5](#0-4) . When miners call `UpdateValue`, they provide a `decrypted_pieces` map [6](#0-5) , and each entry is added to the corresponding miner's `DecryptedPieces` collection.

The 100% requirement means that ALL miners must cooperate to include decrypted pieces for a target miner. This contradicts the fundamental property of Shamir's Secret Sharing, which mathematically only requires the threshold number of pieces.

**Execution Path:**

1. Round N: MinerA provides encrypted pieces via `UpdateValue` (stored in MinerA.EncryptedPieces) [7](#0-6) 
2. Round N+1: Other miners should decrypt and submit via `UpdateValueInput.decrypted_pieces` [8](#0-7) 
3. These decrypted pieces get added to MinerA.DecryptedPieces by `PerformSecretSharing` [9](#0-8) 
4. When generating next round consensus data, `RevealSharedInValues` is called [10](#0-9) 
5. If MinerA's `DecryptedPieces.Count < minersCount`, the reveal is blocked
6. A single malicious miner can withhold their decryption by omitting entries from their `decrypted_pieces` map, preventing MinerA's InValue from ever being revealed

The cryptographic library confirms that `DecodeSecret` only iterates over `threshold` pieces, not all pieces [11](#0-10) .

## Impact Explanation

**Consensus Integrity Impact:**
- **Byzantine Fault Tolerance Broken**: The entire purpose of using Shamir's Secret Sharing with a 2/3 threshold is to tolerate up to 1/3 malicious or offline nodes. This bug completely defeats that security property.
- **Single Point of Failure**: Even ONE miner refusing to provide decrypted pieces blocks ALL InValue reveals. In a 10-miner network, the system should only need 7 pieces but currently requires all 10.
- **Selective Censorship**: Malicious miners can strategically block specific miners' InValue reveals, potentially manipulating consensus randomness.

**Who is Affected:**
All miners relying on the secret sharing mechanism to reveal their PreviousInValue. While miners can voluntarily provide their PreviousInValue directly [12](#0-11) , the comment indicates this is permissible (not required), meaning the secret sharing should serve as an automatic fallback. With this bug, that fallback is broken.

**Severity: Medium**
While the system has fallback mechanisms (direct reveals), the core security property of Byzantine fault-tolerant secret recovery is completely defeated. This enables potential manipulation of consensus randomness through selective blocking of reveals.

## Likelihood Explanation

**Attacker Capabilities:**
Any active miner can execute this attack by simply omitting entries from the `decrypted_pieces` map in their `UpdateValueInput` when calling the `UpdateValue` method [13](#0-12) .

**Attack Complexity:**
Trivial - requires no special capabilities beyond being a miner. The attacker merely excludes specific public keys from their submission.

**Feasibility Conditions:**
- Attacker is an active miner (realistic - probability 1/N where N is the number of miners)
- Secret sharing is enabled via configuration [14](#0-13) 
- No cost or penalty for not providing decrypted pieces
- Can be executed selectively against specific targets

**Detection/Operational Constraints:**
Difficult to distinguish malicious withholding from legitimate node failures or network issues. The behavior appears identical to a miner simply not participating.

**Probability: High**
Given the ease of execution, lack of penalties, and the trivial nature of the attack, any malicious miner can disrupt the entire reveal mechanism.

## Recommendation

Change the threshold check at line 36 from requiring 100% of miners to requiring only the minimum threshold:

```csharp
// Change from:
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

// To:
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minimumCount) continue;
```

This aligns the check with the actual cryptographic requirement of Shamir's Secret Sharing and restores the intended Byzantine fault tolerance property, allowing the system to tolerate up to 1/3 malicious or offline miners.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a test network with N miners (e.g., 10 miners where minimumCount = 7)
2. Having MinerA provide encrypted pieces in Round N
3. Having only (N-1) miners provide decrypted pieces for MinerA in Round N+1
4. Observing that `RevealSharedInValues` fails to reveal MinerA's InValue despite having 9 pieces when only 7 are cryptographically required
5. Confirming that `SecretSharingHelper.DecodeSecret` can successfully decode the secret with only 7 pieces

The test would verify that the check at line 36 blocks the reveal even when sufficient pieces (≥ minimumCount) exist for successful decryption.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L21-23)
```csharp
        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L35-35)
```csharp
            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L36-36)
```csharp
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L50-50)
```csharp
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L56-78)
```csharp
    private bool IsSecretSharingEnabled()
    {
        if (State.ConfigurationContract.Value == null)
        {
            var configurationContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.ConfigurationContractSystemName);
            if (configurationContractAddress == null)
            {
                // Which means Configuration Contract hasn't been deployed yet.
                return false;
            }

            State.ConfigurationContract.Value = configurationContractAddress;
        }

        var secretSharingEnabled = new BoolValue();
        secretSharingEnabled.MergeFrom(State.ConfigurationContract.GetConfiguration.Call(new StringValue
        {
            Value = AEDPoSContractConstants.SecretSharingEnabledConfigurationKey
        }).Value);

        return secretSharingEnabled.Value;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-285)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;

        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;

        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
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

**File:** protobuf/aedpos_contract.proto (L194-213)
```text
message UpdateValueInput {
    // Calculated from current in value.
    aelf.Hash out_value = 1;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 2;
    // To ensure the values to update will be apply to correct round by comparing round id.
    int64 round_id = 3;
    // Publish previous in value for validation previous signature and previous out value.
    aelf.Hash previous_in_value = 4;
    // The actual mining time, miners must fill actual mining time when they do the mining.
    google.protobuf.Timestamp actual_mining_time = 5;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 6;
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 8;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 9;
    // The amount of produced blocks.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L44-50)
```csharp
        public static byte[] DecodeSecret(List<byte[]> sharedParts, List<int> orders, int threshold)
        {
            var result = BigInteger.Zero;

            for (var i = 0; i < threshold; i++)
            {
                var numerator = new BigInteger(sharedParts[i]);
```
