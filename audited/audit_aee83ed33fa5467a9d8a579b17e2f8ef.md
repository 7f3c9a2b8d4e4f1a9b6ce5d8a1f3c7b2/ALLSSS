### Title
Insufficient Secret Sharing State Validation Allows DoS and Consensus Corruption in Round Transitions

### Summary
The `ValidationForNextRound()` function only validates that `InValue` is null for miners in the next round, but fails to verify that other secret sharing fields (`EncryptedPieces`, `DecryptedPieces`, `OutValue`, `Signature`) are in their expected clean state. An attacker with NextRound submission privileges can pre-populate these fields with garbage data, causing legitimate miners' transactions to fail via duplicate key exceptions and corrupting the secret sharing recovery mechanism.

### Finding Description

The validation occurs in `RoundTerminateValidationProvider.ValidationForNextRound()` which only checks that `InValue` fields are null: [1](#0-0) 

However, the `MinerInRound` structure contains additional secret sharing fields that should also be empty in a new round: [2](#0-1) 

When a new round is legitimately generated, only basic fields are initialized (Pubkey, Order, ExpectedMiningTime, ProducedBlocks, MissedTimeSlots), leaving all secret sharing fields null/empty: [3](#0-2) 

The `NextRoundInput` structure allows these fields to be populated: [4](#0-3) 

**Attack Path:**

1. When miners produce blocks via `UpdateValue`, the `PerformSecretSharing` method adds encrypted pieces to their `MinerInRound` entry: [5](#0-4) 

2. The `Add()` operation on protobuf `MapField` throws `ArgumentException` when duplicate keys exist, as documented in the codebase patterns.

3. If an attacker pre-populates `EncryptedPieces` with keys that honest miners will attempt to add during their normal secret sharing process, the `Add()` call at line 290 will throw an exception, causing the transaction to fail.

4. For `DecryptedPieces`, pre-populated garbage data corrupts the secret recovery mechanism when transitioning to the subsequent round: [6](#0-5) 

The `SecretSharingHelper.DecodeSecret()` at line 50 would either fail or produce incorrect InValue recovery, corrupting the consensus randomness.

### Impact Explanation

**Primary Impact - Denial of Service:**
- Legitimate miners cannot successfully produce blocks because their `UpdateValue` transactions fail with `ArgumentException` 
- An attacker can target specific miners by pre-populating their `EncryptedPieces` with keys corresponding to other miners' pubkeys
- If enough miners are blocked, consensus can stall completely
- The round remains stuck until manual intervention or timeout mechanisms activate

**Secondary Impact - Secret Sharing Corruption:**
- Pre-populated garbage in `DecryptedPieces` causes `RevealSharedInValues` to compute incorrect previous InValues
- This corrupts the consensus signature calculation and random number generation chain
- Affects the integrity of the randomness used for miner ordering and extra block producer selection in subsequent rounds
- Could enable manipulation of miner selection if attacker controls the corrupted values

**Affected Parties:**
- All honest miners in the affected round lose mining rewards
- The entire network suffers from reduced block production or consensus halt
- Cross-chain operations depending on timely block finalization are delayed

**Severity:** HIGH - Combines operational DoS with cryptographic security degradation affecting consensus integrity.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be selected as the extra block producer at the end of a round (rotates among miners based on signatures)
- Requires being part of the active miner set
- No additional privileges beyond normal miner role needed

**Attack Complexity:**
- LOW - Simply modify the `NextRoundInput` protobuf message before submission to include pre-populated secret sharing fields
- No cryptographic breaks or complex timing attacks required
- The validation explicitly does NOT check these fields, making exploitation straightforward

**Feasibility Conditions:**
- Attacker mines blocks normally to reach extra block producer position (happens periodically)
- The secret sharing feature must be enabled (controlled by configuration): [7](#0-6) 

**Economic Rationality:**
- Attack cost: Normal mining operation costs until gaining extra block producer position
- Attack benefit: Can block specific competitors from mining, potentially increasing attacker's relative rewards
- Detection: Likely detectable through blockchain analysis showing round with pre-populated fields, but damage already done

**Probability:** MEDIUM - Requires periodic opportunity (extra block producer rotation) but execution is trivial once positioned.

### Recommendation

**Code-Level Mitigation:**

Expand the validation in `RoundTerminateValidationProvider.ValidationForNextRound()` to check all secret sharing fields are in their expected initial state:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Check round number increment
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    // Check all secret sharing fields are null/empty for new round
    foreach (var miner in extraData.Round.RealTimeMinersInformation.Values)
    {
        if (miner.InValue != null)
            return new ValidationResult { Message = "InValue must be null in next round." };
        
        if (miner.OutValue != null)
            return new ValidationResult { Message = "OutValue must be null in next round." };
            
        if (miner.Signature != null)
            return new ValidationResult { Message = "Signature must be null in next round." };
            
        if (miner.EncryptedPieces.Count > 0)
            return new ValidationResult { Message = "EncryptedPieces must be empty in next round." };
            
        if (miner.DecryptedPieces.Count > 0)
            return new ValidationResult { Message = "DecryptedPieces must be empty in next round." };
    }

    return new ValidationResult { Success = true };
}
```

**Invariant Checks:**
- Assert that new rounds have clean secret sharing state before storage
- Add state consistency checks in `ProcessNextRound` to verify no pre-existing secret sharing data

**Test Cases:**
1. Test that NextRound submission with pre-populated `EncryptedPieces` is rejected
2. Test that NextRound submission with pre-populated `DecryptedPieces` is rejected
3. Test that NextRound submission with non-null `OutValue`/`Signature` is rejected
4. Verify legitimate round transitions still pass validation
5. Integration test ensuring miners can successfully mine after validated round transition

### Proof of Concept

**Initial State:**
- Network running with AEDPoS consensus and secret sharing enabled
- Round N in progress with 5 miners: MinerA, MinerB, MinerC, MinerD, Attacker
- Attacker is the extra block producer for Round N

**Attack Execution:**

1. **Attacker generates NextRound data:**
   - Calls consensus service to generate legitimate Round N+1 data
   - Round N+1 has clean `MinerInRound` entries per normal generation

2. **Attacker modifies NextRoundInput before submission:**
   ```
   NextRoundInput.RealTimeMinersInformation["MinerA_pubkey"].EncryptedPieces["MinerB_pubkey"] = [garbage_bytes]
   NextRoundInput.RealTimeMinersInformation["MinerA_pubkey"].EncryptedPieces["MinerC_pubkey"] = [garbage_bytes]
   NextRoundInput.RealTimeMinersInformation["MinerC_pubkey"].DecryptedPieces["Attacker_pubkey"] = [garbage_bytes]
   ```

3. **Attacker submits NextRound transaction:**
   - Validation executes via reference: [8](#0-7) 
   
   - Only `InValue` nullness is checked (all null, validation PASSES)
   - Round N+1 is stored with corrupted state

4. **MinerA attempts to mine block in Round N+1:**
   - Generates `UpdateValueInput` with legitimate encrypted pieces for MinerB, MinerC, etc.
   - Transaction enters `ProcessUpdateValue` → `PerformSecretSharing`
   - At MapField.Add() operation: **ArgumentException thrown** (duplicate keys "MinerB_pubkey", "MinerC_pubkey")
   - MinerA's transaction FAILS

5. **MinerC attempts to mine:**
   - Similarly fails if their legitimate pieces conflict with pre-populated data

**Expected vs Actual Result:**
- **Expected:** All miners can successfully produce blocks in Round N+1
- **Actual:** Targeted miners' UpdateValue transactions fail, consensus disrupted

**Success Condition:** 
Blockchain explorer shows Round N+1 with abnormally low block production, transaction logs show ArgumentException failures from legitimate miners' UpdateValue calls, and Round N+1 state inspection reveals pre-populated secret sharing fields that should be empty.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L32-34)
```csharp
        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
```

**File:** protobuf/aedpos_contract.proto (L266-301)
```text
message MinerInRound {
    // The order of the miner producing block.
    int32 order = 1;
    // Is extra block producer in the current round.
    bool is_extra_block_producer = 2;
    // Generated by secret sharing and used for validation between miner.
    aelf.Hash in_value = 3;
    // Calculated from current in value.
    aelf.Hash out_value = 4;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 5;
    // The expected mining time.
    google.protobuf.Timestamp expected_mining_time = 6;
    // The amount of produced blocks.
    int64 produced_blocks = 7;
    // The amount of missed time slots.
    int64 missed_time_slots = 8;
    // The public key of this miner.
    string pubkey = 9;
    // The InValue of the previous round.
    aelf.Hash previous_in_value = 10;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
    // The actual mining time, miners must fill actual mining time when they do the mining.
    repeated google.protobuf.Timestamp actual_mining_times = 13;
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
    // The amount of produced tiny blocks.
    int64 produced_tiny_blocks = 16;
    // The irreversible block height that current miner recorded.
    int64 implied_irreversible_block_height = 17;
}
```

**File:** protobuf/aedpos_contract.proto (L458-481)
```text
message NextRoundInput {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
    // The round number on the main chain
    int64 main_chain_miners_round_number = 3;
    // The time from chain start to current round (seconds).
    int64 blockchain_age = 4;
    // The miner public key that produced the extra block in the previous round.
    string extra_block_producer_of_previous_round = 5;
    // The current term number.
    int64 term_number = 6;
    // The height of the confirmed irreversible block.
    int64 confirmed_irreversible_block_height = 7;
    // The round number of the confirmed irreversible block.
    int64 confirmed_irreversible_block_round_number = 8;
    // Is miner list different from the the miner list in the previous round.
    bool is_miner_list_just_changed = 9;
    // The round id, calculated by summing block producers’ expecting time (second).
    int64 round_id_for_validation = 10;
    // The random number.
    bytes random_number = 11;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-56)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
        }

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L35-52)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```
