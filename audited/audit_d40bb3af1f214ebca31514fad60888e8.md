### Title
Unvalidated Secret Sharing Reveals Allow Consensus State Corruption and Mining Order Manipulation

### Summary
The `UpdateLatestSecretPieces()` function accepts revealed InValues from trigger information without cryptographic verification, allowing malicious miners to inject arbitrary `PreviousInValue` data for other miners who haven't yet produced blocks in the current round. This corrupts consensus state, affects mining order calculations in subsequent rounds, and pollutes the randomness generation mechanism.

### Finding Description

The vulnerability exists in the `UpdateLatestSecretPieces()` function where revealed InValues are processed without validation: [1](#0-0) 

The condition only checks if `PreviousInValue` is currently `Hash.Empty` or `null`, but performs no cryptographic verification that the revealed value is correct. The `RevealedInValues` originate from trigger information provided by the miner's node: [2](#0-1) 

A malicious miner can modify their node's `SecretSharingService` to return arbitrary fake values. These fake values flow through to the consensus contract and are persisted to state via `PerformSecretSharing()`: [3](#0-2) 

The critical difference is that the legitimate `RevealSharedInValues()` function performs cryptographic reconstruction using Shamir's Secret Sharing: [4](#0-3) 

But `UpdateLatestSecretPieces()` bypasses this verification entirely. The only validation that exists checks the sender's own `PreviousInValue`, not revealed values for other miners: [5](#0-4) 

When a victim miner fails to produce a block and the round transitions, `SupplyCurrentRoundInformation()` uses the corrupted `PreviousInValue` to calculate their signature: [6](#0-5) [7](#0-6) 

This fake signature is then used to determine the victim's mining order in the next round: [8](#0-7) 

The signature calculation aggregates all miners' signatures via XOR: [9](#0-8) 

### Impact Explanation

**Consensus Integrity Violation**: The attack directly corrupts on-chain consensus state by setting incorrect `PreviousInValue`, `InValue`, and `Signature` fields for victim miners. This violates the fundamental consensus invariant that each miner's signature must be derived from their genuine InValue.

**Mining Order Manipulation**: The corrupted signature determines the victim's `SupposedOrderOfNextRound`, directly affecting when they can produce blocks. An attacker can systematically target specific miners to alter the mining schedule, potentially gaining unfair block production advantages or causing specific miners to miss their slots.

**Randomness Corruption**: Miner signatures contribute to consensus randomness generation and are aggregated via XOR operations. Injecting fake signatures pollutes this randomness source, potentially enabling prediction or manipulation of round-based randomness.

**State Pollution Persistence**: Once a fake `PreviousInValue` is set through this mechanism, the victim cannot correct it until they successfully produce a block with their real value. During round transitions via `NextRound`, the fake data generates incorrect derived values that propagate through subsequent rounds.

**Affected Parties**: Any miner who misses their time slot becomes vulnerable. In networks with unreliable connectivity or during high load, missed slots are common, making this widely exploitable.

### Likelihood Explanation

**Attacker Profile**: Any authorized miner in the consensus pool can execute this attack. The only requirement is the ability to modify their local node software to return fake values in `GetRevealedInValues()`.

**Attack Complexity**: Low. The attacker simply modifies their `SecretSharingService` implementation to return arbitrary values in the `_revealedInValues` dictionary. No cryptographic operations, complex timing, or coordination with other parties is required.

**Preconditions**: 
1. Attacker is an active miner in the current round
2. Target victim miner misses their time slot (hasn't produced `OutValue` yet in current round)
3. Attacker produces a block before victim in the same round

**Detection Difficulty**: The attack is difficult to detect because:
- No on-chain validation flags fake revealed values
- The corrupted state appears as legitimate consensus data
- Victims only discover the issue when they attempt to mine and their validation fails

**Economic Feasibility**: The attack cost is minimal—only the gas cost of producing a normal block. The potential gain includes unfair mining advantages, ability to manipulate specific miners' schedules, and disruption of consensus randomness.

**Operational Constraints**: None. The attack can be executed repeatedly in every round where conditions are met. Given that missed time slots occur regularly in distributed networks, attack opportunities are frequent.

### Recommendation

**Immediate Fix**: Add cryptographic verification of revealed InValues before accepting them. The revealed InValue must be validated against the miner's previously committed `OutValue` from the previous round:

```csharp
foreach (var revealedInValue in triggerInformation.RevealedInValues)
    if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key))
    {
        // Validate revealed InValue against previous OutValue
        if (TryToGetPreviousRoundInformation(out var previousRound) &&
            previousRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key))
        {
            var previousOutValue = previousRound.RealTimeMinersInformation[revealedInValue.Key].OutValue;
            if (previousOutValue != null && 
                HashHelper.ComputeFrom(revealedInValue.Value) != previousOutValue)
            {
                // Revealed InValue doesn't match OutValue - reject
                continue;
            }
        }
        
        if (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
            updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null)
            updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
    }
```

**Invariant Check**: Enforce that `Hash(PreviousInValue) == PreviousOutValue` for all miners when `PreviousInValue` is set via revealed values, not just for the sender's own value.

**Alternative Approach**: Only accept revealed InValues that have been cryptographically reconstructed via `RevealSharedInValues()` using on-chain encrypted/decrypted pieces. Remove the ability to provide arbitrary revealed values via trigger information.

**Test Cases**: 
1. Test that fake revealed InValues with incorrect hashes are rejected
2. Test that legitimate revealed InValues matching OutValue are accepted
3. Test that miners cannot overwrite another miner's correctly set PreviousInValue
4. Test round transitions with corrupted PreviousInValue to ensure state consistency

### Proof of Concept

**Initial State**:
- Round N: Victim miner produces block with `OutValue_victim = Hash(InValue_victim)`
- Round N+1 begins: Victim's `PreviousInValue` is `null`, victim has not yet produced a block

**Attack Execution**:
1. Attacker modifies their node's `SecretSharingService.GetRevealedInValues()` to return:
   ```
   { "victim_pubkey": FakeInValue }
   ```
   where `FakeInValue` is an arbitrary hash value chosen by attacker

2. Attacker produces block in round N+1 at their assigned time slot

3. `GetConsensusBlockExtraData()` is called with attacker's trigger information containing fake `RevealedInValues`

4. `UpdateLatestSecretPieces()` executes:
   - Line 150-151 checks: victim's `PreviousInValue == null` → TRUE
   - Line 152: Sets `victim.PreviousInValue = FakeInValue`
   - No validation that `Hash(FakeInValue) == OutValue_victim`

5. Block is produced and `ProcessUpdateValue()` persists the corrupted state

6. Round N+1 ends without victim mining, `NextRound()` is called

7. `SupplyCurrentRoundInformation()` executes:
   - Line 191: Reads `victim.PreviousInValue = FakeInValue`
   - Line 199: Calculates `signature = CalculateSignature(FakeInValue)` → wrong signature
   - Line 213-214: Sets `victim.InValue = FakeInValue`, `victim.Signature = wrong_signature`

8. Round N+2 generation uses the wrong signature to calculate victim's mining order

**Expected Result**: Victim's `PreviousInValue` should only be set to their genuine `InValue_victim` (where `Hash(InValue_victim) == OutValue_victim`), either by victim themselves or via cryptographically verified secret sharing reconstruction.

**Actual Result**: Attacker successfully injects arbitrary `FakeInValue`, corrupting victim's consensus state, signature, and next-round mining order.

**Success Condition**: After step 7, verify that `victim.PreviousInValue != InValue_victim` and `Hash(victim.PreviousInValue) != OutValue_victim`, confirming state corruption.

### Notes

This vulnerability specifically affects the trust boundary between off-chain trigger information (generated by miner nodes) and on-chain consensus state. The legitimate `RevealSharedInValues()` function demonstrates the correct approach using cryptographic verification via Shamir's Secret Sharing. The `UpdateLatestSecretPieces()` function should apply equivalent validation before accepting revealed values. The impact is amplified in networks with variable connectivity where missed time slots are common, as each missed slot creates an attack opportunity.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L148-152)
```csharp
        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L112-114)
```csharp
            var revealedInValues = _secretSharingService.GetRevealedInValues(hint.RoundId);
            foreach (var revealedInValue in revealedInValues)
                trigger.RevealedInValues.Add(revealedInValue.Key, revealedInValue.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L295-296)
```csharp
        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-52)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L44-48)
```csharp
        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L191-199)
```csharp
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L213-214)
```csharp
            miner.InValue = previousInValue;
            miner.Signature = signature;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```
