### Title
Consensus Halt via Stale Public Key References in DecryptedPieces After Candidate Replacement

### Summary
When secret sharing is enabled and a candidate's public key is replaced via `RecordCandidateReplacement`, the old public key is removed from `RealTimeMinersInformation` but remains as a key in other miners' `DecryptedPieces` dictionaries. Subsequently, when `RevealSharedInValues` attempts to resolve these stale keys during NextRound block generation, the `First()` call throws `InvalidOperationException`, causing all NextRound transitions to fail and halting consensus progression.

### Finding Description

The vulnerability exists in the interaction between candidate replacement and secret sharing mechanisms:

**Location 1 - The Failing Code:** [1](#0-0) 

The `RevealSharedInValues` function iterates through miners' `DecryptedPieces` dictionaries and uses `First()` to locate corresponding miners in `previousRound.RealTimeMinersInformation`. The `First()` LINQ method throws `InvalidOperationException` when no matching element is found.

**Location 2 - Incomplete Update Logic:** [2](#0-1) 

When `RecordCandidateReplacement` processes a public key replacement, it only updates:
1. The miner's `Pubkey` field
2. The outer `RealTimeMinersInformation` dictionary keys (removes old, adds new)
3. The `ExtraBlockProducerOfPreviousRound` if needed

**Critical Gap:** The function does NOT update the keys within other miners' `DecryptedPieces` dictionaries that reference the old public key.

**Location 3 - Secret Piece Storage:** [3](#0-2) 

When miners submit `UpdateValueInput` with `DecryptedPieces`, the `PerformSecretSharing` function stores the decrypted pieces using the submitting miner's public key as the dictionary key in other miners' records.

**Location 4 - The Call Site:** [4](#0-3) 

`RevealSharedInValues` is invoked during NextRound block generation, making it a critical path for consensus progression.

**Root Cause:** The mismatch between updated `RealTimeMinersInformation` keys and stale `DecryptedPieces` keys creates an inconsistent state where historical references point to non-existent miners.

### Impact Explanation

**Operational Impact - Consensus Halt (Critical):**
- When any miner attempts to generate a NextRound block after a candidate replacement, `RevealSharedInValues` throws an unhandled exception
- ALL miners experience the same failure when trying to transition rounds
- Consensus completely halts - no new rounds can be initiated
- The blockchain stops producing blocks until manual intervention (contract upgrade or configuration change)

**Who is Affected:**
- The entire blockchain network
- All users and applications depending on the chain
- All ongoing transactions and smart contract operations

**Severity Justification:**
This is a HIGH severity issue because:
1. Complete consensus failure (not just degradation)
2. Affects all miners simultaneously 
3. Requires external intervention to recover
4. No automatic recovery mechanism exists
5. Impacts core consensus protocol availability

### Likelihood Explanation

**Preconditions:**
1. Secret sharing must be enabled via configuration [5](#0-4) 

2. At least one miner must have submitted `DecryptedPieces` in a previous round (normal operation when secret sharing is active)

3. A candidate replacement must occur via the legitimate `ReplaceCandidatePubkey` flow [6](#0-5) 

**Attack Complexity:**
- This is NOT a malicious attack vector but a **design flaw** that occurs during legitimate operations
- Candidate replacement is a standard governance operation (e.g., for key rotation due to security concerns)
- The admin of ANY candidate can trigger this by calling `ReplaceCandidatePubkey`
- No special privileges beyond being a candidate admin are required

**Feasibility:**
- Highly feasible as it relies on normal protocol operations
- Secret sharing is a documented feature intended for production use
- Candidate replacement is an expected governance action
- The issue occurs deterministically once preconditions are met

**Detection/Constraints:**
- The failure is immediate and obvious (consensus halt)
- However, root cause diagnosis may be difficult without code inspection
- No existing validation prevents this scenario

**Probability Assessment:** MEDIUM-HIGH
- If secret sharing is enabled (intended feature), likelihood is HIGH when any candidate replacement occurs
- Even if replacements are rare, the impact is catastrophic when it happens

### Recommendation

**Primary Fix - Update DecryptedPieces Keys During Replacement:**

Modify `RecordCandidateReplacement` to iterate through all miners' `DecryptedPieces` dictionaries and update any keys matching the old public key:

```csharp
public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
{
    Assert(Context.Sender == State.ElectionContract.Value,
        "Only Election Contract can record candidate replacement information.");

    if (!TryToGetCurrentRoundInformation(out var currentRound) ||
        !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

    var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
    realTimeMinerInformation.Pubkey = input.NewPubkey;
    currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
    currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
    
    // NEW: Update DecryptedPieces keys in all miners
    foreach (var minerInfo in currentRound.RealTimeMinersInformation.Values)
    {
        if (minerInfo.DecryptedPieces.ContainsKey(input.OldPubkey))
        {
            var decryptedValue = minerInfo.DecryptedPieces[input.OldPubkey];
            minerInfo.DecryptedPieces.Remove(input.OldPubkey);
            minerInfo.DecryptedPieces.Add(input.NewPubkey, decryptedValue);
        }
    }
    
    if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
        currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
    State.Rounds[State.CurrentRoundNumber.Value] = currentRound;
    
    // ... rest of function
}
```

**Alternative Fix - Defensive Lookup in RevealSharedInValues:**

Modify the problematic code to use `FirstOrDefault()` and skip miners that don't exist:

```csharp
var orders = new List<int>();
foreach (var decryptedPieceKey in anotherMinerInPreviousRound.DecryptedPieces.Keys)
{
    var miner = previousRound.RealTimeMinersInformation.Values
        .FirstOrDefault(m => m.Pubkey == decryptedPieceKey);
    if (miner != null)
    {
        orders.Add(miner.Order);
    }
    else
    {
        Context.LogDebug(() => $"Skipping non-existent miner {decryptedPieceKey} in DecryptedPieces");
        // Could optionally skip this entire miner if data is incomplete
    }
}
```

**Test Cases to Add:**
1. Test candidate replacement when DecryptedPieces contain references to the replaced miner
2. Verify NextRound transition succeeds after replacement
3. Test multiple replacements in sequence
4. Test replacement during active secret sharing rounds

### Proof of Concept

**Initial State:**
- Secret sharing is enabled: `IsSecretSharingEnabled() == true`
- Round N is in progress with miners: {Alice, Bob, Carol}
- Alice's public key: `"0xAAA..."`

**Step 1: Normal Secret Sharing (Round N)**
1. Alice calls `UpdateValue` with `DecryptedPieces` containing entries for Bob
2. Transaction processed via `ProcessUpdateValue` → `PerformSecretSharing`
3. Stored: `round_N.RealTimeMinersInformation["Bob"].DecryptedPieces["0xAAA..."] = <encrypted_value>`

**Step 2: Candidate Replacement (During Round N)**
1. Alice's admin calls `ReplaceCandidatePubkey(oldPubkey="0xAAA...", newPubkey="0xAAA2...")`
2. Election contract calls consensus contract's `RecordCandidateReplacement`
3. Round N is updated:
   - `RealTimeMinersInformation["0xAAA..."]` removed
   - `RealTimeMinersInformation["0xAAA2..."]` added
   - **Bob's `DecryptedPieces["0xAAA..."]` NOT updated** ← Vulnerability
4. Round N saved to state

**Step 3: Round Transition (N → N+1)**
- Normal round progression occurs
- Round N becomes `previousRound` for the next transition

**Step 4: NextRound Attempt (N+1 → N+2) - DoS Triggered**
1. Any miner attempts to produce NextRound block
2. `GetConsensusBlockExtraData` called with `AElfConsensusBehaviour.NextRound`
3. `GetConsensusExtraDataForNextRound` invoked
4. Line 189: `RevealSharedInValues(currentRound, pubkey)` called
5. Function retrieves `previousRound` (Round N)
6. Iterates to Bob's information from `previousRound.RealTimeMinersInformation`
7. Bob's `DecryptedPieces` contains key `"0xAAA..."`
8. Line 42: Attempts `previousRound.RealTimeMinersInformation.Values.First(m => m.Pubkey == "0xAAA...")`
9. **No miner with pubkey "0xAAA..." exists** (was replaced with "0xAAA2...")
10. `First()` throws `InvalidOperationException: Sequence contains no matching element`
11. Transaction fails, NextRound block cannot be generated

**Expected Result:** NextRound transition succeeds, consensus continues

**Actual Result:** `InvalidOperationException` thrown, ALL NextRound attempts fail, consensus halted

**Success Condition for Exploit:** After candidate replacement with active secret sharing, any NextRound transition fails indefinitely until manual intervention.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L40-44)
```csharp
            var orders = anotherMinerInPreviousRound.DecryptedPieces.Select((t, i) =>
                    previousRound.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L136-146)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L291-293)
```csharp
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-184)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);
```
