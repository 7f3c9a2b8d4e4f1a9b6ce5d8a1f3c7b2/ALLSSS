### Title
Secret Sharing Revealed In Values Lost Due to Missing State Persistence in NextRound Flow

### Summary
The `RevealSharedInValues` function computes revealed in values from secret shares to recover previous in values of miners who failed to mine. However, these revealed values are computed on a local copy of `currentRound` that is never persisted to contract state. When `SupplyCurrentRoundInformation` later attempts to read these revealed values from state during NextRound execution, they are absent, causing the secret sharing recovery mechanism to fail completely.

### Finding Description

**Root Cause:**
The `RevealSharedInValues` function modifies `currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue` to store revealed in values computed from secret shares. [1](#0-0) 

However, this function is called in `GetConsensusExtraDataForNextRound` where:
1. `currentRound` is obtained from state as a copy (protobuf objects are passed by value) [2](#0-1) 

2. `GenerateNextRoundInformation` creates `nextRound` from `currentRound` BEFORE `RevealSharedInValues` is called [3](#0-2) 

3. `RevealSharedInValues` is called to modify `currentRound` [4](#0-3) 

4. The function returns `nextRound` (which doesn't contain the revealed values), and the modified `currentRound` is discarded [5](#0-4) 

5. There is no call to `TryToUpdateRoundInformation(currentRound)` to persist the modified currentRound to state

**Why Protections Fail:**
When NextRound transaction executes, `SupplyCurrentRoundInformation` attempts to recover in values for miners who didn't mine. It tries to read `currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue` expecting the revealed values computed by secret sharing. [6](#0-5) 

Since these values were never persisted, they are null, forcing the system to fall back to using the previous round's InValue or generating fake values. [7](#0-6) 

**Note:** The `GenerateNextRoundInformation` function only copies basic fields (Pubkey, Order, ExpectedMiningTime, ProducedBlocks, MissedTimeSlots) and does not copy PreviousInValue, so even if the order of operations were reversed, the revealed values would not be included in nextRound. [8](#0-7) 

### Impact Explanation

**Consensus Integrity Violation:**
The secret sharing mechanism is a critical security feature designed to prevent miners from withholding their in values (which would break the random beacon). When miners fail to reveal their in values, other miners can use secret sharing to reconstruct those values from encrypted pieces. This ensures consensus continues even with malicious or offline miners.

**Concrete Harm:**
- **Secret Sharing Failure**: Revealed in values computed at significant computational cost are permanently lost
- **Fallback to Weak Values**: System must use previous round's InValue (if available) or generate fake deterministic values based on miner pubkey [9](#0-8) 
- **Random Beacon Compromise**: The fake values are deterministic and predictable, undermining the random beacon's security properties
- **Consensus Degradation**: The system operates in a degraded state where secret sharing appears enabled but is non-functional

**Severity Justification:**
High severity because it completely negates a critical security mechanism (secret sharing) that's meant to protect against malicious miner behavior. This allows malicious miners to successfully withhold in values without consequence, as the recovery mechanism silently fails and generates predictable values instead.

### Likelihood Explanation

**Attack Complexity:**
This is not an attack - it's a logic bug that occurs automatically during normal operation. No attacker action is required.

**Triggering Conditions:**
- Secret sharing must be enabled [10](#0-9) 
- NextRound behavior must be triggered (happens regularly at round transitions)
- The extra block producer calls `GetConsensusExtraDataForNextRound` [11](#0-10) 

**Frequency:**
Occurs every time NextRound is triggered when secret sharing is enabled, which is a regular consensus operation. High frequency.

**Detection:**
The issue is silent - no errors are thrown. The system appears to function normally but secret sharing recovery silently fails. The comment at line 189 of AEDPoSContract.cs explicitly states the code expects "previous in value recovered by other miners" to be present, but it never is. [12](#0-11) 

**Probability:**
Guaranteed to occur every NextRound when secret sharing is enabled. Likelihood: High.

### Recommendation

**Option 1 (Preferred): Persist currentRound after revealing**
After calling `RevealSharedInValues`, save the modified currentRound to state before returning:

```csharp
RevealSharedInValues(currentRound, pubkey);
TryToUpdateRoundInformation(currentRound); // Add this line
```

Location: [4](#0-3) 

**Option 2: Transfer revealed values to nextRound**
After calling `RevealSharedInValues`, copy the revealed PreviousInValue fields from currentRound to the corresponding miners in nextRound before returning.

**Option 3: Move reveal logic**
Move the `RevealSharedInValues` logic into `SupplyCurrentRoundInformation` where currentRound is already being updated and saved to state. [13](#0-12) 

**Invariant Check:**
Add assertion in `SupplyCurrentRoundInformation` to verify that when secret sharing is enabled and sufficient pieces exist, PreviousInValue should be non-null before falling back to previous round's InValue.

**Test Cases:**
1. Enable secret sharing
2. Have a miner miss their time slot with sufficient encrypted/decrypted pieces from other miners
3. Trigger NextRound
4. Verify the revealed PreviousInValue is present in current round state and used by SupplyCurrentRoundInformation
5. Verify fake values are NOT generated when reveals should be available

### Proof of Concept

**Initial State:**
1. Secret sharing is enabled in configuration
2. Round N has 5 miners: A, B, C, D, E
3. Miner C fails to produce a block and doesn't reveal their in value
4. Miners A, B, D, E all provide encrypted pieces for C during round N
5. In round N+1, miners decrypt each other's pieces, achieving >= 2/3 threshold

**Exploitation Sequence:**
1. Miner E (extra block producer) triggers NextRound behavior at end of round N+1
2. `GetConsensusExtraDataForNextRound` is called [11](#0-10) 
3. `GenerateNextRoundInformation` creates round N+2 from current round N+1 [3](#0-2) 
4. `RevealSharedInValues` computes C's revealed in value from secret shares and stores it in `currentRound.RealTimeMinersInformation[C].PreviousInValue` [14](#0-13) 
5. Function returns round N+2 without saving the modified round N+1 [5](#0-4) 
6. NextRound transaction executes, calling `SupplyCurrentRoundInformation` [15](#0-14) 
7. Code attempts to read revealed value: `previousInValue = currentRound.RealTimeMinersInformation[C].PreviousInValue` [6](#0-5) 
8. Value is null because it was never saved to state
9. System falls back to using fake value: `HashHelper.ComputeFrom(miner)` [16](#0-15) 

**Expected Result:**
C's revealed in value (computed from secret shares) should be used as their InValue for round N+2.

**Actual Result:**
C's revealed in value is lost. A fake deterministic value based on C's pubkey is used instead, undermining the random beacon security.

**Success Condition:**
After step 5, inspect `State.Rounds[N+1].RealTimeMinersInformation[C].PreviousInValue` - it should contain the revealed value but is actually null/empty, proving the reveals are lost.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-52)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L48-54)
```csharp
    private bool TryToGetCurrentRoundInformation(out Round round)
    {
        round = null;
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        round = State.Rounds[roundNumber];
        return !round.IsEmpty;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-174)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L176-176)
```csharp
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L198-203)
```csharp
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L163-163)
```csharp
        SupplyCurrentRoundInformation();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L171-221)
```csharp
    private void SupplyCurrentRoundInformation()
    {
        var currentRound = GetCurrentRoundInformation(new Empty());
        Context.LogDebug(() => $"Before supply:\n{currentRound.ToString(Context.RecoverPublicKey().ToHex())}");
        var notMinedMiners = currentRound.RealTimeMinersInformation.Values.Where(m => m.OutValue == null).ToList();
        if (!notMinedMiners.Any()) return;
        TryToGetPreviousRoundInformation(out var previousRound);
        foreach (var miner in notMinedMiners)
        {
            Context.LogDebug(() => $"Miner pubkey {miner.Pubkey}");

            Hash previousInValue = null;
            Hash signature = null;

            // Normal situation: previous round information exists and contains this miner.
            if (previousRound != null && previousRound.RealTimeMinersInformation.ContainsKey(miner.Pubkey))
            {
                // Check this miner's:
                // 1. PreviousInValue in current round; (means previous in value recovered by other miners)
                // 2. InValue in previous round; (means this miner hasn't produce blocks for a while)
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
                }
            }

            if (previousInValue == null)
            {
                // Handle abnormal situation.

                // The fake in value shall only use once during one term.
                previousInValue = HashHelper.ComputeFrom(miner);
                signature = previousInValue;
            }

            // Fill this two fields at last.
            miner.InValue = previousInValue;
            miner.Signature = signature;

            currentRound.RealTimeMinersInformation[miner.Pubkey] = miner;
        }

        TryToUpdateRoundInformation(currentRound);
        Context.LogDebug(() => $"After supply:\n{currentRound.ToString(Context.RecoverPublicKey().ToHex())}");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-55)
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
```
