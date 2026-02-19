### Title
Miner Can Manipulate Next-Round Position by Setting Arbitrary SupposedOrderOfNextRound Without Block Production

### Summary
A miner can set an arbitrary non-zero `SupposedOrderOfNextRound` value in their `UpdateValue` transaction to falsely gain "mined" status and favorable next-round ordering without actually producing blocks. This bypasses the intended signature-based calculation and exploits both missing input validation and a critical bug in post-execution validation that compares the same object with itself.

### Finding Description

**Core Vulnerability Locations:**

The `GetMinedMiners()` function relies solely on `SupposedOrderOfNextRound != 0` to determine which miners successfully mined: [1](#0-0) 

Miners classified as "mined" receive preferential treatment in next-round generation—they keep their calculated `FinalOrderOfNextRound` positions: [2](#0-1) 

While miners who didn't mine are assigned leftover orders and incur a `MissedTimeSlots` penalty: [3](#0-2) 

**Root Cause:**

In `ProcessUpdateValue`, the `SupposedOrderOfNextRound` from the transaction input is assigned directly to state without any validation: [4](#0-3) 

The intended calculation derives this value from the signature hash modulo miner count: [5](#0-4) 

**Why Protections Fail:**

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue` fields—it never checks `SupposedOrderOfNextRound`: [6](#0-5) 

The post-execution validation `ValidateConsensusAfterExecution` contains a critical bug. It calls `RecoverFromUpdateValue` which modifies the current round object in-place and returns it: [7](#0-6) 

Then assigns this same object to `headerInformation.Round`, making the subsequent hash comparison compare the same object with itself (always passes): [8](#0-7) 

The `RecoverFromUpdateValue` method confirms it returns `this` after in-place modification: [9](#0-8) 

### Impact Explanation

**Consensus Integrity Violation:**
- Miners can falsely claim "mined" status without producing blocks, violating the fundamental consensus assumption that block production determines miner standing
- Attackers gain favorable next-round positions (earlier time slots) without earning them through actual block production
- Legitimate miners who properly produced blocks lose their earned advantages

**Reward Misallocation:**
- Miners avoid `MissedTimeSlots` increments that trigger evil miner detection: [10](#0-9) 

- This allows persistent underperformers to avoid penalties and continue receiving rewards
- Mining reward distribution becomes unfair as non-productive miners maintain equal standing

**Operational Degradation:**
- Over time, the miner set can become dominated by non-productive nodes
- Network block production reliability decreases
- Affects all network participants through slower block times and degraded service quality

**Severity:** HIGH - Direct compromise of consensus mechanism integrity with protocol-wide impact.

### Likelihood Explanation

**Attacker Capabilities:**
- Any active miner in the current round can execute this attack
- Requires no special privileges beyond normal miner status
- Miner controls their own block production and can craft malicious transactions

**Attack Complexity:**
The attack is straightforward:
1. Miner generates proper consensus header with correct `SupposedOrderOfNextRound` calculation via `GetConsensusExtraData`
2. Instead of using `GenerateConsensusTransactions` to create the legitimate transaction: [11](#0-10) 

3. Miner crafts a custom `UpdateValue` transaction with manipulated `SupposedOrderOfNextRound` (e.g., setting to `1` for first position)
4. Includes this malicious transaction in their block alongside the proper header
5. Both validation stages fail to detect the discrepancy

**Feasibility:** 
- No economic barriers (normal mining costs apply)
- No detection mechanism exists due to validation bug
- Can be repeated every round the attacker mines
- Works on both mainchain and sidechains

**Probability:** HIGH - The attack is trivial for any miner to execute with guaranteed success.

### Recommendation

**Immediate Mitigations:**

1. **Add validation in ProcessUpdateValue** to verify `SupposedOrderOfNextRound` matches the calculated value:
```csharp
// In ProcessUpdateValue, after line 244:
var expectedOrder = GetAbsModulus(minerInRound.Signature.ToInt64(), currentRound.RealTimeMinersInformation.Count) + 1;
Assert(updateValueInput.SupposedOrderOfNextRound == expectedOrder, 
    $"Invalid SupposedOrderOfNextRound: expected {expectedOrder}, got {updateValueInput.SupposedOrderOfNextRound}");
```

2. **Fix ValidateConsensusAfterExecution** to properly compare state against header:
```csharp
// Store state hash BEFORE recovery
var stateRoundHash = currentRound.GetHash(isContainPreviousInValue);
// Perform recovery on a CLONE
var recoveredRound = currentRound.Clone();
recoveredRound.RecoverFromUpdateValue(headerInformation.Round, headerInformation.SenderPubkey.ToHex());
// Compare original state with recovered version
if (recoveredRound.GetHash(isContainPreviousInValue) != stateRoundHash)
```

3. **Add validation provider** for `SupposedOrderOfNextRound` calculation in `UpdateValueValidationProvider`

**Test Cases:**
- Miner attempts UpdateValue with `SupposedOrderOfNextRound = 1` when signature hash dictates `5`
- Verify transaction rejection with clear error message
- Verify legitimate miners with correct values still succeed
- Test edge cases: single miner, miner count changes during round

### Proof of Concept

**Initial State:**
- Round N with 5 active miners
- Attacker miner has Order 5 (last position) in current round
- Attacker's signature hash `H` yields calculated `SupposedOrderOfNextRound = 4` (via `H % 5 + 1`)

**Attack Steps:**

1. **Block Production Phase:**
   - Attacker calls `GetConsensusExtraData` which correctly calculates and includes `SupposedOrderOfNextRound = 4` in header via `ApplyNormalConsensusData`
   
2. **Transaction Manipulation:**
   - Attacker crafts malicious `UpdateValueInput` with:
     - Correct `OutValue`, `Signature`, `PreviousInValue` (to pass existing validations)
     - Manipulated `SupposedOrderOfNextRound = 1` (to claim first position)
   
3. **Block Inclusion:**
   - Attacker includes malicious transaction in their block
   - Block contains proper header (SupposedOrder=4) but malicious transaction (SupposedOrder=1)

4. **Validation Bypass:**
   - `ValidateBeforeExecution` checks header fields only, doesn't validate transaction input → PASSES
   - Transaction executes, setting state `SupposedOrderOfNextRound = 1` 
   - `ValidateAfterExecution` compares same object with itself due to bug → PASSES

**Expected Result:** Transaction should be rejected for SupposedOrderOfNextRound mismatch

**Actual Result:** 
- Transaction succeeds
- State incorrectly records `SupposedOrderOfNextRound = 1` for attacker
- In `GenerateNextRoundInformation`, attacker appears in `GetMinedMiners()` with `FinalOrderOfNextRound = 1`
- Next round assigns attacker Order 1 (first position) instead of earned Order 4
- Attacker avoids `MissedTimeSlots` increment despite not mining properly

**Success Condition:** Attacker obtains Order 1 in Round N+1 despite signature hash dictating Order 4, without detection or penalty.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-37)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L42-56)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-42)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-92)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-101)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L144-146)
```csharp
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
                    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-32)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
```
