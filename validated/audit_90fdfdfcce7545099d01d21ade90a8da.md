# Audit Report

## Title
Miner List Manipulation Bypasses Solitary Miner Detection via Unvalidated Round Transitions

## Summary
The AEDPoS consensus contract fails to validate that the miner list in `NextRound` and `NextTerm` transactions matches the expected miner set. A malicious miner can submit a round with a reduced miner list (≤2 miners) to permanently bypass the solitary miner detection mechanism, enabling indefinite solo mining and consensus centralization.

## Finding Description

The `SolitaryMinerDetection` mechanism is designed to prevent a single miner from producing blocks alone for extended periods. It checks if more than 2 miners are configured in the current round [1](#0-0)  and monitors whether only one miner has been producing blocks for 2 consecutive rounds.

However, the validation pipeline for `NextRound` transitions has a critical gap. When `ValidateBeforeExecution` processes a `NextRound` behavior, it only adds two specific validators [2](#0-1) :

**RoundTerminateValidationProvider** validates only that the round number increments by 1 and that all InValue fields are null [3](#0-2) , but does NOT validate the miner count or list membership.

**NextRoundMiningOrderValidationProvider** only checks internal consistency within the provided round - that miners with `FinalOrderOfNextRound > 0` equals miners with `OutValue != null` [4](#0-3) . It does NOT compare against the baseline miner list from the current round.

**ProcessNextRound** directly converts the provided `NextRoundInput` to a `Round` object and stores it [5](#0-4)  via `AddRoundInformation` [6](#0-5)  without validating that the miner list matches the current round's miners. The `AddRoundInformation` method simply stores the round to state [7](#0-6) .

In contrast, legitimate round generation includes all miners from the current round by processing both miners who mined and miners who didn't mine [8](#0-7) , maintaining the complete miner set.

**Attack Execution:**
1. Attacker is a legitimate miner in the current round (verified by `MiningPermissionValidationProvider` checking the base round [9](#0-8) )
2. Crafts a malicious `NextRoundInput` with only 1-2 miner entries (including themselves)
3. Ensures internal consistency so `NextRoundMiningOrderValidationProvider` passes
4. Ensures all `InValue` fields are null and round number increments so `RoundTerminateValidationProvider` passes
5. Submits the `NextRound` transaction during their mining slot
6. Validation passes because no validator compares the miner list against the expected set
7. Malicious round is stored in `State.Rounds[round.RoundNumber]`
8. Future `SolitaryMinerDetection` checks read `currentRound.RealTimeMinersInformation.Count` from state and find Count ≤ 2, causing the check on line 70 to fail and disabling the protection
9. Attacker can mine alone indefinitely without triggering detection

The same vulnerability applies to `NextTerm` transitions, which use the same validation approach [10](#0-9)  and directly store the provided miner list [11](#0-10) .

## Impact Explanation

**Critical Consensus Integrity Compromise:**

1. **Solitary Mining Protection Bypass**: The fundamental security mechanism that prevents single-party control is permanently disabled by manipulating the stored round state that `SolitaryMinerDetection` reads from.

2. **Consensus Centralization**: Once the malicious round is accepted, the attacker effectively controls the blockchain through solo mining without triggering any protection mechanisms.

3. **Honest Miner Exclusion**: All other miners are removed from the consensus set via the manipulated `RealTimeMinersInformation` dictionary and cannot produce blocks or earn rewards.

4. **Network-Wide Impact**: All nodes validate using the same flawed logic and accept the manipulated round, making the attack persistent across the entire network.

5. **Permanent State Corruption**: Future rounds build upon the corrupted state since `GenerateNextRoundInformation` would use the corrupted current round as its basis if elections don't provide new miners [12](#0-11) .

This breaks the core security guarantee of decentralized consensus and degrades the network to single-party control.

## Likelihood Explanation

**High Feasibility:**

1. **Attacker Prerequisites**: Only requires being a legitimate miner in the current consensus set, which is achievable through normal election/staking mechanisms.

2. **No Special Timing**: The attack succeeds whenever the attacker produces blocks, which happens naturally through round rotation.

3. **Deterministic Success**: The validation logic deterministically accepts malicious input that passes the minimal checks implemented in the two validators.

4. **Low Complexity**: No cryptographic breaking, race conditions, or complex state manipulation required. Simply craft and submit a properly-formatted but malicious round with reduced miner list.

5. **Minimal Cost**: Only requires standard transaction fees.

6. **No Detection**: The manipulation occurs silently through valid consensus transactions via the public `NextRound` method [13](#0-12) , making it difficult to detect before the damage is done.

## Recommendation

Add a validator to check that the miner list in `NextRoundInput` matches the expected miner set from the current round. Specifically:

1. Create a new `MinerListConsistencyValidationProvider` that:
   - Extracts the miner list (public keys) from the base round (current round)
   - Compares it against the miner list in the provided round
   - Returns validation failure if they don't match exactly

2. Add this validator to the validation pipeline for `NextRound` behavior in `ValidateBeforeExecution`:

```csharp
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new MinerListConsistencyValidationProvider());
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
```

3. For `NextTerm`, the miner list can legitimately change due to elections, so validation should:
   - If elections produced new miners (via `TryToGetVictories`), validate against election results
   - Otherwise, validate against current round's miners

4. Consider adding an assertion in `ProcessNextRound` as a defense-in-depth measure to check miner count hasn't decreased unexpectedly.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Initialize a round with N miners (e.g., 5 miners)
2. Have one malicious miner craft a `NextRoundInput` with only 2 miners (including themselves)
3. Call `NextRound` with this malicious input during the malicious miner's time slot
4. Verify that validation passes and the round is stored
5. Verify that `SolitaryMinerDetection` now reads Count = 2 and the protection is bypassed
6. Verify that the malicious miner can continue mining alone without triggering detection

The test would demonstrate that the current validation logic accepts a round with an arbitrary reduced miner list, confirming the vulnerability.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L70-70)
```csharp
        if (currentRound.RoundNumber > 3 && currentRound.RealTimeMinersInformation.Count > 2)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-90)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L29-34)
```csharp
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L110-110)
```csharp
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-190)
```csharp
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L105-105)
```csharp
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L16-56)
```csharp
        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-17)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L236-241)
```csharp
            // Miners of new round are same with current round.
            var miners = new MinerList();
            miners.Pubkeys.AddRange(
                currentRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
            newRound = miners.GenerateFirstRoundOfNewTerm(currentRound.GetMiningInterval(),
                Context.CurrentBlockTime, currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-165)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
```
