# Audit Report

## Title
Manipulation of IsMinerListJustChanged Flag Allows Unauthorized Extra Block Production After Miner List Changes

## Summary
A malicious block producer can manipulate the `IsMinerListJustChanged` flag to `false` in `NextRoundInput` during miner replacements, bypassing consensus rules that restrict extra block production rights when the miner list changes. This allows the previous round's extra block producer to continue producing tiny blocks and earning additional mining rewards unfairly.

## Finding Description

The AEDPoS consensus mechanism uses the `IsMinerListJustChanged` flag to control whether the extra block producer from the previous round can continue producing tiny blocks in the current round. When miner replacements occur, this flag should be set to `true` to prevent the extra block producer from retaining their privileges.

**Vulnerability Location:**

The consensus behavior determination logic checks this flag to control tiny block production: [1](#0-0) 

When miner replacement occurs, the system correctly sets `isMinerListChanged = true`: [2](#0-1) 

This flag is transferred through `NextRoundInput`: [3](#0-2) [4](#0-3) 

**The Attack Vector:**

A malicious block producer can modify their node software to manipulate the `IsMinerListJustChanged` flag in the `NextRoundInput` before submitting the `NextRound` transaction. When `ProcessNextRound` executes, it directly converts and stores the input without validation: [5](#0-4) [6](#0-5) 

**Why Validations Fail:**

1. **Pre-execution validation** only checks round number increment and that InValues are null, but does not verify the flag's correctness: [7](#0-6) 

2. **Post-execution validation** uses the manipulated flag from the stored state to calculate hashes, causing both the header and state hashes to match despite the manipulation: [8](#0-7) 

The validation compares hashes calculated using the same manipulated flag value, so the comparison passes even though the flag is incorrect.

## Impact Explanation

**Direct Financial Impact:**
The exploiting miner can produce additional tiny blocks beyond their legitimate allocation. Each extra block earns mining rewards calculated by `GetMiningRewardPerBlock()`: [9](#0-8) 

**Unfair Advantage:**
The extra block producer from the previous round gains block production capacity of `_maximumBlocksCount + blocksBeforeCurrentRound` instead of their normal allocation, as shown in the behavior determination logic.

**Consensus Integrity Violation:**
This breaks the fundamental consensus rule that extra block production rights should not carry over when the miner list changes. The flag is also used to control secret sharing: [10](#0-9) 

**Affected Parties:**
- Honest miners who lose their proportional share of block production and rewards
- The network's consensus fairness guarantees
- Token holders whose mining rewards are unfairly distributed

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be a miner in the consensus set (achievable through normal election process)
- Must be the block producer who terminates a round when miner replacement occurs
- This opportunity rotates regularly among all miners

**Attack Complexity:**
- **LOW** - Requires only modifying node software to change one boolean flag value in the `NextRoundInput` before transaction submission
- No cryptographic operations or complex multi-step processes required
- The block producer controls the generation of their own consensus transactions

**Feasibility:**
- Miner replacements occur regularly when evil miners (those who miss time slots) are detected
- Any miner can become the terminating block producer through normal rotation
- The attack is difficult to detect because the manipulated flag becomes legitimate on-chain state

**Probability:**
HIGH - The combination of regular occurrence, low complexity, direct financial benefit, and lack of detection makes this highly likely to be exploited.

## Recommendation

Add validation in `ProcessNextRound` or the validation providers to verify that `IsMinerListJustChanged` is set correctly based on actual miner list changes:

1. **Option 1 - Validation Provider:** Create a new validation provider that checks if miner replacements occurred and verifies the flag matches:
   - Query the Election contract for miner replacement information
   - Compare the previous round's miner list with the current round's miner list
   - Ensure `IsMinerListJustChanged` is `true` if and only if the miner lists differ

2. **Option 2 - ProcessNextRound Check:** In `ProcessNextRound`, independently calculate whether the miner list changed by comparing miner public keys, and assert that the input's flag matches this calculation.

3. **Option 3 - After-Execution Fix:** In `ValidateConsensusAfterExecution`, independently calculate whether miner replacement occurred rather than trusting the stored flag value for hash comparison.

The recommended approach is Option 1, as it prevents the invalid state from being stored in the first place.

## Proof of Concept

```csharp
// Test case demonstrating the vulnerability
[Fact]
public async Task MinerCanManipulateIsMinerListJustChangedFlag()
{
    // Setup: Initialize consensus with miners and trigger miner replacement
    var currentRound = await GetCurrentRoundInformation();
    var evilMinerPubkey = "evil_miner_pubkey";
    var replacementPubkey = "replacement_pubkey";
    
    // Miner replacement occurs (evil miner detected)
    // GenerateNextRoundInformation would set isMinerListChanged = true
    var legitimateNextRound = GenerateNextRoundWithReplacement(
        currentRound, evilMinerPubkey, replacementPubkey);
    Assert.True(legitimateNextRound.IsMinerListJustChanged);
    
    // ATTACK: Malicious block producer manipulates the flag
    var maliciousNextRoundInput = NextRoundInput.Create(legitimateNextRound, randomNumber);
    maliciousNextRoundInput.IsMinerListJustChanged = false; // Manipulation
    
    // Submit the manipulated transaction
    await ConsensusContract.NextRound(maliciousNextRoundInput);
    
    // Verify: The manipulated flag is stored on-chain
    var storedRound = await GetCurrentRoundInformation();
    Assert.False(storedRound.IsMinerListJustChanged); // Flag was manipulated
    Assert.True(storedRound.RealTimeMinersInformation.ContainsKey(replacementPubkey)); // But replacement occurred
    
    // EXPLOITATION: Extra block producer can now produce additional tiny blocks
    var previousExtraBlockProducer = currentRound.ExtraBlockProducerOfPreviousRound;
    var behavior = GetConsensusBehaviour(previousExtraBlockProducer);
    Assert.Equal(AElfConsensusBehaviour.TinyBlock, behavior); // Should be Nothing, but is TinyBlock
    
    // This allows unfair additional block production and mining rewards
}
```

**Notes:**
- The vulnerability exploits the trust placed in the block producer to generate correct consensus data
- No validation ensures the `IsMinerListJustChanged` flag accurately reflects actual miner list changes
- The after-execution validation uses the manipulated state value, creating a circular validation failure
- This enables the extra block producer to bypass consensus restrictions and earn additional rewards

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L71-79)
```csharp
                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L298-346)
```csharp
        var isMinerListChanged = false;
        if (IsMainChain && previousRound.TermNumber == currentRound.TermNumber) // In same term.
        {
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

            Context.LogDebug(() => $"Got miner replacement information:\n{minerReplacementInformation}");

            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }

                isMinerListChanged = true;
            }
        }

        currentRound.GenerateNextRoundInformation(currentBlockTime, blockchainStartTimestamp, out nextRound,
            isMinerListChanged);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L18-18)
```csharp
            IsMinerListJustChanged = round.IsMinerListJustChanged,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L36-36)
```csharp
            IsMinerListJustChanged = IsMinerListJustChanged,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L99-101)
```csharp
            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L118-120)
```csharp
        var miningRewardPerBlock = GetMiningRewardPerBlock();
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L107-115)
```csharp
        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });
```
