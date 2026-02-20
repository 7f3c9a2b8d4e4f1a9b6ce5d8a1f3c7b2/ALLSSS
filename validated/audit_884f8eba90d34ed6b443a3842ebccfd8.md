# Audit Report

## Title
Missing Validation of ExtraBlockProducerOfPreviousRound Allows Manipulation of Block Producer Privileges

## Summary
The AEDPoS consensus contract fails to validate the `ExtraBlockProducerOfPreviousRound` field during round transitions, allowing any miner to arbitrarily set this value when calling the `NextRound` method. This manipulated field is then used to grant unauthorized mining privileges before the round start time and additional tiny block production quota, directly compromising consensus fairness and reward distribution.

## Finding Description

The vulnerability exists in the round transition validation logic where the `ExtraBlockProducerOfPreviousRound` field is not validated against the actual sender or previous round state.

When a miner calls the public `NextRound` method, they provide a `NextRoundInput` structure containing the `ExtraBlockProducerOfPreviousRound` field. The validation performed by `ValidationForNextRound()` only checks that the round number increments correctly and that InValues are null: [1](#0-0) 

The system converts the NextRoundInput to a Round object via `ToRound()`, which directly copies the unvalidated `ExtraBlockProducerOfPreviousRound` field without any verification: [2](#0-1) 

This unvalidated field is then stored in state and subsequently used to grant special privileges:

**1. Mining permission before round start**: The `IsCurrentMiner()` function allows the `ExtraBlockProducerOfPreviousRound` to mine before the round officially begins: [3](#0-2) 

**2. Additional tiny block quota**: The consensus behavior provider grants extra tiny blocks beyond normal limits to the `ExtraBlockProducerOfPreviousRound`: [4](#0-3) 

The legitimate setting of this field occurs in `GetConsensusExtraDataForNextRound` where it should be set to the actual miner terminating the round: [5](#0-4) 

However, the transaction processing flow directly uses the user-provided input without validating it matches this legitimate value: [6](#0-5) 

The only access control is a basic check that the sender is in the miner list, which does not validate the `ExtraBlockProducerOfPreviousRound` field: [7](#0-6) 

## Impact Explanation

**Consensus Integrity Violation**: An attacker can manipulate which miner receives privileged block production rights, breaking the fundamental fairness of the AEDPoS consensus mechanism.

1. **Unauthorized Mining Windows**: By setting the field to their own or another miner's pubkey, they grant that miner permission to mine during the pre-round period before `GetRoundStartTime()`, a time slot that should be reserved only for the legitimate extra block producer.

2. **Additional Block Production Quota**: The designated miner receives `_maximumBlocksCount + blocksBeforeCurrentRound` tiny blocks instead of the normal `_maximumBlocksCount` limit, as shown in the consensus behavior logic where the extra block producer check grants additional production capacity.

3. **Reward Misallocation**: More blocks produced means more mining rewards. Mining rewards are distributed based on blocks produced, so this directly impacts the economics and fairness of reward distribution, giving unfair advantage to the manipulated beneficiary.

4. **Chain-wide Impact**: This affects all participants in the network as it compromises the deterministic and fair nature of block production scheduling that the consensus mechanism is designed to guarantee.

## Likelihood Explanation

**HIGH Likelihood**:

- **Reachable Entry Point**: The `NextRound` method is a public RPC method callable by any miner in the current round: [8](#0-7) 

- **Minimal Attacker Capabilities**: The attacker only needs to be a valid miner in the current round to execute this exploit. The access control only verifies the sender is in the miner list, not that they are setting legitimate values.

- **Trivial Execution**: The attack requires only constructing a `NextRoundInput` with an arbitrary `ExtraBlockProducerOfPreviousRound` value and calling the public `NextRound` method.

- **No Validation Barrier**: Search of the codebase confirms no validation code exists to check this field against the sender or previous round state.

- **Immediate Benefit**: The attacker gains extra mining privileges in the very next round, providing immediate economic incentive through increased block production and mining rewards.

## Recommendation

Add validation in `ValidationForNextRound()` to verify that `ExtraBlockProducerOfPreviousRound` matches the actual sender of the NextRound transaction:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Existing checks
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null))
        return new ValidationResult { Message = "Incorrect next round information." };
    
    // NEW: Validate ExtraBlockProducerOfPreviousRound matches the sender
    if (!string.IsNullOrEmpty(extraData.Round.ExtraBlockProducerOfPreviousRound) &&
        extraData.Round.ExtraBlockProducerOfPreviousRound != validationContext.SenderPubkey)
        return new ValidationResult { Message = "ExtraBlockProducerOfPreviousRound must match the sender's pubkey." };
    
    return new ValidationResult { Success = true };
}
```

Alternatively, instead of accepting the value from user input, always set it programmatically in `ProcessNextRound()` based on the actual sender, overriding any user-provided value.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task ExtraBlockProducerOfPreviousRound_CanBeManipulated()
{
    // Setup: Initialize consensus with multiple miners
    var initialMiners = new[] { "miner1", "miner2", "miner3" };
    
    // Miner1 calls NextRound and manipulates ExtraBlockProducerOfPreviousRound
    var maliciousNextRoundInput = new NextRoundInput
    {
        RoundNumber = 2,
        ExtraBlockProducerOfPreviousRound = "miner2", // Miner1 sets it to miner2
        // ... other required fields
    };
    
    // Call NextRound from miner1's account
    await AEDPoSContract.NextRound(maliciousNextRoundInput);
    
    // Verify: The manipulated value was accepted
    var currentRound = await AEDPoSContract.GetCurrentRoundInformation(new Empty());
    Assert.Equal("miner2", currentRound.ExtraBlockProducerOfPreviousRound);
    
    // Impact: Miner2 now has unauthorized privileges:
    // 1. Can mine before round start time
    // 2. Has additional tiny block quota
    var isCurrentMiner = await AEDPoSContract.IsCurrentMiner(AddressOfMiner2);
    Assert.True(isCurrentMiner.Value); // Miner2 can mine in privileged time slot
}
```

## Notes

The vulnerability stems from trusting user-provided consensus data without validation. While the system validates many aspects of round transitions (round number, InValues), it fails to validate that the miner terminating the round is correctly identified as the `ExtraBlockProducerOfPreviousRound`. This allows any miner producing a NextRound block to arbitrarily designate which miner receives special privileges, undermining the consensus protocol's fairness guarantees.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L150-155)
```csharp
        if (Context.CurrentBlockTime <= currentRound.GetRoundStartTime() &&
            currentRound.ExtraBlockProducerOfPreviousRound == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]PREVIOUS");
            return true;
        }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-179)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
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

**File:** protobuf/aedpos_contract.proto (L33-35)
```text
    // Update consensus information, create a new round.
    rpc NextRound (NextRoundInput) returns (google.protobuf.Empty) {
    }
```
