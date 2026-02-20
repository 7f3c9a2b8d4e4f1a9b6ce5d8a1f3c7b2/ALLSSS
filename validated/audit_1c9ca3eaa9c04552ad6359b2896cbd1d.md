# Audit Report

## Title
NOTHING Behavior Bypass Allows Malicious Miners to Skip Critical Consensus Validation

## Summary
The AEDPoS consensus validation system contains a critical vulnerability where the `ValidateBeforeExecution` method's switch statement omits a validation case for NOTHING behavior. A malicious miner can craft blocks with NOTHING behavior to bypass critical behavior-specific validators (`UpdateValueValidationProvider`, `LibInformationValidationProvider`) while passing basic validation checks, enabling consensus state corruption.

## Finding Description

The vulnerability exists in the consensus validation flow where the system validates behavior-specific rules only IF a particular behavior is declared, but never validates whether that behavior declaration itself is correct for the current consensus state.

The `ValidateBeforeExecution` method applies three basic validators to all blocks, then uses a switch statement to conditionally add behavior-specific validators: [1](#0-0) 

This switch statement only has cases for `UpdateValue`, `NextRound`, and `NextTerm`. The `AElfConsensusBehaviour` enum defines five possible values including NOTHING: [2](#0-1) 

NOTHING behavior is intended to signal "do not mine" and is returned as `InvalidConsensusCommand`: [3](#0-2) [4](#0-3) 

However, a malicious miner controlling their node software can ignore this command and craft a block with NOTHING behavior anyway. When validated by other nodes, the attack succeeds because:

**1. Basic Validators Pass**: A legitimate miner in their time slot passes mining permission, time slot, and continuous blocks validation.

**2. Behavior-Specific Validators Bypassed**: Critical validators are never instantiated for NOTHING behavior. The `UpdateValueValidationProvider` ensures OutValue and Signature are properly filled: [5](#0-4) 

The `LibInformationValidationProvider` prevents LIB height regression: [6](#0-5) 

These critical validators are only added for UpdateValue behavior, not for NOTHING.

**3. No State Change**: The `GenerateTransactionListByExtraData` method's default case returns an empty transaction list: [7](#0-6) 

**4. Post-Execution Validation Passes**: Since no transactions execute and state doesn't change, round hash comparison succeeds if the miner copies the current round.

## Impact Explanation

**Consensus Integrity Violation (Critical)**:
- Miners bypass `UpdateValueValidationProvider`, producing blocks without proper OutValue/Signature/PreviousInValue, corrupting the consensus state's cryptographic chain required for secret sharing and randomness generation
- `LibInformationValidationProvider` bypass allows LIB height to stagnate, affecting finality guarantees
- Mining actions not recorded in consensus state corrupts round completion tracking and miner reputation

**Operational Denial-of-Service (High)**:
- When UpdateValue behavior is required but NOTHING is used, consensus data is not updated
- When NextRound/NextTerm should trigger but NOTHING is used, critical transitions are delayed: round progression, term changes, miner rewards distribution, and election updates
- Coordinated exploitation across multiple malicious miners compounds delays, severely degrading consensus liveness

**Systemic Risk (High)**:
- No detection mechanism exists within validation - blocks appear valid
- Requires external monitoring to detect anomalies in consensus behavior sequences
- No automatic recovery mechanism

## Likelihood Explanation

**Attacker Prerequisites (Easily Satisfied)**:
- Must be a legitimate miner in the current round (normal operational state)
- Must mine during assigned time slot (normal operational state)

**Attack Complexity (Trivial)**:
- Single-step: craft block header with NOTHING behavior
- No cryptographic operations or complex state manipulation required
- Miner controls their node software and can craft arbitrary block headers

**Repeatability (High)**:
- Exploitable every time the malicious miner has a time slot
- No cooldown or resource cost beyond forgoing transaction fees
- Coordinatable across multiple colluding miners

**Economic Rationality (Positive)**:
- Cost: Only loses one block's transaction fee revenue
- Benefit: Skip revealing OutValue when convenient, delay unfavorable transitions, cause competitor harm
- Strategic value when approaching term transitions

## Recommendation

Add an explicit validation case for NOTHING behavior that rejects it, or add a pre-validation check that verifies the declared behavior matches the expected behavior from `GetConsensusCommand`:

```csharp
switch (extraData.Behaviour)
{
    case AElfConsensusBehaviour.UpdateValue:
        validationProviders.Add(new UpdateValueValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider());
        break;
    case AElfConsensusBehaviour.NextRound:
        validationProviders.Add(new NextRoundMiningOrderValidationProvider());
        validationProviders.Add(new RoundTerminateValidationProvider());
        break;
    case AElfConsensusBehaviour.NextTerm:
        validationProviders.Add(new RoundTerminateValidationProvider());
        break;
    case AElfConsensusBehaviour.Nothing:
        return new ValidationResult { Success = false, Message = "NOTHING behavior is not allowed in blocks." };
    case AElfConsensusBehaviour.TinyBlock:
        // Already handled by RecoverFromTinyBlock above, basic validators sufficient
        break;
}
```

## Proof of Concept

A malicious miner can craft a block during their legitimate time slot with the following extra data:
```protobuf
AElfConsensusHeaderInformation {
    sender_pubkey: <miner's pubkey>
    behaviour: NOTHING  // Value 3
    round: <copy of current round>
}
```

This block will:
1. Pass `MiningPermissionValidationProvider` (legitimate miner)
2. Pass `TimeSlotValidationProvider` (correct time slot)
3. Pass `ContinuousBlocksValidationProvider` (not exceeded limits)
4. Skip `UpdateValueValidationProvider` (no case for NOTHING)
5. Skip `LibInformationValidationProvider` (no case for NOTHING)
6. Generate empty transaction list (default case)
7. Pass post-execution validation (no state change)

The consensus state will not be updated with the miner's OutValue, Signature, or mining timestamp, corrupting the consensus protocol's cryptographic chain and round progression tracking.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-92)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };

        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** protobuf/aedpos_contract.proto (L321-327)
```text
enum AElfConsensusBehaviour {
    UPDATE_VALUE = 0;
    NEXT_ROUND = 1;
    NEXT_TERM = 2;
    NOTHING = 3;
    TINY_BLOCK = 4;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusCommandProvider.cs (L23-30)
```csharp
        public static ConsensusCommand InvalidConsensusCommand => new()
        {
            ArrangedMiningTime = new Timestamp { Seconds = int.MaxValue },
            Hint = ByteString.CopyFrom(new AElfConsensusHint
            {
                Behaviour = AElfConsensusBehaviour.Nothing
            }.ToByteArray())
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L51-53)
```csharp
        return behaviour == AElfConsensusBehaviour.Nothing
            ? ConsensusCommandProvider.InvalidConsensusCommand
            : GetConsensusCommand(behaviour, currentRound, _processingBlockMinerPubkey, Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L135-182)
```csharp
        switch (behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                Context.LogDebug(() =>
                    $"Previous in value in extra data:{round.RealTimeMinersInformation[pubkey.ToHex()].PreviousInValue}");
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
                    }
                };
            case AElfConsensusBehaviour.TinyBlock:
                var minerInRound = round.RealTimeMinersInformation[pubkey.ToHex()];
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(UpdateTinyBlockInformation),
                            new TinyBlockInput
                            {
                                ActualMiningTime = minerInRound.ActualMiningTimes.Last(),
                                ProducedBlocks = minerInRound.ProducedBlocks,
                                RoundId = round.RoundIdForValidation,
                                RandomNumber = randomNumber
                            })
                    }
                };
            case AElfConsensusBehaviour.NextRound:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextRound), NextRoundInput.Create(round,randomNumber))
                    }
                };
            case AElfConsensusBehaviour.NextTerm:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextTerm), NextTermInput.Create(round,randomNumber))
                    }
                };
            default:
                return new TransactionList();
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }
```
