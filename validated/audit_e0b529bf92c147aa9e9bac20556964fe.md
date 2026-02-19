# Audit Report

## Title
Negative LIB Height Bypasses Validation in NextRound, Causing Consensus DoS

## Summary
The AEDPoS consensus contract fails to validate that `ConfirmedIrreversibleBlockHeight` is non-negative during `NextRound` transitions. A malicious miner can inject a negative LIB height into the consensus state, causing all miners to be limited to producing only 1 block at a time, effectively performing a denial-of-service attack on blockchain consensus.

## Finding Description

The vulnerability exists due to a missing validation step in the consensus validation framework. When a miner produces a block with `NextRound` behavior, the consensus extra data undergoes validation before execution. However, the validation logic treats different consensus behaviors differently.

**Root Cause**: The `NextRoundInput.Create()` method directly copies `ConfirmedIrreversibleBlockHeight` from the current round without any validation to ensure the value is non-negative: [1](#0-0) 

The protobuf schema defines this field as `int64` (signed integer), which allows negative values: [2](#0-1) 

**Validation Gap**: The `ValidateBeforeExecution` method applies different validators based on the consensus behavior type. For `NextRound` behavior, it only adds `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider`: [3](#0-2) 

In contrast, `UpdateValue` behavior correctly receives LIB validation through `LibInformationValidationProvider`: [4](#0-3) 

The `RoundTerminateValidationProvider` only validates that the round number increments correctly and that InValues are null, but does not check LIB height validity: [5](#0-4) 

**Execution Path**: When a malicious miner produces a block with `NextRound` behavior containing a negative `ConfirmedIrreversibleBlockHeight`, the `ValidateConsensusBeforeExecution` method is called: [6](#0-5) 

The validation passes because `LibInformationValidationProvider` is not applied. The `NextRound` transaction then executes via `ProcessConsensusInformation`, which converts the malicious input to a Round object: [7](#0-6) 

The corrupted round is stored to state without validation: [8](#0-7) 

State storage occurs via `AddRoundInformation`: [9](#0-8) 

## Impact Explanation

The negative LIB height causes critical malfunction in the consensus mechanism's block production throttling system.

**Direct Impact**: The `GetMaximumBlocksCount()` method reads the corrupted LIB height from the current round: [10](#0-9) 

When calculating the distance to the last irreversible block, a negative `libBlockHeight` (e.g., -1) combined with a positive `currentHeight` (e.g., 1000) produces an artificially huge distance (1001 blocks): [11](#0-10) 

This triggers the `Severe` mining status condition, which forces the method to return 1, limiting ALL miners to producing only 1 block at a time: [12](#0-11) 

**Persistence**: The negative value propagates to all future rounds because `GenerateNextRoundInformation` copies the LIB height forward without validation: [13](#0-12) 

This represents a severe denial-of-service attack on consensus. The blockchain's throughput is drastically reduced as miners are artificially limited to producing 1 block per time slot instead of the normal maximum (typically 8+ blocks). The entire network operates in a crippled state until manual intervention or chain recovery.

## Likelihood Explanation

**Attacker Prerequisites**: The attacker must be an active miner in the current miner list, which is verified by the `PreCheck` method: [14](#0-13) 

**Attack Feasibility**: The attack is straightforward to execute:
1. The attacker (who is an elected miner) waits for their turn to produce a block with `NextRound` behavior
2. They modify the consensus extra data in the block header to set `ConfirmedIrreversibleBlockHeight` to -1
3. The block is validated using `ValidateBeforeExecution`, which does not apply LIB validation for NextRound
4. The validation passes, and the malicious round data is stored to state
5. Immediately, `GetMaximumBlocksCount` is called and returns 1, triggering the DoS
6. The negative value persists across all future rounds

**Realistic Scenario**: Any elected miner can perform this attack. There are no economic costs beyond normal block production. The attack does not require special state setup or coordination. Detection would occur through `IrreversibleBlockHeightUnacceptable` events and drastically reduced block production rate, but by then the damage is done and persists.

## Recommendation

Apply `LibInformationValidationProvider` to `NextRound` behavior in the validation framework:

```csharp
case AElfConsensusBehaviour.NextRound:
    // Is sender's order of next round correct?
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    // ADD THIS LINE:
    validationProviders.Add(new LibInformationValidationProvider());
    break;
```

Additionally, add explicit validation in `NextRoundInput.Create()` to ensure LIB height is non-negative:

```csharp
public static NextRoundInput Create(Round round, ByteString randomNumber)
{
    Assert(round.ConfirmedIrreversibleBlockHeight >= 0, 
           "ConfirmedIrreversibleBlockHeight cannot be negative");
    
    return new NextRoundInput
    {
        // ... existing code ...
    };
}
```

## Proof of Concept

The vulnerability can be demonstrated by:
1. Setting up a test network with multiple miners
2. Having one miner produce a block with NextRound behavior
3. Injecting a negative value (-1) for `ConfirmedIrreversibleBlockHeight` in the consensus extra data
4. Observing that the block passes validation
5. Verifying that `GetMaximumBlocksCount()` returns 1 instead of the normal maximum
6. Confirming that all subsequent miners are limited to 1 block production
7. Verifying the negative value persists in subsequent rounds

The test would validate that the `LibInformationValidationProvider` is not called for NextRound behavior and that the negative LIB height causes the Severe mining status to be triggered.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L16-16)
```csharp
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
```

**File:** protobuf/aedpos_contract.proto (L472-472)
```text
    int64 confirmed_irreversible_block_height = 7;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L29-34)
```csharp
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L105-105)
```csharp
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L24-28)
```csharp
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-67)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```
