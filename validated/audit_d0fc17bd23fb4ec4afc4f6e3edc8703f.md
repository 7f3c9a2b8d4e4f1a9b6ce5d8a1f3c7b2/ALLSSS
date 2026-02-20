# Audit Report

## Title
Consensus Halt Attack via Empty Miner List in NextRound Validation

## Summary
The AEDPoS consensus contract fails to validate that round transitions must contain at least one miner. A malicious miner can craft a `NextRound` transaction with an empty `RealTimeMinersInformation` map, which passes all validation checks due to incorrect logic handling empty collections. Once stored, the empty round permanently halts consensus as no miner can subsequently obtain valid consensus commands.

## Finding Description

The vulnerability exists in the round termination validation logic within `RoundTerminateValidationProvider`. When `RealTimeMinersInformation` is an empty collection, the validation expression incorrectly returns success. [1](#0-0) 

When the miner list is empty, `.Any(m => m.InValue != null)` evaluates to `false` (no elements exist to check), causing the ternary operator to return `new ValidationResult { Success = true }`.

The validation orchestration for `NextRound` behavior includes multiple validators that are configured during the `ValidateBeforeExecution` process: [2](#0-1) 

However, none of these validators prevent empty miner lists:

**MiningPermissionValidationProvider** only verifies the sender exists in the BaseRound (current round from state), not the proposed next round: [3](#0-2) 

**NextRoundMiningOrderValidationProvider** performs an equality check that passes when both sides equal zero (empty list scenario): [4](#0-3) 

When `RealTimeMinersInformation` is empty, both `distinctCount` and the count of miners with non-null `OutValue` equal zero, making the inequality check `0 != 0` evaluate to false, thus passing validation.

After passing all validations, the empty round is unconditionally stored as the current round: [5](#0-4) [6](#0-5) 

Once the empty round becomes the current state, all miners are permanently locked out. When any miner requests a consensus command through the ACS4 interface, the system performs a membership check: [7](#0-6) 

The `IsInMinerList` method checks if the pubkey exists in `RealTimeMinersInformation.Keys`: [8](#0-7) 

With an empty `RealTimeMinersInformation` map, this returns `false` for ALL miners, causing `GetConsensusCommand` to return `InvalidConsensusCommand` for everyone, permanently halting block production.

## Impact Explanation

**CRITICAL**: This vulnerability causes complete and irreversible consensus failure, breaking the fundamental blockchain availability guarantee:

- **No blocks can be produced**: All miners receive `InvalidConsensusCommand` and cannot mine blocks
- **Transaction processing halts**: No new transactions can be included or executed on-chain
- **Chain permanently frozen**: The empty round becomes the current consensus state with no in-protocol mechanism to recover
- **Hard fork required**: Recovery necessitates out-of-band coordination, emergency governance, and potentially a chain restart
- **Economic disruption**: All pending transactions stuck, DeFi operations cease, token transfers impossible, complete loss of chain utility

This violates the core consensus invariant that valid rounds must contain at least one miner capable of producing blocks. The attack breaks the liveness property of the blockchain consensus system.

## Likelihood Explanation

**MEDIUM-HIGH**: The attack is straightforward to execute with minimal preconditions:

**Attacker Capabilities**: Any current miner who reaches their block production opportunity can execute this attack by proposing a malicious `NextRound` transition. The attacker only needs to be a legitimate participant in the current round.

**Attack Complexity**: LOW
- Attacker crafts a `NextRoundInput` with an empty `RealTimeMinersInformation` map using the public protobuf interface
- No cryptographic manipulation, signature forging, or complex exploit chaining required
- Single transaction execution via the public `NextRound` method
- Attack succeeds immediately upon transaction inclusion

**Preconditions**:
- Attacker must be a legitimate miner in the current round (achievable through normal election/staking mechanisms)
- Attacker must have the opportunity to propose NextRound (occurs naturally at round boundaries during their time slot)

**Detection**: The attack is immediately detectable (consensus stops), but damage is irreversible without hard fork intervention.

## Recommendation

Add explicit validation to ensure `RealTimeMinersInformation` is non-empty during round transitions. The fix should be implemented in `RoundTerminateValidationProvider`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // NEW: Validate minimum miners count
    if (extraData.Round.RealTimeMinersInformation.Count == 0)
        return new ValidationResult { Message = "Next round must contain at least one miner." };
    
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

Additionally, consider adding a similar check in `AddRoundInformation` as a defense-in-depth measure to prevent any empty round from being stored, regardless of how it bypasses validation.

## Proof of Concept

```csharp
[Fact]
public async Task EmptyMinerList_HaltsConsensus_Test()
{
    // Setup: Initialize chain with legitimate miners
    var initialMiners = GenerateMinerList(3);
    await InitializeConsensusAsync(initialMiners);
    
    // Attacker (current miner) crafts malicious NextRound with empty miner list
    var maliciousNextRound = new NextRoundInput
    {
        RoundNumber = 2,
        RealTimeMinersInformation = { }, // EMPTY - This is the attack
        TermNumber = 1,
        RandomNumber = GenerateRandomNumber()
    };
    
    // Execute attack
    var result = await ConsensusStub.NextRound.SendAsync(maliciousNextRound);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Attack succeeds
    
    // Verify consensus is halted: All miners get InvalidConsensusCommand
    foreach (var miner in initialMiners)
    {
        var command = await ConsensusStub.GetConsensusCommand.CallAsync(
            new BytesValue { Value = ByteString.CopyFrom(miner.PublicKey) });
        
        // All miners locked out - consensus halted
        command.ArrangedMiningTime.ShouldBeNull();
        command.Hint.ShouldBe(ByteString.Empty);
    }
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L32-34)
```csharp
        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-21)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-106)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L23-27)
```csharp
        if (!TryToGetCurrentRoundInformation(out var currentRound))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
    }
```
