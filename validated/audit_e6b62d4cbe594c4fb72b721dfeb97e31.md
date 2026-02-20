# Audit Report

## Title
Missing Validation of ExtraBlockProducerOfPreviousRound in NextTermInput Allows Reward Manipulation

## Summary
The AEDPoS consensus contract fails to validate the `ExtraBlockProducerOfPreviousRound` field during NextTerm block processing. A malicious miner producing a NextTerm block can manipulate this field to grant arbitrary miners extra tiny block production privileges before the round starts, artificially inflating their `ProducedBlocks` count and unfairly affecting mining reward distribution.

## Finding Description

The vulnerability exists across multiple consensus validation layers that collectively fail to ensure the integrity of the `ExtraBlockProducerOfPreviousRound` field during term transitions.

**1. No validation in NextTermInput.Create():**

The `Create()` method directly copies `ExtraBlockProducerOfPreviousRound` from the input Round without any validation. [1](#0-0) 

**2. RoundTerminateValidationProvider lacks field validation:**

The `ValidationForNextTerm` method only validates that the round number and term number increment correctly, and that InValues are null. It completely omits validation of `ExtraBlockProducerOfPreviousRound`. [2](#0-1) 

**3. Field excluded from hash-based validation:**

The `GetCheckableRound()` method constructs a checkable round containing only `RoundNumber`, `TermNumber`, `RealTimeMinersInformation`, and `BlockchainAge`, explicitly excluding `ExtraBlockProducerOfPreviousRound` from hash-based integrity checks. [3](#0-2) 

**4. Field grants special mining privileges:**

In `HandleMinerInNewRound()`, when `ExtraBlockProducerOfPreviousRound` matches a miner's pubkey and the current time is before the round start time, that miner is granted `TinyBlock` permission, bypassing normal time slot restrictions. [4](#0-3) 

Additionally, miners already in the round who match this field can produce extra blocks beyond normal limits. [5](#0-4) 

**5. Tiny blocks increment ProducedBlocks counter:**

Each tiny block produced increments the miner's `ProducedBlocks` count by calling `Add(1)`. [6](#0-5) 

**6. Correct generation vs. actual usage:**

While `GenerateFirstRoundOfNextTerm()` correctly sets `ExtraBlockProducerOfPreviousRound` to the sender's pubkey, there is no enforcement mechanism that validates the actual NextTermInput received matches this expected value. [7](#0-6) 

**7. Manipulated data persisted to state:**

The `ProcessNextTerm` method converts the input to a Round object via `ToRound()` which copies all fields including the unvalidated `ExtraBlockProducerOfPreviousRound`. [8](#0-7)  This Round is then stored directly to state via `AddRoundInformation()`. [9](#0-8) 

**8. ProducedBlocks affects rewards:**

The total mined blocks calculated by summing all miners' `ProducedBlocks` is multiplied by reward per block to determine total mining rewards donated to Treasury. [10](#0-9) 

Individual `ProducedBlocks` counts are also reported to the Election contract where they influence reward distribution and miner reputation. [11](#0-10) 

**9. Limited validation for NextTerm:**

The validation service only applies `RoundTerminateValidationProvider` for NextTerm blocks, which doesn't check `ExtraBlockProducerOfPreviousRound`. [12](#0-11) 

## Impact Explanation

This vulnerability enables direct manipulation of mining rewards and consensus fairness through the following attack chain:

1. **Privilege Grant**: A malicious miner producing a NextTerm block can set `ExtraBlockProducerOfPreviousRound` to any miner's pubkey (including a colluding party)

2. **Extra Mining Opportunities**: The beneficiary miner gains the ability to produce tiny blocks before the round officially starts, a privilege honest miners don't have during this transition period

3. **Inflated Block Count**: Each tiny block increments the beneficiary's `ProducedBlocks` counter, artificially inflating their mining contribution

4. **Reward Misallocation**: The inflated `ProducedBlocks` count directly affects:
   - Total mining reward calculations donated to Treasury (based on aggregate block count)
   - Individual miner statistics reported to the Election contract
   - Proportional reward distribution among miners
   - Miner reputation and voting weight in governance

**Attack Scenarios:**

- **Collusion**: Attacker sets field to colluding miner's pubkey, both parties share the extra rewards
- **Self-enrichment via alternate identity**: If the attacker operates multiple miner identities, they can grant privileges to another identity they control
- **Denial of Service**: Setting to non-existent pubkey could prevent proper transition block production

**Affected Parties:**

- Honest miners receive proportionally reduced rewards when attackers inflate block counts
- Protocol integrity is compromised as rewards no longer accurately reflect work performed
- Treasury receives inflated mining reward donations based on manipulated block counts

## Likelihood Explanation

**Attack Prerequisites:**

The attacker must be selected to produce the NextTerm block, which is a standard consensus role that rotates among miners during term transitions. This is a normal operational requirement, not an exceptional privilege.

**Execution Feasibility:**

1. When the attacker's turn to produce a NextTerm block arrives, they receive properly formatted consensus extra data via `GetConsensusExtraData`
2. Before signing and broadcasting the block, the attacker modifies the `ExtraBlockProducerOfPreviousRound` field to their chosen target pubkey
3. The modified block passes all validation checks because no validator examines this field
4. The manipulated Round data is persisted to state and used for subsequent mining permission checks
5. The beneficiary miner exploits the extra privileges to produce additional tiny blocks

**Detection Difficulty:**

The manipulation is effectively undetectable through normal consensus validation because:
- Validators do not regenerate expected Round data to compare against received data
- The field is intentionally excluded from hash-based integrity checks
- The block appears valid to all consensus validators
- No on-chain audit trail exists to identify the discrepancy

**Economic Rationality:**

The attack is economically rational:
- **Cost**: Minimal (single field modification before block signing)
- **Benefit**: Direct increase in mining rewards through extra block production
- **Risk**: Low detection probability due to validation gaps
- **Frequency**: Every term transition provides an attack opportunity (regular occurrence in consensus operation)

## Recommendation

Implement validation of `ExtraBlockProducerOfPreviousRound` in the `RoundTerminateValidationProvider` by adding a check that compares the received value against the expected value (sender's pubkey):

```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Validate term number increment
    if (validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Incorrect term number for next round." };
    
    // NEW: Validate ExtraBlockProducerOfPreviousRound matches sender
    var senderPubkey = extraData.SenderPubkey.ToHex();
    if (extraData.Round.ExtraBlockProducerOfPreviousRound != senderPubkey)
        return new ValidationResult { Message = "ExtraBlockProducerOfPreviousRound does not match sender." };
    
    return new ValidationResult { Success = true };
}
```

Alternatively, include `ExtraBlockProducerOfPreviousRound` in the `GetCheckableRound()` method to enable hash-based validation of this field's integrity.

## Proof of Concept

This vulnerability can be demonstrated by creating a test that:
1. Simulates a miner producing a NextTerm block
2. Modifies the `ExtraBlockProducerOfPreviousRound` field to a different miner's pubkey before calling `NextTerm()`
3. Verifies the transaction succeeds (passes validation)
4. Confirms the manipulated value is persisted to state
5. Shows the beneficiary miner can now produce extra tiny blocks before the round start time
6. Verifies the beneficiary's `ProducedBlocks` count is artificially inflated
7. Demonstrates this affects the total mining reward calculation

The test would confirm that no validation prevents this manipulation and that the exploit successfully increases the attacker's (or colluding party's) mining rewards at the expense of honest miners.

---

## Notes

This vulnerability represents a critical consensus integrity issue because it allows miners to manipulate the reward distribution mechanism that underpins the economic security of the AEDPoS consensus system. The lack of validation on `ExtraBlockProducerOfPreviousRound` creates an exploitable gap between what the protocol expects (sender's pubkey) and what it enforces (no validation), enabling rational attackers to gain unfair economic advantages with minimal risk.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L13-13)
```csharp
            ExtraBlockProducerOfPreviousRound = round.ExtraBlockProducerOfPreviousRound,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L31-31)
```csharp
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L199-206)
```csharp
        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L104-112)
```csharp
            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L305-305)
```csharp
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L254-254)
```csharp
        newRound.ExtraBlockProducerOfPreviousRound = senderPubkey;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L105-105)
```csharp
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L46-46)
```csharp
                    RecentlyProducedBlocks = i.Value.ProducedBlocks,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L119-120)
```csharp
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```
