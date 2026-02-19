### Title
Malicious Miner Can Halt Blockchain by Setting Empty Miner List Through Unvalidated NextTerm Input

### Summary
A current miner can directly call the `NextTerm` method with a crafted `NextTermInput` containing an empty `RealTimeMinersInformation` dictionary. The consensus contract lacks validation to prevent empty miner lists in this code path, allowing the attacker to set a term with zero miners and permanently halt block production.

### Finding Description

The vulnerability exists in the `NextTerm` transaction flow, which fails to validate that the miner list is non-empty before processing term transitions.

**Entry Point**: The `NextTerm` method is publicly callable and only performs basic authorization via `PreCheck()`: [1](#0-0) 

**Authorization Bypass**: `PreCheck()` only verifies the sender is in the current or previous round's miner list, but does not validate the input's content: [2](#0-1) 

**Validation Gap**: The `RoundTerminateValidationProvider` validates NextTerm behavior but only checks round number increment, term number increment, and null InValues - it does NOT validate that `RealTimeMinersInformation` is non-empty: [3](#0-2) 

**NextTermInput Creation**: The `NextTermInput.Create()` method blindly copies the provided Round's `RealTimeMinersInformation` without validation: [4](#0-3) 

**Vulnerable Execution Path**: In `ProcessNextTerm`, an empty `RealTimeMinersInformation` leads to creating and setting an empty `MinerList`: [5](#0-4) 

The `SetMinerList` method accepts the empty list without validation: [6](#0-5) 

**Why Existing Protections Fail**: While `CheckRoundTimeSlots()` would catch an empty round by throwing an exception when accessing array indices, this validation is only executed during ACS4 consensus block validation (`ValidateConsensusBeforeExecution`), not when `NextTerm` is called directly as a transaction: [7](#0-6) [8](#0-7) 

### Impact Explanation

**Complete Blockchain Halt**: Once an empty miner list is set for the new term:
- All subsequent calls to `PreCheck()` fail because no miner exists in `currentRound.IsInMinerList()` 
- `GetConsensusCommand` returns `InvalidConsensusCommand` for all nodes since the sender cannot be found in the empty miner list: [9](#0-8) 
- No node can produce blocks, including the attacker
- The blockchain permanently stops at the beginning of the compromised term

**Irreversible Damage**: The attack cannot be undone through normal consensus mechanisms since no miner can produce blocks to execute recovery transactions. Only an off-chain intervention (hard fork or chain reset) could restore operations.

**Affected Parties**: All blockchain participants - validators lose block rewards, users cannot submit transactions, smart contracts become inaccessible, and the entire network becomes non-functional.

**Severity Justification**: This is CRITICAL because it causes complete, permanent denial of service to the entire blockchain with no recovery path through on-chain mechanisms.

### Likelihood Explanation

**Attacker Capabilities**: The attacker must be a current or previous miner to pass `PreCheck()`. This is a realistic constraint as it requires being an elected validator, but any single compromised or malicious validator can execute the attack.

**Attack Complexity**: The attack is straightforward:
1. Construct a `NextTermInput` with correct `RoundNumber` (current + 1) and `TermNumber` (current + 1)
2. Set `RealTimeMinersInformation` to an empty dictionary
3. Set other required fields (e.g., `RandomNumber`)
4. Call `NextTerm(input)` as a transaction

**Execution Practicality**: The attack requires only a single transaction and no special timing. The attacker doesn't need to compromise multiple nodes or coordinate complex actions.

**Economic Rationality**: While the attack destroys the blockchain (including the attacker's own stake), motivations could include:
- Griefing/sabotage by a disgruntled validator
- Attack sponsored by competitors
- Exit scam after profiting from the validator position
- Exploiting vulnerabilities before coordinated patch deployment

**Detection Constraints**: The attack executes instantly in a single block. Once the empty miner list is set, it's too late to prevent the halt.

**Probability**: MEDIUM-HIGH likelihood given that any single malicious validator can execute it with minimal effort.

### Recommendation

**Immediate Fix**: Add validation in `ProcessNextTerm` to reject empty miner lists:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // Add validation for non-empty miner list
    Assert(nextRound.RealTimeMinersInformation.Count > 0, 
           "Cannot transition to term with zero miners.");
    
    RecordMinedMinerListOfCurrentRound();
    // ... rest of implementation
}
```

**Additional Validation**: Add a check in `RoundTerminateValidationProvider.ValidationForNextTerm()`: [3](#0-2) 

```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Add miner list validation
    if (extraData.Round.RealTimeMinersInformation.Count == 0)
        return new ValidationResult { Message = "Next term must have at least one miner." };

    // Is next term number correct?
    return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
        ? new ValidationResult { Message = "Incorrect term number for next round." }
        : new ValidationResult { Success = true };
}
```

**Test Cases**: Add regression tests that verify:
1. Calling `NextTerm` with empty `RealTimeMinersInformation` fails with appropriate error
2. Validation catches the empty miner list before state changes
3. Normal term transitions with valid miner lists continue to work

### Proof of Concept

**Initial State**:
- Blockchain is running with current miner set M = {miner1, miner2, ..., minerN}
- Attacker controls miner1 who is an active validator
- Current term number = T, current round number = R

**Attack Steps**:

1. Attacker constructs malicious `NextTermInput`:
```
NextTermInput maliciousInput = new NextTermInput {
    RoundNumber = R + 1,
    TermNumber = T + 1,
    RealTimeMinersInformation = {}, // Empty dictionary
    RandomNumber = [valid VRF output],
    BlockchainAge = [current age],
    // ... other required fields
}
```

2. Attacker submits transaction: `consensusContract.NextTerm(maliciousInput)`

3. Transaction executes:
   - `PreCheck()` passes (attacker is in current miner list)
   - `ProcessNextTerm()` processes the input
   - Empty `MinerList` is created and set for term T+1
   - Transaction succeeds

**Expected Result**: Transaction should fail with "Cannot transition to term with zero miners"

**Actual Result**: Transaction succeeds, empty miner list is set, blockchain halts permanently

**Success Condition**: After the attack, attempting to produce any block fails because:
- `PreCheck()` returns false (no one in empty miner list)
- `GetConsensusCommand()` returns `InvalidConsensusCommand`
- Block production completely stops

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L70-82)
```csharp
    private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
    {
        // Miners for one specific term should only update once.
        var minerListFromState = State.MinerListMap[termNumber];
        if (gonnaReplaceSomeone || minerListFromState == null)
        {
            State.MainChainCurrentMinerList.Value = minerList;
            State.MinerListMap[termNumber] = minerList;
            return true;
        }

        return false;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-190)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L7-23)
```csharp
    public static NextTermInput Create(Round round, ByteString randomNumber)
    {
        return new NextTermInput
        {
            RoundNumber = round.RoundNumber,
            RealTimeMinersInformation = { round.RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = round.ExtraBlockProducerOfPreviousRound,
            BlockchainAge = round.BlockchainAge,
            TermNumber = round.TermNumber,
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = round.IsMinerListJustChanged,
            RoundIdForValidation = round.RoundIdForValidation,
            MainChainMinersRoundNumber = round.MainChainMinersRoundNumber,
            RandomNumber = randomNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-58)
```csharp
    public ValidationResult CheckRoundTimeSlots()
    {
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
        if (miners.Count == 1)
            // No need to check single node.
            return new ValidationResult { Success = true };

        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L10-35)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        // If provided round is a new round
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
        }
        else
        {
            // Is sender respect his time slot?
            // It is maybe failing due to using too much time producing previous tiny blocks.
            if (!CheckMinerTimeSlot(validationContext))
            {
                validationResult.Message =
                    $"Time slot already passed before execution.{validationContext.SenderPubkey}";
                validationResult.IsReTrigger = true;
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L26-27)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;
```
