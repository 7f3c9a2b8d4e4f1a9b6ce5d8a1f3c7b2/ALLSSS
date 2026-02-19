# Audit Report

## Title
Malicious Miner Can Halt Blockchain by Setting Empty Miner List Through Unvalidated NextTerm Input

## Summary
A current miner can directly call the `NextTerm` method with a crafted `NextTermInput` containing an empty `RealTimeMinersInformation` dictionary. The consensus contract lacks validation to prevent empty miner lists when NextTerm is called as a direct transaction (as opposed to through the consensus block validation flow), allowing the attacker to set a term with zero miners and permanently halt block production.

## Finding Description

The vulnerability exploits a critical difference between two execution paths for the `NextTerm` method:

**Path 1 (Block Validation - SAFE)**: When NextTerm is executed as part of consensus block production, `ValidateConsensusBeforeExecution` is called, which invokes `ValidateBeforeExecution` [1](#0-0) . This validation includes `TimeSlotValidationProvider`, which calls `CheckRoundTimeSlots()` [2](#0-1) . The `CheckRoundTimeSlots()` method would throw an `IndexOutOfRangeException` when attempting to access array indices on an empty miner list [3](#0-2) .

**Path 2 (Direct Transaction - VULNERABLE)**: When NextTerm is called directly as a transaction (it's a public RPC method [4](#0-3) ), it bypasses block validation and only goes through `ProcessConsensusInformation` [5](#0-4) , which only performs a `PreCheck()` authorization that validates the sender is in the current or previous miner list [6](#0-5) . No validation checks if the input contains an empty miner list.

The `RoundTerminateValidationProvider` used during header validation only checks that round and term numbers increment correctly and that InValues are null [7](#0-6) , but does NOT validate that `RealTimeMinersInformation` is non-empty.

In `ProcessNextTerm`, the empty `RealTimeMinersInformation` dictionary is used to create an empty `MinerList` [8](#0-7) , which is then set in state via `SetMinerList` without any validation [9](#0-8) .

**Attack Execution**:
1. Malicious miner crafts `NextTermInput` with `RoundNumber = current + 1`, `TermNumber = current + 1`, empty `RealTimeMinersInformation`, and valid `RandomNumber`
2. Calls `NextTerm(input)` directly as a transaction (not through consensus mechanism)
3. Passes `PreCheck()` since attacker is in current miner list
4. Empty miner list gets set in state for the new term
5. All subsequent `GetConsensusCommand` calls return `InvalidConsensusCommand` because no public key exists in the empty miner list [10](#0-9) 
6. Blockchain permanently halts

## Impact Explanation

**CRITICAL** - This vulnerability causes complete, irreversible blockchain denial of service:

- **Complete Halt**: Once the empty miner list is set, no validator can produce blocks because `GetConsensusCommand` returns `InvalidConsensusCommand` for all nodes since their public key cannot be found in the empty miner list
- **Permanent Damage**: The attack cannot be undone through normal consensus mechanisms. Since no miner can pass authorization checks with an empty miner list, no recovery transactions can be executed on-chain
- **Total Network Failure**: All blockchain operations cease - users cannot submit transactions, smart contracts become inaccessible, validators lose rewards, and the entire network becomes non-functional
- **Recovery Requires Hard Fork**: Only off-chain intervention (hard fork with chain state rollback) can restore operations

The severity is CRITICAL because it violates the fundamental blockchain availability guarantee and has no on-chain recovery path.

## Likelihood Explanation

**MEDIUM-HIGH** likelihood:

- **Attacker Prerequisites**: Must be a current or previous miner to pass `PreCheck()`, requiring the attacker to be an elected validator. While this is a privileged position, any single compromised validator can execute the attack
- **Attack Simplicity**: Requires only crafting a single transaction with correct round/term numbers and an empty miner list - no complex timing or coordination needed
- **No Detection Window**: The attack executes in a single block, leaving no time for intervention
- **Economic Irrationality Not a Barrier**: Despite destroying the blockchain (including the attacker's stake), motivations include:
  - Griefing by disgruntled validators
  - Competitor-sponsored attacks
  - Exit scams after extracting value
  - Exploiting before coordinated security patches

The attack is technically straightforward for any current miner, making it a realistic threat despite requiring validator privileges.

## Recommendation

Add validation in `ProcessNextTerm` to reject empty miner lists before state updates:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // Add validation for empty miner list
    Assert(nextRound.RealTimeMinersInformation.Count > 0, 
        "Miner list cannot be empty for term transition.");
    
    // ... rest of the method
}
```

Additionally, add validation in `RoundTerminateValidationProvider.ValidationForNextTerm`:

```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Add check for empty miner list
    if (extraData.Round.RealTimeMinersInformation.Count == 0)
        return new ValidationResult { Message = "Miner list cannot be empty." };

    // Is next term number correct?
    return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
        ? new ValidationResult { Message = "Incorrect term number for next round." }
        : new ValidationResult { Success = true };
}
```

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMinerCanHaltBlockchainWithEmptyMinerList()
{
    // Setup: Get current round and term info
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var currentTerm = await ConsensusStub.GetCurrentTermNumber.CallAsync(new Empty());
    
    // Attacker (current miner) crafts malicious NextTermInput with empty miner list
    var maliciousInput = new NextTermInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentTerm.Value + 1,
        RealTimeMinersInformation = {}, // Empty dictionary - this is the attack
        RandomNumber = GenerateValidRandomNumber(),
        BlockchainAge = currentRound.BlockchainAge,
        ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight,
        ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber
    };
    
    // Execute attack - call NextTerm directly as transaction (not through consensus)
    await ConsensusStub.NextTerm.SendAsync(maliciousInput);
    
    // Verify blockchain is halted - all miners get InvalidConsensusCommand
    var newMinerList = await ConsensusStub.GetCurrentMinerList.CallAsync(new Empty());
    newMinerList.Pubkeys.Count.ShouldBe(0); // Miner list is empty
    
    // Verify no miner can produce blocks
    foreach (var miner in InitialMiners)
    {
        var command = await ConsensusStub.GetConsensusCommand.CallAsync(
            BytesValue.Parser.ParseFrom(ByteString.CopyFrom(miner.PublicKey)));
        command.ShouldBe(ConsensusCommandProvider.InvalidConsensusCommand);
    }
    
    // Blockchain is permanently halted - no recovery possible on-chain
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L26-27)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L17-17)
```csharp
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L35-47)
```csharp
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
```

**File:** protobuf/aedpos_contract.proto (L38-38)
```text
    rpc NextTerm (NextTermInput) returns (google.protobuf.Empty) {
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-190)
```csharp
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
