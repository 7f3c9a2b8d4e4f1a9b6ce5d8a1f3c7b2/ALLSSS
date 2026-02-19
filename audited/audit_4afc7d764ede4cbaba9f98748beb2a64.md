# Audit Report

## Title
Malicious Miner Can Halt Blockchain by Calling NextTerm with Empty Miner List

## Summary
A malicious authorized miner can permanently halt the AElf blockchain by submitting a `NextTerm` transaction with an empty `RealTimeMinersInformation` dictionary. This bypasses all validation checks and sets an empty miner list, preventing all miners from producing subsequent blocks because the consensus command generation fails when no miners exist in the round.

## Finding Description

The vulnerability exists in the term transition logic of the AEDPoS consensus contract. The security guarantee that should be maintained is: **the miner list for any term must contain at least one miner to enable block production**.

### Attack Vector

1. **Entry Point**: The `NextTerm` method is a public RPC method that accepts `NextTermInput` from any transaction sender. [1](#0-0) 

2. **Insufficient Authorization**: The `PreCheck()` method only validates that the transaction sender is in the current or previous miner list, but does NOT validate the content of the `NextTermInput` parameter. [2](#0-1) 

3. **Validation Gap**: The `RoundTerminateValidationProvider` validates round and term number increments, but the critical check `extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)` returns false when the dictionary is empty, allowing validation to pass. [3](#0-2) 

4. **Unchecked State Corruption**: In `ProcessNextTerm`, the miner list is created from `nextRound.RealTimeMinersInformation.Keys` without validation. An empty dictionary produces an empty `MinerList`. [4](#0-3) 

5. **No Bounds Check**: The `SetMinerList` method directly sets the state variables without any validation that the list contains at least one miner. [5](#0-4) 

6. **Consensus Failure**: When miners attempt to get a consensus command, `GetConsensusCommand` checks `currentRound.IsInMinerList(_processingBlockMinerPubkey)`. [6](#0-5)  The `IsInMinerList` method returns `RealTimeMinersInformation.Keys.Contains(pubkey)`. [7](#0-6)  With an empty dictionary, this always returns false for any miner, causing all miners to receive `InvalidConsensusCommand`.

7. **Additional Failures**: Multiple code paths will fail with empty miner lists, including `GetNextMinerPubkey()` which calls `.First(m => m.IsExtraBlockProducer)` on an empty collection. [8](#0-7) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability achieves complete and permanent denial of service of the entire blockchain:

- **Consensus Breakdown**: Once the empty miner list is set, `GetConsensusCommand` returns `InvalidConsensusCommand` for ALL miners, meaning no miner can produce any blocks.
- **Permanent Halt**: There is no recovery mechanism in the contract code. The blockchain remains halted until extraordinary measures (hard fork or manual state intervention) are taken.
- **Network-Wide Impact**: All network participants lose access. Token holders cannot transfer assets, DApps become inoperable, cross-chain bridges halt, and all governance operations cease.
- **Economic Damage**: Complete loss of network functionality affects all stakeholders and could result in massive economic losses.

The impact is maximal because it breaks the fundamental consensus invariant (non-empty miner list) and has no programmatic recovery path.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is easily executable with minimal barriers:

- **Attacker Requirements**: Must be an authorized miner (in current or previous round). Since miners are elected through the Election contract and multiple miners exist in the network, this is a realistic constraint.
- **Attack Complexity**: VERY LOW. The attacker simply crafts a `NextTermInput` with correct round/term numbers but an empty `real_time_miners_information` dictionary, then submits it via a transaction.
- **No Special Conditions**: No timing requirements, race conditions, or coordination needed. The attack can be executed at any time during normal operation.
- **Low Cost**: Only requires a normal transaction fee.
- **Undetectable**: The malicious transaction appears as a normal term transition until after execution when the chain halts.

Any disgruntled or compromised miner can execute this attack instantly with minimal effort and cost.

## Recommendation

Add validation to ensure the miner list is non-empty at multiple defense layers:

1. **In `ProcessNextTerm`**: Before calling `SetMinerList`, verify that `nextRound.RealTimeMinersInformation` is not empty:
```csharp
// After line 187
Assert(nextRound.RealTimeMinersInformation.Count > 0, 
    "Miner list cannot be empty for new term.");
```

2. **In `SetMinerList`**: Add validation that the miner list contains at least one miner:
```csharp
// After line 74
Assert(minerList?.Pubkeys?.Count > 0, 
    "Cannot set empty miner list.");
```

3. **In `RoundTerminateValidationProvider.ValidationForNextTerm`**: Add explicit check for non-empty miner list:
```csharp
// After line 41
if (extraData.Round.RealTimeMinersInformation.Count == 0)
    return new ValidationResult { Message = "Miner list cannot be empty." };
```

These checks should be added at all three layers for defense in depth.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanHaltChain_WithEmptyMinerList()
{
    // Setup: Initialize chain with normal miners
    var initialMiners = await ElectionContractStub.GetVictories.CallAsync(new Empty());
    Assert.True(initialMiners.Value.Count > 0);
    
    var consensusStub = GetConsensusContractTester(initialMiners.Value[0]);
    var currentRound = await consensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var currentTerm = await consensusStub.GetCurrentTermNumber.CallAsync(new Empty());
    
    // Generate VRF for random number (attacker can generate this)
    var randomNumber = HashHelper.ComputeFrom("attack").ToByteString();
    
    // Craft malicious NextTermInput with EMPTY RealTimeMinersInformation
    var maliciousInput = new NextTermInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentTerm.Value + 1,
        RealTimeMinersInformation = { }, // EMPTY dictionary - this is the attack
        BlockchainAge = currentRound.BlockchainAge + 1000,
        RandomNumber = randomNumber
    };
    
    // Execute the attack - miner calls NextTerm with empty miner list
    var result = await consensusStub.NextTerm.SendAsync(maliciousInput);
    Assert.True(result.TransactionResult.Status == TransactionResultStatus.Mined);
    
    // Verify the chain is now halted
    var newRound = await consensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    Assert.Equal(0, newRound.RealTimeMinersInformation.Count); // Empty miner list set!
    
    // Verify NO miner can produce blocks anymore
    foreach (var miner in initialMiners.Value)
    {
        var minerStub = GetConsensusContractTester(miner);
        var pubkey = ByteString.CopyFrom(miner.ToByteArray());
        
        // GetConsensusCommand should return InvalidConsensusCommand for all miners
        var command = await minerStub.GetConsensusCommand.CallAsync(pubkey);
        Assert.Equal(0, command.NextBlockMiningLeftMilliseconds); // Invalid command
        Assert.Equal(0, command.LimitMillisecondsOfMiningBlock);
    }
    
    // Chain is permanently halted - no miner can produce blocks
}
```

**Notes**

The vulnerability is valid because it directly exploits missing input validation in a critical consensus operation. The protobuf definition allows empty `real_time_miners_information` maps [9](#0-8) , and no downstream validation ensures this invariant is maintained. Once triggered, the blockchain enters an unrecoverable state where consensus cannot proceed, requiring external intervention to restore functionality.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-190)
```csharp
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-330)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-34)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L26-27)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L96-98)
```csharp
                Value = round.RealTimeMinersInformation.Values
                            .FirstOrDefault(m => m.ExpectedMiningTime > Context.CurrentBlockTime)?.Pubkey ??
                        round.RealTimeMinersInformation.Values.First(m => m.IsExtraBlockProducer).Pubkey
```

**File:** protobuf/aedpos_contract.proto (L484-507)
```text
message NextTermInput {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
    // The round number on the main chain
    int64 main_chain_miners_round_number = 3;
    // The time from chain start to current round (seconds).
    int64 blockchain_age = 4;
    // The miner public key that produced the extra block in the previous round.
    string extra_block_producer_of_previous_round = 5;
    // The current term number.
    int64 term_number = 6;
    // The height of the confirmed irreversible block.
    int64 confirmed_irreversible_block_height = 7;
    // The round number of the confirmed irreversible block.
    int64 confirmed_irreversible_block_round_number = 8;
    // Is miner list different from the the miner list in the previous round.
    bool is_miner_list_just_changed = 9;
    // The round id, calculated by summing block producers’ expecting time (second).
    int64 round_id_for_validation = 10;
    // The random number.
    bytes random_number = 11;
}
```
