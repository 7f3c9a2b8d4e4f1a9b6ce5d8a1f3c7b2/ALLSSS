### Title
Unhandled NOTHING Consensus Behaviour Causes Node Crash via Null Round Dereference

### Summary
The `GetConsensusBlockExtraData()` method fails to handle the legitimate `NOTHING` consensus behaviour (enum value 3), resulting in a null `Round` object being returned. This causes immediate NullReferenceException crashes in two separate code paths when the consensus system attempts to process this unhandled behaviour, leading to node DoS during block production.

### Finding Description

**Root Cause:**
The `AElfConsensusBehaviour` enum defines five values: UPDATE_VALUE(0), NEXT_ROUND(1), NEXT_TERM(2), NOTHING(3), and TINY_BLOCK(4). [1](#0-0) 

The `GetConsensusBlockExtraData()` method's switch statement only handles four of these behaviours (UPDATE_VALUE, TINY_BLOCK, NEXT_ROUND, NEXT_TERM) and completely omits the NOTHING case. [2](#0-1) 

When NOTHING behaviour is provided in trigger information, the switch statement matches no cases, leaving the `information` object created at line 25 with its default values: `Round = null` (default for protobuf message fields) and `Behaviour = UPDATE_VALUE` (enum default 0).

**Crash Path 1 - GetConsensusExtraData:**
When `GetConsensusExtraData()` calls `GetConsensusBlockExtraData(input)` with the default `isGeneratingTransactions = false` parameter [3](#0-2) , the code immediately crashes at line 50 attempting to invoke `information.Round.DeleteSecretSharingInformation()` on a null Round object. [4](#0-3) 

**Crash Path 2 - GenerateConsensusTransactions:**
When `GenerateConsensusTransactions()` calls `GetConsensusBlockExtraData(input, true)` [5](#0-4) , the null Round is serialized and then deserialized back. The resulting `consensusInformation` object has `Round = null` but `Behaviour = UPDATE_VALUE` (default). When `GenerateTransactionListByExtraData()` processes this, it assigns `round = null` at line 133 and then executes the switch statement. [6](#0-5) 

For UPDATE_VALUE behaviour, line 139 attempts to access `round.RealTimeMinersInformation[pubkey.ToHex()]`, causing NullReferenceException. [7](#0-6) 

For TINY_BLOCK, line 149 similarly accesses null round. [8](#0-7) 

For NEXT_ROUND and NEXT_TERM, the `Create()` methods attempt to access null round members (e.g., `round.RoundNumber`), causing crashes. [9](#0-8) [10](#0-9) 

**Why NOTHING is Legitimate:**
The NOTHING behaviour is not a malformed value—it's actively used by the consensus behaviour provider when a miner's time slot has passed, returning NOTHING to indicate no action should be taken. [11](#0-10) 

**Regarding pubkey and randomNumber:**
The `pubkey` parameter has validation checks at line 66-67 in `GenerateConsensusTransactions` and line 18 in `GetConsensusBlockExtraData`, preventing null/empty values. [12](#0-11) [13](#0-12) 

The `randomNumber` parameter has no validation, but in protobuf C#, `ByteString` defaults to `ByteString.Empty` rather than null, and it's only passed around without dereferencing, so it doesn't cause crashes.

### Impact Explanation

**Operational Impact - Consensus DoS:**
When this vulnerability triggers, the node experiences an unhandled NullReferenceException, causing the block production process to fail. This has several consequences:

1. **Missed Block Production:** The affected miner fails to produce their assigned block, disrupting the consensus schedule
2. **Node Instability:** Unhandled exceptions can crash the consensus service or entire node
3. **Network Degradation:** If multiple miners encounter this condition (e.g., during time slot transitions), consensus could significantly slow or temporarily halt

**Who is Affected:**
All consensus participants (miners/validators) are affected. Any node that encounters trigger information with NOTHING behaviour during block production will crash.

**Severity Justification:**
This is a **Medium severity** vulnerability because:
- It causes complete DoS of affected nodes' consensus operations
- NOTHING is a legitimate behaviour value that occurs in normal operation (not just malicious input)
- The crash is deterministic and unavoidable once the condition is met
- However, it's typically self-inflicted (node's own consensus logic generates NOTHING) rather than externally exploitable
- Recovery is possible by restarting the node after the time slot passes

### Likelihood Explanation

**Reachable Entry Point:**
The ACS4 consensus methods (`GetConsensusExtraData`, `GenerateConsensusTransactions`) are marked as view methods and are part of the consensus contract's public interface. [14](#0-13) 

While primarily called by the consensus system during block production [15](#0-14) , view methods can technically be invoked by anyone for querying.

**Feasible Preconditions:**
The NOTHING behaviour is returned by `ConsensusBehaviourProviderBase` when a miner's time slot has passed, which is a normal operational condition. [16](#0-15) 

When `GetConsensusCommand` determines behaviour is NOTHING, it returns `InvalidConsensusCommand` to prevent block production. [17](#0-16) 

However, if there's any code path where trigger information with NOTHING behaviour still gets passed to `GetConsensusExtraData` or `GenerateConsensusTransactions` (e.g., due to timing issues, race conditions, or bugs in the consensus engine), the crash is guaranteed.

**Attack Complexity:**
Low to Medium. While the normal flow prevents NOTHING from reaching the vulnerable functions, several scenarios could trigger it:
1. Race conditions in consensus timing
2. Bugs in the consensus trigger information provider
3. External invocation of view methods with crafted NOTHING behaviour (if view methods are truly publicly callable)
4. Corrupted or malformed consensus state

**Likelihood Assessment:**
**Medium** - The vulnerability exists in production code with a legitimate trigger condition (NOTHING behaviour), but normal operation flow attempts to filter it out. The risk increases during:
- Network congestion causing timing anomalies
- Node synchronization issues
- Consensus engine bugs
- Any scenario where defensive validation is bypassed

### Recommendation

**Immediate Fix:**
1. Add a case for `AElfConsensusBehaviour.Nothing` in the switch statement in `GetConsensusBlockExtraData()` that returns an appropriate response or throws a clear error message:

```csharp
case AElfConsensusBehaviour.Nothing:
    // NOTHING behaviour indicates no consensus action should be taken
    // Return empty information or throw descriptive error
    Assert(false, "NOTHING behaviour should not generate consensus extra data.");
    break;
```

2. Add null checks in `GenerateTransactionListByExtraData()` before accessing `round`:

```csharp
Assert(round != null, "Consensus round information cannot be null.");
```

3. Add null check in `GetConsensusBlockExtraData()` before line 50:

```csharp
if (!isGeneratingTransactions && information.Round != null) 
    information.Round.DeleteSecretSharingInformation();
```

**Invariant Checks:**
- All enum values in `AElfConsensusBehaviour` must be explicitly handled in switch statements
- Round information must not be null when processing any consensus transaction generation
- Trigger information behaviour must be validated against allowed values for each operation

**Test Cases:**
1. Test `GetConsensusExtraData` with trigger information containing NOTHING behaviour
2. Test `GenerateConsensusTransactions` with trigger information containing NOTHING behaviour
3. Test all switch statements handle default/unknown enum values gracefully
4. Add integration tests for time slot transition edge cases where NOTHING behaviour might occur

### Proof of Concept

**Required Initial State:**
- AEDPoS consensus contract deployed and initialized
- Consensus round in progress

**Exploitation Steps:**

1. Construct trigger information with NOTHING behaviour:
```
var triggerInfo = new AElfConsensusTriggerInformation {
    Pubkey = ByteString.CopyFrom(validMinerPublicKey),
    Behaviour = AElfConsensusBehaviour.Nothing,
    RandomNumber = ByteString.CopyFrom(randomBytes)
};
```

2. Call GetConsensusExtraData with this trigger:
```
var result = consensusContract.GetConsensusExtraData(triggerInfo.ToBytesValue());
```

**Expected Result:**
The method should either:
- Handle NOTHING behaviour gracefully with appropriate response, or
- Throw a descriptive error message about invalid behaviour

**Actual Result:**
NullReferenceException at line 50 when attempting to call `information.Round.DeleteSecretSharingInformation()` on null Round object, causing node crash.

**Alternative Path:**
Calling `GenerateConsensusTransactions` with the same NOTHING behaviour trigger results in NullReferenceException at line 139 (or 149, 169, 177 depending on the default behaviour mapping) when the null round is accessed.

**Success Condition:**
The exploit succeeds if the node crashes with an unhandled NullReferenceException, disrupting consensus operations and preventing block production.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L18-18)
```csharp
        Assert(triggerInformation.Pubkey.Any(), "Invalid pubkey.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L26-48)
```csharp
        switch (triggerInformation.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);

                break;

            case AElfConsensusBehaviour.TinyBlock:
                information = GetConsensusExtraDataForTinyBlock(currentRound, pubkey,
                    triggerInformation);
                break;

            case AElfConsensusBehaviour.NextRound:
                information = GetConsensusExtraDataForNextRound(currentRound, pubkey,
                    triggerInformation);
                break;

            case AElfConsensusBehaviour.NextTerm:
                information = GetConsensusExtraDataForNextTerm(pubkey, triggerInformation);
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L50-52)
```csharp
        if (!isGeneratingTransactions) information.Round.DeleteSecretSharingInformation();

        return information.ToBytesValue();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L51-53)
```csharp
        return behaviour == AElfConsensusBehaviour.Nothing
            ? ConsensusCommandProvider.InvalidConsensusCommand
            : GetConsensusCommand(behaviour, currentRound, _processingBlockMinerPubkey, Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L56-59)
```csharp
    public override BytesValue GetConsensusExtraData(BytesValue input)
    {
        return GetConsensusBlockExtraData(input);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L66-67)
```csharp
        Assert(triggerInformation.Pubkey.Any(),
            "Data to request consensus information should contain pubkey.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L71-73)
```csharp
        var consensusInformation = new AElfConsensusHeaderInformation();
        consensusInformation.MergeFrom(GetConsensusBlockExtraData(input, true).Value);
        var transactionList = GenerateTransactionListByExtraData(consensusInformation, pubkey, randomNumber);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L130-136)
```csharp
    private TransactionList GenerateTransactionListByExtraData(AElfConsensusHeaderInformation consensusInformation,
        ByteString pubkey, ByteString randomNumber)
    {
        var round = consensusInformation.Round;
        var behaviour = consensusInformation.Behaviour;
        switch (behaviour)
        {
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L137-147)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L148-163)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L7-23)
```csharp
    public static NextRoundInput Create(Round round, ByteString randomNumber)
    {
        return new NextRoundInput
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L39-56)
```csharp
        public AElfConsensusBehaviour GetConsensusBehaviour()
        {
            // The most simple situation: provided pubkey isn't a miner.
            // Already checked in GetConsensusCommand.
//                if (!CurrentRound.IsInMinerList(_pubkey))
//                {
//                    return AElfConsensusBehaviour.Nothing;
//                }

            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L114-114)
```csharp
            return !_isTimeSlotPassed ? AElfConsensusBehaviour.UpdateValue : AElfConsensusBehaviour.Nothing;
```

**File:** protobuf/acs4.proto (L25-34)
```text
    rpc GetConsensusExtraData (google.protobuf.BytesValue) returns (google.protobuf.BytesValue) {
        option (aelf.is_view) = true;
    }
    
    // Generate consensus system transactions when a block is generated. 
    // Each block will contain only one consensus transaction, which is used to write the latest consensus information 
    // to the State database.
    rpc GenerateConsensusTransactions (google.protobuf.BytesValue) returns (TransactionList) {
        option (aelf.is_view) = true;
    }
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L216-232)
```csharp
    public async Task<List<Transaction>> GenerateConsensusTransactionsAsync(ChainContext chainContext)
    {
        _blockTimeProvider.SetBlockTime(_nextMiningTime, chainContext.BlockHash);

        Logger.LogDebug(
            $"Block time of getting consensus system txs: {_nextMiningTime.ToDateTime():hh:mm:ss.ffffff}.");

        var contractReaderContext =
            await _consensusReaderContextService.GetContractReaderContextAsync(chainContext);
        var generatedTransactions =
            (await _contractReaderFactory
                .Create(contractReaderContext)
                .GenerateConsensusTransactions
                .CallAsync(_triggerInformationProvider.GetTriggerInformationForConsensusTransactions(
                    chainContext, _consensusCommand.ToBytesValue())))
            .Transactions
            .ToList();
```
