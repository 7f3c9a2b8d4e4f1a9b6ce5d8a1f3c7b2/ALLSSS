### Title
Memory Exhaustion via Unbounded Consensus Extra Data Parsing in Block Validation

### Summary
The `ValidateConsensusBeforeExecution` function parses consensus extra data from block headers without validating the input size before deserialization. A malicious miner can craft blocks with extremely large `AElfConsensusHeaderInformation` payloads (up to the 100MB network limit) that cause memory exhaustion on validating nodes during the protobuf parsing phase, before the data is validated and rejected.

### Finding Description

The vulnerability exists in the `ValidateConsensusBeforeExecution` method where consensus extra data is deserialized without prior size validation: [1](#0-0) 

The execution flow is:
1. Block validation calls `ConsensusValidationProvider.ValidateBlockBeforeExecuteAsync()` [2](#0-1) 
2. Consensus extra data is extracted from block header [3](#0-2) 
3. The contract parses the raw bytes immediately without size checks

**Root Cause**: The protobuf `Parser.ParseFrom()` operation allocates memory proportional to the input size before any validation logic executes. The `AElfConsensusHeaderInformation` structure contains multiple unbounded collections: [4](#0-3) 

The `Round` message contains a map of miner information: [5](#0-4) 

Each `MinerInRound` includes repeated fields (`actual_mining_times`) and maps (`encrypted_pieces`, `decrypted_pieces`) that can be arbitrarily large.

**Why Existing Protections Fail**:
- Network message limit (100MB) prevents larger attacks but still allows dangerously large payloads [6](#0-5) 
- Transaction size limits (5MB) don't apply to block header extra data [7](#0-6) 
- Consensus validation occurs AFTER parsing completes [8](#0-7) 

While legitimate block production includes data cleanup operations: [9](#0-8) [10](#0-9) 

A malicious miner can bypass these by manually crafting block headers with inflated data structures.

### Impact Explanation

**Operational DoS Impact**: Validating nodes experience memory exhaustion when processing malicious blocks, causing:
- Temporary memory spikes proportional to payload size (up to 100MB per block)
- CPU overhead parsing complex protobuf structures
- On resource-constrained nodes: out-of-memory crashes requiring restart
- Disruption of consensus participation while nodes recover

**Affected Parties**: All non-malicious consensus validators receiving and validating blocks from the network.

**Attack Repeatability**: The malicious miner can produce multiple consecutive blocks with oversized payloads during their time slot, amplifying the DoS effect across the network.

**Severity Justification (Medium)**: While this doesn't directly compromise funds or consensus integrity, it creates a reliable operational DoS vector that degrades network performance and can force node restarts. The impact is contained by requiring miner privileges and eventual detection, but the exploitation window during assigned time slots is guaranteed.

### Likelihood Explanation

**Attacker Capabilities**: Requires being elected as a consensus miner through the Election contract. Miners are staked and monitored, but a compromised or malicious miner can execute the attack during their scheduled blocks.

**Attack Complexity**: LOW - The attacker simply crafts a `Round` protobuf with inflated collections (many fake miner entries, large arrays/maps per miner) and includes it in block headers instead of using the standard `GetConsensusExtraData` flow.

**Feasibility Conditions**:
- Attacker must be an elected miner (significant but achievable barrier)
- Attack window limited to miner's assigned time slots
- Multiple blocks can be produced during one time slot for amplified effect

**Detection Constraints**: The malicious blocks are signed by the attacker and will be rejected after validation, making the attack easily attributable. However, the damage (memory allocation, parsing overhead) occurs before rejection.

**Economic Rationality**: The attack cost includes:
- Initial election/staking requirements to become a miner
- Loss of mining rewards from rejected blocks
- Potential slashing of stake if detected
- However, if the goal is disruption rather than profit, the cost may be acceptable to a motivated attacker

**Probability Assessment**: MEDIUM - Trusted role compromise (miner) reduces likelihood, but the attack is technically trivial to execute once miner status is achieved, and the impact is guaranteed during the exploitation window.

### Recommendation

**Immediate Mitigation**: Add size validation before protobuf parsing in `ValidateConsensusBeforeExecution`:

```csharp
public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
{
    // Add size limit check (e.g., 1MB reasonable for consensus data)
    const int MaxConsensusExtraDataSize = 1024 * 1024; // 1MB
    
    if (input.Value.Length > MaxConsensusExtraDataSize)
    {
        return new ValidationResult 
        { 
            Success = false, 
            Message = $"Consensus extra data exceeds maximum size: {input.Value.Length} > {MaxConsensusExtraDataSize}"
        };
    }
    
    var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
    return ValidateBeforeExecution(extraData);
}
```

**Additional Invariant Checks**:
1. Validate `Round.RealTimeMinersInformation.Count` against expected miner count before detailed processing
2. Add limits on repeated field sizes (e.g., `actual_mining_times` array length)
3. Consider adding block-level size validation in `ConsensusValidationProvider` before calling contract validation

**Test Cases**:
1. Unit test with consensus extra data exceeding size limit - should be rejected before parsing
2. Integration test simulating block with 10MB+ consensus data - should fail validation early
3. Performance test measuring memory allocation with various payload sizes

### Proof of Concept

**Required Initial State**:
- Attacker has been elected as a consensus miner
- Attacker is in current round's miner list with assigned time slot

**Attack Steps**:
1. Attacker's node prepares to produce a block during their time slot
2. Instead of calling standard `GetConsensusExtraData`, attacker crafts malicious `AElfConsensusHeaderInformation`:
   - Create `Round` with 1000+ fake miner entries in `RealTimeMinersInformation` map
   - Each `MinerInRound` includes 100+ entries in `actual_mining_times`
   - Add large byte arrays to `encrypted_pieces`/`decrypted_pieces` maps
   - Total serialized size approaches 50-100MB
3. Attacker includes this in block header's `ExtraData["Consensus"]` field
4. Block is signed and broadcast to network
5. Receiving nodes call `ValidateBlockBeforeExecuteAsync` which extracts consensus data
6. Contract's `ValidateConsensusBeforeExecution` is invoked
7. Line 79 executes: `Parser.ParseFrom(input.Value.ToByteArray())`

**Expected vs Actual Result**:
- **Expected (with fix)**: Size check immediately rejects oversized payload before parsing, minimal resource consumption
- **Actual (current)**: Full protobuf deserialization allocates 50-100MB memory, parsing overhead of complex nested structure, potential OOM on constrained nodes. Only after parsing completes does validation detect invalid miner data and reject the block.

**Success Condition**: Attacker observes target nodes experiencing memory spikes, slow block validation times, or crashes during block processing, while the malicious blocks are eventually rejected with the attacker's signature clearly identifying them.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
    }
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusValidationProvider.cs (L70-75)
```csharp
        var isValid = await _consensusService.ValidateConsensusBeforeExecutionAsync(new ChainContext
        {
            BlockHash = block.Header.PreviousBlockHash,
            BlockHeight = block.Header.Height - 1
        }, consensusExtraData.ToByteArray());
        if (!isValid) return false;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L21-33)
```csharp
    public ByteString ExtractConsensusExtraData(BlockHeader header)
    {
        var consensusExtraData =
            _blockExtraDataService.GetExtraDataFromBlockHeader(_consensusExtraDataProvider.BlockHeaderExtraDataKey,
                header);
        if (consensusExtraData == null)
            return null;

        var headerInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData);

        // Validate header information
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
    }
```

**File:** protobuf/aedpos_contract.proto (L243-264)
```text
message Round {
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
}
```

**File:** protobuf/aedpos_contract.proto (L266-301)
```text
message MinerInRound {
    // The order of the miner producing block.
    int32 order = 1;
    // Is extra block producer in the current round.
    bool is_extra_block_producer = 2;
    // Generated by secret sharing and used for validation between miner.
    aelf.Hash in_value = 3;
    // Calculated from current in value.
    aelf.Hash out_value = 4;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 5;
    // The expected mining time.
    google.protobuf.Timestamp expected_mining_time = 6;
    // The amount of produced blocks.
    int64 produced_blocks = 7;
    // The amount of missed time slots.
    int64 missed_time_slots = 8;
    // The public key of this miner.
    string pubkey = 9;
    // The InValue of the previous round.
    aelf.Hash previous_in_value = 10;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
    // The actual mining time, miners must fill actual mining time when they do the mining.
    repeated google.protobuf.Timestamp actual_mining_times = 13;
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
    // The amount of produced tiny blocks.
    int64 produced_tiny_blocks = 16;
    // The irreversible block height that current miner recorded.
    int64 implied_irreversible_block_height = 17;
}
```

**File:** src/AElf.OS.Network.Grpc/GrpcConstants.cs (L28-29)
```csharp
    public const int DefaultMaxReceiveMessageLength = 100 * 1024 * 1024;
    public const int DefaultMaxSendMessageLength = 100 * 1024 * 1024;
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L5-5)
```csharp
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L16-104)
```csharp
    private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
    {
        // According to current round information:
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };

        // Skip the certain initial miner during first several rounds. (When other nodes haven't produce blocks yet.)
        if (baseRound.RealTimeMinersInformation.Count != 1 &&
            Context.CurrentHeight < AEDPoSContractConstants.MaximumTinyBlocksCount.Mul(3))
        {
            string producedMiner = null;
            var result = true;
            for (var i = baseRound.RoundNumber; i > 0; i--)
            {
                var producedMiners = State.Rounds[i].RealTimeMinersInformation.Values
                    .Where(m => m.ActualMiningTimes.Any()).ToList();
                if (producedMiners.Count != 1)
                {
                    result = false;
                    break;
                }

                if (producedMiner == null)
                    producedMiner = producedMiners.Single().Pubkey;
                else if (producedMiner != producedMiners.Single().Pubkey) result = false;
            }

            if (result) return new ValidationResult { Success = true };
        }

        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };

        /* Ask several questions: */

        // Add basic providers at first.
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

        var service = new HeaderInformationValidationService(validationProviders);

        Context.LogDebug(() => $"Validating behaviour: {extraData.Behaviour.ToString()}");

        var validationResult = service.ValidateInformation(validationContext);

        if (validationResult.Success == false)
            Context.LogDebug(() => $"Consensus Validation before execution failed : {validationResult.Message}");

        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L50-50)
```csharp
        if (!isGeneratingTransactions) information.Round.DeleteSecretSharingInformation();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_GetLighterRound.cs (L7-14)
```csharp
    public void DeleteSecretSharingInformation()
    {
        var encryptedPieces = RealTimeMinersInformation.Values.Select(i => i.EncryptedPieces);
        foreach (var encryptedPiece in encryptedPieces) encryptedPiece.Clear();

        var decryptedPieces = RealTimeMinersInformation.Values.Select(i => i.DecryptedPieces);
        foreach (var decryptedPiece in decryptedPieces) decryptedPiece.Clear();
    }
```
