### Title
Non-Deterministic Miner Ordering in Term Generation Causes Consensus Forks

### Summary
The `GenerateFirstRoundOfNewTerm()` method sorts miners by only the first byte of their public keys using LINQ's `orderby descending`, which does not guarantee stable ordering for equal values. When multiple miners have identical first bytes, different nodes may produce different miner orderings, leading to divergent consensus states and blockchain forks.

### Finding Description

The vulnerability exists in the miner sorting logic that determines the order and roles for the first round of each consensus term. [1](#0-0) 

The code creates a dictionary mapping each miner's hex public key to its first byte value (`miner[0]`), then sorts by this byte value in descending order. However, LINQ's `OrderBy` operation in C# does not guarantee stable sorting - when multiple elements have equal sort keys (same first byte), their relative order is undefined and implementation-dependent.

**Root Cause**: The sorting uses only `obj.Value` (the first byte) as the sort key without any secondary tie-breaker. Different .NET runtime implementations, different execution contexts, or even different runs on the same node may order miners with identical first bytes differently.

**Execution Path**:
1. During term transitions, the extra block producer calls `NextTerm` [2](#0-1) 

2. This generates consensus extra data via `GetConsensusExtraDataForNextTerm` [3](#0-2) 

3. Which calls `GenerateFirstRoundOfNextTerm` to create the new round [4](#0-3) 

4. This invokes the vulnerable `GenerateFirstRoundOfNewTerm` method on the MinerList [5](#0-4) 

**Why Existing Protections Fail**: While the consensus validation logic detects round hash mismatches, it only rejects divergent blocks rather than preventing the divergence: [6](#0-5) 

When nodes generate different round hashes due to different miner orderings, validation fails with "Current round information is different with consensus extra data", causing consensus deadlock rather than resolution.

### Impact Explanation

**Consensus Integrity Violation (Critical)**: Different nodes will generate different consensus states for the same term, violating the fundamental blockchain invariant that all honest nodes must agree on state.

**Specific Consequences**:
1. **Extra Block Producer Divergence**: The first miner in the sorted list becomes the extra block producer. Different orderings mean different nodes designate different extra block producers. [7](#0-6) 

2. **Mining Time Slot Conflicts**: Each miner's `Order` and `ExpectedMiningTime` depend on their position in the sorted list. Divergent orderings cause miners to have conflicting time slots across nodes. [8](#0-7) 

3. **Consensus Deadlock**: Nodes cannot validate each other's blocks because round hashes differ, preventing the network from making progress and potentially causing permanent chain split.

4. **Scope**: Affects all consensus participants and all dependent contracts (governance, token, treasury, cross-chain) as they rely on valid consensus state.

### Likelihood Explanation

**Probability: HIGH** - This is not a theoretical attack but a naturally occurring bug that will manifest without any malicious action.

**Birthday Paradox Analysis**: With 256 possible values for the first byte and ~20-100 miners in typical AElf networks, the probability of at least two miners sharing a first byte is:
- 20 miners: ~55% probability
- 50 miners: ~99.7% probability
- 100 miners: ~99.999% probability

**No Attack Required**: The vulnerability triggers naturally when:
1. Miners are selected through the normal election process
2. At least two miners happen to have public keys starting with the same byte (highly likely)
3. A term transition occurs (happens regularly per protocol design)

**Execution Practicality**: 
- Entry point is the normal `NextTerm` consensus method
- No special permissions or preconditions needed beyond natural miner selection
- Will manifest during routine term transitions
- Non-determinism may vary across different node implementations, OS versions, or .NET runtime versions

**Detection Difficulty**: The issue may go unnoticed in homogeneous test environments where all nodes run identical software/hardware, only manifesting in production with diverse node configurations.

### Recommendation

**Immediate Fix**: Add a secondary sort key using the full public key hex string to ensure deterministic ordering:

```csharp
var sortedMiners =
    (from obj in Pubkeys
            .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
        orderby obj.Value descending, obj.Key
        select obj.Key).ToList();
```

The fix requires adding `, obj.Key` to the orderby clause in all implementations:
- Main contract implementation [1](#0-0) 

- Kernel extension implementation [9](#0-8) 

- Side chain implementation [10](#0-9) 

- All test implementations (19+ files found)

**Additional Safeguards**:
1. Add determinism validation tests that verify identical output across multiple executions with same input
2. Add unit tests specifically for miners with identical first bytes
3. Consider using a cryptographic hash of the full public key instead of just the first byte for better distribution
4. Document the sorting algorithm explicitly in code comments

**Migration**: After deployment, trigger a coordinated term transition to ensure all nodes adopt the new deterministic ordering simultaneously.

### Proof of Concept

**Initial State**:
- Network has elected miners with public keys where at least two share the same first byte
- Example: Miner A's pubkey starts with `0x5A`, Miner B's pubkey starts with `0x5A`
- Current term is ending, term transition is imminent

**Execution Steps**:
1. Extra block producer of current term produces a block calling `NextTerm`
2. The block producer's node executes `GenerateFirstRoundOfNextTerm`
3. For miners with identical first bytes (0x5A), LINQ `orderby` produces ordering: [Miner A, Miner B]
4. Round is generated with Miner A as extra block producer (Order=1)
5. Block is broadcast with this round information in consensus extra data

**Divergent State**:
1. Another node receives and validates the block
2. That node independently calculates what the round should be
3. Due to non-deterministic LINQ ordering, it orders as: [Miner B, Miner A]
4. Its calculated round has Miner B as extra block producer (Order=1)
5. Round hash comparison fails: `headerInformation.Round.GetHash() != currentRound.GetHash()` [11](#0-10) 

6. Validation returns failure: "Current round information is different with consensus extra data" [12](#0-11) 

**Result**: 
- Block is rejected by validating nodes
- Consensus deadlock occurs as different nodes cannot agree on round information
- Network splits or stalls until manual intervention
- Expected: All nodes agree on same round | Actual: Nodes generate different rounds for same term

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L15-19)
```csharp
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L27-28)
```csharp
            // The first miner will be the extra block producer of first round of each term.
            if (i == 0) minerInRound.IsExtraBlockProducer = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L30-33)
```csharp
            minerInRound.Pubkey = sortedMiners[i];
            minerInRound.Order = i + 1;
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-220)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
        Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
        if (firstRoundOfNextTerm.RealTimeMinersInformation.ContainsKey(pubkey))
            firstRoundOfNextTerm.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = firstRoundOfNextTerm,
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-257)
```csharp
    private Round GenerateFirstRoundOfNextTerm(string senderPubkey, int miningInterval)
    {
        Round newRound;
        TryToGetCurrentRoundInformation(out var currentRound);

        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
        }
        else
        {
            // Miners of new round are same with current round.
            var miners = new MinerList();
            miners.Pubkeys.AddRange(
                currentRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
            newRound = miners.GenerateFirstRoundOfNewTerm(currentRound.GetMiningInterval(),
                Context.CurrentBlockTime, currentRound);
        }

        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;

        newRound.BlockchainAge = GetBlockchainAge();

        if (newRound.RealTimeMinersInformation.ContainsKey(senderPubkey))
            newRound.RealTimeMinersInformation[senderPubkey].ProducedBlocks = 1;
        else
            UpdateCandidateInformation(senderPubkey, 1, 0);

        newRound.ExtraBlockProducerOfPreviousRound = senderPubkey;

        return newRound;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-113)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Extensions/MinerListExtensions.cs (L15-19)
```csharp
        var sortedMiners =
            (from obj in miners.Pubkeys.Distinct()
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```

**File:** src/AElf.Blockchains.SideChain/Protobuf/MinerListExtension.cs (L14-18)
```csharp
        var sortedMiners =
            (from obj in miners.Pubkeys.Distinct()
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```
