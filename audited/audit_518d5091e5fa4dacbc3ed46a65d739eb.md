### Title
Nothing-at-Stake: Miners Can Produce Blocks on Multiple Forks Without Detection or Penalty

### Summary
The `LibInformationValidationProvider.ValidateHeaderInformation()` performs stateless validation that does not detect when miners produce blocks on multiple competing forks. The system lacks any mechanism to identify or penalize double-signing behavior, allowing rational miners to hedge their bets across all forks without consequence, undermining consensus security and finality guarantees.

### Finding Description

The vulnerability exists in the consensus validation layer where blocks are validated before execution. The `LibInformationValidationProvider.ValidateHeaderInformation()` only verifies that LIB values do not regress, but performs no cross-fork consistency checks: [1](#0-0) 

The validation context contains only the BaseRound (current node state) and ProvidedRound (from the block being validated), with no information about which specific blocks a miner has already produced or which fork/branch the block belongs to: [2](#0-1) 

When a fork occurs at height H with branches A and B:
- Nodes on Branch A validate blocks against Branch A's state (BaseRound from A)
- Nodes on Branch B validate blocks against Branch B's state (BaseRound from B)
- A miner can produce Block_A at height H+1 extending Branch A
- The same miner can produce Block_B at height H+1 extending Branch B
- Both blocks pass validation on their respective branches independently
- No detection or penalty mechanism exists

The only evil miner detection mechanism checks for missed time slots, not double-signing: [3](#0-2) 

The Election Contract's `UpdateCandidateInformation` can mark nodes as evil, but only through manual governance action by the Emergency Response Organization or automatic detection by the consensus contract for missed time slots: [4](#0-3) 

There is no mechanism to submit cryptographic proof of double-signing, and no automated detection of miners producing blocks on multiple forks. The documentation claims "if a vicious node mines in two forked Blockchains simultaneously to attack the network, that node would be voted out" but provides no implementation: [5](#0-4) 

The mining service accepts any PreviousBlockHash without checking if the miner has already produced a block at that height on a different fork: [6](#0-5) 

### Impact Explanation

This vulnerability fundamentally undermines the consensus security model:

1. **Consensus Integrity Violation**: Miners can produce blocks on all competing forks simultaneously without risk, creating the classic "nothing-at-stake" problem where rational miners should always hedge across all forks since there is no penalty for doing so.

2. **Delayed Finality**: When forks occur, miners producing blocks on multiple branches can extend the fork duration, delaying the point at which the Last Irreversible Block (LIB) advances and consensus finalizes.

3. **Broken Security Assumptions**: The system claims to detect and punish this behavior through voting, but the detection mechanism does not exist. This creates a false sense of security while the actual protocol is vulnerable.

4. **Protocol-Wide Impact**: Affects all participants relying on consensus finality guarantees, including cross-chain operations that depend on irreversible block heights.

The severity is Critical because it violates the "Consensus & Cross-Chain Integrity" invariant requiring correct round transitions and miner schedule integrity.

### Likelihood Explanation

**Attacker Capabilities**: Any elected miner (Core Data Center) can execute this attack. Miners are already expected to maintain high-availability infrastructure and can easily track multiple forks.

**Attack Complexity**: LOW
- Forks occur naturally due to network partitions or timing issues in distributed systems
- Miner runs nodes tracking both fork branches
- Miner requests consensus commands from nodes on each fork
- Miner produces and broadcasts blocks on both forks
- Each fork validates blocks independently without cross-fork checks

**Feasibility Conditions**:
- Forks are acknowledged as possible in the system design (longest chain rule for resolution)
- No additional permissions or compromises required beyond being an elected miner
- The time slot mechanism does not prevent this (both forks may have identical time slot schedules until they diverge significantly)

**Economic Rationality**: Extremely high. Rational miners should ALWAYS engage in this behavior when forks occur because:
- Zero cost (no detection or penalty)
- Positive expected value (ensures blocks on whichever fork wins)
- No reputational damage (no one can prove double-signing without detection mechanism)

**Detection Constraints**: None. The system has no mechanism to detect this behavior, and manual governance action requires first becoming aware of the issue, which is difficult without automated monitoring.

**Probability**: HIGH whenever forks occur, which is a natural occurrence in any distributed blockchain system.

### Recommendation

Implement cryptographic double-signing detection and slashing:

1. **Add Block Production Tracking**: Extend the consensus state to track which specific blocks (by hash) each miner has produced at each height. Store a mapping of `miner_pubkey -> height -> block_hash` in the consensus contract state.

2. **Add Evidence Submission Mechanism**: Create a public function `SubmitDoubleSigningEvidence(proof)` that accepts:
   - Two block headers at the same height
   - Both signed by the same miner public key
   - Different block hashes
   - Valid signatures

3. **Automated Detection**: During block validation, check if the miner has already produced a different block at the same height on the current chain or any tracked fork.

4. **Slashing Implementation**: When double-signing is detected:
   - Immediately mark miner as evil via `UpdateCandidateInformation`
   - Remove from current round
   - Ban from future elections
   - Slash staked tokens if staking is implemented

5. **Update LibInformationValidationProvider**: Add validation that queries the block production history:
```
// Pseudo-code - add to ValidateHeaderInformation
if (State.MinerBlockProductionHistory[pubkey][currentHeight] != null 
    && State.MinerBlockProductionHistory[pubkey][currentHeight] != providedBlockHash) {
    validationResult.Message = "Double-signing detected";
    return validationResult;
}
```

6. **Test Cases**: Add comprehensive tests for:
   - Detecting same miner producing two blocks at same height
   - Evidence submission and verification
   - Slashing execution
   - Prevention of false positives (same block propagated to different nodes)

### Proof of Concept

**Initial State**:
- Chain at height 100, miners M1, M2, M3 elected
- Network partition occurs creating Fork A and Fork B
- Both forks at height 100 with different block hashes

**Attack Sequence**:

1. **Fork Creation**: Network partition causes Fork A (nodes N1, N2) and Fork B (nodes N3, N4) to diverge at height 100

2. **Miner M1's Time Slot**: At time T, M1 is scheduled to produce block at height 101
   - M1 connects to node N1 (tracking Fork A)
   - Calls GetConsensusCommand, receives command for Block_A extending Fork A
   - Produces Block_A with PreviousBlockHash = Hash_A_100
   - Signs Block_A with M1's private key
   - Broadcasts Block_A to Fork A nodes

3. **Double-Signing**: Simultaneously, M1:
   - Connects to node N3 (tracking Fork B)
   - Calls GetConsensusCommand, receives command for Block_B extending Fork B
   - Produces Block_B with PreviousBlockHash = Hash_B_100
   - Signs Block_B with M1's private key (same key, different content)
   - Broadcasts Block_B to Fork B nodes

4. **Validation Passes on Both Forks**:
   - Fork A nodes validate Block_A: `ValidateHeaderInformation()` checks BaseRound (from Fork A) vs ProvidedRound (in Block_A) → PASS
   - Fork B nodes validate Block_B: `ValidateHeaderInformation()` checks BaseRound (from Fork B) vs ProvidedRound (in Block_B) → PASS
   - No cross-fork validation occurs

5. **No Penalty Triggered**:
   - `TryToDetectEvilMiners()` only checks missed time slots → M1 produced blocks on time → PASS
   - No mechanism to detect M1 produced two different blocks at height 101
   - M1 continues mining on both forks without consequences

**Expected Result**: System should detect double-signing and penalize M1

**Actual Result**: Both blocks are accepted on their respective forks, M1 receives no penalty, attack succeeds

**Success Condition**: M1 successfully produces blocks on both forks at height 101 with no detection or penalty, demonstrating the nothing-at-stake vulnerability.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L8-34)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var baseRound = validationContext.BaseRound;
        var providedRound = validationContext.ProvidedRound;
        var pubkey = validationContext.SenderPubkey;
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }

        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L8-41)
```csharp
public class ConsensusValidationContext
{
    public long CurrentTermNumber { get; set; }
    public long CurrentRoundNumber { get; set; }

    /// <summary>
    ///     We can trust this because we already validated the pubkey
    ///     during `AEDPoSExtraDataExtractor.ExtractConsensusExtraData`
    /// </summary>
    public string SenderPubkey => ExtraData.SenderPubkey.ToHex();

    /// <summary>
    ///     Round information fetch from StateDb.
    /// </summary>
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;

    /// <summary>
    ///     Previous round information fetch from StateDb.
    /// </summary>
    public Round PreviousRound { get; set; }

    /// <summary>
    ///     This filed is to prevent one miner produces too many continues blocks
    ///     (which may cause problems to other parts).
    /// </summary>
    public LatestPubkeyToTinyBlocksCount LatestPubkeyToTinyBlocksCount { get; set; }

    public AElfConsensusHeaderInformation ExtraData { get; set; }
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L83-120)
```csharp
    public override Empty UpdateCandidateInformation(UpdateCandidateInformationInput input)
    {
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) ==
            Context.Sender || Context.Sender == GetEmergencyResponseOrganizationAddress(),
            "Only consensus contract can update candidate information.");

        var candidateInformation = State.CandidateInformationMap[input.Pubkey];
        if (candidateInformation == null) return new Empty();

        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
            var rankingList = State.DataCentersRankingList.Value;
            if (rankingList.DataCenters.ContainsKey(input.Pubkey))
            {
                rankingList.DataCenters[input.Pubkey] = 0;
                UpdateDataCenterAfterMemberVoteAmountChanged(rankingList, input.Pubkey, true);
                State.DataCentersRankingList.Value = rankingList;
            }

            Context.LogDebug(() => $"Marked {input.Pubkey.Substring(0, 10)} as an evil node.");
            Context.Fire(new EvilMinerDetected { Pubkey = input.Pubkey });
            State.CandidateInformationMap.Remove(input.Pubkey);
            var candidates = State.Candidates.Value;
            candidates.Value.Remove(ByteString.CopyFrom(publicKeyByte));
            State.Candidates.Value = candidates;
            RemoveBeneficiary(input.Pubkey);
            return new Empty();
        }

        candidateInformation.ProducedBlocks = candidateInformation.ProducedBlocks.Add(input.RecentlyProducedBlocks);
        candidateInformation.MissedTimeSlots =
            candidateInformation.MissedTimeSlots.Add(input.RecentlyMissedTimeSlots);
        State.CandidateInformationMap[input.Pubkey] = candidateInformation;
        return new Empty();
    }
```

**File:** docs-sphinx/protocol/consensus.md (L81-81)
```markdown
In the systematic design, aelf defines that only one node generates blocks within a certain period. Therefore, it is unlikely for a fork to happen in an environment where mining nodes are working under good connectivity. If multiple orphan node groups occur due to network problems, the system will adopt the longest chain since that is 19 the chain that most likely comes from the orphan node group with largest number of mining nodes. If a vicious node mines in two forked Blockchains simultaneously to attack the network, that node would be voted out of the entire network.
```

**File:** src/AElf.Kernel/Miner/Application/MiningService.cs (L45-98)
```csharp
    public async Task<BlockExecutedSet> MineAsync(RequestMiningDto requestMiningDto, List<Transaction> transactions,
        Timestamp blockTime)
    {
        try
        {
            using var cts = new CancellationTokenSource();
            var expirationTime = blockTime + requestMiningDto.BlockExecutionTime;
            if (expirationTime < TimestampHelper.GetUtcNow())
            {
                cts.Cancel();
            }
            else
            {
                var ts = (expirationTime - TimestampHelper.GetUtcNow()).ToTimeSpan();
                if (ts.TotalMilliseconds > int.MaxValue) ts = TimeSpan.FromMilliseconds(int.MaxValue);

                cts.CancelAfter(ts);
            }

            var block = await GenerateBlock(requestMiningDto.PreviousBlockHash, requestMiningDto.PreviousBlockHeight, blockTime);
            var systemTransactions = await GenerateSystemTransactions(requestMiningDto.PreviousBlockHash, requestMiningDto.PreviousBlockHeight);
            
            _systemTransactionExtraDataProvider.SetSystemTransactionCount(systemTransactions.Count,
                block.Header);
            
            var txTotalCount = transactions.Count + systemTransactions.Count;

            var pending = txTotalCount > requestMiningDto.TransactionCountLimit
                ? transactions
                    .Take(requestMiningDto.TransactionCountLimit - systemTransactions.Count)
                    .ToList()
                : transactions;
            var blockExecutedSet = await _blockExecutingService.ExecuteBlockAsync(block.Header,
                systemTransactions, pending, cts.Token);

            block = blockExecutedSet.Block;
            await SignBlockAsync(block);
            if (block.Body.TransactionsCount > 2)
            {
                Logger.LogInformation("Generated block: {Block}, " +
                                      "previous: {PreviousBlockHash}, " +
                                      "executed transactions: {TransactionsCount}, " +
                                      "not executed transactions {NotExecutedTransactionsCount}",
                    block.ToDiagnosticString(), block.Header.PreviousBlockHash.ToHex(), block.Body.TransactionsCount,
                    pending.Count + systemTransactions.Count - block.Body.TransactionsCount);
            }
            return blockExecutedSet;
        }
        catch (Exception e)
        {
            Logger.LogError(e, "Failed while mining block");
            throw;
        }
    }
```
