# Audit Report

## Title
Duplicate FinalOrderOfNextRound Values Bypass Validation Due to Incorrect Distinct() Usage

## Summary
The `NextRoundMiningOrderValidationProvider` incorrectly validates mining order uniqueness by applying `.Distinct()` to `MinerInRound` protobuf message objects instead of their `FinalOrderOfNextRound` values. This allows a malicious miner to submit a NextRound block with duplicate order assignments, causing multiple miners to attempt block production at identical time slots, resulting in consensus failure and blockchain forks.

## Finding Description

The vulnerability exists in the validation logic that ensures all miners have unique mining orders for the next round.

**Root Cause:** 

The validation provider applies `.Distinct()` to a collection of `MinerInRound` objects. [1](#0-0) 

Since `MinerInRound` is a protobuf message with multiple fields including pubkey, OutValue, Signature, InValue, Order, ExpectedMiningTime, and FinalOrderOfNextRound, [2](#0-1)  protobuf equality comparison evaluates ALL fields, not just `FinalOrderOfNextRound`. Therefore, two miners with identical `FinalOrderOfNextRound` values (e.g., both have order 3) but different pubkeys are considered distinct objects, and the validation incorrectly passes.

**Attack Vector:**

A malicious miner can craft a `NextRoundInput` with duplicate `FinalOrderOfNextRound` values and submit it via the public `NextRound` method. [3](#0-2) 

The flawed validation allows the malicious data through, and the corrupted round is processed and stored in state. [4](#0-3) 

**Consensus Corruption:**

When the next round is generated from this corrupted data, the `GenerateNextRoundInformation` method directly assigns each miner's `Order` from their `FinalOrderOfNextRound`. [5](#0-4) 

Miners with duplicate `FinalOrderOfNextRound` values receive identical `Order` and `ExpectedMiningTime` values, causing them to attempt block production at the exact same time slot, violating the fundamental consensus invariant of one miner per time slot.

## Impact Explanation

**Consensus Integrity Violation:**

Multiple miners receive identical time slots, causing:
- Simultaneous block production attempts by different miners at the same timestamp
- Different nodes may accept different valid blocks from different miners
- Blockchain forks as the network diverges on the canonical chain
- Complete consensus mechanism breakdown
- Potential network partition into incompatible states

**Severity Justification - HIGH:**

1. Directly violates the critical "unique mining time slot" consensus invariant
2. Causes immediate, network-wide consensus failure
3. Affects all participants - validators cannot reach agreement on canonical chain
4. No built-in recovery mechanism once corrupted round data is persisted in immutable blockchain state
5. Disrupts chain finality, affecting all dependent applications and cross-chain operations

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an active miner in the current consensus round
- Must have the opportunity to produce a NextRound block (when terminating a round)
- Can construct arbitrary `NextRoundInput` data for submission

**Attack Complexity - LOW:**

The attacker only needs to:
1. Wait for their turn to produce a NextRound block
2. Generate a `NextRoundInput` structure
3. Manually assign duplicate `FinalOrderOfNextRound` values to multiple miners in the `RealTimeMinersInformation` dictionary
4. Submit via the public `NextRound` method - the flawed validation guarantees it passes

**Feasibility - HIGH:**

- NextRound blocks are produced regularly (at least once per round, typically every few minutes)
- Any miner in the consensus set can exploit this during their NextRound turn
- No additional privileges required beyond being a current miner (obtainable through election process)
- The exploit is deterministic - the validation flaw guarantees success
- Attack is repeatable and causes immediate observable impact

**Detection Difficulty:**

- The validation returns success for malicious data, providing no warning
- Corruption manifests when the subsequent round attempts to use the data
- By that time, the corrupted round data is already persisted in blockchain state

## Recommendation

Fix the validation logic to check uniqueness of `FinalOrderOfNextRound` values themselves, not the entire `MinerInRound` objects:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Extract the value first
    .Distinct()
    .Count();
```

This ensures that the validation properly detects duplicate order assignments regardless of other field differences in the `MinerInRound` objects.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Create a valid `NextRoundInput` with correct structure
2. Modify the `RealTimeMinersInformation` to assign the same `FinalOrderOfNextRound` value to two different miners (e.g., both miners get order 3)
3. Ensure other fields differ (different pubkeys, OutValues, etc.)
4. Submit this input to the `NextRound` method
5. Observe that validation passes (when it should fail)
6. Verify that both miners are assigned identical `Order` and `ExpectedMiningTime` in the generated next round
7. Confirm consensus failure when both miners attempt to produce blocks at the same time

The test would validate that the current code incorrectly allows duplicate orders while the fixed version properly rejects them.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L266-290)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-165)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```
