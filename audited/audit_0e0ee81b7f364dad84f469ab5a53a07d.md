### Title
Unvalidated LIB Values in NextRound Allow Consensus Finality DoS

### Summary
The `GenerateNextRoundInformation()` function blindly copies `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` from the current round without validation. A malicious miner producing a NextRound block can inject arbitrarily high values through `NextRoundInput`, permanently freezing LIB advancement and causing consensus finality DoS. The `LibInformationValidationProvider` is only applied to UpdateValue behavior, not to NextRound or NextTerm behaviors.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** The `GenerateNextRoundInformation()` method unconditionally copies LIB values from the current round to the next round without any validation of their correctness or monotonicity.

**Missing Protection:** During consensus validation, the `LibInformationValidationProvider` that checks LIB values don't go backwards is only added for `UpdateValue` behavior [2](#0-1) , but NOT for `NextRound` behavior [3](#0-2)  or `NextTerm` behavior [4](#0-3) .

**Attack Vector:** A malicious miner who becomes the extra block producer can submit a `NextRoundInput` with maliciously crafted LIB fields [5](#0-4) . The public `NextRound` method [6](#0-5)  accepts this input, converts it to a Round object [7](#0-6) , and stores it without validation.

**Propagation Mechanism:** Once corrupted values are stored in a Round, they propagate indefinitely through all future round transitions because `GenerateNextRoundInformation()` is called for each new round, perpetually copying the corrupted values.

**Impact on LIB Updates:** The `ProcessUpdateValue()` method only updates LIB if the newly calculated value is GREATER than `currentRound.ConfirmedIrreversibleBlockHeight` [8](#0-7) . If an attacker sets this to an arbitrarily high value (e.g., `Int64.MaxValue`), legitimate LIB calculations will never exceed it, permanently freezing LIB advancement.

### Impact Explanation

**Consensus Finality DoS:** By injecting an artificially high `ConfirmedIrreversibleBlockHeight` value, an attacker freezes the Last Irreversible Block (LIB) mechanism. No legitimate blocks can achieve finality because the comparison in ProcessUpdateValue will always fail. This violates the critical invariant that "LIB height rules" must be maintained.

**Cross-Chain Security Impact:** The LIB is consumed by cross-chain operations through the `IrreversibleBlockFound` event [9](#0-8) . With frozen LIB, cross-chain indexing and verification become unreliable, potentially allowing double-spend attacks across chains.

**Protocol-Wide Disruption:** All nodes in the network will have their consensus state corrupted once the malicious NextRound block is accepted. The corrupted LIB values persist in state and propagate through subsequent rounds, requiring manual intervention or hard fork to recover.

**Severity:** High - This is a consensus-level DoS that affects chain finality and cross-chain security, core protocol invariants.

### Likelihood Explanation

**Attacker Capabilities:** Any miner in the current miner list who becomes the extra block producer can execute this attack. The extra block producer is determined by consensus mechanism rotation, making this accessible to any active miner over time.

**Attack Complexity:** Very low. The attacker simply needs to:
1. Wait until they are the extra block producer for a round
2. Generate a `NextRoundInput` with `confirmed_irreversible_block_height` set to `Int64.MaxValue` or other high value
3. Submit the NextRound transaction

**Feasibility:** The attack is highly practical:
- The public `NextRound` method accepts attacker-controlled input
- No validation provider checks the LIB fields for NextRound behavior
- The attack requires no economic resources beyond being a valid miner
- Detection is difficult as the malicious round looks structurally valid

**Operational Constraints:** None. The attack can be executed immediately when the attacker becomes extra block producer.

**Probability:** High. Given the ease of execution and the rotating nature of extra block producer assignment, a motivated malicious miner can reliably execute this attack.

### Recommendation

**Immediate Fix:** Apply `LibInformationValidationProvider` to NextRound and NextTerm behaviors in the validation logic:

```csharp
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
```

Location: [10](#0-9) 

**Additional Validation:** In `GenerateNextRoundInformation()`, add defensive checks:
```csharp
// Validate LIB values are non-decreasing
Assert(nextRound.ConfirmedIrreversibleBlockHeight >= ConfirmedIrreversibleBlockHeight,
    "LIB height cannot decrease");
Assert(nextRound.ConfirmedIrreversibleBlockRoundNumber >= ConfirmedIrreversibleBlockRoundNumber,
    "LIB round number cannot decrease");
```

**Test Cases:**
1. Test that NextRound with lower LIB values is rejected
2. Test that NextRound with excessively high LIB values is rejected
3. Test that LIB advancement continues correctly across round transitions
4. Test that malformed NextRoundInput with corrupted LIB is detected during validation

### Proof of Concept

**Initial State:**
- Current round number: 100
- Current `ConfirmedIrreversibleBlockHeight`: 1000
- Current `ConfirmedIrreversibleBlockRoundNumber`: 99
- Blockchain actual LIB: 1000
- Attacker is scheduled as extra block producer for round 101

**Attack Steps:**

1. Attacker generates consensus extra data for NextRound but modifies it before submission
2. Creates `NextRoundInput` with:
   - `round_number`: 101 (valid)
   - `confirmed_irreversible_block_height`: 9223372036854775807 (Int64.MaxValue)
   - `confirmed_irreversible_block_round_number`: 9223372036854775806
   - All other fields: valid values from `GenerateNextRoundInformation()`
   
3. Submits NextRound transaction with malicious input

4. Validation passes because `LibInformationValidationProvider` is not applied to NextRound [3](#0-2) 

5. `ProcessNextRound` executes, storing the corrupted Round [11](#0-10) 

**Result:**
- Round 101 now has `ConfirmedIrreversibleBlockHeight` = 9223372036854775807
- All future rounds (102, 103, ...) copy this corrupted value via line 69-70
- In subsequent UpdateValue calls, the calculated LIB (e.g., 1200) fails the check `if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)` because `9223372036854775807 < 1200 = false`
- No `IrreversibleBlockFound` events are fired
- Chain's LIB is frozen at height 1000
- Cross-chain operations depending on LIB progression are disrupted

**Success Condition:** Monitor state after attack - `ConfirmedIrreversibleBlockHeight` in Round state remains at the malicious high value indefinitely, and no new LIB events are emitted despite blocks being produced.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-91)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** protobuf/aedpos_contract.proto (L471-474)
```text
    // The height of the confirmed irreversible block.
    int64 confirmed_irreversible_block_height = 7;
    // The round number of the confirmed irreversible block.
    int64 confirmed_irreversible_block_round_number = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L34-35)
```csharp
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-281)
```csharp
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockFoundLogEventProcessor.cs (L54-87)
```csharp
    private async Task ProcessLogEventAsync(Block block, IrreversibleBlockFound irreversibleBlockFound)
    {
        try
        {
            var chain = await _blockchainService.GetChainAsync();

            if (chain.LastIrreversibleBlockHeight > irreversibleBlockFound.IrreversibleBlockHeight)
                return;

            var libBlockHash = await _blockchainService.GetBlockHashByHeightAsync(chain,
                irreversibleBlockFound.IrreversibleBlockHeight, block.GetHash());
            if (libBlockHash == null) return;

            if (chain.LastIrreversibleBlockHeight == irreversibleBlockFound.IrreversibleBlockHeight) return;

            var blockIndex = new BlockIndex(libBlockHash, irreversibleBlockFound.IrreversibleBlockHeight);
            Logger.LogDebug($"About to set new lib height: {blockIndex.BlockHeight} " +
                            $"Event: {irreversibleBlockFound} " +
                            $"BlockIndex: {blockIndex.BlockHash} - {blockIndex.BlockHeight}");
            _taskQueueManager.Enqueue(
                async () =>
                {
                    var currentChain = await _blockchainService.GetChainAsync();
                    if (currentChain.LastIrreversibleBlockHeight < blockIndex.BlockHeight)
                        await _blockchainService.SetIrreversibleBlockAsync(currentChain, blockIndex.BlockHeight,
                            blockIndex.BlockHash);
                }, KernelConstants.UpdateChainQueueName);
        }
        catch (Exception e)
        {
            Logger.LogError(e, "Failed to resolve IrreversibleBlockFound event.");
            throw;
        }
    }
```
