### Title
Missing LIB Height Validation in NextTerm Allows Consensus Finality Rollback

### Summary
The `ToRound()` method in `NextTermInput` preserves `ConfirmedIrreversibleBlockHeight` without validation, and the consensus validation logic does not apply `LibInformationValidationProvider` for `NextTerm` behavior. This allows a malicious miner producing the first block of a new term to manipulate the Last Irreversible Block (LIB) height downward, violating the fundamental consensus invariant that finality can never be reversed.

### Finding Description

**Root Cause:**

The `ToRound()` method directly copies `ConfirmedIrreversibleBlockHeight` from `NextTermInput` to the `Round` object without any validation: [1](#0-0) 

**Missing Validation:**

The consensus validation logic in `ValidateBeforeExecution` adds `LibInformationValidationProvider` for `UpdateValue` behavior but explicitly omits it for `NextTerm` behavior: [2](#0-1) 

The `LibInformationValidationProvider` checks that LIB heights never decrease: [3](#0-2) 

**Exploitation Path:**

When `ProcessNextTerm` is called, it converts the input to a Round object and stores it without validating the LIB height: [4](#0-3) 

The manipulated round with lowered LIB is stored via `AddRoundInformation` and becomes the base for future consensus validation: [5](#0-4) 

### Impact Explanation

**Consensus Integrity Violation:**

A malicious miner can roll back the consensus contract's understanding of which blocks are irreversible, violating the critical invariant that LIB heights must never decrease. This undermines the entire finality mechanism of the AEDPoS consensus.

**Cross-Chain Security:**

Cross-chain operations rely on LIB heights for security guarantees. A manipulated LIB could enable attacks on cross-chain indexing and verification, potentially allowing double-spending across chains.

**Chain State Integrity:**

The `IrreversibleBlockFoundLogEventProcessor` uses the consensus contract's LIB to update the chain's `LastIrreversibleBlockHeight`: [6](#0-5) 

While a manipulated lower LIB won't directly trigger a rollback (the event isn't fired), it corrupts the consensus contract's internal state, causing future LIB calculations to be based on incorrect baseline values.

**Severity:** HIGH - Violates core consensus finality guarantees, affects all network participants, enables potential double-spending and cross-chain attacks.

### Likelihood Explanation

**Attacker Prerequisites:**
- Must be a current miner (passes the `PreCheck` authorization): [7](#0-6) 

- Must be scheduled to produce the first block of a new term

**Attack Complexity:**
- LOW - Single malicious miner can execute the attack
- Requires waiting for term transition (happens regularly based on blockchain age and period seconds)
- No special economic cost beyond being an elected miner
- Block producers control the consensus extra data in blocks they produce

**Detection Difficulty:**
- Manipulated LIB values would be within valid ranges (past heights)
- No immediate event or alert triggered
- Corruption would appear as legitimate consensus data
- Would require external monitoring to detect LIB height decreases

**Economic Rationality:**
- High reward for sophisticated attackers (enable double-spending, cross-chain exploits)
- Low cost (just requires miner status and patience)

**Probability:** HIGH - Practical for any malicious miner, happens at regular term transitions.

### Recommendation

**Immediate Fix:**

Add `LibInformationValidationProvider` to the `NextTerm` behavior validation in `ValidateBeforeExecution`: [8](#0-7) 

Modify to include LIB validation:
```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new LibInformationValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
```

**Additional Safeguards:**

1. Add explicit validation in `ProcessNextTerm` before accepting the round:
   - Verify `nextRound.ConfirmedIrreversibleBlockHeight >= currentRound.ConfirmedIrreversibleBlockHeight`
   - Verify `nextRound.ConfirmedIrreversibleBlockRoundNumber >= currentRound.ConfirmedIrreversibleBlockRoundNumber`

2. Add assertion in `ToRound()` or make it validate against current state before conversion

3. Add unit tests specifically validating that NextTerm transactions with manipulated LIB heights are rejected

4. Add integration tests verifying LIB height monotonicity across term transitions

### Proof of Concept

**Initial State:**
- Current term number: N
- Current round with `ConfirmedIrreversibleBlockHeight = 10000`
- Attacker is miner scheduled to produce first block of term N+1

**Attack Steps:**

1. Attacker's node generates normal consensus data for NextTerm via `GetConsensusExtraDataForNextTerm`, which correctly copies current LIB: [9](#0-8) 

2. Attacker modifies the consensus extra data before including in block, changing `NextTermInput.ConfirmedIrreversibleBlockHeight` from 10000 to 9000

3. Attacker produces block with manipulated consensus data

4. Block validation calls `ValidateConsensusBeforeExecution`, which does NOT check LIB for NextTerm

5. Block execution calls `NextTerm` → `ProcessConsensusInformation` → `ProcessNextTerm`

6. Line 163 converts input to Round with manipulated LIB=9000

7. Line 196 stores this round with lowered LIB

**Expected Result:**
Block should be rejected due to decreasing LIB height

**Actual Result:**
Block is accepted, consensus contract now has `ConfirmedIrreversibleBlockHeight = 9000`, rolling back finality by 1000 blocks

**Success Condition:**
Query the new round's `ConfirmedIrreversibleBlockHeight` - it will be 9000 instead of maintaining or increasing from 10000, proving the LIB was successfully rolled back.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-196)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockFoundLogEventProcessor.cs (L54-80)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```
