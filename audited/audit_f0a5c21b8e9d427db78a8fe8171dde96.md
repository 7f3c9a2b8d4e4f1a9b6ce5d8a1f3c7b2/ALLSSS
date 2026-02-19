### Title
Insufficient Validation of ImpliedIrreversibleBlockHeight Enables Consensus Halt via LIB Manipulation

### Summary
The `LibInformationValidationProvider` only validates that `ImpliedIrreversibleBlockHeight` does not decrease, but does not enforce that it must equal or be reasonably close to the current block height. If more than 1/3 of elected miners collude to report stale `ImpliedIrreversibleBlockHeight` values, they can prevent Last Irreversible Block (LIB) progression, ultimately triggering a blockchain halt via automatic rollback mechanisms rather than just forcing excessive state retention.

### Finding Description

**Root Cause:**

The consensus contract generates `ImpliedIrreversibleBlockHeight` by setting it to `Context.CurrentHeight` for honest miners: [1](#0-0) 

However, the validation in `LibInformationValidationProvider.ValidateHeaderInformation()` only checks that the value does not decrease compared to the base round: [2](#0-1) 

There is no validation enforcing that `ImpliedIrreversibleBlockHeight` must equal `Context.CurrentHeight` or be within a reasonable range of the current block height.

**Exploitation Path:**

1. Malicious miners modify their node software to report stale `ImpliedIrreversibleBlockHeight` values (e.g., keep it constant or increase it very slowly)

2. During block production, `ProcessUpdateValue` stores whatever value miners provide: [3](#0-2) 

3. The LIB calculation uses `LastIrreversibleBlockHeightCalculator` which takes the value at position `(count-1)/3` of sorted implied heights from miners: [4](#0-3) 

4. If more than 1/3 of miners report low values, the 1/3 position in the sorted list remains low, preventing LIB progression: [5](#0-4) 

5. After `max(8, MaximumTinyBlocksCount)` rounds without LIB progression, the blockchain enters "Severe" status and fires `IrreversibleBlockHeightUnacceptable`: [6](#0-5) 

6. This triggers an automatic chain rollback to the stale LIB height: [7](#0-6) 

### Impact Explanation

**Concrete Harm:**
- **Blockchain Halt**: When the rollback occurs, nodes revert to the stale LIB height, orphaning all blocks produced since then. The chain cannot make forward progress, resulting in complete loss of liveness.
- **Transaction Loss**: All transactions included in blocks after the stale LIB are discarded during rollback.
- **Service Unavailability**: Users cannot execute transactions, smart contracts become unusable, and the entire blockchain network becomes non-functional.

**Affected Parties:**
- All network participants (users, dApp developers, node operators)
- The entire blockchain ecosystem loses availability
- Economic value is frozen as no transactions can be processed

**Severity Justification:**
This is worse than a storage DoS attack—it's a consensus halt attack. While the original question focused on forcing nodes to retain excessive historical state, the actual impact is far more severe: the blockchain loses liveness completely. The automatic rollback mechanism designed to protect against fork scenarios becomes a weapon that halts the chain when LIB progression is prevented.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Control over more than 1/3 of elected miner nodes (approximately 7 out of 21 typical miners based on the `MinersCountOfConsent` calculation) [8](#0-7) 

- Ability to modify node software to submit manipulated consensus data
- Miners are elected through voting and must lock 100,000 ELF as stake, but there is no explicit penalty mechanism for reporting incorrect `ImpliedIrreversibleBlockHeight` values (only for missing time slots)

**Attack Complexity:**
- Medium complexity: Requires coordinating multiple miners and modifying node software
- The attack is technically straightforward—miners simply provide stale values while continuing to produce blocks normally
- No detection mechanism specifically identifies which miners are reporting incorrect LIB values

**Economic Considerations:**
- Attackers risk their staked tokens and reputation, but the immediate penalty mechanism only applies to missed blocks (evil miner detection): [9](#0-8) 

- Malicious miners producing blocks normally would not be flagged as "evil" by the existing detection mechanism

**Probability Assessment:**
Medium-Low likelihood due to the requirement for 1/3+ miner collusion. However, in Byzantine Fault Tolerance systems, the expectation is that consensus should tolerate up to 1/3 Byzantine participants without losing liveness. This vulnerability violates that fundamental assumption.

### Recommendation

**Code-Level Mitigation:**

Add validation in `LibInformationValidationProvider.ValidateHeaderInformation()` to enforce that `ImpliedIrreversibleBlockHeight` must be reasonably close to the current block height:

```csharp
// In LibInformationValidationProvider.ValidateHeaderInformation()
// After line 30, add:

if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
{
    var providedImpliedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    if (providedImpliedHeight != 0)
    {
        // ImpliedIrreversibleBlockHeight should equal current height for UpdateValue behavior
        // Allow a small tolerance for edge cases
        var maxAllowedDifference = 1; // or AEDPoSContractConstants.MaximumTinyBlocksCount
        if (validationContext.ExtraData.Behaviour == AElfConsensusBehaviour.UpdateValue &&
            Math.Abs(validationContext.CurrentHeight - providedImpliedHeight) > maxAllowedDifference)
        {
            validationResult.Message = $"ImpliedIrreversibleBlockHeight ({providedImpliedHeight}) too far from current height ({validationContext.CurrentHeight}).";
            return validationResult;
        }
    }
}
```

**Additional Checks:**

Modify the consensus validation context to include `CurrentHeight`: [10](#0-9) 

**Test Cases:**

1. Test that a miner providing `ImpliedIrreversibleBlockHeight` significantly below `Context.CurrentHeight` fails validation
2. Test that LIB progresses normally when all miners provide correct values
3. Test that minority of miners (<1/3) providing incorrect values does not prevent LIB progression
4. Test that validation rejects stale values while allowing reasonable variance

### Proof of Concept

**Initial State:**
- 21 elected miners in the network
- Current block height: 10,000
- Current LIB height: 9,950
- 8 miners collude (>1/3)

**Attack Sequence:**

1. **Round N (Block 10,000-10,020)**:
   - 8 malicious miners report `ImpliedIrreversibleBlockHeight = 9,950` (stale value)
   - 13 honest miners report `ImpliedIrreversibleBlockHeight = 10,000+` (current height)
   - LIB calculation sorts: [9950, 9950, 9950, 9950, 9950, 9950, 9950, 9950, 10000+, ...]
   - Index `(21-1)/3 = 6` selects the 7th element = 9,950
   - LIB stays at 9,950 (no progression)

2. **Rounds N+1 through N+8**:
   - Attack continues, LIB remains at 9,950
   - Current block height advances to ~10,160
   - Gap between current round and LIB round exceeds `max(8, MaximumTinyBlocksCount)`

3. **Round N+9**:
   - `GetMaximumBlocksCount()` detects severe status
   - Fires `IrreversibleBlockHeightUnacceptable` event with distance = 10,160 - 9,950 = 210
   - System triggers `ResetChainToLibAsync()`
   - Chain rolls back to block 9,950
   - All blocks from 9,951 to 10,160 are orphaned
   - **Blockchain halts—cannot make forward progress**

**Expected vs Actual Result:**
- **Expected**: Validation should reject miners reporting `ImpliedIrreversibleBlockHeight` significantly below current height
- **Actual**: Validation only checks non-decrease, allowing stale values that halt the blockchain

**Success Condition:**
Attack succeeds when the chain enters rollback loop and loses liveness, preventing any new transactions from being finalized.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-30)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L266-282)
```csharp
        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-32)
```csharp
            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-67)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockHeightUnacceptableLogEventProcessor.cs (L54-64)
```csharp
        if (distanceToLib.DistanceToIrreversibleBlockHeight > 0)
        {
            Logger.LogDebug($"Distance to lib height: {distanceToLib.DistanceToIrreversibleBlockHeight}");
            Logger.LogDebug("Will rollback to lib height.");
            _taskQueueManager.Enqueue(
                async () =>
                {
                    var chain = await _blockchainService.GetChainAsync();
                    await _blockchainService.ResetChainToLibAsync(chain);
                }, KernelConstants.UpdateChainQueueName);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
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
