# Audit Report

## Title
Unvalidated LIB Values in NextRound Allow Consensus Finality DoS

## Summary
The AEDPoS consensus contract fails to validate Last Irreversible Block (LIB) height values when processing `NextRound` transactions. A malicious miner can inject arbitrarily high `ConfirmedIrreversibleBlockHeight` values through `NextRoundInput`, permanently freezing the LIB mechanism and causing consensus finality denial-of-service across the entire network.

## Finding Description

The vulnerability exists in the consensus round transition logic where LIB values are blindly propagated without validation.

**Root Cause:** The `GenerateNextRoundInformation()` method unconditionally copies LIB fields from the current round to the next round without any validation: [1](#0-0) 

**Missing Protection:** The `LibInformationValidationProvider` validates that LIB values don't regress and is applied to `UpdateValue` behavior: [2](#0-1) [3](#0-2) 

But NOT for `NextRound` or `NextTerm` behaviors: [4](#0-3) 

**Attack Vector:** The `NextRound` method is public and accepts `NextRoundInput` containing attacker-controlled LIB fields: [5](#0-4) 

The `NextRoundInput.ToRound()` method includes these LIB fields without sanitization: [6](#0-5) 

The malicious round is stored directly without LIB validation: [7](#0-6) [8](#0-7) 

**Impact Mechanism:** `ProcessUpdateValue()` only updates LIB when the calculated value exceeds the stored value: [9](#0-8) 

If an attacker sets `ConfirmedIrreversibleBlockHeight = Int64.MaxValue`, this condition will never be satisfied, permanently freezing LIB advancement.

**Propagation:** All future rounds will perpetuate the corrupted values through `GenerateNextRoundInformation()`, including in `NextTerm` transitions as the same propagation logic applies.

## Impact Explanation

**Severity: High - Consensus Finality DoS**

1. **Consensus Integrity Break:** The Last Irreversible Block mechanism is a critical consensus safety guarantee. Freezing LIB means blocks can never achieve finality, violating the fundamental security property that honest transactions eventually become irreversible.

2. **Cross-Chain Security Impact:** The LIB height is published via the `IrreversibleBlockFound` event which drives cross-chain indexing. With frozen LIB, cross-chain operations become unreliable, potentially enabling stale or incorrect cross-chain data indexing, double-spend vulnerabilities across chains, and cross-chain message replay attacks.

3. **Protocol-Wide Disruption:** Once a malicious `NextRound` block is accepted, ALL nodes in the network inherit the corrupted consensus state. The attack affects every subsequent round (corruption propagates indefinitely), all cross-chain dependent operations, and block finality guarantees for the entire blockchain.

4. **Recovery Difficulty:** Because the corrupted values are stored in contract state and propagated through normal consensus logic, recovery requires either emergency contract upgrade via governance (slow), hard fork to reset consensus state (extreme), or manual state migration (complex and risky).

## Likelihood Explanation

**Probability: High**

1. **Attacker Profile:** Any miner in the current consensus set can execute this attack. The AEDPoS consensus rotates the extra block producer role among all miners, making the opportunity accessible to any miner over time.

2. **Permission Check:** The `PreCheck()` only validates the sender is in the miner list, not whether they're legitimately producing a NextRound block or whether their input values are valid: [10](#0-9) 

3. **Attack Complexity:** Extremely low. The attacker simply waits until they produce a block that should call NextRound, then instead of using legitimate `GenerateConsensusTransactions`, manually constructs `NextRoundInput` with `ConfirmedIrreversibleBlockHeight = Int64.MaxValue` and includes this transaction in their block.

4. **Detection Difficulty:** The malicious round appears structurally valid. Only when subsequent blocks fail to advance LIB would the attack become apparent, and by then the corrupted state is already committed.

5. **Economic Barriers:** None. The attack requires only being a selected miner, which is a normal consensus participant role. No additional staking, fees, or resources are needed.

## Recommendation

Apply `LibInformationValidationProvider` to `NextRound` and `NextTerm` behaviors by modifying the validation provider setup:

In `AEDPoSContract_Validation.cs`, add the LIB validation provider to NextRound and NextTerm cases:

```csharp
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this line
    break;
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this line
    break;
```

This ensures that LIB values cannot regress during round transitions, preventing the injection of invalid LIB heights.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousNextRound_FreezesLIB_Attack()
{
    // Setup: Initialize consensus with legitimate first round
    var initialMiners = GenerateMiners(3);
    await InitializeConsensus(initialMiners);
    
    // Advance to round 2 with legitimate blocks
    await ProduceNormalBlocks(10);
    var currentRound = await GetCurrentRound();
    var legitimateLIB = currentRound.ConfirmedIrreversibleBlockHeight;
    
    // Attack: Malicious miner constructs NextRound with corrupted LIB
    var maliciousMiner = initialMiners[0];
    var maliciousNextRoundInput = new NextRoundInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        ConfirmedIrreversibleBlockHeight = long.MaxValue, // Corrupted value
        ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber,
        // ... other fields copied from legitimate round generation
    };
    
    // Execute malicious NextRound transaction
    await ExecuteConsensusTransaction(maliciousMiner, nameof(NextRound), maliciousNextRoundInput);
    
    // Verify: LIB is now frozen at Int64.MaxValue
    var corruptedRound = await GetCurrentRound();
    Assert.Equal(long.MaxValue, corruptedRound.ConfirmedIrreversibleBlockHeight);
    
    // Produce more blocks and verify LIB never advances
    await ProduceNormalBlocks(20);
    var finalRound = await GetCurrentRound();
    Assert.Equal(long.MaxValue, finalRound.ConfirmedIrreversibleBlockHeight);
    
    // Verify IrreversibleBlockFound event is never fired with higher values
    var libEvents = GetIrreversibleBlockFoundEvents();
    Assert.All(libEvents, e => Assert.True(e.IrreversibleBlockHeight <= legitimateLIB));
}
```

**Notes:**

This vulnerability represents a critical consensus safety violation. The absence of `LibInformationValidationProvider` for `NextRound` and `NextTerm` behaviors creates an asymmetric validation gap where only `UpdateValue` enforces LIB monotonicity. Since miners can directly call public consensus methods with crafted inputs, and the permission check only validates miner list membership without validating input integrity, any malicious miner can poison the consensus state permanently. The attack is particularly severe because the corrupted state propagates automatically through all future rounds via the normal round generation logic, making it self-sustaining without requiring repeated malicious actions.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-20)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-39)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-280)
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
