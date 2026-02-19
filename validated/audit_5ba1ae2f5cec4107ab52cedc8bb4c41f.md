# Audit Report

## Title
Unvalidated LIB Values in NextRound Allow Consensus Finality DoS

## Summary
The AEDPoS consensus contract fails to validate Last Irreversible Block (LIB) height values when processing `NextRound` transactions. A malicious miner can inject arbitrarily high `ConfirmedIrreversibleBlockHeight` values through `NextRoundInput`, permanently freezing the LIB mechanism and causing consensus finality denial-of-service across the entire network.

## Finding Description

The vulnerability exists in the consensus round transition logic where LIB values are blindly propagated without validation.

**Root Cause:** The `GenerateNextRoundInformation()` method unconditionally copies LIB fields from the current round to the next round: [1](#0-0) 

**Missing Protection:** The `LibInformationValidationProvider` that validates LIB values don't regress is only applied to `UpdateValue` behavior: [2](#0-1) 

But NOT for `NextRound` or `NextTerm` behaviors: [3](#0-2) 

**Attack Vector:** The `NextRound` method is public and accepts `NextRoundInput` containing attacker-controlled LIB fields: [4](#0-3) 

The `NextRoundInput.ToRound()` method includes these LIB fields without sanitization: [5](#0-4) 

The malicious round is stored directly without LIB validation: [6](#0-5) [7](#0-6) 

**Impact Mechanism:** `ProcessUpdateValue()` only updates LIB when the calculated value exceeds the stored value: [8](#0-7) 

If an attacker sets `ConfirmedIrreversibleBlockHeight = Int64.MaxValue`, this condition will never be satisfied, permanently freezing LIB advancement.

**Propagation:** All future rounds will perpetuate the corrupted values through `GenerateNextRoundInformation()`, including in `NextTerm` transitions: [9](#0-8) 

## Impact Explanation

**Severity: High - Consensus Finality DoS**

1. **Consensus Integrity Break:** The Last Irreversible Block mechanism is a critical consensus safety guarantee. Freezing LIB means blocks can never achieve finality, violating the fundamental security property that honest transactions eventually become irreversible.

2. **Cross-Chain Security Impact:** The LIB height is published via the `IrreversibleBlockFound` event which drives cross-chain indexing. With frozen LIB, cross-chain operations become unreliable, potentially enabling:
   - Stale or incorrect cross-chain data indexing
   - Double-spend vulnerabilities across chains
   - Cross-chain message replay attacks

3. **Protocol-Wide Disruption:** Once a malicious `NextRound` block is accepted, ALL nodes in the network inherit the corrupted consensus state. The attack affects:
   - Every subsequent round (corruption propagates indefinitely)
   - All cross-chain dependent operations
   - Block finality guarantees for the entire blockchain

4. **Recovery Difficulty:** Because the corrupted values are stored in contract state and propagated through normal consensus logic, recovery requires either:
   - Emergency contract upgrade via governance (slow)
   - Hard fork to reset consensus state (extreme)
   - Manual state migration (complex and risky)

## Likelihood Explanation

**Probability: High**

1. **Attacker Profile:** Any miner in the current consensus set can execute this attack. The AEDPoS consensus rotates the extra block producer role among all miners, making the opportunity accessible to any miner over time.

2. **Permission Check:** The `PreCheck()` only validates the sender is in the miner list, not whether they're legitimately producing a NextRound block: [10](#0-9) 

3. **Attack Complexity:** Extremely low. The attacker simply:
   - Waits until they produce a block that should call NextRound
   - Instead of using legitimate `GenerateConsensusTransactions`, manually constructs `NextRoundInput` with `ConfirmedIrreversibleBlockHeight = Int64.MaxValue`
   - Includes this transaction in their block

4. **Detection Difficulty:** The malicious round appears structurally valid. Only when subsequent blocks fail to advance LIB would the attack become apparent, and by then the corrupted state is already committed.

5. **Economic Barriers:** None. The attack requires only being a selected miner, which is a normal consensus participant role. No additional staking, fees, or resources are needed.

## Recommendation

Add `LibInformationValidationProvider` to the validation pipeline for `NextRound` and `NextTerm` behaviors:

```csharp
// In AEDPoSContract_Validation.cs, modify ValidateBeforeExecution:
switch (extraData.Behaviour)
{
    case AElfConsensusBehaviour.UpdateValue:
        validationProviders.Add(new UpdateValueValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider());
        break;
    case AElfConsensusBehaviour.NextRound:
        validationProviders.Add(new NextRoundMiningOrderValidationProvider());
        validationProviders.Add(new RoundTerminateValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
    case AElfConsensusBehaviour.NextTerm:
        validationProviders.Add(new RoundTerminateValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
}
```

Additionally, add bounds validation in `GenerateNextRoundInformation()` and `GenerateFirstRoundOfNextTerm()` to ensure LIB values are monotonically increasing and don't exceed the current block height.

## Proof of Concept

```csharp
[Fact]
public async Task NextRound_WithMaliciousLIBValues_FreezesFinality()
{
    // Setup: Initialize consensus with legitimate first round
    var initialMiners = GenerateInitialMiners(3);
    await InitializeConsensus(initialMiners);
    
    // Produce several legitimate blocks to establish baseline LIB
    for (int i = 0; i < 10; i++)
    {
        await ProduceNormalBlock(initialMiners[i % 3]);
    }
    
    var legitimateLIB = await GetCurrentLIBHeight();
    Assert.True(legitimateLIB > 0, "LIB should have advanced");
    
    // Attack: Malicious miner crafts NextRoundInput with corrupted LIB
    var currentRound = await GetCurrentRound();
    var maliciousNextRound = GenerateNextRoundInformation(currentRound);
    maliciousNextRound.ConfirmedIrreversibleBlockHeight = long.MaxValue; // Poison LIB
    maliciousNextRound.ConfirmedIrreversibleBlockRoundNumber = long.MaxValue;
    
    var maliciousInput = NextRoundInput.Create(maliciousNextRound, GenerateRandomNumber());
    
    // Execute malicious NextRound - should fail but doesn't due to missing validation
    var result = await ConsensusStub.NextRound.SendAsync(maliciousInput);
    Assert.True(result.TransactionResult.Status == TransactionResultStatus.Mined);
    
    // Verify: LIB is now frozen
    var corruptedLIB = await GetCurrentLIBHeight();
    Assert.Equal(long.MaxValue, corruptedLIB);
    
    // Produce more legitimate blocks - LIB should advance but won't
    for (int i = 0; i < 20; i++)
    {
        await ProduceNormalBlock(initialMiners[i % 3]);
    }
    
    var finalLIB = await GetCurrentLIBHeight();
    Assert.Equal(long.MaxValue, finalLIB); // LIB is permanently frozen
    Assert.True(finalLIB == corruptedLIB, "LIB failed to advance - finality DoS confirmed");
}
```

## Notes

This vulnerability represents a critical consensus-level attack that violates fundamental blockchain safety properties. The absence of input validation for `NextRound` transactions creates an opportunity for any malicious miner to permanently disrupt the finality mechanism. The attack is particularly severe because:

1. It affects the entire network, not just individual transactions
2. Recovery requires exceptional measures (governance intervention or hard fork)  
3. The corrupted state propagates automatically through normal consensus operations
4. Cross-chain security depends on reliable LIB advancement

The fix is straightforward (add validation), but the impact of the unpatched vulnerability is severe enough to warrant immediate attention.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L268-281)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```
